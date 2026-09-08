//! What the peers publish.
//!
//! Sizes are measured, not estimated. They come from serialising real fragments
//! with `concurrent-psbt` (fungi-protocol/concurrent-psbt, branch develop at
//! 24bcca7e6545), which implements the concurrent-PSBT construction roles:
//!
//! ```text
//! empty fragment (concurrent-PSBT globals alone)   105 bytes
//! + one segwit input                               +77   -> 182
//! + one legacy input (prev tx, 2 in / 2 out)      +420   -> 525
//! + one output                                     +73   -> 178
//! + a signature on an input                       +107   -> 289
//! ```
//!
//! Three things the spoken estimates got wrong, and this fixture corrects. A
//! segwit input registration costs about twice the 40 bytes the call cited. An
//! output is NOT smaller than an input — 73 against 77. And every fragment pays
//! a 105-byte floor for the concurrent-PSBT globals, which the estimates left
//! out entirely: even the smallest fragment is about three times a 32-byte
//! message id, so announcing instead of pushing saves less than raw payload
//! sizes suggest.
//!
//! The segwit sizes are used here because they are the common case. The legacy
//! input is 5.5x a segwit one and is the reason previous transactions are the
//! object the validation-dependency work makes separately addressable; a
//! construction of thirteen legacy inputs already approaches the ~7 KB a BIP 77
//! mailbox frame can carry.
//!
//! `Publication.bytes` record the full canonical encoding, which adds roughly
//! 37 bytes of context, type and length prefix on top of the fragment.

use std::collections::HashMap;

use fungi_wire::{
    Body, CanonicalMessage, Message, MessageContext, ProtocolSessionId, ProtocolVersion,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::deps::{DepId, InputDependencies, InputKind};
use crate::meter::FrameId;

/// The three phases of the happy path, in order. Each is a barrier: it
/// converges before the next begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Input registration.
    Inputs,
    /// Output registration.
    Outputs,
    /// Signatures.
    Signatures,
}

/// One message a peer puts into the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// Which peer publishes it.
    pub origin: usize,
    /// The canonical bytes.
    pub bytes: Vec<u8>,
}

/// An open-broadcast workload's parameters.
#[derive(Debug, Clone, Copy)]
pub struct OpenBroadcastConfig {
    /// Node count. The open network is the larger of the two settings.
    pub peers: usize,
    /// Seed for every random draw this workload makes.
    pub seed: u64,
    /// Share of peers that put a co-spend proposal on the network as well as
    /// an ownership proof. NOT a measured figure.
    pub proposal_fraction: f64,
    /// Which proof format co-spend proposals carry. This is the axis that
    /// decides whether the open network wants a different policy at all.
    pub proofs: ProofFormat,
}

/// How large a co-spend proposal's validity proof is.
///
/// Both figures are spoken estimates, not measured artifacts: there is no
/// implementation to serialise a coalition-formation message from yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofFormat {
    /// About two kilobytes.
    Compact,
    /// Tens of kilobytes.
    Naive,
}

impl ProofFormat {
    /// The size band a proposal in this format is drawn from.
    fn bytes(self) -> std::ops::RangeInclusive<usize> {
        match self {
            Self::Compact => PROPOSAL_BYTES,
            Self::Naive => NAIVE_PROPOSAL_BYTES,
        }
    }

    /// What to call it in a table.
    pub fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Naive => "naive",
        }
    }
}

/// A construction workload's parameters. Every field is stated by the caller
/// because three of them are assumptions, not measurements — see the doc on
/// each.
#[derive(Debug, Clone, Copy)]
pub struct ConstructionConfig {
    /// Node count.
    pub peers: usize,
    /// Seed for every random draw this workload makes.
    pub seed: u64,
    /// Share of peers whose input is legacy, and so needs a whole previous
    /// transaction rather than just a prevout. NOT a measured figure: vary it
    /// and report the curve rather than defending one value.
    pub legacy_fraction: f64,
    /// Share of peers that can resolve prevouts locally (full nodes). NOT a
    /// measured figure, same treatment.
    pub full_node_fraction: f64,
    /// Validity proofs each peer publishes per phase, on top of its own
    /// construction fragment: the BFT overhead the happy path does not carry
    /// and that the measurement was asked to be run with.
    ///
    /// NOT a measured count, and their size is not a measured size either —
    /// there is no proof format to serialise one from. It is what closes the
    /// gap between the one fragment per peer per phase this workload started
    /// with and the ten to fifteen messages per peer the target scale is
    /// described in, so it is stated by the caller and swept rather than
    /// fixed. Zero reproduces the happy-path workload exactly, byte for
    /// byte.
    pub validity_proofs_per_phase: usize,
}

/// A whole run's traffic.
#[derive(Debug, Clone)]
pub struct Workload {
    context: MessageContext,
    phases: Vec<Vec<Publication>>,
    /// Whether peer `i` is a full node: it can resolve any dependency object
    /// locally, so it holds all of them a priori.
    full_nodes: Vec<bool>,
    /// Which dependency, if any, a given frame carries — built the same way
    /// `depth::origins_of` keys frames, from the bytes actually published.
    dependency_of: HashMap<FrameId, DepId>,
}

fn payload(rng: &mut StdRng, phase: Phase) -> Vec<u8> {
    let len = match phase {
        // Measured fragment sizes, +/- a few bytes for the variation real
        // scripts and amounts introduce.
        Phase::Inputs => rng.gen_range(178..=186),
        Phase::Outputs => rng.gen_range(174..=182),
        Phase::Signatures => rng.gen_range(283..=295),
    };
    (0..len).map(|_| rng.r#gen::<u8>()).collect()
}

/// Wrap raw dependency bytes the same way every other publication is wrapped:
/// a canonical message under the run's session and version. `Body::Payment`
/// is reused for this rather than `Body::Psbt` — a dependency object is not
/// itself a construction-role fragment, and the registry has no dedicated
/// type for it.
fn publish_dependency(context: MessageContext, origin: usize, bytes: Vec<u8>) -> Publication {
    let message = CanonicalMessage::encode(context, &Message::new(Body::Payment(bytes)))
        .expect("dependency objects are well within the wire limit");
    Publication {
        origin,
        bytes: message.as_bytes().to_vec(),
    }
}

/// A validity proof, spanning the two sizes the call does name: an ownership
/// proof at 200-300 bytes at the low end, a co-spend proposal in the compact
/// format at about 2 KB at the high end. A construction validity proof is
/// described only as "larger messages", so this is a stated assumption. The
/// scheme comparison does not turn on it — announcing beats flooding for
/// anything above about 1.5x the identity width, which every value in this
/// range clears — but the absolute per-peer figures do.
const VALIDITY_PROOF_BYTES: std::ops::RangeInclusive<usize> = 200..=2000;

/// Bytes of the given size, all distinct. Filling with a constant would make
/// two draws of the same length byte-identical, and identity here is the
/// hash of the content — the set would silently dedupe them and the run
/// would never converge on the count it published.
fn filler(rng: &mut StdRng, size: std::ops::RangeInclusive<usize>) -> Vec<u8> {
    let len = rng.gen_range(size);
    (0..len).map(|_| rng.r#gen::<u8>()).collect()
}

/// An ownership proof, per Yuval 4 Sep: "only going to be like about 200
/// 300 bytes". A spoken estimate.
const OWNERSHIP_PROOF_BYTES: std::ops::RangeInclusive<usize> = 200..=300;
/// A co-spend proposal in the compact proof format: "at most like 2
/// kilobytes". A spoken estimate.
const PROPOSAL_BYTES: std::ops::RangeInclusive<usize> = 1200..=2000;
/// The same proposal in the naive proof format: "a few tens of kilobytes".
/// A spoken estimate, and the case that decides whether the open network
/// needs a different policy from a construction.
const NAIVE_PROPOSAL_BYTES: std::ops::RangeInclusive<usize> = 10_000..=40_000;

/// Round a share of `peers` to a peer count, so `0.0` and `1.0` land on
/// exactly none and all of them regardless of `peers`.
fn quota(fraction: f64, peers: usize) -> usize {
    ((fraction * peers as f64).round() as usize).min(peers)
}

/// The three phases of a closed transaction construction, with no
/// dependency objects: one publication per peer per phase, exactly as this
/// harness measured before validation dependencies existed at all.
fn base_phases(peers: usize, seed: u64) -> (MessageContext, Vec<Vec<Publication>>) {
    let context = MessageContext::new(ProtocolSessionId::new([0xa5; 32]), ProtocolVersion::new(1));
    let mut rng = StdRng::seed_from_u64(seed);
    let phases = [Phase::Inputs, Phase::Outputs, Phase::Signatures]
        .into_iter()
        .map(|phase| {
            (0..peers)
                .map(|origin| {
                    let body = match phase {
                        Phase::Inputs => Body::Psbt(payload(&mut rng, phase)),
                        Phase::Outputs => Body::Psbt(payload(&mut rng, phase)),
                        Phase::Signatures => Body::Confirmation(payload(&mut rng, phase)),
                    };
                    let message = CanonicalMessage::encode(context, &Message::new(body))
                        .expect("workload payloads are within the wire limit");
                    Publication {
                        origin,
                        bytes: message.as_bytes().to_vec(),
                    }
                })
                .collect()
        })
        .collect();
    (context, phases)
}

impl Workload {
    /// A closed transaction construction: every peer publishes once per
    /// phase, and no validation dependency ever joins the traffic. This is
    /// the slice 1/2 workload — a construction with no dependencies is a
    /// different workload, not a corner of [`ConstructionConfig`]'s space,
    /// so it keeps its own constructor rather than being expressed as some
    /// combination of fractions on [`Self::construction_with`]. Every number
    /// those slices measured stays reproducible byte for byte because of
    /// that: nothing here changed when dependency modelling was added.
    pub fn construction(peers: usize, seed: u64) -> Self {
        let (context, phases) = base_phases(peers, seed);
        Self {
            context,
            phases,
            full_nodes: vec![false; peers],
            dependency_of: HashMap::new(),
        }
    }

    /// A closed transaction construction, with validation dependencies
    /// joining the Inputs phase.
    ///
    /// Every configuration — including `legacy_fraction: 0.0` and/or
    /// `full_node_fraction: 0.0` — adds, per peer, one `Outpoint` dependency
    /// object: a prevout is what any input commits to, legacy or not, so
    /// there is no fraction of the config space where it goes unpublished.
    /// `full_node_fraction: 0.0` is a meaningful, ordinary configuration —
    /// nobody happens to hold anything a priori this run — not a signal to
    /// skip dependency modelling; only [`Self::construction`] does that, by
    /// being a different constructor entirely. For the peers this run
    /// classifies as legacy (by `legacy_fraction`), one `Txid` dependency
    /// object also joins, for the previous transaction that peer's outpoint
    /// belongs to.
    pub fn construction_with(config: ConstructionConfig) -> Self {
        let ConstructionConfig {
            peers,
            seed,
            legacy_fraction,
            full_node_fraction,
            validity_proofs_per_phase,
        } = config;
        let (context, mut phases) = base_phases(peers, seed);

        let legacy_count = quota(legacy_fraction, peers);
        let full_node_count = quota(full_node_fraction, peers);
        let full_nodes: Vec<bool> = (0..peers).map(|origin| origin < full_node_count).collect();

        let mut dependency_of = HashMap::new();
        for origin in 0..peers {
            let kind = if origin < legacy_count {
                InputKind::Legacy
            } else {
                InputKind::Segwit
            };
            let deps = InputDependencies::derive(seed, origin, kind);

            let outpoint_pub = publish_dependency(context, origin, deps.outpoint.bytes);
            dependency_of.insert(FrameId::of(&outpoint_pub.bytes), deps.outpoint.id);
            phases[0].push(outpoint_pub);

            if let Some(prev_tx) = deps.prev_tx {
                let prev_tx_pub = publish_dependency(context, origin, prev_tx.bytes);
                dependency_of.insert(FrameId::of(&prev_tx_pub.bytes), prev_tx.id);
                phases[0].push(prev_tx_pub);
            }
        }

        // Drawn from an RNG of its own, seeded apart from both the base
        // phases and the dependency derivation, so that adding proofs cannot
        // shift a single byte of the workload measured without them.
        let mut proofs = StdRng::seed_from_u64(seed ^ 0x7bf1_2c0e_9a45_d310);
        for phase in phases.iter_mut() {
            for origin in 0..peers {
                for _ in 0..validity_proofs_per_phase {
                    let proof = filler(&mut proofs, VALIDITY_PROOF_BYTES);
                    phase.push(publish_dependency(context, origin, proof));
                }
            }
        }

        Self {
            context,
            phases,
            full_nodes,
            dependency_of,
        }
    }

    /// The open-broadcast setting: coalition information on a network
    /// anybody can receive from.
    ///
    /// **These sizes are spoken estimates, not measured artifacts**, unlike
    /// every figure in [`Self::construction`] — there is no implementation to
    /// serialise a coalition-formation message from yet. They come from
    /// Yuval's own description: ownership proofs of a couple of hundred
    /// bytes, co-spend proposals of at most a couple of kilobytes, or tens of
    /// kilobytes in the naive proof format. Ratios to the floor survive a
    /// uniform error in them; absolute per-peer figures do not, and the
    /// report says so.
    ///
    /// Structurally it is a different workload, not a parameter of the
    /// construction one: one phase rather than three, because an open
    /// broadcast has no barriers to converge across, and fewer messages from
    /// more peers.
    pub fn open_broadcast(config: OpenBroadcastConfig) -> Self {
        let OpenBroadcastConfig {
            peers,
            seed,
            proposal_fraction,
            proofs,
        } = config;
        let context =
            MessageContext::new(ProtocolSessionId::new([0x5a; 32]), ProtocolVersion::new(1));
        let mut rng = StdRng::seed_from_u64(seed);
        let proposers = quota(proposal_fraction, peers);

        let mut phase = Vec::with_capacity(peers + proposers);
        for origin in 0..peers {
            let proof = filler(&mut rng, OWNERSHIP_PROOF_BYTES);
            phase.push(publish_dependency(context, origin, proof));

            if origin < proposers {
                let proposal = filler(&mut rng, proofs.bytes());
                phase.push(publish_dependency(context, origin, proposal));
            }
        }

        Self {
            context,
            phases: vec![phase],
            full_nodes: vec![false; peers],
            dependency_of: HashMap::new(),
        }
    }

    /// The session and version every publication commits to.
    pub fn context(&self) -> MessageContext {
        self.context
    }

    /// Publications, phase by phase.
    pub fn phases(&self) -> &[Vec<Publication>] {
        &self.phases
    }

    /// Total distinct bytes in the run — the per-peer floor, one copy of
    /// everything.
    pub fn set_bytes(&self) -> usize {
        self.phases.iter().flatten().map(|p| p.bytes.len()).sum()
    }

    /// Whether `node` already holds `id` before any message about it is
    /// sent. Every full node holds every dependency object a priori — it can
    /// resolve any of them locally — and a light client holds none, so `id`
    /// only ever selects between those two answers, not a per-object one.
    pub fn holds_a_priori(&self, node: usize, _id: DepId) -> bool {
        self.full_nodes.get(node).copied().unwrap_or(false)
    }

    /// The dependency object `frame` carries, if any — ordinary input,
    /// output and signature fragments carry none.
    pub fn dependency_of(&self, frame: FrameId) -> Option<DepId> {
        self.dependency_of.get(&frame).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(peers: usize, proposal_fraction: f64, proofs: ProofFormat) -> Workload {
        Workload::open_broadcast(OpenBroadcastConfig {
            peers,
            seed: 3,
            proposal_fraction,
            proofs,
        })
    }

    /// Zero proofs must leave the workload the earlier slices measured
    /// untouched to the byte, or every figure in `FINDINGS.md` that predates
    /// the BFT overhead silently stops being reproducible.
    #[test]
    fn adding_no_validity_proofs_changes_nothing() {
        let base = Workload::construction_with(ConstructionConfig {
            peers: 20,
            seed: 7,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            validity_proofs_per_phase: 0,
        });

        assert_eq!(base.set_bytes(), 19414, "the workload slices 3-6 measured");
        assert_eq!(
            base.phases().iter().map(Vec::len).sum::<usize>(),
            86,
            "one fragment per peer per phase, one outpoint each, a prev tx for the legacy share"
        );
    }

    /// The target scale is described in messages per peer, not in phases, and
    /// the happy path alone does not reach it. This pins that the knob closes
    /// the gap rather than merely existing.
    #[test]
    fn validity_proofs_reach_the_message_count_the_target_scale_is_described_in() {
        let peers = 100;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 0,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            validity_proofs_per_phase: 3,
        });

        let per_peer = workload.phases().iter().map(Vec::len).sum::<usize>() as f64 / peers as f64;
        assert!(
            (10.0..=15.0).contains(&per_peer),
            "ten to fifteen messages per peer: {per_peer}"
        );
    }

    /// An open broadcast has no barriers to converge across, and the count
    /// of publications has to follow the proposal share rather than a phase
    /// structure.
    #[test]
    fn an_open_broadcast_is_one_phase_of_proofs_plus_the_proposals() {
        let peers = 20;
        assert_eq!(
            open(peers, 0.0, ProofFormat::Compact).phases().len(),
            1,
            "one phase"
        );
        assert_eq!(
            open(peers, 0.0, ProofFormat::Compact).phases()[0].len(),
            peers
        );
        assert_eq!(
            open(peers, 0.5, ProofFormat::Compact).phases()[0].len(),
            peers + peers / 2
        );
        assert_eq!(
            open(peers, 1.0, ProofFormat::Compact).phases()[0].len(),
            2 * peers
        );
    }

    /// The proof format is the axis that decides whether the open network
    /// wants its own policy, so the two formats must actually differ by the
    /// order of magnitude the transcript describes — a workload where they
    /// nearly coincide would answer the question by construction.
    #[test]
    fn the_naive_proof_format_dominates_the_set() {
        let peers = 20;
        let compact = open(peers, 0.5, ProofFormat::Compact).set_bytes();
        let naive = open(peers, 0.5, ProofFormat::Naive).set_bytes();

        assert!(
            naive > 8 * compact,
            "naive proofs must dominate: {naive} against {compact}"
        );
    }

    /// Ownership proofs are the floor of this workload, and the report reads
    /// the crossover against the identity width off them.
    #[test]
    fn ownership_proofs_sit_in_their_documented_band() {
        let workload = open(50, 0.0, ProofFormat::Compact);
        for publication in &workload.phases()[0] {
            let payload = publication.bytes.len();
            assert!(
                payload >= *OWNERSHIP_PROOF_BYTES.start()
                    && payload <= OWNERSHIP_PROOF_BYTES.end() + 64,
                "an ownership proof plus its envelope: {payload}"
            );
        }
    }

    #[test]
    fn every_peer_publishes_once_per_phase() {
        let w = Workload::construction(20, 1);
        assert_eq!(w.phases().len(), 3);
        for phase in w.phases() {
            assert_eq!(phase.len(), 20);
            let mut origins: Vec<usize> = phase.iter().map(|p| p.origin).collect();
            origins.sort_unstable();
            origins.dedup();
            assert_eq!(origins.len(), 20, "one publication per peer per phase");
        }
    }

    #[test]
    fn publications_are_canonical_messages_of_the_run_session() {
        let w = Workload::construction(5, 2);
        for phase in w.phases() {
            for publication in phase {
                let context = CanonicalMessage::validate(&publication.bytes)
                    .expect("every publication is canonical");
                assert_eq!(context, w.context());
            }
        }
    }

    #[test]
    fn the_set_size_is_the_sum_of_distinct_publications() {
        use std::collections::HashSet;
        let w = Workload::construction(5, 3);
        let all_publications: Vec<_> = w.phases().iter().flatten().collect();
        let distinct_bytes: HashSet<_> = all_publications.iter().map(|p| &p.bytes).collect();
        assert_eq!(
            distinct_bytes.len(),
            all_publications.len(),
            "all publications must be distinct"
        );
        let summed: usize = distinct_bytes.iter().map(|b| b.len()).sum();
        assert_eq!(w.set_bytes(), summed);
    }

    #[test]
    fn sizes_track_the_phase() {
        let w = Workload::construction(50, 4);
        for (phase_idx, phase_publications) in w.phases().iter().enumerate() {
            let expected_phase = [Phase::Inputs, Phase::Outputs, Phase::Signatures][phase_idx];
            let (min, max) = match expected_phase {
                Phase::Inputs => (178, 186),
                Phase::Outputs => (174, 182),
                Phase::Signatures => (283, 295),
            };
            for publication in phase_publications {
                let canonical =
                    CanonicalMessage::parse(publication.bytes.clone()).expect("valid canonical");
                let message = canonical.decode();
                let payload_len = message.body.payload().len();
                assert!(
                    payload_len >= min && payload_len <= max,
                    "phase {expected_phase:?}: payload {payload_len}B not in range {min}..={max}"
                );
            }
        }
    }

    /// Pins `construction`'s output against a hash taken before this slice
    /// touched `workload.rs` at all (peers=20, seed=7, before any
    /// dependency-modelling code existed). `construction` never joins
    /// dependency objects to the traffic, so this must keep producing
    /// exactly this, and slices 1 and 2's numbers stay reproducible. If this
    /// ever fails, that is a regression in the existing behaviour, not a
    /// value to update.
    #[test]
    fn construction_is_byte_identical_to_before_this_slice() {
        use sha2::{Digest, Sha256};

        let w = Workload::construction(20, 7);
        assert_eq!(w.set_bytes(), 15171);

        let mut all = Vec::new();
        for phase in w.phases() {
            for publication in phase {
                all.extend_from_slice(&publication.bytes);
            }
        }
        let hash = format!("{:x}", Sha256::digest(&all));
        assert_eq!(
            hash,
            "21fff7443b345cb2eacb61515aba0e2d9e807006d0d59090c880d65be175fea7"
        );
    }

    /// `construction` and `construction_with` are different workloads, not
    /// two corners of the same config space: `construction_with` with both
    /// fractions at `0.0` still joins one `Outpoint` dependency object per
    /// peer to the Inputs phase — nobody happens to be legacy or a full node
    /// this run, but every input still commits to a prevout. Only
    /// `construction` itself carries zero dependency objects.
    #[test]
    fn zero_fractions_still_publish_an_outpoint_per_peer() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 10,
            seed: 3,
            legacy_fraction: 0.0,
            full_node_fraction: 0.0,
            validity_proofs_per_phase: 0,
        });
        assert_eq!(
            w.phases()[0].len(),
            20,
            "10 input fragments plus 10 outpoint dependency objects"
        );
        let (outpoints, txids) = dependency_kinds(&w);
        assert_eq!(outpoints, 10, "every peer still publishes its outpoint");
        assert_eq!(txids, 0, "no peer was classified legacy");
        for node in 0..10 {
            assert!(
                !w.holds_a_priori(node, DepId::Outpoint([0; 32], 0)),
                "no peer was classified a full node either"
            );
        }
    }

    #[test]
    fn plain_construction_carries_no_dependency_objects_at_all() {
        let w = Workload::construction(10, 3);
        assert_eq!(w.phases()[0].len(), 10, "input fragments only");
        assert!(w.dependency_of(FrameId::for_test(0)).is_none());
    }

    #[test]
    fn no_full_nodes_means_nobody_holds_anything_a_priori() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 10,
            seed: 3,
            legacy_fraction: 0.3,
            full_node_fraction: 0.0,
            validity_proofs_per_phase: 0,
        });
        for node in 0..10 {
            assert!(!w.holds_a_priori(node, DepId::Txid([0; 32])));
        }
    }

    #[test]
    fn every_peer_a_full_node_means_everyone_holds_everything_a_priori() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 10,
            seed: 3,
            legacy_fraction: 0.0,
            full_node_fraction: 1.0,
            validity_proofs_per_phase: 0,
        });
        for node in 0..10 {
            assert!(w.holds_a_priori(node, DepId::Txid([0; 32])));
            assert!(w.holds_a_priori(node, DepId::Outpoint([0; 32], 0)));
        }
    }

    /// Counts the dependency objects actually published by walking the
    /// Inputs phase and asking `dependency_of` about each frame, rather than
    /// re-deriving the count from `legacy_fraction` — that would restate the
    /// same arithmetic back to itself instead of checking what the workload
    /// produced.
    fn dependency_kinds(w: &Workload) -> (usize, usize) {
        let mut outpoints = 0;
        let mut txids = 0;
        for publication in &w.phases()[0] {
            match w.dependency_of(FrameId::of(&publication.bytes)) {
                Some(DepId::Outpoint(_, _)) => outpoints += 1,
                Some(DepId::Txid(_)) => txids += 1,
                None => {}
            }
        }
        (outpoints, txids)
    }

    #[test]
    fn zero_legacy_fraction_produces_no_txid_objects() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 12,
            seed: 5,
            legacy_fraction: 0.0,
            full_node_fraction: 0.5,
            validity_proofs_per_phase: 0,
        });
        let (outpoints, txids) = dependency_kinds(&w);
        assert_eq!(outpoints, 12, "every peer still publishes its outpoint");
        assert_eq!(txids, 0, "no peer was classified legacy");
    }

    #[test]
    fn full_legacy_fraction_produces_one_txid_per_peer() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 12,
            seed: 5,
            legacy_fraction: 1.0,
            full_node_fraction: 0.0,
            validity_proofs_per_phase: 0,
        });
        let (outpoints, txids) = dependency_kinds(&w);
        assert_eq!(outpoints, 12);
        assert_eq!(txids, 12, "every peer was classified legacy");
    }

    #[test]
    fn dependency_bytes_are_within_their_documented_ranges() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 12,
            seed: 5,
            legacy_fraction: 1.0,
            full_node_fraction: 0.0,
            validity_proofs_per_phase: 0,
        });
        for publication in &w.phases()[0] {
            let Some(id) = w.dependency_of(FrameId::of(&publication.bytes)) else {
                continue;
            };
            let canonical = CanonicalMessage::parse(publication.bytes.clone())
                .expect("dependency publications are canonical");
            let payload_len = canonical.decode().body.payload().len();
            match id {
                DepId::Outpoint(_, _) => assert!(
                    (31..=43).contains(&payload_len),
                    "prevout payload {payload_len}B not in 31..=43"
                ),
                DepId::Txid(_) => assert!(
                    (410..=430).contains(&payload_len),
                    "prev tx payload {payload_len}B not in 410..=430"
                ),
            }
        }
    }
}
