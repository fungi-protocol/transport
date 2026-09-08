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
//! segwit input registration costs about twice the 40 bytes estimated. An
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

use std::collections::{HashMap, HashSet};

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

    /// The size band a validity proof in this format is drawn from.
    ///
    /// A separate band from [`Self::bytes`]: a proposal carries the proof
    /// plus the co-spend it proves, while a construction proof is the proof
    /// alone, so the two do not coincide even in the same format.
    fn validity_bytes(self) -> std::ops::RangeInclusive<usize> {
        match self {
            Self::Compact => COMPACT_VALIDITY_PROOF_BYTES,
            Self::Naive => NAIVE_VALIDITY_PROOF_BYTES,
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

/// Whether a validation dependency travels as an object of its own or inside
/// the input fragment that needs it.
///
/// This is the decision separate addressing exists to make, so it is an axis
/// rather than a fixture: the value of naming an object is exactly what a peer
/// declining it saves, minus what naming it costs, and neither term is known
/// without running both arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyAddressing {
    /// Its own message, identified by txid or outpoint, which a peer that
    /// already holds the object can decline.
    Separate,
    /// Carried inside the input fragment. Content-addressed like every other
    /// message, so no peer can hold it in advance and no announcement is spent
    /// naming it.
    Bundled,
    /// Previous transactions separately, prevouts bundled. The two objects
    /// sit on opposite sides of the break-even: an outpoint identity is the
    /// same width as the prevout it names, so naming one is pure overhead,
    /// while a previous transaction is an order of magnitude larger than its
    /// txid.
    PreviousTransactionsOnly,
}

impl DependencyAddressing {
    /// What to call it in a table.
    pub fn label(self) -> &'static str {
        match self {
            Self::Separate => "separate",
            Self::Bundled => "bundled",
            Self::PreviousTransactionsOnly => "prev-tx only",
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
    /// Share of peers whose validation dependencies are not already known to
    /// every participant, and so have to be replicated.
    ///
    /// The protocol's reason for that is a late addition: an input the signed
    /// proposal does not name. This models the DISSEMINATION consequence of
    /// being one, which is the dependency nobody holds in advance. It does
    /// not model the rest of what a late addition costs; the input has to be
    /// proven spendable by a key the proposal did not name either, so it also
    /// carries an ownership proof certifying that key, an ordinary
    /// content-addressed message of a couple of hundred bytes that no peer
    /// can decline. A real late addition therefore costs more than this
    /// share charges it, by roughly one ownership proof each.
    ///
    /// The remaining peers' inputs are named in the proposal every
    /// participant signed, so their prevouts and previous transactions are
    /// known to all of them before the session starts; separate addressing
    /// exists for what is not named there. NOT a measured figure: `1.0`
    /// treats every input as a late addition and is the ceiling, `0.0` the
    /// floor, so it is swept rather than defended.
    ///
    /// Late additions are taken from the END of the peer range while
    /// [`Self::legacy_fraction`] takes its own from the start, so the two
    /// shares overlap only when they sum past one. Drawing both as prefixes
    /// would make every late addition a legacy input at the shares this is
    /// swept over, which is a correlation the workload has no reason to
    /// assert.
    pub late_addition_fraction: f64,
    /// Content-addressed objects each late addition publishes on top of the
    /// dependency nobody holds in advance, sized as ownership proofs.
    ///
    /// An input the signed proposal does not name has to be proven spendable
    /// by an online key the proposal does not name either, so it arrives with
    /// at least an ownership proof certifying that key. Whether the key is a
    /// gossiped object of its own or a field inside that proof is not
    /// settled, so this counts such objects rather than naming them: at `1`
    /// the cell prices one, and a second would cost the same again.
    ///
    /// No peer can decline any of them — they carry no identity that exists
    /// before the message does — so they sit outside what separate
    /// addressing can be worth, and every table taken at `0` measures the
    /// a-priori-knowledge axis alone, which is what those tables claim.
    pub late_addition_overhead: usize,
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
    /// Whether validation dependencies are separately addressable objects or
    /// ride inside the fragment that needs them.
    pub dependencies: DependencyAddressing,
    /// Which format those proofs are carried in, and so how large they are.
    ///
    /// NOT a measured format, same treatment as the count above. It is the
    /// assumption the per-peer figures are most sensitive to, so it is swept
    /// rather than fixed: the ranking of the schemes survives it, the budget
    /// a constrained device is held to does not.
    pub proofs: ProofFormat,
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
    /// Dependencies of inputs named in the coalition formation proposal, and
    /// so known to every participant before the session starts.
    named_in_proposal: HashSet<DepId>,
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

/// A validity proof in the compact format, spanning an ownership proof at
/// 200-300 bytes at the low end and a compact co-spend proposal at about 2 KB
/// at the high end. A stated assumption: a construction validity proof is
/// described only as a larger message, with no format to serialise one from.
///
/// The scheme comparison does not turn on it; announcing beats flooding for
/// anything above about 1.5x the identity width, which every value in this
/// range clears. The acceptance criterion does turn on it, which is why the
/// format is a caller's input rather than a constant.
const COMPACT_VALIDITY_PROOF_BYTES: std::ops::RangeInclusive<usize> = 200..=2000;
/// The same proof where the range proof is carried naively rather than
/// compacted. The band that decides whether the push baseline still fits a
/// constrained device's budget once the BFT overhead is real.
const NAIVE_VALIDITY_PROOF_BYTES: std::ops::RangeInclusive<usize> = 10_000..=40_000;

/// Bytes of the given size, all distinct. Filling with a constant would make
/// two draws of the same length byte-identical, and identity here is the
/// hash of the content — the set would silently dedupe them and the run
/// would never converge on the count it published.
fn filler(rng: &mut StdRng, size: std::ops::RangeInclusive<usize>) -> Vec<u8> {
    let len = rng.gen_range(size);
    (0..len).map(|_| rng.r#gen::<u8>()).collect()
}

/// An ownership proof: about 200 to 300 bytes. A spoken estimate, not a
/// measured artifact.
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
fn base_phases(
    peers: usize,
    seed: u64,
    carried: &[Vec<u8>],
) -> (MessageContext, Vec<Vec<Publication>>) {
    let context = MessageContext::new(ProtocolSessionId::new([0xa5; 32]), ProtocolVersion::new(1));
    let mut rng = StdRng::seed_from_u64(seed);
    let phases = [Phase::Inputs, Phase::Outputs, Phase::Signatures]
        .into_iter()
        .map(|phase| {
            (0..peers)
                .map(|origin| {
                    let body = match phase {
                        // Drawn before the carried bytes are appended, so a
                        // run that carries none is byte-identical to one that
                        // never had the option.
                        Phase::Inputs => {
                            let mut bytes = payload(&mut rng, phase);
                            if let Some(extra) = carried.get(origin) {
                                bytes.extend_from_slice(extra);
                            }
                            Body::Psbt(bytes)
                        }
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
        let (context, phases) = base_phases(peers, seed, &[]);
        Self {
            context,
            phases,
            full_nodes: vec![false; peers],
            dependency_of: HashMap::new(),
            named_in_proposal: HashSet::new(),
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
            late_addition_fraction,
            late_addition_overhead,
            validity_proofs_per_phase,
            dependencies,
            proofs: proof_format,
        } = config;
        let legacy_count = quota(legacy_fraction, peers);
        let full_node_count = quota(full_node_fraction, peers);
        let late_count = quota(late_addition_fraction, peers);
        let full_nodes: Vec<bool> = (0..peers).map(|origin| origin < full_node_count).collect();

        let derived: Vec<InputDependencies> = (0..peers)
            .map(|origin| {
                let kind = if origin < legacy_count {
                    InputKind::Legacy
                } else {
                    InputKind::Segwit
                };
                InputDependencies::derive(seed, origin, kind)
            })
            .collect();

        // Bundling appends the dependency bytes to the fragment that needs
        // them, so the fragment has to be built already carrying them. The
        // separate arm carries nothing, which reproduces the earlier workload
        // byte for byte.
        let carried: Vec<Vec<u8>> = match dependencies {
            DependencyAddressing::Separate => Vec::new(),
            DependencyAddressing::Bundled => derived
                .iter()
                .map(|deps| {
                    let mut bytes = deps.outpoint.bytes.clone();
                    if let Some(prev_tx) = &deps.prev_tx {
                        bytes.extend_from_slice(&prev_tx.bytes);
                    }
                    bytes
                })
                .collect(),
            DependencyAddressing::PreviousTransactionsOnly => derived
                .iter()
                .map(|deps| deps.outpoint.bytes.clone())
                .collect(),
        };
        let (context, mut phases) = base_phases(peers, seed, &carried);

        let mut dependency_of = HashMap::new();
        let mut named_in_proposal = HashSet::new();
        for (origin, deps) in derived.into_iter().enumerate() {
            // Late additions come from the end of the range; see the field's
            // own doc for why they are not drawn as a prefix.
            let late = origin >= peers.saturating_sub(late_count);

            // A bundled dependency left with its fragment and has no identity
            // to name, so there is nothing here for a peer to decline.
            if dependencies == DependencyAddressing::Bundled {
                continue;
            }

            if dependencies == DependencyAddressing::PreviousTransactionsOnly {
                // The prevout left with the fragment; only the previous
                // transaction keeps an identity of its own.
                if let Some(prev_tx) = deps.prev_tx {
                    if !late {
                        named_in_proposal.insert(prev_tx.id);
                    }
                    let publication = publish_dependency(context, origin, prev_tx.bytes);
                    dependency_of.insert(FrameId::of(&publication.bytes), prev_tx.id);
                    phases[0].push(publication);
                }
                continue;
            }

            if !late {
                named_in_proposal.insert(deps.outpoint.id);
            }
            let outpoint_pub = publish_dependency(context, origin, deps.outpoint.bytes);
            dependency_of.insert(FrameId::of(&outpoint_pub.bytes), deps.outpoint.id);
            phases[0].push(outpoint_pub);

            if let Some(prev_tx) = deps.prev_tx {
                if !late {
                    named_in_proposal.insert(prev_tx.id);
                }
                let prev_tx_pub = publish_dependency(context, origin, prev_tx.bytes);
                dependency_of.insert(FrameId::of(&prev_tx_pub.bytes), prev_tx.id);
                phases[0].push(prev_tx_pub);
            }
        }

        // Seeded apart for the same reason the proofs below are: a table run
        // at zero overhead must read identically whether or not the axis
        // exists.
        let mut overheads = StdRng::seed_from_u64(seed ^ 0x51a7_e309_c4b6_2f8d);
        for origin in peers.saturating_sub(late_count)..peers {
            for _ in 0..late_addition_overhead {
                let proof = filler(&mut overheads, OWNERSHIP_PROOF_BYTES);
                phases[0].push(publish_dependency(context, origin, proof));
            }
        }

        // Drawn from an RNG of its own, seeded apart from both the base
        // phases and the dependency derivation, so that adding proofs cannot
        // shift a single byte of the workload measured without them.
        let mut proofs = StdRng::seed_from_u64(seed ^ 0x7bf1_2c0e_9a45_d310);
        for phase in phases.iter_mut() {
            for origin in 0..peers {
                for _ in 0..validity_proofs_per_phase {
                    let proof = filler(&mut proofs, proof_format.validity_bytes());
                    phase.push(publish_dependency(context, origin, proof));
                }
            }
        }

        Self {
            context,
            phases,
            full_nodes,
            dependency_of,
            named_in_proposal,
        }
    }

    /// The open-broadcast setting: coalition information on a network
    /// anybody can receive from.
    ///
    /// **These sizes are spoken estimates, not measured artifacts**, unlike
    /// every figure in [`Self::construction`]: there is no implementation to
    /// serialise a coalition-formation message from yet. They span ownership
    /// proofs of a couple of hundred bytes, co-spend proposals of at most a
    /// couple of kilobytes, and tens of kilobytes in the naive proof format.
    /// Ratios to the floor survive a uniform error in them; absolute per-peer
    /// figures do not, and the report says so.
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
            named_in_proposal: HashSet::new(),
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
    pub fn holds_a_priori(&self, node: usize, id: DepId) -> bool {
        // Two independent reasons to already hold it, and they are not the
        // same kind of fact: naming in the signed proposal is a property of
        // the object and reaches every participant, while resolving locally
        // is a property of this peer.
        self.named_in_proposal.contains(&id) || self.full_nodes.get(node).copied().unwrap_or(false)
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 3,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
    /// order of magnitude that separates them; a workload where they nearly
    /// coincide would answer the question by construction.
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

    /// Every peer's dependency objects, as (id, node) pairs the a-priori
    /// question can be asked of.
    fn dependency_ids(workload: &Workload) -> Vec<DepId> {
        workload
            .phases()
            .iter()
            .flatten()
            .filter_map(|p| workload.dependency_of(FrameId::of(&p.bytes)))
            .collect()
    }

    /// The counterfactual the separate-addressing decision rests on. A
    /// dependency carried inside the input fragment is content-addressed like
    /// any other message: no identity of its own, so no peer can say it
    /// already holds it, and no announcement is spent naming it. Addressing
    /// it separately is only worth what declining is worth, and that trade
    /// has to be measured against this arm rather than assumed.
    #[test]
    fn bundling_a_dependency_leaves_no_identity_a_peer_could_decline() {
        let config = ConstructionConfig {
            peers: 20,
            seed: 7,
            legacy_fraction: 0.3,
            full_node_fraction: 1.0,
            late_addition_fraction: 1.0,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
            dependencies: DependencyAddressing::Separate,
        };
        let separate = Workload::construction_with(config);
        let bundled = Workload::construction_with(ConstructionConfig {
            dependencies: DependencyAddressing::Bundled,
            ..config
        });

        assert!(
            !dependency_ids(&separate).is_empty(),
            "separate objects carry the identities a peer declines by"
        );
        assert!(
            dependency_ids(&bundled).is_empty(),
            "a bundled dependency has no identity of its own"
        );
    }

    /// Bundling must move the dependency bytes into the fragment, not drop
    /// them: a cheaper arm that simply sends less would make separate
    /// addressing look worse for free.
    #[test]
    fn bundling_moves_the_dependency_bytes_rather_than_dropping_them() {
        let config = ConstructionConfig {
            peers: 20,
            seed: 7,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            late_addition_fraction: 1.0,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
            dependencies: DependencyAddressing::Separate,
        };
        let separate = Workload::construction_with(config).set_bytes();
        let bundled = Workload::construction_with(ConstructionConfig {
            dependencies: DependencyAddressing::Bundled,
            ..config
        })
        .set_bytes();

        assert!(
            bundled < separate,
            "bundling saves one envelope per dependency: {bundled} against {separate}"
        );
        assert!(
            bundled * 10 > separate * 9,
            "the payload must survive the move: {bundled} against {separate}"
        );
    }

    /// An input named in the coalition formation proposal every participant
    /// signed carries no dependency any of them has to be sent: the prevout
    /// or previous transaction is known to all of them before the session
    /// starts. Separate addressing exists for what is NOT named there, so a
    /// workload where every input is a late addition measures the ceiling
    /// rather than the setting, and a peer's ability to decline has to be a
    /// property of the object, not only of whether that peer is a full node.
    #[test]
    fn a_dependency_named_in_the_coalition_proposal_is_held_by_every_peer() {
        let peers = 20;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 7,
            legacy_fraction: 0.3,
            // Nobody can resolve anything locally, so holding it can only
            // come from the proposal.
            full_node_fraction: 0.0,
            late_addition_fraction: 0.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
        });

        let ids = dependency_ids(&workload);
        assert!(!ids.is_empty(), "the workload must publish dependencies");
        for id in ids {
            for node in 0..peers {
                assert!(
                    workload.holds_a_priori(node, id),
                    "{id:?} is named in the proposal, so node {node} already holds it"
                );
            }
        }
    }

    /// The complement, and the configuration every measured figure was taken
    /// under: an input added after the proposal was signed is known to no
    /// participant that cannot resolve it itself.
    #[test]
    fn a_late_addition_is_held_only_by_peers_that_can_resolve_it() {
        let peers = 20;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 7,
            legacy_fraction: 0.3,
            full_node_fraction: 0.0,
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
        });

        let ids = dependency_ids(&workload);
        assert!(!ids.is_empty(), "the workload must publish dependencies");
        for id in ids {
            for node in 0..peers {
                assert!(
                    !workload.holds_a_priori(node, id),
                    "{id:?} is a late addition and node {node} is a light client"
                );
            }
        }
    }

    /// The construction workload carries validity proofs too, and their size
    /// is the assumption the acceptance criterion is most sensitive to: the
    /// happy-path fragments are all measured, while a proof has no format to
    /// serialise from. The two bands must therefore be reachable from a
    /// construction and differ by the order of magnitude that separates a
    /// compact proof from a naive one, or the criterion is only ever tested
    /// under the assumption that flatters it.
    #[test]
    fn a_construction_can_carry_naive_validity_proofs_as_well_as_compact_ones() {
        let base = ConstructionConfig {
            peers: 20,
            seed: 5,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 3,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
        };
        let compact = Workload::construction_with(base).set_bytes();
        let naive = Workload::construction_with(ConstructionConfig {
            proofs: ProofFormat::Naive,
            ..base
        })
        .set_bytes();

        assert!(
            naive > 8 * compact,
            "naive validity proofs must dominate the set: {naive} against {compact}"
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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

    fn late_cfg(peers: usize, late: f64, overhead: usize) -> ConstructionConfig {
        ConstructionConfig {
            peers,
            seed: 5,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            late_addition_fraction: late,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: overhead,
            proofs: ProofFormat::Compact,
        }
    }

    /// Arriving late costs more than the dependency nobody holds in advance:
    /// the input has to be proven spendable by a key the signed proposal does
    /// not name, which is an object of its own.
    #[test]
    fn a_late_addition_carries_one_object_per_unit_of_overhead() {
        let base = Workload::construction_with(late_cfg(12, 1.0, 0));
        let with = Workload::construction_with(late_cfg(12, 1.0, 1));
        assert_eq!(
            with.phases()[0].len() - base.phases()[0].len(),
            12,
            "one object per peer that arrives late"
        );
    }

    /// The charge follows the share that arrives late, not the peer count.
    #[test]
    fn overhead_is_charged_only_to_peers_that_arrive_late() {
        let base = Workload::construction_with(late_cfg(12, 0.0, 0));
        let with = Workload::construction_with(late_cfg(12, 0.0, 1));
        assert_eq!(
            base.phases()[0].len(),
            with.phases()[0].len(),
            "nobody arrives late, so the overhead has nobody to charge"
        );
    }

    /// The object exists to be undeclinable. If it carried a dependency
    /// identity a holder could decline it, and it would be measuring the
    /// axis it was added to sit outside of.
    #[test]
    fn the_overhead_object_carries_no_identity_a_peer_could_hold() {
        let base = Workload::construction_with(late_cfg(12, 1.0, 0));
        let with = Workload::construction_with(late_cfg(12, 1.0, 1));
        let named = |w: &Workload| {
            w.phases()[0]
                .iter()
                .filter(|p| w.dependency_of(FrameId::of(&p.bytes)).is_some())
                .count()
        };
        assert_eq!(
            named(&base),
            named(&with),
            "the overhead adds content, never a dependency identity"
        );
    }

    /// Adding the charge must not move a byte of what was measured without
    /// it, or every figure taken at overhead zero would silently restate.
    #[test]
    fn overhead_does_not_shift_the_workload_measured_without_it() {
        let base = Workload::construction_with(late_cfg(12, 1.0, 0));
        let with = Workload::construction_with(late_cfg(12, 1.0, 1));
        let base_bytes: Vec<_> = base.phases()[0].iter().map(|p| p.bytes.clone()).collect();
        let carried: Vec<_> = with.phases()[0]
            .iter()
            .map(|p| p.bytes.clone())
            .filter(|b| base_bytes.contains(b))
            .collect();
        assert_eq!(
            carried.len(),
            base_bytes.len(),
            "every object published without the overhead is still published with it"
        );
    }

    #[test]
    fn zero_legacy_fraction_produces_no_txid_objects() {
        let w = Workload::construction_with(ConstructionConfig {
            peers: 12,
            seed: 5,
            legacy_fraction: 0.0,
            full_node_fraction: 0.5,
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
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
