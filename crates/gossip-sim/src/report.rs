//! Reducing an event log to the number the design doc asks for.

use std::collections::{HashMap, HashSet};

use crate::depth::PhaseDepth;
use crate::meter::{Dir, Event, LinkId, NodeId};
use crate::run::Outcome;
use crate::workload::Workload;

/// The framing prefix each frame pays on the wire.
const FRAME_PREFIX: usize = 4;

/// One cell of the grid, reduced.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// Node count.
    pub peers: usize,
    /// Node degree.
    pub degree: usize,
    /// Which sample.
    pub seed: u64,
    /// Whether the group agreed.
    pub converged: bool,
    /// Whether every node's shutdown drain completed cleanly. `false` names
    /// the operational boundary the design asks this harness to find: the
    /// capacity or fanout at which the engine starts failing rather than
    /// silently under-reporting.
    pub drained: bool,
    /// Application bytes handed to a link, per peer. Derived from
    /// `Dir::Sent` events, which are complete once a run's shutdown drain
    /// returns — unlike `Dir::Received` events, which are a lower bound at
    /// teardown (see `Outcome::events`).
    pub per_peer_bytes: usize,
    /// The same with the framing prefix added.
    pub wire_bytes: usize,
    /// Per-peer bytes divided by the set size: the headline.
    pub factor: f64,
    /// Receipts of a message the receiving node already held. A LOWER
    /// BOUND: shutdown drains what a node owes, not what it is owed, so a
    /// forward still in flight toward a node that has already ended is
    /// never received, and so never counted here.
    pub duplicates: usize,
    /// Sends the transport rejected during this run — never on the wire, so
    /// never in `per_peer_bytes` or `factor`. See [`Outcome::failed_sends`].
    pub failed_sends: usize,
    /// Announce/request/respond cycles spent in each phase, for the schemes
    /// that have them. Empty for push, whose latency shows up as hop depth.
    /// The item's acceptance criteria name both, because pull buys bandwidth
    /// with latency and a table showing only bandwidth hides the price.
    pub rounds: Vec<usize>,
    /// The most frames that stood queued on one link direction at once: the
    /// link buffer depth this run actually needed. Reconstructed from the
    /// event log, so it is available for every scheme and measured the same
    /// way for all of them.
    pub peak_link_frames: usize,
    /// Convergence latency per phase, in hops: how many relays a frame
    /// crossed before each node first held it (see [`crate::depth`]). Empty
    /// unless the caller attaches it with [`Row::with_phase_depths`] — a
    /// row built with only [`Row::from_outcome`] carries no hop-depth data.
    pub phase_depths: Vec<PhaseDepth>,
    /// Total bytes of validation-dependency objects sent, across all links.
    /// Derived from `Dir::Sent` events, for the same reason `per_peer_bytes`
    /// is (see its doc and `Outcome::events`). Zero unless the caller
    /// attaches this with [`Row::with_dependency_accounting`].
    pub dependency: Option<DependencyBytes>,
    /// Of `dependency_bytes`, the bytes sent on a link whose receiving end
    /// already held that dependency object a priori — a byte the peer did
    /// not need. This is an UPPER BOUND on what an announce/pull scheme
    /// could save, not the saving itself: such a scheme would still pay
    /// announcement traffic and a round trip to avoid sending these bytes,
    /// and that trade is what the next slice measures.
    /// Every `Dir::Sent` byte this run generated, dependency objects and
    /// ordinary fragments alike — `per_peer_bytes` times `peers`, kept exact
    /// here rather than re-derived through that integer division. Needed to
    /// turn `dependency_bytes_to_holders` into a share of the whole run's
    /// traffic rather than only a share of its own (self-consistency-
    /// checking) denominator — see [`Self::avoidable_traffic_share`].
    pub total_sent_bytes: usize,
}

impl Row {
    /// Reduce one run.
    pub fn from_outcome(outcome: &Outcome, degree: usize, seed: u64) -> Self {
        let sent = outcome.events.iter().filter(|e| e.dir == Dir::Sent);
        let sent_bytes: usize = sent.clone().map(|e| e.bytes).sum();
        let sent_count = sent.count();
        let peers = outcome.peers.max(1);
        let per_peer_bytes = sent_bytes / peers;
        let wire_bytes = (sent_bytes + sent_count * FRAME_PREFIX) / peers;

        // Keyed on (node, frame), not (link, frame): a node's two links can
        // each carry a first receipt of the same frame — arriving over
        // different edges from different neighbours — and both are receipts
        // the node did not already hold. Keying on the link alone collapses
        // those two distinct nodes' events onto one key and miscounts which
        // is the "duplicate". What makes a receipt a duplicate is that the
        // NODE already held the frame, regardless of which link it arrives
        // on this time.
        let mut seen = HashSet::new();
        let duplicates = outcome
            .events
            .iter()
            .filter(|e| e.dir == Dir::Received)
            .filter(|e| !seen.insert((e.node, e.frame)))
            .count();

        Self {
            peers: outcome.peers,
            degree,
            seed,
            converged: outcome.converged,
            drained: outcome.drained,
            per_peer_bytes,
            wire_bytes,
            factor: per_peer_bytes as f64 / outcome.set_bytes.max(1) as f64,
            duplicates,
            failed_sends: outcome.failed_sends,
            rounds: outcome.rounds.clone(),
            peak_link_frames: peak_link_occupancy(&outcome.events),
            phase_depths: Vec::new(),
            dependency: None,
            total_sent_bytes: sent_bytes,
        }
    }

    /// Attach hop-depth statistics computed separately (see
    /// [`crate::depth`]), since they need the workload's phase structure,
    /// which `Outcome` alone does not carry.
    #[must_use]
    pub fn with_phase_depths(mut self, phase_depths: Vec<PhaseDepth>) -> Self {
        self.phase_depths = phase_depths;
        self
    }

    /// Attach validation-dependency accounting, computed from `outcome` and
    /// the `workload` that drove it — `Outcome` alone carries only bare
    /// frames, not which of them are dependency objects or who held what a
    /// priori, so both are needed here the same way [`with_phase_depths`]
    /// needs the workload's phase structure.
    ///
    /// [`with_phase_depths`]: Self::with_phase_depths
    #[must_use]
    pub fn with_dependency_accounting(mut self, outcome: &Outcome, workload: &Workload) -> Self {
        // The receiving end of a `Dir::Sent` event is not the event's own
        // `node` (that is the sender) — it is whichever other node recorded
        // an event on the same link, the same technique `depth::hop_depths`
        // uses to find a link's other endpoint.
        let mut link_nodes: HashMap<LinkId, HashSet<NodeId>> = HashMap::new();
        for event in &outcome.events {
            link_nodes.entry(event.link).or_default().insert(event.node);
        }

        let mut dependency_bytes = 0usize;
        let mut dependency_bytes_to_holders = 0usize;
        for event in outcome.events.iter().filter(|e| e.dir == Dir::Sent) {
            let Some(dep_id) = workload.dependency_of(event.frame) else {
                continue;
            };
            dependency_bytes += event.bytes;
            let receiver = link_nodes
                .get(&event.link)
                .and_then(|nodes| nodes.iter().find(|&&n| n != event.node));
            if let Some(&receiver) = receiver
                && workload.holds_a_priori(receiver.0, dep_id)
            {
                dependency_bytes_to_holders += event.bytes;
            }
        }

        self.dependency = Some(DependencyBytes {
            total: dependency_bytes,
            to_holders: dependency_bytes_to_holders,
        });
        self
    }

    /// The share of `dependency_bytes` that went to a peer who already held
    /// the object.
    ///
    /// This is a SELF-CONSISTENCY CHECK on the accounting, not a finding
    /// about dissemination: under flooding, every dependency object reaches
    /// every peer, so this ratio is the holder fraction
    /// (`full_node_fraction`) by construction, whatever the topology, the
    /// engine or the object sizes are. `FINDINGS.md` documents the identical
    /// trap on the seed axis ("3.05 flat across five seeds is an identity,
    /// not empirical stability") — same discipline applies here. The number
    /// that is NOT an identity is [`Self::avoidable_traffic_share`].
    /// `0.0` when no dependency bytes were sent at all, rather than an
    /// undefined division.
    pub fn dependency_waste_ratio(&self) -> Option<f64> {
        let counted = self.dependency?;
        Some(if counted.total == 0 {
            0.0
        } else {
            counted.to_holders as f64 / counted.total as f64
        })
    }

    /// Avoidable dependency bytes (`dependency_bytes_to_holders`) as a share
    /// of ALL bytes this run sent — fragments and dependency objects alike.
    ///
    /// Unlike [`Self::dependency_waste_ratio`], this is not fixed by the
    /// holder fraction alone: it also depends on the dependency objects'
    /// sizes, `legacy_fraction`, and how much of the run's traffic is
    /// dependency objects rather than fragments at all. It is the real
    /// ceiling on what announce/pull could save end to end — the number
    /// that says whether the next slice's trade (announcement traffic and a
    /// round trip, against avoiding these bytes) is worth taking at all.
    /// `0.0` when the run sent no bytes at all, rather than an undefined
    /// division.
    pub fn avoidable_traffic_share(&self) -> Option<f64> {
        let counted = self.dependency?;
        Some({
            if self.total_sent_bytes == 0 {
                0.0
            } else {
                counted.to_holders as f64 / self.total_sent_bytes as f64
            }
        })
    }
}

/// The most frames that stood queued on one link direction at once.
///
/// A frame occupies a link from the moment its send is recorded — the meter
/// records after the transport has taken it, which is before the peer can
/// receive it — until the peer's matching receive is recorded. Walking the
/// log in order and tracking that difference per direction gives what the
/// link buffer actually had to hold, which is a different and smaller number
/// than how many frames a scheme hands to a link in one go.
///
/// A receipt is attributed to the OTHER endpoint of its link: a link has two
/// ends, so a frame node B took off link L was put on it by whoever else
/// appears on L.
pub fn peak_link_occupancy(events: &[Event]) -> usize {
    let mut ends: HashMap<LinkId, HashSet<NodeId>> = HashMap::new();
    for event in events {
        ends.entry(event.link).or_default().insert(event.node);
    }

    let mut queued: HashMap<(LinkId, NodeId), usize> = HashMap::new();
    let mut peak = 0usize;
    for event in events {
        let sender = match event.dir {
            Dir::Sent => Some(event.node),
            Dir::Received => ends
                .get(&event.link)
                .and_then(|nodes| nodes.iter().find(|node| **node != event.node))
                .copied(),
        };
        let Some(sender) = sender else {
            continue;
        };
        let depth = queued.entry((event.link, sender)).or_default();
        match event.dir {
            Dir::Sent => {
                *depth += 1;
                peak = peak.max(*depth);
            }
            Dir::Received => *depth = depth.saturating_sub(1),
        }
    }
    peak
}

/// Dependency traffic on one run, attached only when it was accounted for.
/// Absence is not zero: a scheme whose frames the accounting cannot read has
/// no figure here, and printing zeroes for it would be a claim rather than a
/// gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyBytes {
    /// Bytes of dependency objects put on the wire.
    pub total: usize,
    /// Of those, the bytes whose receiving end already held the object.
    pub to_holders: usize,
}

/// One line per row, with a header.
///
/// `hops_max` and `hops_mean` each hold one comma-separated value per phase
/// (phase 0 first), so the column stays one field wide however many phases
/// the workload has. Both are empty when a row carries no `phase_depths`.
/// `dep_bytes` and `dep_to_holders` are `0` and `dep_ratio`/`avoid_share` are
/// `0.00` for a row with no dependency accounting attached —
/// indistinguishable from a run that genuinely sent no dependency bytes,
/// which is the correct rendering for both. `dep_ratio` is a
/// self-consistency check on the accounting (see
/// [`Row::dependency_waste_ratio`]); `avoid_share` is the actual finding
/// (see [`Row::avoidable_traffic_share`]).
pub fn render(rows: &[Row]) -> String {
    let mut out = String::from(
        "peers\tdegree\tseed\tconverged\tdrained\tper_peer\twire\tfactor\tdupes\tfailed\trounds\tpeak\thops_max\thops_mean\tdep_bytes\tdep_to_holders\tdep_ratio\tavoid_share\n",
    );
    for r in rows {
        let hops_max = r
            .phase_depths
            .iter()
            .map(|p| p.max_depth.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let rounds = if r.rounds.is_empty() {
            "-".to_string()
        } else {
            r.rounds
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        // A row that carries no dependency accounting has none to report.
        // Printing its zeroes would say the run sent no dependency bytes,
        // which is a claim, not an absence.
        let deps = match r.dependency {
            None => [
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
            ],
            Some(counted) => [
                counted.total.to_string(),
                counted.to_holders.to_string(),
                format!("{:.2}", r.dependency_waste_ratio().unwrap_or_default()),
                format!("{:.2}", r.avoidable_traffic_share().unwrap_or_default()),
            ],
        };
        let peak = r.peak_link_frames;
        let hops_mean = r
            .phase_depths
            .iter()
            .map(|p| format!("{:.2}", p.mean_depth))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            r.peers,
            r.degree,
            r.seed,
            r.converged,
            r.drained,
            r.per_peer_bytes,
            r.wire_bytes,
            r.factor,
            r.duplicates,
            r.failed_sends,
            rounds,
            peak,
            hops_max,
            hops_mean,
            deps[0],
            deps[1],
            deps[2],
            deps[3],
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::meter::{Dir, Event, FrameId, LinkId, NodeId};
    use crate::run::Outcome;

    fn event(node: usize, dir: Dir, frame: u8, bytes: usize) -> Event {
        Event {
            node: NodeId(node),
            link: LinkId(0),
            dir,
            frame: FrameId::for_test(frame),
            bytes,
        }
    }

    #[test]
    fn a_row_reports_the_factor_and_the_duplicates() {
        let outcome = Outcome {
            events: vec![
                event(0, Dir::Sent, 1, 100),
                event(1, Dir::Received, 1, 100),
                event(1, Dir::Received, 1, 100),
            ],
            converged: true,
            drained: true,
            drain_error: None,
            set_bytes: 100,
            peers: 2,
            failed_sends: 0,
            rounds: Vec::new(),
        };
        let row = Row::from_outcome(&outcome, 1, 0);
        assert_eq!(row.per_peer_bytes, 50, "100 sent bytes across 2 peers");
        assert_eq!(row.wire_bytes, 52, "(100 + 1 prefix of 4) over 2 peers");
        assert!(
            (row.factor - 0.5).abs() < f64::EPSILON,
            "50 per-peer bytes over a 100-byte set"
        );
        assert_eq!(row.duplicates, 1, "node 1 received the same frame twice");
        assert!(row.drained);
        assert_eq!(row.failed_sends, 0);
    }

    #[test]
    fn duplicates_are_keyed_on_the_receiving_node_not_the_link() {
        // The same link can carry a first receipt for BOTH of its
        // endpoints: node 0 gets frame 1 for the first time over link 0,
        // and — independently — node 1 also gets frame 1 for the first
        // time over that same link (the ordinary case when a third
        // neighbour floods both of them concurrently). Keying on
        // `(link, frame)` would flag the second of these as a duplicate
        // even though neither node had held the frame before; keying on
        // `(node, frame)` does not, and correctly counts only node 0's
        // later, genuine second receipt.
        let outcome = Outcome {
            events: vec![
                Event {
                    node: NodeId(0),
                    link: LinkId(0),
                    dir: Dir::Received,
                    frame: FrameId::for_test(1),
                    bytes: 10,
                },
                Event {
                    node: NodeId(1),
                    link: LinkId(0),
                    dir: Dir::Received,
                    frame: FrameId::for_test(1),
                    bytes: 10,
                },
                Event {
                    node: NodeId(0),
                    link: LinkId(2),
                    dir: Dir::Received,
                    frame: FrameId::for_test(1),
                    bytes: 10,
                },
            ],
            converged: true,
            drained: true,
            drain_error: None,
            set_bytes: 10,
            peers: 2,
            failed_sends: 0,
            rounds: Vec::new(),
        };
        let row = Row::from_outcome(&outcome, 1, 0);
        assert_eq!(
            row.duplicates, 1,
            "only node 0's second receipt, on a different link, is a duplicate"
        );
    }

    #[test]
    fn the_table_carries_one_line_per_row() {
        let rows = vec![
            Row {
                peers: 5,
                degree: 4,
                seed: 0,
                converged: true,
                drained: true,
                per_peer_bytes: 400,
                wire_bytes: 416,
                factor: 4.0,
                duplicates: 12,
                failed_sends: 0,
                rounds: Vec::new(),
                peak_link_frames: 0,
                phase_depths: vec![PhaseDepth {
                    phase: 0,
                    max_depth: 1,
                    mean_depth: 1.0,
                }],
                dependency: Some(DependencyBytes {
                    total: 100,
                    to_holders: 25,
                }),
                total_sent_bytes: 500,
            },
            Row {
                peers: 5,
                degree: 2,
                seed: 0,
                converged: true,
                drained: false,
                per_peer_bytes: 200,
                wire_bytes: 208,
                factor: 2.0,
                duplicates: 4,
                failed_sends: 2,
                rounds: Vec::new(),
                peak_link_frames: 0,
                phase_depths: Vec::new(),
                dependency: None,
                total_sent_bytes: 1000,
            },
        ];
        let table = render(&rows);
        assert_eq!(table.lines().count(), 3, "header plus two rows");
        assert!(table.contains("4.00"));
        assert!(table.contains("drained"), "the header names the column");
        assert!(table.contains("failed"), "the header names the column");
        assert!(table.contains("hops_max"), "the header names the column");
        assert!(table.contains("dep_bytes"), "the header names the column");
        assert!(
            table
                .lines()
                .nth(2)
                .is_some_and(|line| line.contains("false")),
            "the un-drained row's flag makes it into the rendered line"
        );
        assert!(
            table
                .lines()
                .nth(1)
                .is_some_and(|line| line.ends_with("1\t1.00\t100\t25\t0.25\t0.05")),
            "the first row's phase-0 hop depth and dependency accounting render together"
        );
        assert!(
            table
                .lines()
                .nth(2)
                .is_some_and(|line| line.ends_with("\t\t-\t-\t-\t-")),
            "a row with no phase depths renders empty hops columns, and one with no \
             dependency accounting renders dashes rather than zeroes — absence is \
             not a measurement of zero"
        );
    }

    /// Pins the actual content of the finding that hop depth is
    /// scheduling-dependent (not just that it can exceed 1 once, on one
    /// run): the byte-derived numbers are analytic in `(n, k)` and must
    /// reproduce exactly across two runs of the identical config, which
    /// this asserts. Hop depth is deliberately left unchecked — see the
    /// comment below for why asserting it either way would be wrong.
    ///
    /// This cannot flake the way a "two runs differ" assertion would: it
    /// makes no claim about whether the two runs' hop depth agrees, only
    /// that the byte metrics do, which they always do by construction (see
    /// `FINDINGS.md`'s closed-form derivation of the redundancy factor).
    #[tokio::test]
    async fn byte_metrics_reproduce_exactly_but_hop_depth_is_not_pinned_to() {
        use crate::run::{RunConfig, Schedule, run};
        use crate::topology::Topology;
        use crate::workload::Workload;

        let peers = 20;
        let workload = Workload::construction(peers, 0);
        let config = || RunConfig {
            topology: Topology::complete(peers),
            workload: workload.clone(),
            capacity: 32,
            queue_capacity: 64,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        };

        let first = run(config()).await;
        let second = run(config()).await;
        assert!(
            first.converged && second.converged,
            "both runs must converge for a byte-metric comparison to mean anything"
        );

        let row_a = Row::from_outcome(&first, peers - 1, 0);
        let row_b = Row::from_outcome(&second, peers - 1, 0);

        assert_eq!(
            row_a.per_peer_bytes, row_b.per_peer_bytes,
            "per-peer bytes are analytic in (n, k) and must reproduce exactly"
        );
        assert_eq!(
            row_a.wire_bytes, row_b.wire_bytes,
            "wire bytes are per-peer bytes plus a fixed per-frame prefix, so the same holds"
        );
        assert!(
            (row_a.factor - row_b.factor).abs() < f64::EPSILON,
            "the factor is per-peer bytes over the (seed-fixed) set size, so it follows too"
        );

        // Deliberately NOT asserted: `duplicates` and hop depth. Both are
        // derived from `Dir::Received` events, and receipt order is not
        // something the workload seed controls — it follows whichever
        // branch of a `tokio::select!` a task's peer happened to have ready
        // first, which is a per-process scheduling detail. Empirically,
        // back-to-back runs of this exact config disagree on `duplicates`
        // on 5 out of 5 tries (never equal), while `per_peer_bytes` agreed
        // on 5 out of 5. Asserting either receipt-derived number equal
        // here would flake the moment two runs' scheduling happened to
        // coincide the other way; the point of this test is precisely that
        // the byte metrics don't have that problem and the receipt-derived
        // ones do.
    }

    /// With no full nodes, nobody holds any dependency object a priori, so
    /// every dependency byte sent is to a peer that did not already have
    /// it — `dependency_bytes_to_holders` must be exactly zero, even though
    /// `dependency_bytes` itself is not.
    #[tokio::test]
    async fn no_full_nodes_makes_dependency_bytes_to_holders_exactly_zero() {
        use crate::run::{RunConfig, Schedule, run};
        use crate::topology::Topology;
        use crate::workload::{ConstructionConfig, DependencyAddressing, ProofFormat, Workload};

        let peers = 6;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 1,
            legacy_fraction: 0.5,
            full_node_fraction: 0.0,
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
        });
        let outcome = run(RunConfig {
            topology: Topology::complete(peers),
            workload: workload.clone(),
            capacity: 32,
            queue_capacity: 64,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        })
        .await;
        assert!(outcome.converged);

        let row = Row::from_outcome(&outcome, peers - 1, 1)
            .with_dependency_accounting(&outcome, &workload);
        assert!(
            row.dependency.expect("accounting was attached").total > 0,
            "the mixed workload must actually carry dependency objects"
        );
        assert_eq!(
            row.dependency.expect("accounting was attached").to_holders,
            0
        );
        assert_eq!(row.dependency_waste_ratio(), Some(0.0));
        assert_eq!(
            row.avoidable_traffic_share(),
            Some(0.0),
            "zero avoidable bytes is zero of any denominator"
        );
    }

    /// With every peer a full node, every peer holds every dependency
    /// object a priori, so every dependency byte sent is avoidable —
    /// `dependency_bytes_to_holders` must equal `dependency_bytes` exactly.
    /// That equality (and the resulting `dependency_waste_ratio` of `1.0`)
    /// is the identity `full_node_fraction: 1.0` guarantees structurally —
    /// see that method's doc. `avoidable_traffic_share` is not: it is
    /// dependency bytes as a share of ALL traffic this run sent, which
    /// depends on how much of the traffic is dependency objects at all, not
    /// on the holder fraction.
    #[tokio::test]
    async fn every_peer_a_full_node_makes_every_dependency_byte_avoidable() {
        use crate::run::{RunConfig, Schedule, run};
        use crate::topology::Topology;
        use crate::workload::{ConstructionConfig, DependencyAddressing, ProofFormat, Workload};

        let peers = 6;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 1,
            legacy_fraction: 0.5,
            full_node_fraction: 1.0,
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
        });
        let outcome = run(RunConfig {
            topology: Topology::complete(peers),
            workload: workload.clone(),
            capacity: 32,
            queue_capacity: 64,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        })
        .await;
        assert!(outcome.converged);

        let row = Row::from_outcome(&outcome, peers - 1, 1)
            .with_dependency_accounting(&outcome, &workload);
        let counted = row.dependency.expect("accounting was attached");
        assert!(counted.total > 0);
        assert_eq!(counted.to_holders, counted.total);
        let waste = row
            .dependency_waste_ratio()
            .expect("accounting was attached");
        assert!((waste - 1.0).abs() < f64::EPSILON);
        let share = row
            .avoidable_traffic_share()
            .expect("accounting was attached");
        assert!(
            share > 0.0 && share < 1.0,
            "dependency objects are real traffic but not the whole run's traffic: {share}"
        );
    }

    /// The scale the target names: 20 peers, a mixed
    /// population of legacy and full-node peers, converging and reporting
    /// `dependency_bytes`, `dependency_bytes_to_holders`, and the
    /// non-identity figure this slice actually owes,
    /// `avoidable_traffic_share`.
    ///
    /// A degree-4 graph, not a complete one: the dependency objects roughly
    /// double the Inputs phase's message count over plain `construction`,
    /// and at 20 peers that heavier traffic is enough to walk a complete
    /// graph into the known capacity boundary this crate already documents
    /// (`FINDINGS.md`'s capacity sweep) even at capacity 32 — confirmed by
    /// hand, this exact config hangs on `Topology::complete(20)` at that
    /// capacity. Degree 4 stays well clear of it (clean from capacity 4 up
    /// on the undecorated workload), so it is the cell that exercises this
    /// slice's accounting without also chasing that transport-side defect.
    /// The `timeout` is a tripwire in case a future change moves the
    /// boundary back into this cell: a regression here should fail loudly,
    /// not stall the suite.
    #[tokio::test]
    async fn twenty_peers_with_a_mixed_config_converges_and_reports_both_figures() {
        use crate::run::{RunConfig, Schedule, run};
        use crate::topology::Topology;
        use crate::workload::{ConstructionConfig, DependencyAddressing, ProofFormat, Workload};

        let peers = 20;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 0,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            late_addition_fraction: 1.0,
            dependencies: DependencyAddressing::Separate,
            validity_proofs_per_phase: 0,
            late_addition_overhead: 0,
            proofs: ProofFormat::Compact,
        });
        let topology = Topology::degree_k(peers, 4, 0).expect("n=20, k=4 is feasible");
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            run(RunConfig {
                topology,
                workload: workload.clone(),
                capacity: 32,
                queue_capacity: 64,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            }),
        )
        .await
        .expect("degree 4 at this scale is known to converge promptly, not hang");
        assert!(outcome.converged);
        assert!(outcome.drained);

        let row = Row::from_outcome(&outcome, 4, 0).with_dependency_accounting(&outcome, &workload);
        assert!(
            row.dependency.expect("accounting was attached").total > 0,
            "the mixed config sends dependency traffic"
        );
        let counted = row.dependency.expect("accounting was attached");
        assert!(
            counted.to_holders > 0 && counted.to_holders < counted.total,
            "with full nodes present but not universal, some — not all, not none — \
             dependency bytes land on a peer that already held the object: {} of {}",
            counted.to_holders,
            counted.total,
        );
        let share = row
            .avoidable_traffic_share()
            .expect("accounting was attached");
        assert!(
            share > 0.0 && share < 1.0,
            "avoidable bytes are a real but partial share of this run's total traffic: {share}"
        );
    }
}
