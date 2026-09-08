//! One run: wire a graph, publish a workload, wait for convergence, hand back
//! the event log.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fungi_transport::mem::{MemConfig, duplex};
use fungi_transport::{AssumeSessionBound, BroadcastChannel, GossipBroadcast, GossipConfig};
use fungi_transport::{RecvError, SendError};

use crate::async_pull::{AnnounceBroadcast, PullConfig};
use crate::engine::ObjId;
use fungi_wire::{CanonicalMessage, MessageSet};
use tokio::sync::Notify;

use crate::engine::Engine;
use crate::meter::{Event, LinkId, Metered, NodeId, Recorder};
use crate::topology::Topology;
use crate::workload::Workload;

/// How fast a phase's publications are produced relative to how fast the
/// group consumes what they generate.
///
/// The byte totals do not depend on this — every message still crosses
/// `k + (n-1)(k-1)` links whenever it is published — but queue occupancy
/// does, and so do the duplicate counts and the capacity at which the engine
/// stops being able to preserve convergence. It is the producer side of the
/// same knob the link buffer is the consumer side of.
///
/// Modelled engines ignore it: the lockstep driver takes every frame off the
/// link as it is put on, so it has no queue for a schedule to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// Every publication of a phase goes in before any of it is drained.
    /// The case where the channel is usually full.
    Burst,
    /// A phase goes in this many publications at a time, each slice drained
    /// to convergence before the next is published. The case where the
    /// channel is usually empty.
    Staggered {
        /// Publications per slice.
        publications: usize,
    },
}

impl Schedule {
    /// How many of a phase's `total` publications go in before a drain.
    fn slice(self, total: usize) -> usize {
        match self {
            Self::Burst => total.max(1),
            Self::Staggered { publications } => publications.max(1),
        }
    }
}

/// One cell of the grid.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// The peer graph.
    pub topology: Topology,
    /// What the peers publish.
    pub workload: Workload,
    /// Per-direction link buffer.
    pub capacity: usize,
    /// The engine's own queue bound, one per internal stage. Stated by the
    /// caller rather than defaulted, because it is a distinct resource from
    /// [`Self::capacity`] and fails in a distinct way: the engine's queues
    /// are served by `try_send` and end the group outright when they
    /// overflow, while a full link buffer parks the sending task. A value
    /// that is comfortable at twenty peers ends the group at forty, so it is
    /// an axis of the grid, not a constant.
    pub queue_capacity: usize,
    /// How a phase's publications are fed in relative to the draining of
    /// what they generate.
    pub schedule: Schedule,
    /// Which dissemination scheme to run. The single selection point: a
    /// cell differs from another by configuration, never by which driver
    /// was reached for, so a difference between two rows is a difference
    /// between schemes.
    pub engine: Engine,
}

/// What one run produced.
#[derive(Debug)]
pub struct Outcome {
    /// Every frame that crossed every link. `Dir::Sent` events are complete
    /// once the shutdown drain returns: a node only stops sending once it
    /// has nothing left to forward, and the drain waits for that. `Dir::
    /// Received` events are a LOWER BOUND, not a complete count: shutdown
    /// drains what a node owes, not what it is owed, so a node that ends
    /// stops receiving — forwards a peer still had in flight at that
    /// node's teardown are never recorded, even though the peer's matching
    /// `Sent` event is. Derive the redundancy factor from `Dir::Sent`.
    pub events: Vec<Event>,
    /// Whether all nodes ended with the same commitment.
    pub converged: bool,
    /// Why the first drain that failed did, when one did. `drained: false`
    /// on its own says a run hit the operational boundary this harness
    /// exists to find without saying which one, and reading a table row
    /// that way costs more than carrying the reason.
    pub drain_error: Option<String>,
    /// Whether every node's shutdown drain completed cleanly. `false` means
    /// at least one node reported a failure other than a peer that had
    /// already finished (`LinkClosed`/`AllLinksEnded`) — the engine ending a
    /// group because a queue could not preserve convergence, which is an
    /// operational boundary this harness exists to find, not a bug in it.
    pub drained: bool,
    /// The per-peer floor: one copy of every published message.
    pub set_bytes: usize,
    /// Node count.
    pub peers: usize,
    /// Sends the transport itself rejected (never events, since nothing
    /// reached the wire). Made visible rather than eliminated: a healthy
    /// complete-graph run still records a few, because shutdown proceeds
    /// concurrently and a node that finishes first closes its links while a
    /// peer's queued forward is still in flight. A count that grows well
    /// past that baseline says a link or a bounded queue is failing for real.
    pub failed_sends: usize,
    /// Announce/request/respond cycles spent in each phase, for the schemes
    /// that have them. Empty for the asynchronous engine, which has no
    /// rounds — its latency shows up as hop depth instead.
    pub rounds: Vec<usize>,
}

/// One node, under whichever asynchronous engine this cell selects. Both
/// expose the same broadcast surface, so the driver below is the same driver
/// for either — a difference between two rows is a difference between
/// schemes, not between drivers.
enum Node {
    /// The production engine.
    Push(GossipBroadcast),
    /// The announce/pull engine built to its shape.
    Pull(AnnounceBroadcast),
}

impl Node {
    /// Publish one message to the group.
    async fn send(&mut self, msg: &[u8]) -> Result<(), SendError> {
        match self {
            Self::Push(node) => node.send(msg).await,
            Self::Pull(node) => node.send(msg).await,
        }
    }

    /// Take the next message this node learned of.
    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        match self {
            Self::Push(node) => node.recv().await,
            Self::Pull(node) => node.recv().await,
        }
    }

    /// Drain and end this node. The two engines report different error
    /// types; what the harness needs is whether the local drain completed.
    async fn shutdown(self) -> Result<(), String> {
        match self {
            Self::Push(node) => node.shutdown().await.map_err(|error| error.to_string()),
            Self::Pull(node) => node.shutdown().await.map_err(|error| format!("{error:?}")),
        }
    }
}

/// Wire the graph, publish everything, drain, and report.
pub async fn run(config: RunConfig) -> Outcome {
    let RunConfig {
        topology,
        workload,
        capacity,
        queue_capacity,
        schedule,
        engine,
    } = config;
    assert!(
        matches!(engine, Engine::Push | Engine::AsyncAnnouncePull { .. }),
        "run() drives the asynchronous engines; every modelled scheme goes \
         through engine::run_modelled"
    );
    let log = Arc::new(Recorder::default());
    let cfg = MemConfig {
        capacity: Some(capacity),
        ..MemConfig::default()
    };

    // One duplex per edge; both ends carry the same link id, so a receipt can
    // be traced back to the peer that sent it.
    let mut links: HashMap<usize, Vec<_>> = HashMap::new();
    for (index, &(a, b)) in topology.edges.iter().enumerate() {
        let id = LinkId(index as u32);
        let (left, right) = duplex(cfg.clone());
        links.entry(a).or_default().push(Metered::new(
            AssumeSessionBound(left),
            NodeId(a),
            id,
            log.clone(),
        ));
        links.entry(b).or_default().push(Metered::new(
            AssumeSessionBound(right),
            NodeId(b),
            id,
            log.clone(),
        ));
    }

    let mut sets: Vec<MessageSet> = (0..topology.n)
        .map(|_| MessageSet::new(workload.context()))
        .collect();

    // A peer that resolves a dependency locally holds it before anything
    // crosses a link, and announces it like anything else it holds. Push has
    // no way to use that — it cannot decline what is being forwarded — so it
    // is granted only to the scheme that can, which is the comparison.
    let shared = Arc::new(workload.clone());
    let mut known: Vec<Vec<(ObjId, Arc<[u8]>)>> = match engine {
        Engine::Push => vec![Vec::new(); topology.n],
        _ => {
            let mut known = vec![Vec::new(); topology.n];
            for publication in workload.phases().iter().flatten() {
                let id = ObjId::of(&publication.bytes, &workload);
                let ObjId::Dependency(dep) = id else { continue };
                let bytes: Arc<[u8]> = Arc::from(publication.bytes.as_slice());
                for (node, holdings) in known.iter_mut().enumerate() {
                    if node != publication.origin && workload.holds_a_priori(node, dep) {
                        holdings.push((id, bytes.clone()));
                        let message = CanonicalMessage::parse(publication.bytes.clone())
                            .expect("workload publications are canonical");
                        sets[node]
                            .insert(message)
                            .expect("a resolved dependency belongs to this session");
                    }
                }
            }
            known
        }
    };

    let mut nodes: Vec<Node> = (0..topology.n)
        .map(|node| {
            let channels = links.remove(&node).unwrap_or_default();
            match engine {
                Engine::Push => Node::Push(GossipBroadcast::with_config(
                    channels,
                    GossipConfig { queue_capacity },
                )),
                _ => Node::Pull(AnnounceBroadcast::with_config(
                    channels,
                    PullConfig {
                        queue_capacity,
                        batch: match engine {
                            Engine::AsyncAnnouncePull { batch } => batch,
                            _ => 1,
                        },
                    },
                    shared.clone(),
                    std::mem::take(&mut known[node]),
                )),
            }
        })
        .collect();

    let expected: usize = workload.phases().iter().map(Vec::len).sum();
    let mut published = 0usize;
    // Whether every send and receive this run has attempted has succeeded
    // so far. A node whose engine ended a group — a queue that could not
    // preserve convergence, or a peer whose own link died — reports that
    // through `SendError`/`RecvError::Closed` from then on; that is the
    // operational boundary this harness exists to find, not a bug in it, so
    // hitting it stops driving the workload rather than panicking. `drained`
    // still carries the detail of what failed, from `shutdown` below.
    let mut healthy = true;

    'phases: for phase in workload.phases() {
        for slice in phase.chunks(schedule.slice(phase.len())) {
            for publication in slice {
                if nodes[publication.origin]
                    .send(&publication.bytes)
                    .await
                    .is_err()
                {
                    healthy = false;
                    break 'phases;
                }
                // The publisher holds its own message: gossip delivers to others.
                let message = CanonicalMessage::parse(publication.bytes.clone())
                    .expect("workload publications are canonical");
                sets[publication.origin]
                    .insert(message)
                    .expect("a node's own publication belongs to its set");
            }
            published += slice.len();

            // Every node ends the phase holding every publication so far — the
            // phases are barriers. Drain them CONCURRENTLY, and keep EVERY node
            // draining until the WHOLE GROUP reaches `published`, not just its
            // own set: a node that stops calling `recv` the instant its own set
            // is complete leaves duplicates still in flight toward it sitting
            // unconsumed, which fills its incoming buffer and blocks whichever
            // peer is still trying to forward to it — wedging the run even
            // though nothing has actually failed. `MessageSet::insert` is
            // idempotent, so a node past its own completion can keep consuming
            // and simply absorb what arrives.
            //
            // `lens` publishes each node's current set length so every task can
            // check the group-wide condition; `progressed` wakes every waiting
            // task whenever any one of them changes it, so a node with nothing
            // left to gain for itself does not block forever in `recv` once the
            // group actually finishes. `aborted` lets a real engine failure on
            // one node stop every other node's wait immediately, rather than
            // having them wait forever for a peer that can no longer converge.
            let lens: Vec<AtomicUsize> = sets.iter().map(|s| AtomicUsize::new(s.len())).collect();
            let progressed = Notify::new();
            let aborted = AtomicBool::new(false);

            let drains = nodes.iter_mut().zip(sets.iter_mut()).enumerate().map(
                |(i, (node, set))| {
                    let lens = &lens;
                    let progressed = &progressed;
                    let aborted = &aborted;
                    async move {
                        loop {
                            // `enable`d (not just created) before either
                            // check below: with several tasks racing on the
                            // same `Notify`, a `Notified` future that is
                            // merely constructed does not yet count as a
                            // registered waiter, so a `notify_waiters` call
                            // landing between construction and the first
                            // poll would otherwise be lost. `enable` forces
                            // that registration synchronously.
                            let woken = progressed.notified();
                            tokio::pin!(woken);
                            woken.as_mut().enable();
                            if aborted.load(Ordering::Acquire) {
                                return false;
                            }
                            if lens.iter().all(|l| l.load(Ordering::Acquire) >= published) {
                                return true;
                            }
                            tokio::select! {
                                _ = woken.as_mut() => {}
                                result = node.recv() => {
                                    match result {
                                        Ok(bytes) => {
                                            let message = CanonicalMessage::parse(bytes)
                                                .expect("relayed bytes stay canonical");
                                            set.insert(message)
                                                .expect("every message belongs to this session");
                                            lens[i].store(set.len(), Ordering::Release);
                                            progressed.notify_waiters();
                                        }
                                        // This node's group ended before it
                                        // converged; nobody can reach the
                                        // group-wide target now, so stop
                                        // everyone rather than let them wait
                                        // on a peer that cannot finish.
                                        Err(_) => {
                                            aborted.store(true, Ordering::Release);
                                            progressed.notify_waiters();
                                            return false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            );
            if !futures_util::future::join_all(drains)
                .await
                .into_iter()
                .all(|ok| ok)
            {
                healthy = false;
            }
            if !healthy {
                break 'phases;
            }
        }
    }

    let first = sets[0].commitment();
    let converged = healthy
        && sets
            .iter()
            .all(|s| s.commitment() == first && s.len() == expected);

    // Consumer-level convergence is not transport quiescence: the message
    // that completed the last node's set may still have redundant copies
    // queued for forwarding elsewhere, and the number this harness exists to
    // produce is the traffic the scheme generated, in-flight forwards
    // included. Shut every node down CONCURRENTLY so those forwards finish
    // crossing the wire before the log is read — one at a time would have a
    // node that finishes first close its links, and the peers still draining
    // would see LinkClosed before their own trailing forwards crossed.
    let shutdowns = nodes.into_iter().map(Node::shutdown);
    let drain_error = futures_util::future::join_all(shutdowns)
        .await
        .into_iter()
        .find_map(Result::err);
    let drained = drain_error.is_none();

    Outcome {
        events: log.take_events(),
        converged,
        drained,
        drain_error,
        set_bytes: workload.set_bytes(),
        peers: topology.n,
        failed_sends: log.failed_sends(),
        rounds: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::Dir;
    use crate::workload::ConstructionConfig;
    use std::time::Duration;

    /// 20 peers, degree 4, capacity 2 sits on the boundary this sweep
    /// exists to find (see `src/bin/run.rs`'s capacity sweep): this slice's
    /// own measurements show this exact cell sometimes converges cleanly
    /// and sometimes only partially drains, as a function of runtime
    /// scheduling rather than the workload seed — the same kind of
    /// non-determinism ruling 1 pins down for hop depth in
    /// `report.rs`'s `byte_metrics_reproduce_exactly_but_hop_depth_is_not_pinned_to`.
    /// A test parked here must not assert a particular converged/drained/
    /// failed_sends combination, since a run where the marginal cell
    /// happens to converge cleanly would fail such an assertion — that
    /// used to be exactly this test, and it flaked for exactly that
    /// reason. What actually holds regardless of which way the scheduling
    /// falls: the run terminates (bounded by a generous timeout so a
    /// regression that turns this into a hang fails loudly instead of
    /// stalling the suite) without panicking, and the `Outcome` it reports
    /// is structurally sound — not corrupted by whichever branch of the
    /// drain loop's `tokio::select!` happened to fire.
    #[tokio::test]
    async fn a_strained_link_buffer_terminates_with_a_coherent_outcome() {
        let peers = 20;
        let workload = Workload::construction(peers, 0);
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            run(RunConfig {
                topology: Topology::degree_k(peers, 4, 0).expect("feasible at n=20, k=4"),
                workload: workload.clone(),
                capacity: 2,
                queue_capacity: 64,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            }),
        )
        .await
        .expect("this capacity is known to resolve promptly, not hang");

        // Deliberately not asserted: `converged`, `drained`, or a specific
        // `failed_sends` value — this exact cell's whole point is that
        // those are not pinned down by the seed. What remains invariant
        // regardless of which way the boundary falls this run:
        assert_eq!(
            outcome.peers, peers,
            "node count is structural, not a function of how the run went"
        );
        assert_eq!(
            outcome.set_bytes,
            workload.set_bytes(),
            "the published set is fixed by the workload, independent of transport behavior"
        );
        assert!(
            outcome.failed_sends <= outcome.peers * outcome.peers,
            "a failed-send counter that free-runs past the number of ordered \
             peer pairs would mean the drain fix is double-counting, not that \
             the boundary shifted"
        );
    }

    /// A capacity this thin, on a graph this dense, used to hang: the drain
    /// never returned at all. It does now, and it converges, because a link
    /// whose peer has stopped talking abandons the forward it was parked on
    /// instead of waiting on it forever (fixed upstream in `fungi-transport`
    /// by `461a3ea` and `1a16a2b`).
    ///
    /// What a thin buffer costs is no longer liveness but redundancy: the
    /// forwards it abandons are the copies a dense graph did not need, so the
    /// group still agrees and simply sends less. `drained` reports that as a
    /// failure to flush, which is the honest way to surface it.
    #[tokio::test]
    async fn a_thin_buffer_abandons_redundant_forwards_instead_of_hanging() {
        let peers = 7;
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            run(RunConfig {
                topology: Topology::complete(peers),
                workload: Workload::construction(peers, 0),
                capacity: 1,
                queue_capacity: 64,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            }),
        )
        .await
        .expect("a thin buffer costs redundancy, not the run");

        assert!(
            outcome.converged,
            "the group still agrees on the whole set: what is abandoned is redundant"
        );
    }

    /// The larger half of the same finding. Twenty peers on a complete graph
    /// used to wedge at capacities 1, 2, 4 AND 8, with only 32 converging.
    /// Every one of them converges now; what separates them is how much
    /// redundancy survives, which the capacity sweep in `src/bin/run.rs`
    /// reports as a factor falling from 18.05 to 11.77 as the buffer thins.
    #[tokio::test]
    async fn a_dense_graph_converges_at_a_buffer_that_used_to_wedge_it() {
        let peers = 20;
        let outcome = tokio::time::timeout(
            Duration::from_secs(60),
            run(RunConfig {
                topology: Topology::complete(peers),
                workload: Workload::construction(peers, 0),
                capacity: 8,
                queue_capacity: 64,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            }),
        )
        .await
        .expect("the boundary this documented was liveness, and it has moved");

        assert!(
            outcome.converged,
            "a buffer that cannot hold the fan-out still carries the set"
        );
    }

    /// The engine's own queue bound and the link buffer are two different
    /// resources, and only one of them is the reason a run at forty peers
    /// stops finishing. Both cells below hand every link the same generous
    /// buffer, so the link buffer cannot be what separates them: what
    /// changes is `queue_capacity`, and the run that ends the group is the
    /// one whose engine queues are the engine's own default.
    ///
    /// Written because the capacity sweep in `src/bin/run.rs` swept only the
    /// link buffer and therefore could not see this axis at all — a sweep of
    /// 32 through 1024 on the link leaves a forty-peer run failing
    /// identically, which reads as "the buffer does not matter" when the
    /// real reading is "the buffer is not the bound that binds".
    ///
    /// The generous value carries deliberate margin and the exact threshold
    /// is NOT pinned here: where it sits depends on how the runtime
    /// interleaves the drain, the same way hop depth does, and a value just
    /// past the boundary flakes. What is pinned is the direction — the
    /// engine's default ends this group, and a wide enough queue does not.
    #[tokio::test]
    async fn the_engine_queue_bound_binds_before_the_link_buffer_does() {
        let peers = 40;
        let workload = Workload::construction_with(ConstructionConfig {
            peers,
            seed: 0,
            legacy_fraction: 0.3,
            full_node_fraction: 0.5,
            validity_proofs_per_phase: 0,
        });
        let cell = |queue_capacity| RunConfig {
            topology: Topology::degree_k(peers, 4, 0).expect("feasible at n=40, k=4"),
            workload: workload.clone(),
            capacity: 256,
            queue_capacity,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        };

        let engine_default = run(cell(64)).await;
        assert!(
            !engine_default.converged || !engine_default.drained,
            "at forty peers the engine's default queue bound must still be \
             the thing that ends the group; if this now passes cleanly the \
             engine has changed and the grid's queue axis needs re-measuring"
        );

        let generous = run(cell(4096)).await;
        // Never interpolate an `Outcome`: it carries the whole event log,
        // and a failure here would print megabytes.
        assert!(
            generous.converged && generous.drained,
            "the same graph, workload and link buffer must converge and drain \
             once the engine's queues are wide enough — converged={}, \
             drained={}, failed_sends={}",
            generous.converged,
            generous.drained,
            generous.failed_sends
        );
    }

    /// The publication schedule is a queue-occupancy knob, not a traffic
    /// knob: every message still crosses `k + (n-1)(k-1)` links whichever
    /// order it goes in. If this ever fails, the schedule has started
    /// changing what is measured rather than the conditions it is measured
    /// under, and the two columns stop being comparable.
    #[tokio::test]
    async fn a_publication_schedule_changes_queue_occupancy_and_not_the_traffic() {
        let peers = 20;
        let workload = Workload::construction(peers, 0);
        let cell = |schedule| RunConfig {
            topology: Topology::degree_k(peers, 4, 0).expect("n=20, k=4 is feasible"),
            workload: workload.clone(),
            capacity: 32,
            queue_capacity: 64,
            schedule,
            engine: Engine::Push,
        };

        let burst = run(cell(Schedule::Burst)).await;
        let staggered = run(cell(Schedule::Staggered { publications: 1 })).await;

        assert!(burst.converged && staggered.converged);
        let sent = |outcome: &Outcome| {
            outcome
                .events
                .iter()
                .filter(|e| e.dir == Dir::Sent)
                .map(|e| e.bytes)
                .sum::<usize>()
        };
        assert_eq!(
            sent(&staggered),
            sent(&burst),
            "one publication at a time must cost the same bytes as all of them at once"
        );
    }

    #[tokio::test]
    async fn a_complete_graph_converges_and_costs_one_copy_per_neighbour() {
        let peers = 5;
        let outcome = run(RunConfig {
            topology: Topology::complete(peers),
            workload: Workload::construction(peers, 11),
            capacity: 32,
            queue_capacity: 64,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        })
        .await;

        assert!(outcome.converged, "every node must hold the same set");
        assert!(
            outcome.drained,
            "every node's shutdown drain must complete cleanly on a complete graph"
        );

        // A node receives every message it did not publish n-1 times: once
        // from the origin and once from each other node, since a relay
        // forwards to every link but the one it arrived on. A node never
        // receives its own. Averaged over all n peers, each of which published
        // 1/n of the set, that is (n-1)^2 / n copies of the set — 3.2 at n=5,
        // and asymptotically n.
        //
        // Measured from `Dir::Sent`, not `Dir::Received`: every byte handed
        // to a link is a byte the scheme caused to cross the wire, and sends
        // are complete once the drain returns, unlike receives (see
        // `Outcome::events`).
        let sent: usize = outcome
            .events
            .iter()
            .filter(|e| e.dir == Dir::Sent)
            .map(|e| e.bytes)
            .sum();
        let per_peer = sent / peers;
        let factor = per_peer as f64 / outcome.set_bytes as f64;
        let expected = ((peers - 1) * (peers - 1)) as f64 / peers as f64;
        assert!(
            (factor - expected).abs() < 0.15,
            "redundancy factor should be (n-1)^2/n = {expected:.2}, got {factor:.2}"
        );
    }

    #[tokio::test]
    async fn a_degree_two_ring_converges_far_more_cheaply() {
        let peers = 8;
        // Degree 2 samples a union of cycles; take the first seed that yields
        // a connected one rather than betting on a particular draw.
        let ring = (0..50u64)
            .find_map(|seed| Topology::degree_k(peers, 2, seed))
            .expect("some seed yields a connected 2-regular graph over 8 nodes");
        let outcome = run(RunConfig {
            topology: ring,
            workload: Workload::construction(peers, 12),
            capacity: 32,
            queue_capacity: 64,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        })
        .await;

        assert!(outcome.converged);
        assert!(outcome.drained, "a degree-2 ring should drain cleanly too");
        // Measured from `Dir::Sent` — see the note on `a_complete_graph_...`
        // above and on `Outcome::events`.
        let sent: usize = outcome
            .events
            .iter()
            .filter(|e| e.dir == Dir::Sent)
            .map(|e| e.bytes)
            .sum();
        let factor = (sent / peers) as f64 / outcome.set_bytes as f64;
        assert!(
            factor < 4.0,
            "degree 2 should cost far less than n-1 = 7: {factor:.2}"
        );
    }
}
