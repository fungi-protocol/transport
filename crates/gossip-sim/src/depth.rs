//! Hop depth: how many relays a frame crossed before each node first held
//! it.
//!
//! The redundancy factor prices dissemination in bytes; this prices it in
//! rounds. It is grouped per phase because the phases are barriers — each
//! converges before the next begins, so a scheme's latency is paid once per
//! phase, and a session-wide number would hide that.
//!
//! **This measures realized delivery order, not graph distance.** On a
//! small complete graph the two coincide — every node is one hop from the
//! origin, so its first receipt is that direct hop. At 20 peers they can
//! diverge: a node's recorded first receipt of a frame is sometimes a
//! relayed copy that happened to be scheduled ahead of the direct link's
//! own delivery, on this harness's single-threaded executor. Traced by hand
//! for one such case (20 peers, seed 0, phase "Outputs"): node 0's earliest
//! `Dir::Received` event for a frame node 18 published came in over its
//! link to node 15, two full phases' worth of events before the direct
//! link to node 18 delivered the same frame. Nothing here is wrong: depth 4
//! is what node 0 actually experienced first. It means a maximum depth
//! greater than one on a complete graph is not proof of a reconstruction
//! bug the way it would be for a real network; it is this in-memory
//! harness's task scheduling leaking into the number.

use std::collections::{HashMap, HashSet};

use crate::meter::{Dir, Event, FrameId, LinkId, NodeId};
use crate::workload::Publication;

/// Map every frame in `phases` to the node that published it, keyed by the
/// same [`FrameId`] the event log carries. This is the seed [`hop_depths`]
/// needs: the origin's depth is `0` by definition, and it is never the
/// target of a `Dir::Received` event for its own publication.
pub fn origins_of(phases: &[Vec<Publication>]) -> HashMap<FrameId, NodeId> {
    phases
        .iter()
        .flatten()
        .map(|publication| (FrameId::of(&publication.bytes), NodeId(publication.origin)))
        .collect()
}

/// The hop distance from a frame's origin to the first time each node held
/// it: `(node, frame) -> depth`. An origin's own entry, seeded from
/// `origins`, is depth `0`.
///
/// A link's two endpoints are derived from the events themselves: both ends
/// of an edge record with their own [`NodeId`] but the same [`LinkId`].
///
/// Events are processed in the order they were recorded, which is what
/// makes one pass enough: when a node first receives a frame, the peer on
/// the other end of that link already has a depth for it — either because
/// that peer is the origin, or because it received the frame earlier in
/// this same order. A receipt whose peer has no known depth yet is skipped
/// rather than treated as an error: that only happens when `origins` does
/// not cover every frame in `events`, or when a run ended before every node
/// converged.
pub fn hop_depths(
    events: &[Event],
    origins: &HashMap<FrameId, NodeId>,
) -> HashMap<(NodeId, FrameId), u32> {
    let mut link_nodes: HashMap<LinkId, HashSet<NodeId>> = HashMap::new();
    for event in events {
        link_nodes.entry(event.link).or_default().insert(event.node);
    }

    let mut depths: HashMap<(NodeId, FrameId), u32> = origins
        .iter()
        .map(|(&frame, &node)| ((node, frame), 0))
        .collect();

    for event in events {
        if event.dir != Dir::Received || depths.contains_key(&(event.node, event.frame)) {
            continue;
        }
        let Some(other) = link_nodes
            .get(&event.link)
            .and_then(|nodes| nodes.iter().find(|&&n| n != event.node))
        else {
            continue;
        };
        if let Some(&other_depth) = depths.get(&(*other, event.frame)) {
            depths.insert((event.node, event.frame), other_depth + 1);
        }
    }

    depths
}

/// One phase's convergence latency, in hops.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PhaseDepth {
    /// Index of the phase, in publication order.
    pub phase: usize,
    /// The maximum depth over all (frame, node) pairs in this phase — the
    /// phase's convergence latency in hops.
    pub max_depth: u32,
    /// The mean depth over the same pairs.
    pub mean_depth: f64,
}

/// Reduce a [`hop_depths`] map to one [`PhaseDepth`] per phase.
///
/// `phases` supplies both the frame identity (hashed from a publication's
/// bytes, the same way [`origins_of`] built `depths`' seed) and the grouping
/// into phases; `peers` bounds which nodes to look a depth up for. A (node,
/// frame) pair absent from `depths` — a node that never received the frame,
/// in a run that did not converge — is left out of both statistics rather
/// than counted as a zero.
pub fn phase_depths(
    depths: &HashMap<(NodeId, FrameId), u32>,
    phases: &[Vec<Publication>],
    peers: usize,
) -> Vec<PhaseDepth> {
    let mut out = Vec::with_capacity(phases.len());
    for (phase, publications) in phases.iter().enumerate() {
        let frames: Vec<FrameId> = publications
            .iter()
            .map(|publication| FrameId::of(&publication.bytes))
            .collect();
        let mut values = Vec::new();
        for node in 0..peers {
            for &frame in &frames {
                if let Some(&depth) = depths.get(&(NodeId(node), frame)) {
                    values.push(depth);
                }
            }
        }
        let max_depth = values.iter().copied().max().unwrap_or(0);
        let mean_depth = if values.is_empty() {
            0.0
        } else {
            values.iter().copied().sum::<u32>() as f64 / values.len() as f64
        };
        out.push(PhaseDepth {
            phase,
            max_depth,
            mean_depth,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::run::{RunConfig, Schedule, run};
    use crate::topology::Topology;
    use crate::workload::Workload;

    fn sent(node: usize, link: u32, frame: FrameId) -> Event {
        Event {
            node: NodeId(node),
            link: LinkId(link),
            dir: Dir::Sent,
            frame,
            bytes: 1,
        }
    }

    fn received(node: usize, link: u32, frame: FrameId) -> Event {
        Event {
            node: NodeId(node),
            link: LinkId(link),
            dir: Dir::Received,
            frame,
            bytes: 1,
        }
    }

    #[test]
    fn depth_grows_by_one_along_a_chain() {
        // node0 --link0-- node1 --link1-- node2, frame originated at node0.
        let frame = FrameId::for_test(1);
        let events = vec![
            sent(0, 0, frame),
            received(1, 0, frame),
            sent(1, 1, frame),
            received(2, 1, frame),
        ];
        let origins = HashMap::from([(frame, NodeId(0))]);

        let depths = hop_depths(&events, &origins);

        assert_eq!(depths[&(NodeId(0), frame)], 0, "the origin is depth 0");
        assert_eq!(depths[&(NodeId(1), frame)], 1, "one hop from the origin");
        assert_eq!(
            depths[&(NodeId(2), frame)],
            2,
            "one hop from node 1, which is itself one hop from the origin"
        );
    }

    #[test]
    fn the_first_receipt_wins_even_when_a_shorter_path_arrives_later() {
        // node0 is the origin. node2 first hears the frame via node1 (depth
        // 2), and only afterwards receives it directly from node0 over a
        // second link (which would compute as depth 1). "First seen" must
        // win: node2's recorded depth is 2, not the smaller value a later
        // duplicate would suggest.
        let frame = FrameId::for_test(7);
        let events = vec![
            sent(0, 0, frame),
            received(1, 0, frame), // node1 depth 1
            sent(1, 1, frame),
            received(2, 1, frame), // node2's FIRST receipt: depth 2
            sent(0, 2, frame),
            received(2, 2, frame), // a later, shorter-path duplicate
        ];
        let origins = HashMap::from([(frame, NodeId(0))]);

        let depths = hop_depths(&events, &origins);

        assert_eq!(
            depths[&(NodeId(2), frame)],
            2,
            "the first-recorded receipt fixes the depth, not the shortest path"
        );
    }

    #[test]
    fn a_receipt_with_no_known_peer_depth_is_skipped_not_panicked() {
        // The peer on the other end of the link never appears with a known
        // depth (no origin, no prior receipt) — this must not panic, and
        // must simply leave the receiving node's depth unset.
        let frame = FrameId::for_test(9);
        let events = vec![received(1, 0, frame)];
        let origins = HashMap::new();

        let depths = hop_depths(&events, &origins);

        assert!(
            !depths.contains_key(&(NodeId(1), frame)),
            "no basis to assign a depth, so none is assigned"
        );
    }

    #[test]
    fn phase_depths_reduces_to_max_and_mean_per_phase() {
        let a = Publication {
            origin: 0,
            bytes: b"a".to_vec(),
        };
        let b = Publication {
            origin: 1,
            bytes: b"b".to_vec(),
        };
        let frame_a = FrameId::of(&a.bytes);
        let frame_b = FrameId::of(&b.bytes);
        let phases = vec![vec![a, b]];

        let mut depths = HashMap::new();
        depths.insert((NodeId(0), frame_a), 0);
        depths.insert((NodeId(1), frame_a), 1);
        depths.insert((NodeId(0), frame_b), 1);
        depths.insert((NodeId(1), frame_b), 0);

        let result = phase_depths(&depths, &phases, 2);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].phase, 0);
        assert_eq!(result[0].max_depth, 1);
        assert!(
            (result[0].mean_depth - 0.5).abs() < f64::EPSILON,
            "(0 + 1 + 1 + 0) / 4 = 0.5, got {}",
            result[0].mean_depth
        );
    }

    #[test]
    fn phase_depths_skips_pairs_with_no_recorded_depth() {
        let a = Publication {
            origin: 0,
            bytes: b"only-one-node-saw-this".to_vec(),
        };
        let frame_a = FrameId::of(&a.bytes);
        let phases = vec![vec![a]];

        let mut depths = HashMap::new();
        depths.insert((NodeId(0), frame_a), 0);
        // Node 1 never received it in this (unconverged) run.

        let result = phase_depths(&depths, &phases, 2);

        assert_eq!(result[0].max_depth, 0);
        assert!((result[0].mean_depth - 0.0).abs() < f64::EPSILON);
    }

    /// The sanity check the design calls for: on a complete graph every
    /// node is adjacent to the origin, so the maximum depth over any phase
    /// must be exactly 1 — at this scale. It holds here; see
    /// [`hop_depth_can_exceed_one_on_a_complete_graph_at_scale`] below for
    /// where it stops holding, and why that is a property of this harness's
    /// scheduling rather than a bug in the reduction.
    #[tokio::test]
    async fn a_complete_graph_gives_every_node_depth_one() {
        let peers = 10;
        let workload = Workload::construction(peers, 7);
        let outcome = run(RunConfig {
            topology: Topology::complete(peers),
            workload: workload.clone(),
            capacity: 32,
            queue_capacity: 64,
            schedule: Schedule::Burst,
            engine: Engine::Push,
        })
        .await;
        assert!(
            outcome.converged,
            "must converge for depth to mean anything"
        );

        let origins = origins_of(workload.phases());
        let depths = hop_depths(&outcome.events, &origins);
        let phases = phase_depths(&depths, workload.phases(), peers);

        assert_eq!(phases.len(), 3);
        for phase in &phases {
            assert_eq!(
                phase.max_depth, 1,
                "every node is one hop from the origin on a complete graph (phase {})",
                phase.phase
            );
        }
    }

    /// Documents a verified surprise (see the module docs): at the thin
    /// slice's actual scale, the sanity check above stops holding. Traced by
    /// hand for this exact case — node 0's first `Received` event for the
    /// frame node 18 published in the "Outputs" phase arrives over its link
    /// to node 15, long before the direct link to node 18 delivers the same
    /// frame — so `max_depth > 1` here is this harness's task scheduling
    /// showing up in the number, not evidence the reduction is wrong. If
    /// this ever starts asserting `max_depth == 1`, that is a real change in
    /// the harness's scheduling behavior worth investigating, not a
    /// regression to silently accept.
    #[tokio::test]
    async fn hop_depth_can_exceed_one_on_a_complete_graph_at_scale() {
        let peers = 20;
        let workload = Workload::construction(peers, 0);
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

        let origins = origins_of(workload.phases());
        let depths = hop_depths(&outcome.events, &origins);
        let phases = phase_depths(&depths, workload.phases(), peers);

        assert!(
            phases.iter().any(|p| p.max_depth > 1),
            "expected at least one phase to show the scheduling artifact at this scale"
        );
    }
}
