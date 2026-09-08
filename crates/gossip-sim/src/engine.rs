//! The dissemination schemes under comparison, and the one point that
//! selects between them.
//!
//! Push is the production engine, driven asynchronously by [`crate::run`].
//! Announce/pull and hybrid cannot be: `BroadcastChannel` carries no per-peer
//! state and has no request path, so expressing them would mean a second
//! asynchronous engine, and then a difference between variants might be a
//! difference between drivers rather than between schemes.
//!
//! Instead every modelled variant runs in one lockstep round driver over the
//! same metered links, and the push policy is implemented in it as well —
//! [`Engine::ModelledPush`] — so the model can be checked against the engine
//! it stands in for. The check is exact equality on bytes and message counts,
//! which follow from the topology rather than from scheduling.
//!
//! The driver owns both ends of every link and carries each frame across as
//! it is sent, so no buffer can fill. Link capacity is not a variable of a
//! modelled run; the capacity findings belong to the asynchronous engine,
//! where they were measured.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use fungi_transport::mem::{MemChannel, MemConfig, duplex};
use fungi_transport::{AssumeSessionBound, RecvHalf, SendHalf, SplitChannel};
use fungi_wire::{CanonicalMessage, MessageSet};

use crate::deps::DepId;
use crate::meter::{FrameId, LinkId, Metered, NodeId, Recorder};
use crate::run::{Outcome, RunConfig};
use crate::workload::Workload;

/// Which dissemination scheme a run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Forward every message on first sight to every link but the one it
    /// arrived on: the production `GossipBroadcast`, driven asynchronously.
    /// The baseline every other variant is measured against.
    Push,
    /// The same forwarding policy in the lockstep model. It exists to
    /// validate the model against the engine, not to contribute a result of
    /// its own — two numbers for one scheme would be two numbers for one
    /// scheme.
    ModelledPush,
    /// Announce identities, send only what a peer asks for. `batch` is how
    /// many identities ride in one announcement or request frame.
    AnnouncePull {
        /// Identities per announcement or request frame.
        batch: usize,
    },
    /// Push anything at or below `push_below` payload bytes, announce the
    /// rest. The threshold is the knob the transcript's own rule predicts:
    /// announcing pays when the identity is much smaller than the object.
    Hybrid {
        /// Identities per announcement or request frame.
        batch: usize,
        /// Payload size at or below which an object is pushed outright.
        push_below: usize,
    },
}

/// A frame carrying one object's bytes.
pub const TAG_DATA: u8 = 0;
/// A frame carrying identities their sender holds.
pub const TAG_ANNOUNCE: u8 = 1;
/// A frame carrying identities their sender wants.
pub const TAG_REQUEST: u8 = 2;

/// How an object is addressed while a run is in progress.
///
/// Two spaces, and the difference is the point: a content identity only
/// exists once someone has produced the bytes, while a txid or an outpoint
/// names an object a peer may already hold and can therefore decline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjId {
    /// Identified by the hash of its own content.
    Content(FrameId),
    /// Identified by an identity that exists before the message does.
    Dependency(DepId),
}

impl ObjId {
    /// What one entry costs on the wire: a kind byte and the identity at its
    /// real width. `FrameId` is truncated to sixteen bytes for bookkeeping
    /// inside this harness; charging that would make announcement look about
    /// forty per cent cheaper than it is.
    fn wire_len(self) -> usize {
        1 + match self {
            Self::Content(_) | Self::Dependency(DepId::Txid(_)) => 32,
            Self::Dependency(DepId::Outpoint(..)) => 36,
        }
    }

    /// The identity of a published object: its dependency identity when the
    /// workload gives it one, and the hash of its content otherwise.
    ///
    /// In production this would be read off the message. Here the workload
    /// stands in for the encoding that would carry it, which is another
    /// item's work.
    pub fn of(bytes: &[u8], workload: &Workload) -> Self {
        let frame = FrameId::of(bytes);
        match workload.dependency_of(frame) {
            Some(dep) => Self::Dependency(dep),
            None => Self::Content(frame),
        }
    }
}

/// Encode a control frame of the given tag over `ids`.
///
/// Each entry is a kind byte and the identity at the width a real one would
/// occupy: 32 bytes for a content hash or a txid, 36 for an outpoint. A
/// content identity is truncated to sixteen bytes inside this harness, so the
/// remaining sixteen are padding — the frame must still be charged for them,
/// or announcing comes out about forty per cent cheaper than it is.
pub fn control_frame(tag: u8, ids: &[ObjId]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + ids.iter().map(|id| id.wire_len()).sum::<usize>());
    frame.push(tag);
    for id in ids {
        match id {
            ObjId::Content(frame_id) => {
                frame.push(0);
                frame.extend_from_slice(frame_id.as_bytes());
                frame.resize(frame.len() + 16, 0);
            }
            ObjId::Dependency(DepId::Txid(txid)) => {
                frame.push(1);
                frame.extend_from_slice(txid);
            }
            ObjId::Dependency(DepId::Outpoint(txid, index)) => {
                frame.push(2);
                frame.extend_from_slice(txid);
                frame.extend_from_slice(&index.to_be_bytes());
            }
        }
    }
    frame
}

/// Read the identities back out of a control frame's body. A frame this
/// harness did not write decodes to nothing rather than panicking.
pub fn decode_control(mut body: &[u8]) -> Vec<ObjId> {
    let mut ids = Vec::new();
    while let Some((&kind, rest)) = body.split_first() {
        let (id, width) = match kind {
            // Every slice below is taken at a width this arm's own guard
            // has already found present, so none of these conversions can
            // fail on a frame that reaches them.
            // A content identity is 16 bytes, but `control_frame` pads its
            // slot to 32 so an announcement costs the same per identity
            // whichever kind it names — which is the width the redundancy
            // arithmetic prices. Hence reading 16 and stepping over 32.
            0 if rest.len() >= 32 => (
                ObjId::Content(FrameId::from_bytes(
                    rest[..16].try_into().expect("guarded above"),
                )),
                32,
            ),
            1 if rest.len() >= 32 => (
                ObjId::Dependency(DepId::Txid(rest[..32].try_into().expect("guarded above"))),
                32,
            ),
            2 if rest.len() >= 36 => (
                ObjId::Dependency(DepId::Outpoint(
                    rest[..32].try_into().expect("guarded above"),
                    u32::from_be_bytes(rest[32..36].try_into().expect("guarded above")),
                )),
                36,
            ),
            _ => return ids,
        };
        ids.push(id);
        body = &rest[width..];
    }
    ids
}

/// Split a frame into its tag and its body.
pub fn frame_tag(frame: &[u8]) -> Option<(u8, &[u8])> {
    frame.split_first().map(|(tag, body)| (*tag, body))
}

/// Prefix an object's bytes with the data tag.
pub fn data_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + bytes.len());
    frame.push(TAG_DATA);
    frame.extend_from_slice(bytes);
    frame
}

/// One link, both ends.
type Half = Metered<AssumeSessionBound<MemChannel>>;

/// Which half of a duplex link an end holds. The halves are not
/// interchangeable: what one puts on comes off the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The half held by the lower-numbered node of the edge.
    Left,
    /// The half held by the higher-numbered one.
    Right,
}

/// Which neighbour sits at the other end of one of a node's links.
#[derive(Debug, Clone, Copy)]
struct Neighbour {
    /// Index into the driver's link table.
    link: usize,
    /// Which half of that link this node holds.
    end: End,
    /// The node at the other end.
    peer: usize,
    /// Which of `peer`'s neighbours this node is, so the two sides agree on
    /// who told whom.
    back: usize,
}

/// What one node knows and has said.
#[derive(Debug, Default)]
struct Peer {
    /// Objects held complete, by identity. Shared rather than copied: at a
    /// thousand peers every node holding its own copy of every object is
    /// hundreds of megabytes, and a round's plan names each of them again.
    held: HashMap<ObjId, Arc<[u8]>>,
    /// Per neighbour: identities already sent or announced to it, so
    /// nothing crosses the same link twice.
    sent: Vec<HashSet<ObjId>>,
    /// Per neighbour: identities it has announced to us, or handed us. What
    /// this node believes that neighbour holds.
    offered: Vec<HashSet<ObjId>>,
    /// Which neighbour delivered the FIRST copy of each identity. Push
    /// forwards on first sight to every link but that one — and to no
    /// other rule, which is why a later copy arriving from a second
    /// neighbour does not stop the forward that was already on its way to
    /// it.
    arrived: HashMap<ObjId, usize>,
    /// Identities asked of some neighbour and not yet received. Asking two
    /// peers for the same object is exactly the waste pull exists to avoid.
    in_flight: HashSet<ObjId>,
    /// Requests received this round, to answer at the end of it.
    to_serve: Vec<(usize, ObjId)>,
}

/// Run one cell under a modelled engine.
///
/// Panics on [`Engine::Push`], which is the asynchronous engine's own path
/// through [`crate::run::run`] — routing it here would silently replace the
/// production engine with a model of it.
pub async fn run_modelled(config: RunConfig) -> Outcome {
    let RunConfig {
        topology,
        workload,
        capacity,
        queue_capacity: _,
        // A lockstep run takes every frame off the link as it is put on, so
        // it has no queue for a publication schedule to fill.
        schedule: _,
        engine,
    } = config;
    let batch = match engine {
        Engine::Push => panic!("Engine::Push is the asynchronous engine; drive it with run()"),
        Engine::ModelledPush => 1,
        Engine::AnnouncePull { batch } | Engine::Hybrid { batch, .. } => batch.max(1),
    };

    let log = Arc::new(Recorder::default());
    let cfg = MemConfig {
        capacity: Some(capacity),
        ..MemConfig::default()
    };

    let mut links: Vec<(Half, Half)> = Vec::with_capacity(topology.edges.len());
    let mut adjacency: Vec<Vec<Neighbour>> = vec![Vec::new(); topology.n];
    for (index, &(a, b)) in topology.edges.iter().enumerate() {
        let id = LinkId(index as u32);
        let (left, right) = duplex(cfg.clone());
        links.push((
            Metered::new(AssumeSessionBound(left), NodeId(a), id, log.clone()),
            Metered::new(AssumeSessionBound(right), NodeId(b), id, log.clone()),
        ));
        let back_of_a = adjacency[b].len();
        let back_of_b = adjacency[a].len();
        adjacency[a].push(Neighbour {
            link: index,
            end: End::Left,
            peer: b,
            back: back_of_a,
        });
        adjacency[b].push(Neighbour {
            link: index,
            end: End::Right,
            peer: a,
            back: back_of_b,
        });
    }

    let mut peers: Vec<Peer> = (0..topology.n)
        .map(|node| Peer {
            sent: vec![HashSet::new(); adjacency[node].len()],
            offered: vec![HashSet::new(); adjacency[node].len()],
            ..Peer::default()
        })
        .collect();
    let mut sets: Vec<MessageSet> = (0..topology.n)
        .map(|_| MessageSet::new(workload.context()))
        .collect();

    let mut rounds = Vec::new();
    let mut published = 0usize;
    let mut healthy = true;

    for phase in workload.phases() {
        for publication in phase {
            let id = ObjId::of(&publication.bytes, &workload);
            // One allocation per published object for the whole run: every
            // node that ends up holding it shares this.
            let bytes: Arc<[u8]> = Arc::from(publication.bytes.as_slice());
            hold(
                &mut peers[publication.origin],
                &mut sets[publication.origin],
                id,
                &bytes,
            );

            // A peer that can resolve a dependency locally holds it without
            // anything crossing a link. That is the whole of what separate
            // addressing buys, and it is why the population has to be
            // heterogeneous for the question to have an answer.
            //
            // Push cannot use it. A forwarding scheme has no way for a peer
            // to decline what is coming, so a full node receives the object
            // anyway and the bytes are spent — which is the comparison this
            // slice exists to make, and the reason the a-priori holding is
            // withheld here rather than granted to every scheme alike.
            if engine != Engine::ModelledPush
                && let ObjId::Dependency(dep) = id
            {
                for node in 0..topology.n {
                    if node != publication.origin && workload.holds_a_priori(node, dep) {
                        hold(&mut peers[node], &mut sets[node], id, &bytes);
                    }
                }
            }
        }
        published += phase.len();

        // Run to a fixpoint, not to convergence. Forward-on-first-sight
        // does not stop when the group is complete — it has no way to know
        // that — and on a complete graph the origin's own fan-out already
        // completes every set in one round, so stopping at convergence
        // would drop every relay the engine actually sends. Convergence is
        // checked afterwards, as an outcome rather than a stopping rule.
        let mut phase_rounds = 0usize;
        loop {
            let moved = match engine {
                Engine::ModelledPush => {
                    push_round(&mut links, &adjacency, &mut peers, &mut sets).await
                }
                Engine::AnnouncePull { .. } => {
                    announce_round(&mut links, &adjacency, &mut peers, &mut sets, batch, 0).await
                }
                Engine::Hybrid { push_below, .. } => {
                    announce_round(
                        &mut links, &adjacency, &mut peers, &mut sets, batch, push_below,
                    )
                    .await
                }
                Engine::Push => unreachable!("rejected above"),
            };
            if !moved {
                break;
            }
            phase_rounds += 1;
        }

        if sets.iter().any(|set| set.len() < published) {
            healthy = false;
        }

        rounds.push(phase_rounds);
        if !healthy {
            break;
        }
    }

    let first = sets[0].commitment();
    let converged = healthy
        && sets
            .iter()
            .all(|set| set.commitment() == first && set.len() == published);

    Outcome {
        events: log.take_events(),
        converged,
        // A lockstep run has no teardown: every frame is taken off the link
        // as it is put on, so there is nothing left owed at the end.
        drained: healthy,
        drain_error: (!healthy).then(|| "the group stopped short of its published set".into()),
        set_bytes: workload.set_bytes(),
        peers: topology.n,
        failed_sends: log.failed_sends(),
        rounds,
    }
}

/// Record that `peer` now holds `id`, and put it in the node's set.
fn hold(peer: &mut Peer, set: &mut MessageSet, id: ObjId, bytes: &Arc<[u8]>) {
    if peer.held.insert(id, bytes.clone()).is_some() {
        return;
    }
    let message = CanonicalMessage::parse(bytes.to_vec()).expect("publications are canonical");
    set.insert(message)
        .expect("every message belongs to this session");
}

/// A frame on its way across a link. Push puts an object on the wire
/// unwrapped, so its frame is the object itself and is shared rather than
/// copied; every control frame and every tagged data frame is built.
enum Frame {
    /// The object's own bytes, untouched.
    Raw(Arc<[u8]>),
    /// A frame this scheme assembled.
    Built(Vec<u8>),
}

impl Frame {
    /// What crosses the wire.
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Raw(bytes) => bytes,
            Self::Built(bytes) => bytes,
        }
    }
}

/// One frame's worth of work: which link it crosses, in which direction, and
/// what it carries.
struct Delivery {
    /// Which link.
    link: usize,
    /// Which half sends it.
    from: End,
    /// The frame.
    frame: Frame,
}

/// Put a whole step's frames on the links at once and take them off at once.
///
/// Every link's two directions run concurrently, so a bounded link buffer
/// acts as backpressure — a sender waits for its peer to make room — rather
/// than being a number the model ignores. Returns, per delivery in plan
/// order, whether it crossed.
///
/// How deep the buffer actually had to be is NOT decided here. It is read
/// off the event log afterwards, by `report::peak_link_occupancy`: how many
/// frames a scheme hands to a link in one go is an upper bound on what the
/// buffer holds, not a measurement of it, since the peer is draining
/// throughout.
///
/// What this does NOT reproduce is the asynchronous engine's wedge. There one
/// hub per node serves every link, so a node that cannot finish with one link
/// stops draining its others and a cycle of waiting tasks can close. Here
/// each link direction has a reader of its own, so no such cycle exists. The
/// depth reported below is a property of the scheme's traffic; whether a
/// given implementation deadlocks at that depth is a property of that
/// implementation.
///
/// The receive loops are bounded by how many frames their peer ATTEMPTED, not
/// by how many succeeded, which is sound only because nothing closes a link
/// mid-run here: every half lives in `links` for the whole run. A transport
/// that could close one would need those counts reconciled.
async fn deliver_step(links: &mut [(Half, Half)], plan: &[Delivery]) -> Vec<bool> {
    let mut by_link: HashMap<usize, (Vec<usize>, Vec<usize>)> = HashMap::new();
    for (index, delivery) in plan.iter().enumerate() {
        let entry = by_link.entry(delivery.link).or_default();
        match delivery.from {
            End::Left => entry.0.push(index),
            End::Right => entry.1.push(index),
        }
    }
    let per_link =
        futures_util::future::join_all(links.iter_mut().enumerate().map(|(id, (left, right))| {
            let (rightward, leftward) = by_link.get(&id).cloned().unwrap_or_default();
            async move {
                let (mut left_out, mut left_in) = left.split();
                let (mut right_out, mut right_in) = right.split();
                let send_rightward = async {
                    let mut crossed = Vec::with_capacity(rightward.len());
                    for &index in &rightward {
                        crossed.push(left_out.send(plan[index].frame.bytes()).await.is_ok());
                    }
                    crossed
                };
                let take_rightward = async {
                    for _ in 0..rightward.len() {
                        if right_in.recv().await.is_err() {
                            break;
                        }
                    }
                };
                let send_leftward = async {
                    let mut crossed = Vec::with_capacity(leftward.len());
                    for &index in &leftward {
                        crossed.push(right_out.send(plan[index].frame.bytes()).await.is_ok());
                    }
                    crossed
                };
                let take_leftward = async {
                    for _ in 0..leftward.len() {
                        if left_in.recv().await.is_err() {
                            break;
                        }
                    }
                };
                let (right_ok, (), left_ok, ()) = futures_util::future::join4(
                    send_rightward,
                    take_rightward,
                    send_leftward,
                    take_leftward,
                )
                .await;
                (rightward, right_ok, leftward, left_ok)
            }
        }))
        .await;

    let mut crossed = vec![false; plan.len()];
    for (rightward, right_ok, leftward, left_ok) in per_link {
        for (index, ok) in rightward.into_iter().zip(right_ok) {
            crossed[index] = ok;
        }
        for (index, ok) in leftward.into_iter().zip(left_ok) {
            crossed[index] = ok;
        }
    }
    crossed
}

/// Where a planned frame is going.
fn addressed(adjacency: &[Vec<Neighbour>], node: usize, index: usize, frame: Frame) -> Delivery {
    let at = adjacency[node][index];
    Delivery {
        link: at.link,
        from: at.end,
        frame,
    }
}

/// One round of forward-on-first-sight: every node offers every neighbour
/// everything it holds and has not already exchanged with it.
///
/// The plan is computed from the state at the START of the round and only
/// then executed, so every node acts on what it knew when the round began.
/// Updating as the round proceeds would let a node that has just received a
/// frame decline to send its own copy back, suppressing exactly the crossing
/// duplicates the asynchronous engine really emits — and the model would then
/// undercount the baseline it exists to reproduce.
async fn push_round(
    links: &mut [(Half, Half)],
    adjacency: &[Vec<Neighbour>],
    peers: &mut [Peer],
    sets: &mut [MessageSet],
) -> bool {
    let planned = plan_forwards(adjacency, peers);
    let plan: Vec<Delivery> = planned
        .iter()
        .map(|(node, index, _, bytes)| {
            addressed(adjacency, *node, *index, Frame::Raw(bytes.clone()))
        })
        .collect();
    let crossed = deliver_step(links, &plan).await;

    let mut moved = false;
    for ((node, index, id, bytes), ok) in planned.into_iter().zip(crossed) {
        if !ok {
            continue;
        }
        let at = adjacency[node][index];
        peers[node].sent[index].insert(id);
        let (peer, set) = (&mut peers[at.peer], &mut sets[at.peer]);
        peer.arrived.entry(id).or_insert(at.back);
        peer.offered[at.back].insert(id);
        hold(peer, set, id, &bytes);
        moved = true;
    }
    moved
}

/// What push has left to forward, read off one consistent snapshot: whatever
/// a node holds, on every link but the one the first copy came in on, and not
/// twice on the same link.
fn plan_forwards(
    adjacency: &[Vec<Neighbour>],
    peers: &[Peer],
) -> Vec<(usize, usize, ObjId, Arc<[u8]>)> {
    plan(adjacency, peers, |peer, index, id| {
        !peer.sent[index].contains(id) && peer.arrived.get(id) != Some(&index)
    })
}

/// What an announcing node has left to offer: whatever it holds that this
/// neighbour has neither been told about nor told it about. The second clause
/// is a real advantage of announcing over forwarding — a peer that has
/// announced an identity to you does not need to be told about it — and it is
/// why push and pull cannot share one planner.
fn plan_offers(
    adjacency: &[Vec<Neighbour>],
    peers: &[Peer],
) -> Vec<(usize, usize, ObjId, Arc<[u8]>)> {
    plan(adjacency, peers, |peer, index, id| {
        !peer.sent[index].contains(id) && !peer.offered[index].contains(id)
    })
}

/// Every held object each node still owes each neighbour under `owes`.
fn plan(
    adjacency: &[Vec<Neighbour>],
    peers: &[Peer],
    owes: impl Fn(&Peer, usize, &ObjId) -> bool,
) -> Vec<(usize, usize, ObjId, Arc<[u8]>)> {
    let mut plan = Vec::new();
    for (node, links) in adjacency.iter().enumerate() {
        for index in 0..links.len() {
            for (id, bytes) in &peers[node].held {
                if owes(&peers[node], index, id) {
                    plan.push((node, index, *id, bytes.clone()));
                }
            }
        }
    }
    plan
}

/// One announce/request/respond cycle. `push_below` pushes an object outright
/// instead of announcing it when its payload is that size or smaller; passing
/// zero announces everything, which is the pure announce/pull case.
///
/// Each of the three steps plans from a snapshot and then executes, for the
/// same reason [`push_round`] does: within a step the group acts at once.
async fn announce_round(
    links: &mut [(Half, Half)],
    adjacency: &[Vec<Neighbour>],
    peers: &mut [Peer],
    sets: &mut [MessageSet],
    batch: usize,
    push_below: usize,
) -> bool {
    let mut moved = false;

    // 1. Say what is held, or hand over what is too small to be worth a
    //    round trip.
    let mut announcements: Vec<(usize, usize, Vec<ObjId>)> = Vec::new();
    let mut pushes: Vec<(usize, usize, ObjId, Arc<[u8]>)> = Vec::new();
    for (node, index, id, bytes) in plan_offers(adjacency, peers) {
        if bytes.len() <= push_below {
            pushes.push((node, index, id, bytes));
        } else {
            match announcements.last_mut() {
                Some((n, i, ids)) if *n == node && *i == index && ids.len() < batch => {
                    ids.push(id);
                }
                _ => announcements.push((node, index, vec![id])),
            }
        }
    }

    let plan: Vec<Delivery> = pushes
        .iter()
        .map(|(node, index, _, bytes)| {
            addressed(adjacency, *node, *index, Frame::Built(data_frame(bytes)))
        })
        .chain(announcements.iter().map(|(node, index, ids)| {
            addressed(
                adjacency,
                *node,
                *index,
                Frame::Built(control_frame(TAG_ANNOUNCE, ids)),
            )
        }))
        .collect();
    let crossed = deliver_step(links, &plan).await;

    let pushed = pushes.len();
    for ((node, index, id, bytes), ok) in pushes.into_iter().zip(crossed.iter().copied()) {
        if !ok {
            continue;
        }
        let at = adjacency[node][index];
        peers[node].sent[index].insert(id);
        let (peer, set) = (&mut peers[at.peer], &mut sets[at.peer]);
        peer.arrived.entry(id).or_insert(at.back);
        peer.offered[at.back].insert(id);
        hold(peer, set, id, &bytes);
        moved = true;
    }
    for ((node, index, ids), ok) in announcements
        .into_iter()
        .zip(crossed.into_iter().skip(pushed))
    {
        if !ok {
            continue;
        }
        let at = adjacency[node][index];
        peers[node].sent[index].extend(&ids);
        peers[at.peer].offered[at.back].extend(&ids);
        moved = true;
    }

    // 2. Ask for what is missing, once, and only of one peer: asking two
    //    peers for the same object is the waste pull exists to avoid.
    let mut requests: Vec<(usize, usize, Vec<ObjId>)> = Vec::new();
    for node in 0..peers.len() {
        let mut asked: HashSet<ObjId> = peers[node].in_flight.clone();
        for index in 0..adjacency[node].len() {
            let wanted: Vec<ObjId> = peers[node].offered[index]
                .iter()
                .filter(|id| !peers[node].held.contains_key(id) && !asked.contains(id))
                .copied()
                .collect();
            asked.extend(&wanted);
            for chunk in wanted.chunks(batch) {
                requests.push((node, index, chunk.to_vec()));
            }
        }
    }
    let plan: Vec<Delivery> = requests
        .iter()
        .map(|(node, index, ids)| {
            addressed(
                adjacency,
                *node,
                *index,
                Frame::Built(control_frame(TAG_REQUEST, ids)),
            )
        })
        .collect();
    let crossed = deliver_step(links, &plan).await;

    for ((node, index, ids), ok) in requests.into_iter().zip(crossed) {
        if !ok {
            continue;
        }
        let at = adjacency[node][index];
        peers[node].in_flight.extend(&ids);
        for id in ids {
            peers[at.peer].to_serve.push((at.back, id));
        }
        moved = true;
    }

    // 3. Answer.
    let mut answers: Vec<(usize, usize, ObjId, Arc<[u8]>)> = Vec::new();
    for (node, peer) in peers.iter_mut().enumerate() {
        for (index, id) in std::mem::take(&mut peer.to_serve) {
            if let Some(bytes) = peer.held.get(&id).cloned() {
                answers.push((node, index, id, bytes));
            }
        }
    }
    let plan: Vec<Delivery> = answers
        .iter()
        .map(|(node, index, _, bytes)| {
            addressed(adjacency, *node, *index, Frame::Built(data_frame(bytes)))
        })
        .collect();
    let crossed = deliver_step(links, &plan).await;

    for ((node, index, id, bytes), ok) in answers.into_iter().zip(crossed) {
        if !ok {
            continue;
        }
        let at = adjacency[node][index];
        let (peer, set) = (&mut peers[at.peer], &mut sets[at.peer]);
        peer.in_flight.remove(&id);
        peer.arrived.entry(id).or_insert(at.back);
        hold(peer, set, id, &bytes);
        moved = true;
    }

    moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Row;
    use crate::run::Schedule;
    use crate::run::run;
    use crate::topology::Topology;
    use crate::workload::ConstructionConfig;

    fn cell(peers: usize, degree: usize, seed: u64, engine: Engine) -> RunConfig {
        RunConfig {
            topology: if degree + 1 == peers {
                Topology::complete(peers)
            } else {
                Topology::degree_k(peers, degree, seed).expect("feasible")
            },
            workload: Workload::construction_with(ConstructionConfig {
                peers,
                seed,
                legacy_fraction: 0.3,
                full_node_fraction: 0.5,
                validity_proofs_per_phase: 0,
            }),
            capacity: 512,
            queue_capacity: 4096,
            schedule: Schedule::Burst,
            engine,
        }
    }

    /// The acceptance rule for the model, from the design: exact equality on
    /// the quantities that follow from the topology rather than from
    /// scheduling. If this fails, no comparison between an engine and a
    /// modelled variant means anything.
    #[tokio::test]
    async fn the_model_sends_exactly_what_the_engine_sends() {
        for (peers, degree) in [(5usize, 4usize), (20, 4)] {
            let engine = run(cell(peers, degree, 0, Engine::Push)).await;
            let modelled = run_modelled(cell(peers, degree, 0, Engine::ModelledPush)).await;

            assert!(engine.converged, "n={peers}, k={degree}: engine");
            assert!(modelled.converged, "n={peers}, k={degree}: model");

            let engine_row = Row::from_outcome(&engine, degree, 0);
            let modelled_row = Row::from_outcome(&modelled, degree, 0);
            assert_eq!(
                modelled_row.per_peer_bytes, engine_row.per_peer_bytes,
                "n={peers}, k={degree}: the model must send the same bytes as the engine"
            );
            assert_eq!(
                modelled_row.wire_bytes, engine_row.wire_bytes,
                "n={peers}, k={degree}: and the same number of frames"
            );
        }
    }

    #[tokio::test]
    async fn announce_pull_converges_and_costs_less_than_push() {
        let peers = 20;
        let push = run(cell(peers, 4, 0, Engine::Push)).await;
        let pull = run_modelled(cell(peers, 4, 0, Engine::AnnouncePull { batch: 50 })).await;

        assert!(pull.converged, "announce/pull must reach one message set");
        let push_row = Row::from_outcome(&push, 4, 0);
        let pull_row = Row::from_outcome(&pull, 4, 0);
        assert!(
            pull_row.per_peer_bytes < push_row.per_peer_bytes,
            "pull sent {} bytes per peer against push's {}",
            pull_row.per_peer_bytes,
            push_row.per_peer_bytes
        );
    }

    /// The link buffer is a real bound on a modelled run, not a number the
    /// model ignores: both directions of every link are drained alongside
    /// being written, so a buffer of one is backpressure rather than a
    /// deadlock, and the traffic it carries is the same traffic.
    ///
    /// It also pins what the depth column means. Given room, a scheme queues
    /// more than one frame at a time; given a buffer of one it queues
    /// exactly one, because that is all there is. So the column reports what
    /// a run USED, and it only reports what a scheme WANTS when the buffer
    /// was generous enough not to clip it — which is why the comparison
    /// tables run at 512 and check the figure against it.
    #[tokio::test]
    async fn a_modelled_run_is_bounded_by_the_link_buffer_without_wedging_on_it() {
        let deep = run_modelled(cell(20, 4, 0, Engine::AnnouncePull { batch: 8 })).await;
        let mut shallow_config = cell(20, 4, 0, Engine::AnnouncePull { batch: 8 });
        shallow_config.capacity = 1;
        let shallow = run_modelled(shallow_config).await;

        assert!(
            shallow.converged,
            "a buffer of one must not wedge the model"
        );
        let deep_row = Row::from_outcome(&deep, 4, 0);
        let shallow_row = Row::from_outcome(&shallow, 4, 0);
        assert_eq!(
            shallow_row.per_peer_bytes, deep_row.per_peer_bytes,
            "the buffer bounds when frames cross, not how many"
        );
        assert_eq!(
            shallow_row.peak_link_frames, 1,
            "a buffer of one can never hold two"
        );
        assert!(
            deep_row.peak_link_frames > 1,
            "and given room the scheme queues more than one: {}",
            deep_row.peak_link_frames
        );
    }

    /// The model plans a round by walking each node's held objects, which
    /// live in a hash map — so the order it visits them in is not stable
    /// between one run and the next, and a measurement harness has to say
    /// which of its columns that reaches.
    ///
    /// It reaches none of the byte ones. Which link carries a copy, and in
    /// what order, moves; how many copies there are and how many bytes they
    /// weigh does not, because both follow from the topology. Duplicates and
    /// the depth of the propagation tree sit on the other side of that line,
    /// the same way they do for the asynchronous engine.
    #[tokio::test]
    async fn the_model_reproduces_its_byte_columns_across_runs() {
        let once = run_modelled(cell(20, 4, 0, Engine::AnnouncePull { batch: 8 })).await;
        let twice = run_modelled(cell(20, 4, 0, Engine::AnnouncePull { batch: 8 })).await;

        let (first, second) = (
            Row::from_outcome(&once, 4, 0),
            Row::from_outcome(&twice, 4, 0),
        );
        assert_eq!(first.per_peer_bytes, second.per_peer_bytes);
        assert_eq!(first.wire_bytes, second.wire_bytes);
        assert_eq!(first.peak_link_frames, second.peak_link_frames);
        assert_eq!(once.rounds, twice.rounds);
        // `duplicates` is deliberately not asserted: it counts receipts, and
        // which link delivered a given copy first is exactly what the visit
        // order decides.
    }

    /// Pull pays a cycle per phase that push does not, and the item's
    /// acceptance criteria name it: bandwidth is bought with latency.
    #[tokio::test]
    async fn pull_reports_the_round_trips_it_costs() {
        let pull = run_modelled(cell(20, 4, 0, Engine::AnnouncePull { batch: 50 })).await;

        assert_eq!(pull.rounds.len(), 3, "one count per phase");
        assert!(
            pull.rounds.iter().all(|&r| r > 0),
            "every phase costs at least one cycle: {:?}",
            pull.rounds
        );
    }

    /// The threshold has to be able to turn hybrid into either of the two
    /// schemes it sits between, or a sweep over it proves nothing.
    #[tokio::test]
    async fn the_hybrid_threshold_spans_both_schemes() {
        let peers = 20;
        let announce_everything =
            run_modelled(cell(peers, 4, 0, Engine::AnnouncePull { batch: 8 })).await;
        let hybrid_at_zero = run_modelled(cell(
            peers,
            4,
            0,
            Engine::Hybrid {
                batch: 8,
                push_below: 0,
            },
        ))
        .await;
        let hybrid_at_everything = run_modelled(cell(
            peers,
            4,
            0,
            Engine::Hybrid {
                batch: 8,
                push_below: usize::MAX,
            },
        ))
        .await;

        let bytes = |o: &Outcome| Row::from_outcome(o, 4, 0).per_peer_bytes;
        assert_eq!(
            bytes(&hybrid_at_zero),
            bytes(&announce_everything),
            "a threshold below every object must be pure announce/pull"
        );
        assert!(
            bytes(&hybrid_at_everything) > bytes(&announce_everything),
            "a threshold above every object must push everything, which costs more"
        );
    }
}
