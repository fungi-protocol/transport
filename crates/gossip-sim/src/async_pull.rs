//! An announce/pull engine with the production engine's shape.
//!
//! The lockstep model in [`crate::engine`] measures what announce/pull costs,
//! but it measures it in a driver that plans a step and then executes it.
//! Everything it says about the scheme therefore rests on a model validated
//! against the real engine on PUSH alone — where the agreement is guaranteed
//! anyway, because push sends `k + (n-1)(k-1)` copies of every object
//! whatever order it runs in.
//!
//! Announce/pull is not like that. How much announcement a peer suppresses
//! depends on what it has already been told when it decides, and that is
//! exactly what an interleaving changes. So this is the same scheme built the
//! way the production engine is built — a hub task per node, a task per link,
//! bounded internal queues that fail loudly — so the model's numbers have
//! something to be checked against.
//!
//! What it is not: production code. There is no type-state, no conformance
//! suite, no negotiated capability, and the identity of an object is handed
//! in by the harness rather than read off the message, because the encoding
//! that would carry it is another item's work.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use fungi_transport::{BroadcastChannel, RecvError, RecvHalf, SendError, SendHalf, SessionBound};
use std::future::Future;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::engine::{ObjId, control_frame, data_frame, decode_control, frame_tag};
use crate::workload::Workload;

/// What ended a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullError {
    /// A bounded internal queue overflowed. Like the production engine, this
    /// ends the group rather than dropping: a node that silently discards
    /// has diverged from its peers, and divergence is the one thing a
    /// dissemination scheme may not do quietly.
    QueueFull,
    /// A link could no longer carry.
    LinkClosed(String),
    /// Every link ended.
    AllLinksEnded,
    /// A task did not finish.
    TaskFailed(String),
}

/// Internal bounds, mirroring the production engine's.
#[derive(Debug, Clone, Copy)]
pub struct PullConfig {
    /// Every internal queue's depth.
    pub queue_capacity: usize,
    /// How many identities ride in one announcement or request frame. A
    /// partial batch is flushed as soon as the hub has nothing else to do,
    /// so this bounds a frame rather than delaying one.
    pub batch: usize,
}

/// What a link handed the hub.
enum LinkEvent {
    /// A frame arrived.
    Frame { link: usize, bytes: Vec<u8> },
    /// A link ended.
    Failed(PullError),
}

/// One node of an announce/pull group.
#[derive(Debug)]
pub struct AnnounceBroadcast {
    outbound: Option<mpsc::Sender<Vec<u8>>>,
    incoming: mpsc::Receiver<Vec<u8>>,
    tasks: Vec<tokio::task::JoinHandle<Result<(), PullError>>>,
}

impl AnnounceBroadcast {
    /// Build a node over already-established links.
    ///
    /// `known` are objects this node resolves locally and therefore holds
    /// without anything crossing a link — a full node's prevouts. It
    /// announces them like anything else it holds, which is the whole point
    /// of addressing them separately.
    pub fn with_config<C: SessionBound + 'static>(
        channels: Vec<C>,
        config: PullConfig,
        workload: Arc<Workload>,
        known: Vec<(ObjId, Arc<[u8]>)>,
    ) -> Self {
        assert!(config.queue_capacity > 0, "queue capacity must be nonzero");
        let (incoming_tx, incoming) = mpsc::channel(config.queue_capacity);
        if channels.is_empty() {
            drop(incoming_tx);
            return Self {
                outbound: None,
                incoming,
                tasks: Vec::new(),
            };
        }

        let (outbound_tx, outbound_rx) = mpsc::channel(config.queue_capacity);
        let (to_hub, from_links) = mpsc::channel::<LinkEvent>(config.queue_capacity);
        let mut link_cmds = Vec::with_capacity(channels.len());
        let mut tasks = Vec::with_capacity(channels.len() + 1);

        for (index, mut channel) in channels.into_iter().enumerate() {
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(config.queue_capacity);
            link_cmds.push(cmd_tx);
            let to_hub = to_hub.clone();
            tasks.push(tokio::spawn(async move {
                let (mut tx, mut rx) = channel.split();
                let to_hub_out = to_hub.clone();
                // Two loops, independently driven, for the reason the
                // production engine gives: a forward waiting on a slow peer
                // must not stop this link from draining what that peer sends.
                let sending = async move {
                    while let Some(frame) = cmd_rx.recv().await {
                        if let Err(error) = tx.send(&frame).await {
                            let failure = PullError::LinkClosed(error.to_string());
                            let _ = to_hub_out.send(LinkEvent::Failed(failure.clone())).await;
                            return Err(failure);
                        }
                    }
                    Ok(())
                };
                let receiving = async move {
                    loop {
                        match rx.recv().await {
                            Ok(bytes) => {
                                if to_hub
                                    .send(LinkEvent::Frame { link: index, bytes })
                                    .await
                                    .is_err()
                                {
                                    return Ok(());
                                }
                            }
                            Err(error) => {
                                let failure = PullError::LinkClosed(error.to_string());
                                let _ = to_hub.send(LinkEvent::Failed(failure.clone())).await;
                                return Err(failure);
                            }
                        }
                    }
                };
                let sending = std::pin::pin!(sending);
                let receiving = std::pin::pin!(receiving);
                match futures_util::future::select(sending, receiving).await {
                    futures_util::future::Either::Left((sent, _)) => sent,
                    futures_util::future::Either::Right((received, sending)) => {
                        let sent = sending.await;
                        received.and(sent)
                    }
                }
            }));
        }
        drop(to_hub);

        let links = link_cmds.len();
        let mut state = Hub {
            outbound: outbound_rx,
            from_links,
            link_cmds,
            incoming: incoming_tx,
            config,
            workload,
            held: HashMap::new(),
            announced: vec![HashSet::new(); links],
            offered: vec![HashSet::new(); links],
            in_flight: HashSet::new(),
            pending_announce: vec![Vec::new(); links],
            pending_request: vec![Vec::new(); links],
        };
        // Locally resolved objects go in the same way as anything else, so
        // they are ANNOUNCED like anything else. A node that held them
        // silently would be a peer its neighbours could not pull from, and an
        // object reachable only through such a node would never arrive — which
        // is the whole reason these identities exist.
        for (id, bytes) in known {
            state.hold(id, bytes);
        }
        tasks.push(tokio::spawn(hub(state)));

        Self {
            outbound: Some(outbound_tx),
            incoming,
            tasks,
        }
    }

    /// Drain and end this node.
    pub async fn shutdown(self) -> Result<(), PullError> {
        let Self {
            outbound,
            incoming,
            tasks,
        } = self;
        drop(outbound);
        let mut failure = None;
        for task in tasks {
            match task.await {
                Ok(Ok(())) => {}
                // A peer that converged and started its own teardown ends
                // this fixed group without that being a local failure.
                Ok(Err(PullError::LinkClosed(_) | PullError::AllLinksEnded)) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(PullError::TaskFailed(error.to_string()));
                }
            }
        }
        drop(incoming);
        failure.map_or(Ok(()), Err)
    }
}

impl BroadcastChannel for AnnounceBroadcast {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let outbound = self.outbound.clone();
        let msg = msg.to_vec();
        async move {
            let Some(outbound) = outbound else {
                return Ok(());
            };
            outbound.send(msg).await.map_err(|_| SendError::Closed)
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        // A pure pop: cancel-safe by the queue's contract, which the driver
        // relies on by racing this against a wakeup in a `select!`. Closes
        // when the hub exits, which is the whole channel dying.
        self.incoming.recv().await.ok_or(RecvError::Closed)
    }
}

/// Everything one node's hub owns.
struct Hub {
    outbound: mpsc::Receiver<Vec<u8>>,
    from_links: mpsc::Receiver<LinkEvent>,
    link_cmds: Vec<mpsc::Sender<Vec<u8>>>,
    incoming: mpsc::Sender<Vec<u8>>,
    config: PullConfig,
    workload: Arc<Workload>,
    /// Objects held complete.
    held: HashMap<ObjId, Arc<[u8]>>,
    /// Per link: identities already announced or handed to it.
    announced: Vec<HashSet<ObjId>>,
    /// Per link: identities it told us it holds.
    offered: Vec<HashSet<ObjId>>,
    /// Identities asked of some link and not yet received. Asking two peers
    /// for the same object is the waste this scheme exists to avoid.
    in_flight: HashSet<ObjId>,
    /// Identities waiting to be announced, per link.
    pending_announce: Vec<Vec<ObjId>>,
    /// Identities waiting to be requested, per link.
    pending_request: Vec<Vec<ObjId>>,
}

/// The hub: sole owner of what this node holds and of every link's queue.
///
/// Like the production engine's, it never waits on an output — a full queue
/// ends the group rather than coupling both directions of a link through one
/// task.
async fn hub(mut state: Hub) -> Result<(), PullError> {
    loop {
        // Take everything already available, then put what that produced on
        // the wire before blocking. Accumulating across one burst is what
        // fills a batch; holding it past the point where there is nothing
        // left to add would delay a frame rather than bound it, and a hub
        // that only flushed when it had handled nothing would never flush
        // at all under load.
        while let Ok(msg) = state.outbound.try_recv() {
            state.publish(msg)?;
        }
        while let Ok(event) = state.from_links.try_recv() {
            match event {
                LinkEvent::Failed(error) => return Err(error),
                LinkEvent::Frame { link, bytes } => state.take(link, bytes)?,
            }
        }
        state.flush()?;

        enum Next {
            Out(Option<Vec<u8>>),
            In(Option<LinkEvent>),
        }
        let next = tokio::select! {
            msg = state.outbound.recv() => Next::Out(msg),
            event = state.from_links.recv() => Next::In(event),
        };
        match next {
            // The consumer let go: nobody can publish or receive again.
            Next::Out(None) => {
                state.flush()?;
                return Ok(());
            }
            Next::Out(Some(msg)) => state.publish(msg)?,
            Next::In(None) => return Err(PullError::AllLinksEnded),
            Next::In(Some(LinkEvent::Failed(error))) => return Err(error),
            Next::In(Some(LinkEvent::Frame { link, bytes })) => state.take(link, bytes)?,
        }
    }
}

impl Hub {
    /// This node's own publication.
    fn publish(&mut self, msg: Vec<u8>) -> Result<(), PullError> {
        let id = ObjId::of(&msg, &self.workload);
        self.hold(id, Arc::from(msg.as_slice()));
        Ok(())
    }

    /// A frame arrived on `link`.
    fn take(&mut self, link: usize, bytes: Vec<u8>) -> Result<(), PullError> {
        match frame_tag(&bytes) {
            Some((tag, body)) if tag == crate::engine::TAG_ANNOUNCE => {
                for id in decode_control(body) {
                    self.offered[link].insert(id);
                    // Nothing to tell a peer about an object it just told us
                    // about.
                    self.announced[link].insert(id);
                    if !self.held.contains_key(&id) && self.in_flight.insert(id) {
                        self.pending_request[link].push(id);
                    }
                }
            }
            Some((tag, body)) if tag == crate::engine::TAG_REQUEST => {
                for id in decode_control(body) {
                    if let Some(bytes) = self.held.get(&id).cloned() {
                        self.queue(link, data_frame(&bytes))?;
                    }
                }
            }
            Some((tag, body)) if tag == crate::engine::TAG_DATA => {
                let payload: Arc<[u8]> = Arc::from(body);
                let id = ObjId::of(&payload, &self.workload);
                self.in_flight.remove(&id);
                self.offered[link].insert(id);
                self.announced[link].insert(id);
                if !self.held.contains_key(&id) {
                    self.hold(id, payload.clone());
                    // Deliver AFTER the announcement bookkeeping, and never
                    // wait on the consumer.
                    match self.incoming.try_send(payload.to_vec()) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => return Err(PullError::QueueFull),
                        Err(TrySendError::Closed(_)) => {}
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Record an object and queue an announcement of it to every link that
    /// has neither been told about it nor told us about it.
    fn hold(&mut self, id: ObjId, bytes: Arc<[u8]>) {
        if self.held.insert(id, bytes).is_some() {
            return;
        }
        for link in 0..self.link_cmds.len() {
            if !self.announced[link].contains(&id) && !self.offered[link].contains(&id) {
                self.pending_announce[link].push(id);
            }
        }
    }

    /// Put whatever has accumulated on the wire.
    fn flush(&mut self) -> Result<(), PullError> {
        for link in 0..self.link_cmds.len() {
            let announce = std::mem::take(&mut self.pending_announce[link]);
            for chunk in announce.chunks(self.config.batch.max(1)) {
                self.announced[link].extend(chunk);
                self.queue(link, control_frame(crate::engine::TAG_ANNOUNCE, chunk))?;
            }
            let request = std::mem::take(&mut self.pending_request[link]);
            for chunk in request.chunks(self.config.batch.max(1)) {
                self.queue(link, control_frame(crate::engine::TAG_REQUEST, chunk))?;
            }
        }
        Ok(())
    }

    /// Hand one frame to one link, never waiting on it.
    fn queue(&mut self, link: usize, frame: Vec<u8>) -> Result<(), PullError> {
        match self.link_cmds[link].try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(PullError::QueueFull),
            // A link that has ended is not this node's failure; its own task
            // reports it.
            Err(TrySendError::Closed(_)) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fungi_transport::mem::{MemConfig, duplex};
    use fungi_transport::{AssumeSessionBound, mem::MemChannel};
    use std::collections::HashMap;

    use crate::topology::Topology;
    use crate::workload::{ConstructionConfig, DependencyAddressing, ProofFormat, Workload};

    /// A group of `peers` nodes over `topology`, each told about whichever
    /// dependency objects it resolves locally.
    fn group(
        topology: &Topology,
        workload: &Arc<Workload>,
        batch: usize,
    ) -> Vec<AnnounceBroadcast> {
        let cfg = MemConfig {
            capacity: Some(4096),
            ..MemConfig::default()
        };
        let mut links: HashMap<usize, Vec<AssumeSessionBound<MemChannel>>> = HashMap::new();
        for &(a, b) in &topology.edges {
            let (left, right) = duplex(cfg.clone());
            links.entry(a).or_default().push(AssumeSessionBound(left));
            links.entry(b).or_default().push(AssumeSessionBound(right));
        }
        let mut known: Vec<Vec<(ObjId, Arc<[u8]>)>> = vec![Vec::new(); topology.n];
        for publication in workload.phases().iter().flatten() {
            let id = ObjId::of(&publication.bytes, workload);
            let ObjId::Dependency(dep) = id else { continue };
            let bytes: Arc<[u8]> = Arc::from(publication.bytes.as_slice());
            for (node, holdings) in known.iter_mut().enumerate() {
                if node != publication.origin && workload.holds_a_priori(node, dep) {
                    holdings.push((id, bytes.clone()));
                }
            }
        }
        (0..topology.n)
            .map(|node| {
                AnnounceBroadcast::with_config(
                    links.remove(&node).unwrap_or_default(),
                    PullConfig {
                        queue_capacity: 4096,
                        batch,
                    },
                    workload.clone(),
                    std::mem::take(&mut known[node]),
                )
            })
            .collect()
    }

    /// Publish one phase and take everything each node learns of, bounded so
    /// a scheme that stops making progress fails the test rather than hanging
    /// it. Returns how many objects each node received.
    async fn disseminate(nodes: &mut [AnnounceBroadcast], workload: &Workload) -> Vec<usize> {
        for publication in &workload.phases()[0] {
            nodes[publication.origin]
                .send(&publication.bytes)
                .await
                .expect("a group that has not been shut down accepts publications");
        }
        let mut received = vec![0usize; nodes.len()];
        for _ in 0..40 {
            let mut moved = false;
            for (node, taken) in nodes.iter_mut().zip(received.iter_mut()) {
                while let Ok(Ok(_)) =
                    tokio::time::timeout(std::time::Duration::from_millis(20), node.recv()).await
                {
                    *taken += 1;
                    moved = true;
                }
            }
            if !moved {
                break;
            }
        }
        received
    }

    /// How many of a phase's publications a given node did not publish
    /// itself, which is what it has to be told about.
    fn owed(workload: &Workload, node: usize) -> usize {
        workload.phases()[0]
            .iter()
            .filter(|publication| publication.origin != node)
            .count()
    }

    /// The property the whole scheme is for: everyone ends up holding
    /// everything, without anyone having been sent it twice.
    #[tokio::test]
    async fn every_node_learns_of_every_publication() {
        let peers = 12;
        let workload = Arc::new(Workload::construction(peers, 0));
        let topology = Topology::degree_k(peers, 4, 0).expect("n=12, k=4 is feasible");
        let mut nodes = group(&topology, &workload, 8);

        let received = disseminate(&mut nodes, &workload).await;

        for (node, count) in received.iter().enumerate() {
            assert_eq!(
                *count,
                owed(&workload, node),
                "node {node} was told of {count} publications and is owed {}",
                owed(&workload, node)
            );
        }
    }

    /// A node that resolves a dependency locally must ANNOUNCE it, not merely
    /// hold it: an object whose only path to a peer runs through such a node
    /// otherwise never arrives.
    ///
    /// This fails only on a MIXED population. With nobody resolving locally
    /// there is nothing to announce silently, and with everybody resolving
    /// there is nothing anyone needs — so a test at either end of that axis
    /// passes against the defect, which is how it survived being written in
    /// the first place.
    #[tokio::test]
    async fn a_locally_resolved_object_is_announced_and_not_merely_held() {
        let peers = 16;
        for full_node_fraction in [0.0, 0.5, 1.0] {
            let workload = Arc::new(Workload::construction_with(ConstructionConfig {
                peers,
                seed: 0,
                legacy_fraction: 0.3,
                full_node_fraction,
                late_addition_fraction: 1.0,
                dependencies: DependencyAddressing::Separate,
                validity_proofs_per_phase: 0,
                late_addition_overhead: 0,
                proofs: ProofFormat::Compact,
            }));
            let topology = Topology::degree_k(peers, 4, 0).expect("n=16, k=4 is feasible");
            let mut nodes = group(&topology, &workload, 8);

            let received = disseminate(&mut nodes, &workload).await;

            for (node, count) in received.iter().enumerate() {
                // A node that already resolves an object is not told about
                // it, so what it is owed is what it neither published nor
                // holds a priori.
                let owed = workload.phases()[0]
                    .iter()
                    .filter(|publication| publication.origin != node)
                    .filter(
                        |publication| match ObjId::of(&publication.bytes, &workload) {
                            ObjId::Dependency(dep) => !workload.holds_a_priori(node, dep),
                            ObjId::Content(_) => true,
                        },
                    )
                    .count();
                assert_eq!(
                    *count, owed,
                    "full_node_fraction {full_node_fraction}, node {node}: told of {count}, \
                     owed {owed}"
                );
            }
        }
    }

    /// Batching must bound a frame, not delay one. A hub that only put its
    /// accumulated identities on the wire when it had nothing to handle would
    /// never put them there at all under load, and the group would stop with
    /// every node blocked and nothing in flight.
    #[tokio::test]
    async fn a_batch_is_flushed_even_when_the_hub_never_falls_idle() {
        let peers = 12;
        let workload = Arc::new(Workload::construction(peers, 0));
        let topology = Topology::degree_k(peers, 4, 0).expect("n=12, k=4 is feasible");

        // A batch far larger than anything one node will ever accumulate:
        // if a full batch were the only thing that triggered a flush,
        // nothing would ever be sent.
        let mut nodes = group(&topology, &workload, 10_000);
        let received = disseminate(&mut nodes, &workload).await;

        for (node, count) in received.iter().enumerate() {
            assert_eq!(*count, owed(&workload, node), "node {node}");
        }
    }

    /// A group of one has no peers to announce to, and must still be usable.
    #[tokio::test]
    async fn a_node_with_no_links_accepts_publications_and_ends_cleanly() {
        let workload = Arc::new(Workload::construction(1, 0));
        let mut node = AnnounceBroadcast::with_config(
            Vec::<AssumeSessionBound<MemChannel>>::new(),
            PullConfig {
                queue_capacity: 8,
                batch: 8,
            },
            workload.clone(),
            Vec::new(),
        );

        assert!(node.send(b"nowhere to go").await.is_ok());
        assert!(node.shutdown().await.is_ok());
    }

    /// Shutting a node down ends it rather than leaving its tasks behind, and
    /// says so.
    #[tokio::test]
    async fn shutdown_ends_a_healthy_pair() {
        let workload = Arc::new(Workload::construction(2, 0));
        let topology = Topology::complete(2);
        let mut nodes = group(&topology, &workload, 8);
        let _ = disseminate(&mut nodes, &workload).await;

        for node in nodes {
            assert!(node.shutdown().await.is_ok());
        }
    }
}
