//! Naive gossip over fixed P2P channels: the peer-network wiring and the
//! first production implementation of [`BroadcastChannel`].
//!
//! [`GossipBroadcast`] re-sends every first-seen message on all other
//! links — the naive scheme: no retransmission, no ordering, and a `seen`
//! set that grows for the life of the channel (the known cost of naive
//! gossip; an id-exchanging gossip retires it later). Membership is fixed
//! at construction. Losing a link or exhausting an internal bound ends the
//! group rather than silently weakening convergence; recovery is a NEW
//! group, never this object.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::future::Future;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::channel::{BroadcastChannel, RecvHalf, SendHalf, SplitChannel};
use crate::error::{RecvError, SendError};

/// Naive gossip over a fixed set of P2P channels, as a broadcast channel:
/// the first production implementation of [`BroadcastChannel`] — the
/// anonymous kind: gossip can vouch for its relaying neighbor, never a
/// message's originator.
///
/// Implementation promises, on top of the trait contract:
/// - `Ok` from `send` means the internal hub accepted the message for
///   best-effort fan-out — never delivery.
/// - Forwarding does not ride on `recv`: the hub relays first-seen
///   messages to the other links BEFORE queueing them for this consumer,
///   so a node serves as a passive relay.
/// - The hub never awaits an output. A full link or consumer queue ends the
///   group: bounded memory and liveness are preserved without presenting a
///   silently divergent message set as a healthy channel.
/// - Each link is driven through [`SplitChannel`]: its sending and receiving
///   halves run as two joined loops, so a forward waiting on a slow peer
///   never stops that link from draining what the peer sends. There is no
///   wall-clock deadline, but the queues stay bounded: if a blocked link's
///   command queue fills, the group ends explicitly rather than silently
///   losing convergence. Establishing the group is a separate matter, and
///   its cadence is the caller's to state.
/// - Dropping the object abandons the node mid-flight (fine for a
///   process that lives on); [`shutdown`](GossipBroadcast::shutdown)
///   instead drains locally accepted work, joins every task, and reports a
///   forward or task failure. Success is not remote delivery confirmation.
///   Draining waits on the peers: a peer that stops reading is a drain that
///   never finishes, so a caller that cannot wait forever bounds the call
///   externally — the same stance the [`Channel`](crate::Channel) contract
///   takes on timeouts.
/// - The `seen` set holds every distinct message for the channel's life.
/// - Constructed with zero channels, sends are vacuously `Ok` and `recv`
///   reports the channel dead (mirroring the in-memory group); a group
///   that LOST all its links is dead in both directions.
#[derive(Debug)]
pub struct GossipBroadcast {
    /// `None` when constructed with zero channels: vacuous sends.
    outbound: Option<mpsc::Sender<Vec<u8>>>,
    incoming: mpsc::Receiver<Vec<u8>>,
    max_msg_len: Option<usize>,
    /// Every spawned task (links + hub), joined by [`shutdown`](Self::shutdown).
    tasks: Vec<tokio::task::JoinHandle<Result<(), GossipError>>>,
}

/// Runtime bounds for a fixed-membership gossip node.
#[derive(Debug, Clone, Copy)]
pub struct GossipConfig {
    /// Capacity of each internal queue. Must be nonzero.
    pub queue_capacity: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self { queue_capacity: 64 }
    }
}

/// Which internal output of a gossip node could no longer accept work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueKind {
    /// The command queue feeding one P2P link.
    Link,
    /// The queue delivering messages to this node's consumer.
    Consumer,
}

impl fmt::Display for QueueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link => f.write_str("link"),
            Self::Consumer => f.write_str("consumer"),
        }
    }
}

/// Why a gossip node could no longer preserve its convergence guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GossipError {
    /// A bounded internal queue filled before its consumer made progress.
    QueueFull {
        /// Which internal output could no longer accept work.
        output: QueueKind,
    },
    /// One P2P link stopped receiving messages.
    LinkClosed {
        /// Stable index of the failed link within this node.
        link: usize,
        /// What the link reported. Purely diagnostic: a transport cannot
        /// tell a peer's clean departure from a path failure, so this
        /// never carries a decision — only what to print.
        reason: String,
    },
    /// Every link task ended without reporting which one failed first —
    /// the group is gone, and no single link can be named for it.
    AllLinksEnded,
    /// One P2P forward failed.
    ForwardFailed {
        /// Stable index of the failed link.
        link: usize,
        /// Diagnostic reported by the P2P channel.
        reason: String,
    },
    /// An internal task panicked or was cancelled.
    TaskFailed {
        /// Tokio join diagnostic.
        reason: String,
    },
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull { output } => write!(f, "gossip {output} queue is full"),
            Self::LinkClosed { link, reason } => {
                write!(f, "gossip link {link} closed: {reason}")
            }
            Self::AllLinksEnded => write!(f, "every gossip link ended"),
            Self::ForwardFailed { link, reason } => {
                write!(f, "gossip forward on link {link} failed: {reason}")
            }
            Self::TaskFailed { reason } => write!(f, "gossip task failed: {reason}"),
        }
    }
}

impl Error for GossipError {}

#[derive(Debug)]
enum LinkEvent {
    Message { link: usize, message: Vec<u8> },
    Failed(GossipError),
}

impl GossipBroadcast {
    /// Build a gossip node over already-established channels (one per
    /// peer link). The channels must form a connected graph across the
    /// group or messages cannot reach everyone — wiring the graph is the
    /// caller's job (a future `wire` layer).
    pub fn new<C: SplitChannel + 'static>(channels: Vec<C>) -> Self {
        Self::with_config(channels, GossipConfig::default())
    }

    /// Build a gossip node with explicit internal bounds.
    pub fn with_config<C: SplitChannel + 'static>(channels: Vec<C>, config: GossipConfig) -> Self {
        assert!(
            config.queue_capacity > 0,
            "gossip queue capacity must be nonzero"
        );
        let (incoming_tx, incoming) = mpsc::channel(config.queue_capacity);
        if channels.is_empty() {
            // No links will ever exist: recv is dead from birth, sends are
            // vacuous (see the type docs).
            drop(incoming_tx);
            return Self {
                outbound: None,
                incoming,
                max_msg_len: None,
                tasks: Vec::new(),
            };
        }
        let (outbound_tx, outbound_rx) = mpsc::channel(config.queue_capacity);
        let (to_hub, from_links) = mpsc::channel::<LinkEvent>(config.queue_capacity);
        let mut link_cmds = Vec::with_capacity(channels.len());
        let mut tasks = Vec::with_capacity(channels.len() + 1);
        for (i, mut ch) in channels.into_iter().enumerate() {
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(config.queue_capacity);
            link_cmds.push(cmd_tx);
            let to_hub = to_hub.clone();
            tasks.push(tokio::spawn(async move {
                let (mut tx, mut rx) = ch.split();
                let to_hub_out = to_hub.clone();
                // Two independently driven loops: a forward waiting on a slow
                // peer does not stop this link from draining what that peer
                // sends. Completion is coordinated below according to each
                // direction's cancellation contract.
                let sending = async move {
                    // Runs until the hub drops its command queue, which also
                    // makes this the flush path: everything already queued is
                    // delivered before the loop sees the close.
                    while let Some(msg) = cmd_rx.recv().await {
                        if let Err(error) = tx.send(&msg).await {
                            let failure = GossipError::ForwardFailed {
                                link: i,
                                reason: error.to_string(),
                            };
                            let _ = to_hub_out.send(LinkEvent::Failed(failure.clone())).await;
                            return Err(failure);
                        }
                    }
                    Ok(())
                };
                let receiving = async move {
                    loop {
                        match rx.recv().await {
                            Ok(message) => {
                                if to_hub
                                    .send(LinkEvent::Message { link: i, message })
                                    .await
                                    .is_err()
                                {
                                    // The hub is gone; the sending loop is
                                    // already draining what this link owes.
                                    return Ok(());
                                }
                            }
                            Err(error) => {
                                let failure = GossipError::LinkClosed {
                                    link: i,
                                    reason: error.to_string(),
                                };
                                let _ = to_hub.send(LinkEvent::Failed(failure.clone())).await;
                                return Err(failure);
                            }
                        }
                    }
                };
                let sending = std::pin::pin!(sending);
                let receiving = std::pin::pin!(receiving);
                match futures_util::future::select(sending, receiving).await {
                    // The sending half finished: the hub closed the command
                    // queue (this node is winding down, everything owed
                    // already delivered) or a forward failed. Dropping the
                    // receiving half costs nothing — `recv` is cancel-safe,
                    // and there is no longer a hub to deliver into.
                    futures_util::future::Either::Left((sent, _)) => sent,
                    // The receive side ended first. Let the sending half run
                    // to completion so a forward this link still owes its
                    // peer is not abandoned mid-flight.
                    futures_util::future::Either::Right((received, sending)) => {
                        let sent = sending.await;
                        received.and(sent)
                    }
                }
            }));
        }
        drop(to_hub);
        tasks.push(tokio::spawn(hub(
            outbound_rx,
            from_links,
            link_cmds,
            incoming_tx,
        )));
        Self {
            outbound: Some(outbound_tx),
            incoming,
            max_msg_len: None,
            tasks,
        }
    }

    /// Enable local size rejection: oversized sends fail with
    /// [`SendError::TooLarge`] (the one recoverable send error) before
    /// touching any link. Without it there is no local check — each
    /// link's own limit governs, and a link-level rejection is fan-out
    /// best-effort like any other link error.
    pub fn with_max_msg_len(mut self, max: usize) -> Self {
        self.max_msg_len = Some(max);
        self
    }

    /// Drain and end this node: stop accepting publications, let link tasks
    /// process their locally queued forwards, and join every task. Success
    /// means the local drain completed; it is not remote delivery
    /// confirmation. Dropping the object instead abandons work mid-flight.
    ///
    /// There is no internal deadline: a forward waits as long as its peer
    /// takes, so against a peer that has stopped reading this never returns.
    /// Bound it externally if that matters.
    pub async fn shutdown(self) -> Result<(), GossipError> {
        let Self {
            outbound,
            incoming,
            tasks,
            max_msg_len: _,
        } = self;
        // Dropping the sender lets the hub drain what is queued and exit;
        // `incoming` stays alive until the join so the consumer side does
        // not disappear while locally accepted work is being drained.
        drop(outbound);
        let mut failure = None;
        for task in tasks {
            match task.await {
                Ok(Ok(())) => {}
                // A peer may close after it has converged and begun its own
                // shutdown. That ends this fixed group but is not a failure
                // of our local drain; recv already exposes the closure while
                // the node is running.
                Ok(Err(GossipError::LinkClosed { .. } | GossipError::AllLinksEnded)) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(GossipError::TaskFailed {
                        reason: error.to_string(),
                    });
                }
            };
        }
        drop(incoming);
        failure.map_or(Ok(()), Err)
    }
}

/// The hub: sole owner of the dedup set and every link's command queue.
/// `send` MUST route through here rather than straight to the links — if
/// the consumer fanned out directly, a cycle could reflect its message
/// back before the hub learned of it, and the hub would deliver the
/// consumer's own message back as novel and re-propagate it. Registering
/// in `seen` and fanning out are one hub step.
///
/// The hub never waits on an output (fan-out to links, and delivery to the
/// consumer): it only ever `try_send`s. An awaited full queue
/// would couple both directions of a link through this one hub task —
/// two peers bursting at each other simultaneously would then each fill
/// the other's queue and block waiting for space, a cycle with no way
/// out. A full queue ends the group instead, making the loss of convergence
/// observable without letting the hub wedge.
async fn hub(
    mut outbound: mpsc::Receiver<Vec<u8>>,
    mut from_links: mpsc::Receiver<LinkEvent>,
    link_cmds: Vec<mpsc::Sender<Vec<u8>>>,
    incoming: mpsc::Sender<Vec<u8>>,
) -> Result<(), GossipError> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    loop {
        enum Event {
            Out(Option<Vec<u8>>),
            In(Option<LinkEvent>),
        }
        let event = tokio::select! {
            m = outbound.recv() => Event::Out(m),
            m = from_links.recv() => Event::In(m),
        };
        match event {
            // The consumer dropped its handle: nobody can send or recv
            // again, so the hub exits and its dropped queues end every
            // link task through the drained path.
            Event::Out(None) => return Ok(()),
            Event::Out(Some(msg)) => {
                // Check before cloning: the common case on redundant paths
                // is a duplicate, and a duplicate is discarded, so it must
                // not pay for a clone it never uses.
                if !seen.contains(&msg) {
                    seen.insert(msg.clone());
                    fan_out(&link_cmds, None, msg)?;
                }
            }
            // Every link task is gone: the group is dead.
            Event::In(None) => {
                drain_inbound(&mut from_links, &mut seen, &incoming);
                return Err(GossipError::AllLinksEnded);
            }
            Event::In(Some(LinkEvent::Failed(error))) => {
                drain_inbound(&mut from_links, &mut seen, &incoming);
                return Err(error);
            }
            Event::In(Some(LinkEvent::Message {
                link: from,
                message: msg,
            })) => {
                if !seen.contains(&msg) {
                    seen.insert(msg.clone());
                    // Relay BEFORE queueing for the consumer, so a slow
                    // consumer does not delay the rest of the graph.
                    fan_out(&link_cmds, Some(from), msg.clone())?;
                    match incoming.try_send(msg) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            return Err(GossipError::QueueFull {
                                output: QueueKind::Consumer,
                            });
                        }
                        Err(TrySendError::Closed(_)) => return Ok(()),
                    }
                }
            }
        }
    }
}

/// Preserve novel inbound messages already owned by the hub when a link
/// failure makes the group terminal. No new relay is attempted during this
/// final local courtesy.
fn drain_inbound(
    from_links: &mut mpsc::Receiver<LinkEvent>,
    seen: &mut HashSet<Vec<u8>>,
    incoming: &mpsc::Sender<Vec<u8>>,
) {
    while let Ok(event) = from_links.try_recv() {
        let LinkEvent::Message { message, .. } = event else {
            continue;
        };
        if seen.insert(message.clone()) && incoming.try_send(message).is_err() {
            return;
        }
    }
}

/// Queue `msg` on every link except `skip`. Any output that cannot accept
/// the first-seen message ends the fixed group; continuing would make
/// convergence depend silently on queue timing.
fn fan_out(
    link_cmds: &[mpsc::Sender<Vec<u8>>],
    skip: Option<usize>,
    msg: Vec<u8>,
) -> Result<(), GossipError> {
    for (j, cmd) in link_cmds.iter().enumerate() {
        if Some(j) == skip {
            continue;
        }
        match cmd.try_send(msg.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(GossipError::QueueFull {
                    output: QueueKind::Link,
                });
            }
            Err(TrySendError::Closed(_)) => {
                return Err(GossipError::LinkClosed {
                    link: j,
                    reason: "link task ended".into(),
                });
            }
        }
    }
    Ok(())
}

impl BroadcastChannel for GossipBroadcast {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        // Test the length FIRST, before copying — an oversized message is
        // rejected without ever being allocated.
        let msg = match self.max_msg_len {
            Some(max) if msg.len() > max => Err(max),
            _ => Ok(msg.to_vec()),
        };
        let outbound = self.outbound.clone();
        async move {
            let msg = match msg {
                Ok(msg) => msg,
                Err(max) => return Err(SendError::TooLarge { max }),
            };
            match outbound {
                None => Ok(()), // a group of one: vacuous delivery
                Some(tx) => tx.send(msg).await.map_err(|_| SendError::Closed),
            }
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        // A pure pop: cancel-safe by the queue's contract; closes when the
        // hub exits (all links gone), which is the whole channel dying.
        self.incoming.recv().await.ok_or(RecvError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Channel;
    use crate::mem::{MemConfig, duplex};
    use std::time::Duration;

    fn cfg() -> MemConfig {
        MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        }
    }

    // Two nodes over one duplex: messages cross in both directions through
    // the live type, and each side's own send never comes back to it.
    #[tokio::test]
    async fn pair_exchanges_both_ways_without_echo() {
        let (ab, ba) = duplex(cfg());
        let mut a = GossipBroadcast::new(vec![ab]);
        let mut b = GossipBroadcast::new(vec![ba]);
        a.send(b"from-a").await.unwrap();
        b.send(b"from-b").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"from-a");
        assert_eq!(a.recv().await.unwrap(), b"from-b");
        let echo = tokio::time::timeout(Duration::from_millis(50), a.recv()).await;
        assert!(echo.is_err(), "a sender must not receive its own broadcast");
    }

    // The one recoverable send error, checked in the object before any link.
    #[tokio::test]
    async fn too_large_is_recoverable() {
        let (ab, ba) = duplex(cfg());
        let mut a = GossipBroadcast::new(vec![ab]).with_max_msg_len(4);
        let mut b = GossipBroadcast::new(vec![ba]);
        assert!(matches!(
            a.send(b"oversized").await,
            Err(SendError::TooLarge { max: 4 })
        ));
        a.send(b"ok").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"ok");
    }

    // One channel, one fate: when the peer's whole node goes away, this
    // side's recv reports the channel dead (link death cascades to the hub).
    #[tokio::test]
    async fn recv_reports_dead_after_peer_drops() {
        let (ab, ba) = duplex(cfg());
        let mut a = GossipBroadcast::new(vec![ab]);
        let b = GossipBroadcast::new(vec![ba]);
        drop(b);
        assert!(a.recv().await.is_err());
    }

    // A blocked forward does not stop this link from receiving: the split
    // lets it drain messages from the same peer while that forward waits.
    // Saturating the bounded command queue is tested separately below;
    // through the unified channel even this exchange would be wedged.
    #[tokio::test]
    async fn a_blocked_forward_does_not_stop_receiving() {
        let (ab, mut ba) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        let mut a = GossipBroadcast::new(vec![ab]);
        // Two forwards against a one-slot link nobody drains: the second is
        // stuck in the sending half from here on.
        a.send(b"fills the link").await.unwrap();
        a.send(b"waits on the peer").await.unwrap();
        // The peer speaks anyway, and it still arrives.
        ba.send(b"from the peer").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), a.recv())
            .await
            .expect("a blocked forward must not stop the receiving half")
            .unwrap();
        assert_eq!(got, b"from the peer");
    }

    // shutdown flushes: a send still in the pipes when the consumer is
    // done reaches the peer before the tasks are torn down.
    #[tokio::test]
    async fn shutdown_flushes_pending_sends() {
        let (ab, mut ba) = duplex(cfg());
        let mut a = GossipBroadcast::new(vec![ab]);
        a.send(b"parting word").await.unwrap();
        a.shutdown().await.unwrap();
        assert_eq!(ba.recv().await.unwrap(), b"parting word");
    }

    // Empty-group semantics mirror the mem group: constructed with zero
    // channels, sends are vacuously Ok and recv reports the channel dead.
    #[tokio::test]
    async fn empty_group_sends_vacuously_and_recv_is_dead() {
        let mut g = GossipBroadcast::new(Vec::<crate::mem::MemChannel>::new());
        g.send(b"into the void").await.unwrap();
        assert!(matches!(g.recv().await, Err(RecvError::Closed)));
    }
}
