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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::channel::{
    BroadcastChannel, Connector, ListenParams, Listener, RecvHalf, SendHalf, SessionBound,
    Transport,
};
use crate::error::{ConnectError, RecvError, SendError};
use crate::isolation::CircuitIsolationId;

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
/// - Each link is driven through [`SplitChannel`](crate::SplitChannel): its
///   sending and receiving halves run as two joined loops, so a forward
///   waiting on a slow peer never stops that link from draining what the
///   peer sends. There is no wall-clock deadline, but the queues stay
///   bounded: if a blocked link's command queue fills, the group ends
///   explicitly rather than silently losing convergence. Establishing the
///   group is a separate matter, and its cadence is the caller's to state.
/// - Dropping the object abandons the node mid-flight (fine for a
///   process that lives on); [`shutdown`](GossipBroadcast::shutdown)
///   instead drains locally accepted work, joins every task, and reports a
///   forward or task failure. Success is not remote delivery confirmation.
///   Draining waits on the peers, and nothing here bounds that wait: no
///   duration distinguishes a slow peer from a stopped one, so a node that
///   gave up on its own schedule would be deciding what it cannot observe.
///   [`begin_shutdown`](GossipBroadcast::begin_shutdown) hands back the
///   drain instead, so a caller that cannot wait puts its own clock around
///   [`finish`](Draining::finish) and then asks
///   [`abandon`](Draining::abandon) which links were left owing
///   ([`NotFlushed`](GossipError::NotFlushed)). A group that ends BADLY
///   releases its own links: it has already reported losing convergence, so
///   a forward parked on a peer is owed to nobody and is dropped, which
///   costs nothing now that abandoning a send leaves the stream well formed.
///   A group that ends cleanly still flushes what it accepted. A link the
///   caller abandons is detached rather than cancelled, because that peer is
///   still there and may yet take it, and a late arrival is harmless: `seen`
///   discards what is already held.
/// - The `seen` set holds every distinct message for the channel's life.
/// - Constructed with zero channels, sends are vacuously `Ok` and `recv`
///   reports the channel dead (mirroring the in-memory group); a group
///   that LOST a link is dead in both directions. The local
///   `with_max_msg_len` check still applies, though: an oversized send
///   fails `TooLarge` even with zero links.
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
    /// A link was still delivering what it already owed when the caller's
    /// drain budget ran out.
    ///
    /// Raised by the link itself when the group ended badly, and by
    /// [`Draining::abandon`] when the caller stopped waiting on a group that
    /// had not. In the second case the task is left running rather than
    /// cancelled: the peer is still there and may yet take what it is owed,
    /// and a late arrival is harmless because a message already held is
    /// discarded on sight.
    NotFlushed {
        /// Stable index of the link that had not finished.
        link: usize,
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
            Self::NotFlushed { link } => {
                write!(f, "gossip link {link} did not finish flushing")
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
    /// caller's job (see [`Wiring`]).
    pub fn new<C: SessionBound + 'static>(channels: Vec<C>) -> Self {
        Self::with_config(channels, GossipConfig::default())
    }

    /// Build a gossip node with explicit internal bounds.
    pub fn with_config<C: SessionBound + 'static>(channels: Vec<C>, config: GossipConfig) -> Self {
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
        // Raised when the hub ends the group because it could no longer
        // preserve convergence, and NOT when the consumer simply closed: a
        // clean shutdown still owes its peers what it accepted, so only a
        // terminal group releases a link parked in a send.
        let terminal = Arc::new(AtomicBool::new(false));
        let released = Arc::new(tokio::sync::Notify::new());
        let (outbound_tx, outbound_rx) = mpsc::channel(config.queue_capacity);
        let (to_hub, from_links) = mpsc::channel::<LinkEvent>(config.queue_capacity);
        let mut link_cmds = Vec::with_capacity(channels.len());
        let mut tasks = Vec::with_capacity(channels.len() + 1);
        for (i, mut ch) in channels.into_iter().enumerate() {
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(config.queue_capacity);
            link_cmds.push(cmd_tx);
            let to_hub = to_hub.clone();
            let terminal = terminal.clone();
            let released = released.clone();
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
                        // A forward is owed to a peer only while the group
                        // still exists. Once it does not, waiting on that
                        // peer is waiting on nobody, so the send is dropped:
                        // safe now that abandoning one leaves the stream well
                        // formed rather than half a frame.
                        let sent = tokio::select! {
                            biased;
                            () = group_ended(&terminal, &released) => {
                                return Err(GossipError::NotFlushed { link: i });
                            }
                            result = tx.send(&msg) => result,
                        };
                        if let Err(error) = sent {
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
                    // The receive side ended first, which means this link is
                    // half dead: either the peer stopped talking to us, or our
                    // own hub is gone. A peer that has stopped sending is not
                    // going to keep draining either, so waiting for a forward
                    // to finish is waiting on the very thing that ended. Two
                    // links in this state, each parked in a send the other
                    // would have to drain, is a cycle nothing can break.
                    //
                    // The pending forward is therefore dropped rather than
                    // awaited. That costs nothing on the wire now that
                    // abandoning a send leaves the frame boundary intact, and
                    // a message lost here is one the group can no longer
                    // converge on anyway.
                    futures_util::future::Either::Right((received, _sending)) => received,
                }
            }));
        }
        drop(to_hub);
        tasks.push(tokio::spawn(async move {
            // A guard rather than a branch after the call: a hub that panics
            // is as terminal as one that returns an error, and leaving the
            // links parked would turn a crash here into a hang somewhere
            // else.
            let mut release = ReleaseLinks {
                terminal,
                released,
                armed: true,
            };
            let result = hub(outbound_rx, from_links, link_cmds, incoming_tx).await;
            // Only a group that ended badly releases the links; a clean end
            // leaves them flushing what they owe.
            release.armed = result.is_err();
            result
        }));
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
        let mut draining = self.begin_shutdown();
        draining.finish().await
    }

    /// Stop accepting work and hand back the drain, without waiting for it.
    ///
    /// Splits the two things ending a node means: releasing it locally, which
    /// is immediate, and delivering what it already owes its peers, which is
    /// not bounded by anything this crate knows. No deadline is taken here
    /// and none is applied: how long to wait is the caller's, and a caller
    /// that gives up can still ask [`Draining::abandon`] which links were
    /// left owing.
    pub fn begin_shutdown(self) -> Draining {
        let Self {
            outbound,
            incoming,
            tasks,
            max_msg_len: _,
        } = self;
        // Dropping the sender lets the hub drain what is queued and exit;
        // `incoming` stays alive until the drain ends so the consumer side
        // does not disappear while locally accepted work is being drained.
        drop(outbound);
        // Link tasks are spawned first, in link order, and the hub last, so
        // a task's position names the link it drives.
        let links = tasks.len().saturating_sub(1);
        Draining {
            tasks: tasks.into_iter().map(Some).collect(),
            links,
            failure: None,
            incoming,
        }
    }
}

/// A node that has stopped accepting work and is delivering what it owes.
///
/// Waiting is [`finish`](Draining::finish) and giving up is
/// [`abandon`](Draining::abandon); nothing here decides between them, because
/// no duration distinguishes a slow peer from a stopped one. A caller that
/// cannot wait puts its own clock around `finish` and calls `abandon` after,
/// which is why `finish` borrows rather than consumes.
#[derive(Debug)]
pub struct Draining {
    /// `None` once joined, so a cancelled `finish` loses no result.
    tasks: Vec<Option<tokio::task::JoinHandle<Result<(), GossipError>>>>,
    /// How many of `tasks` drive a link; the rest is the hub.
    links: usize,
    failure: Option<GossipError>,
    incoming: mpsc::Receiver<Vec<u8>>,
}

impl Draining {
    /// Wait for every task to finish delivering.
    ///
    /// Unbounded on purpose: delivery may take arbitrarily long, and a node
    /// that gave up on its own schedule would be deciding something it cannot
    /// observe. Cancel-safe, so a caller may drop the future and still
    /// [`abandon`](Self::abandon) what is left.
    pub async fn finish(&mut self) -> Result<(), GossipError> {
        for index in 0..self.tasks.len() {
            let Some(handle) = self.tasks[index].as_mut() else {
                continue;
            };
            let joined = handle.await;
            self.tasks[index] = None;
            self.record(joined);
        }
        self.failure.clone().map_or(Ok(()), Err)
    }

    /// Stop waiting, naming the first link still owing its peer.
    ///
    /// The unfinished tasks are DETACHED, never cancelled: `send` is not
    /// cancel-safe, so dropping one mid-frame would leave a partial frame on
    /// the wire. A detached forward that lands later is harmless, because a
    /// message already held is discarded on sight.
    pub fn abandon(self) -> Result<(), GossipError> {
        let Self {
            tasks,
            links,
            mut failure,
            incoming,
        } = self;
        for (index, handle) in tasks.into_iter().enumerate() {
            if handle.is_some() && index < links {
                failure.get_or_insert(GossipError::NotFlushed { link: index });
            }
        }
        drop(incoming);
        failure.map_or(Ok(()), Err)
    }

    fn record(&mut self, joined: Result<Result<(), GossipError>, tokio::task::JoinError>) {
        match joined {
            Ok(Ok(())) => {}
            // A peer may close after it has converged and begun its own
            // shutdown. That ends this fixed group but is not a failure of
            // our local drain; recv already exposes the closure while the
            // node is running.
            Ok(Err(GossipError::LinkClosed { .. } | GossipError::AllLinksEnded)) => {}
            Ok(Err(error)) => {
                self.failure.get_or_insert(error);
            }
            Err(error) => {
                self.failure.get_or_insert(GossipError::TaskFailed {
                    reason: error.to_string(),
                });
            }
        }
    }
}

/// Frees every link parked in a send once the hub is gone, unless the hub
/// disarmed it by ending cleanly. Held by the hub's task so it fires however
/// that task ends, a panic included.
struct ReleaseLinks {
    terminal: Arc<AtomicBool>,
    released: Arc<tokio::sync::Notify>,
    armed: bool,
}

impl Drop for ReleaseLinks {
    fn drop(&mut self) {
        if self.armed {
            self.terminal.store(true, Ordering::Release);
            self.released.notify_waiters();
        }
    }
}

/// Resolves only once the group has ended badly, and never merely because
/// the hub finished. A plain notification would be lost if it landed between
/// the flag check and the wait, so the waiter is registered first and the
/// flag read after.
async fn group_ended(terminal: &AtomicBool, released: &tokio::sync::Notify) {
    loop {
        let waiting = released.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        if terminal.load(Ordering::Acquire) {
            return;
        }
        waiting.await;
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

/// The accepting side of a fixed-membership group.
#[derive(Debug)]
pub struct ListenSide {
    /// Listener parameters ([`ListenParams`]): virtual port and identity
    /// hint.
    pub params: ListenParams,
    /// How many inbound links to accept before the group is complete.
    pub accept: u16,
}

/// Caller-supplied dial cadence. Retry cadence is the caller's business
/// (the [`Connector`] contract), so the caller states it here explicitly
/// — the wiring only mechanizes it. No hidden defaults.
#[derive(Debug, Clone, Copy)]
pub struct DialRetry {
    /// Overall budget for one address, across attempts. `None` retries
    /// until the dial succeeds — no deadline of any kind, for a caller
    /// whose only acceptable outcome is a connected peer; ending that wait
    /// is then something else's job.
    pub deadline: Option<Duration>,
    /// Bound on a single connect attempt.
    pub attempt_timeout: Duration,
    /// Pause between failed attempts.
    pub pause: Duration,
}

/// Fixed membership for one gossip group: whom to accept and whom to dial.
/// This is the peer-network notion for naive gossip: addresses are supplied
/// out of band and the resulting links must form a connected graph for the
/// lifetime of the group. Discovery, peer databases, dynamic membership,
/// reconnection, and transport advertisement are deliberately outside it.
#[derive(Debug)]
pub struct WireConfig<A> {
    /// The accepting side, when this node publishes an address.
    pub listen: Option<ListenSide>,
    /// Peers to dial.
    pub dials: Vec<A>,
    /// The dial cadence for every address in `dials`.
    pub dial_retry: DialRetry,
    /// Dial using this circuit-isolation group
    /// ([`Transport::isolated_connector`]); `None` uses the shared default
    /// connector.
    pub circuit_isolation: Option<CircuitIsolationId>,
}

/// Two-phase wiring: a listener must publish its address BEFORE its peers
/// can dial it, so [`start`](Wiring::start) performs the listen and
/// returns the published address for the caller to hand out, and
/// [`establish`](Wiring::establish) then accepts the inbound links and
/// dials every address. The accept and dial sides run concurrently so a
/// node that has both roles cannot deadlock with another mixed-role node.
#[derive(Debug)]
pub struct Wiring<T: Transport> {
    listener: Option<(T::Listener, u16)>,
    connector: T::Connector,
    dials: Vec<T::Addr>,
    retry: DialRetry,
}

impl<T: Transport> Wiring<T>
where
    T::Listener: Listener<Channel = <T::Connector as Connector>::Channel>,
{
    /// Phase one: create the listener (publishing this node's address, if
    /// it has an accepting side) and capture the connector. Returns the
    /// published address for the caller to distribute out of band.
    pub async fn start(
        transport: &T,
        cfg: WireConfig<T::Addr>,
    ) -> Result<(Self, Option<T::Addr>), ConnectError> {
        let connector = match &cfg.circuit_isolation {
            Some(isolation) => transport.isolated_connector(isolation),
            None => transport.connector(),
        };
        let (listener, addr) = match cfg.listen {
            Some(side) => {
                let (listener, addr) = transport.listen(side.params).await?;
                (Some((listener, side.accept)), Some(addr))
            }
            None => (None, None),
        };
        Ok((
            Self {
                listener,
                connector,
                dials: cfg.dials,
                retry: cfg.dial_retry,
            },
            addr,
        ))
    }

    /// Phase two: concurrently accept the configured inbound links and dial
    /// every address with the configured cadence. Any hard failure fails
    /// the whole wiring — a partially wired group is not a group. Accepting
    /// blocks until the configured number of inbound links arrives — there
    /// is no accept timeout; a caller that needs one bounds this call
    /// externally. The returned channels are deterministic: accepted links
    /// first, then dialed links, in their respective configuration order.
    pub async fn establish(
        self,
    ) -> Result<Vec<<T::Connector as Connector>::Channel>, ConnectError> {
        self.establish_with(|_, _| {}).await
    }

    /// [`establish`](Wiring::establish) with a per-attempt observer:
    /// `on_attempt` is called with the address and error of every failed
    /// connect attempt (the terminal one included) — the caller's hook
    /// for retry logging, since the wiring itself stays silent.
    pub async fn establish_with<F>(
        self,
        mut on_attempt: F,
    ) -> Result<Vec<<T::Connector as Connector>::Channel>, ConnectError>
    where
        F: FnMut(&T::Addr, &ConnectError),
    {
        let Self {
            listener,
            connector,
            dials,
            retry,
        } = self;
        let accept_side = async move {
            let mut channels = Vec::new();
            if let Some((mut listener, accept)) = listener {
                for _ in 0..accept {
                    channels.push(listener.accept().await?);
                }
            }
            Ok::<_, ConnectError>(channels)
        };
        let dial_side = async move {
            let mut channels = Vec::with_capacity(dials.len());
            for addr in &dials {
                let deadline = retry
                    .deadline
                    .map(|budget| tokio::time::Instant::now() + budget);
                let channel = loop {
                    // Cap the attempt at what is left of the budget, so one
                    // address can never run past its deadline — the "overall
                    // budget" the docs promise, with no slop.
                    let attempt_end = {
                        let end = tokio::time::Instant::now() + retry.attempt_timeout;
                        match deadline {
                            Some(deadline) => end.min(deadline),
                            None => end,
                        }
                    };
                    let attempt =
                        tokio::time::timeout_at(attempt_end, connector.connect(addr)).await;
                    let err = match attempt {
                        Ok(Ok(channel)) => break channel,
                        Ok(Err(e)) => e,
                        // An attempt that timed out is just a failed attempt,
                        // not a fatal one.
                        Err(_) => ConnectError::Transport("connect attempt timed out".into()),
                    };
                    on_attempt(addr, &err);
                    // Retry only if the pause leaves any budget before the
                    // deadline. The next attempt is capped at whatever time
                    // remains; a caller that set no deadline always retries.
                    if deadline.is_some_and(|deadline| {
                        tokio::time::Instant::now() + retry.pause >= deadline
                    }) {
                        return Err(err);
                    }
                    tokio::time::sleep(retry.pause).await;
                };
                channels.push(channel);
            }
            Ok::<_, ConnectError>(channels)
        };
        let (mut accepted, dialed) = tokio::try_join!(accept_side, dial_side)?;
        accepted.extend(dialed);
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use crate::AssumeSessionBound;

    /// The relay engine under test carries only what these tests write, so
    /// admission is asserted rather than earned.
    fn gossip(channels: Vec<crate::mem::MemChannel>) -> GossipBroadcast {
        GossipBroadcast::new(channels.into_iter().map(AssumeSessionBound).collect())
    }

    fn gossip_with(channels: Vec<crate::mem::MemChannel>, config: GossipConfig) -> GossipBroadcast {
        GossipBroadcast::with_config(
            channels.into_iter().map(AssumeSessionBound).collect(),
            config,
        )
    }
    use super::*;
    use crate::channel::Channel;
    use crate::mem::{MemConfig, duplex};
    use crate::testkit;
    use std::time::Duration;

    fn cfg() -> MemConfig {
        MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        }
    }

    /// A full graph of n gossip nodes over pairwise mem duplexes.
    fn mem_full_graph(n: usize, max_msg_len: Option<usize>) -> Vec<GossipBroadcast> {
        let mut per_node: Vec<Vec<crate::mem::MemChannel>> = (0..n).map(|_| Vec::new()).collect();
        for i in 0..n {
            for j in (i + 1)..n {
                let (a, b) = duplex(cfg());
                per_node[i].push(a);
                per_node[j].push(b);
            }
        }
        per_node
            .into_iter()
            .map(|chs| {
                let g = gossip(chs);
                match max_msg_len {
                    Some(max) => g.with_max_msg_len(max),
                    None => g,
                }
            })
            .collect()
    }

    // CONFORMANCE (broadcast trait contract) — the same generic suite the
    // mem group passes: gossip IS a BroadcastChannel, as an executable
    // assertion.
    #[tokio::test]
    async fn conformance_broadcast_reaches_all_others() {
        testkit::broadcast_reaches_all_others(mem_full_graph(3, None)).await;
    }

    #[tokio::test]
    async fn conformance_broadcast_recv_is_cancel_safe() {
        testkit::broadcast_recv_is_cancel_safe(mem_full_graph(2, None)).await;
    }

    #[tokio::test]
    async fn conformance_broadcast_too_large_is_recoverable() {
        testkit::broadcast_too_large_is_recoverable(mem_full_graph(2, Some(16)), 16).await;
    }

    #[tokio::test]
    async fn conformance_closed_after_group_drop() {
        testkit::closed_after_group_drop(mem_full_graph(3, None)).await;
    }

    // Line topology A—B—C with B as a PASSIVE relay: B never calls recv,
    // yet A's message reaches C — forwarding rides on the hub, not on the
    // consumer.
    #[tokio::test]
    async fn line_relays_through_a_passive_middle_node() {
        let (a_ab, b_ab) = duplex(cfg());
        let (b_bc, c_bc) = duplex(cfg());
        let mut a = gossip(vec![a_ab]);
        let _b = gossip(vec![b_ab, b_bc]); // alive, never consumed
        let mut c = gossip(vec![c_bc]);
        a.send(b"through").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), c.recv())
            .await
            .expect("the passive middle node must relay")
            .unwrap();
        assert_eq!(got, b"through");
    }

    // Triangle: duplicates arrive over the redundant paths and are
    // forwarded/delivered only on first sight — each node sees each
    // message exactly once.
    #[tokio::test]
    async fn triangle_dedups_redundant_paths() {
        let mut nodes = mem_full_graph(3, None);
        nodes[0].send(b"from-a").await.unwrap();
        nodes[1].send(b"from-b").await.unwrap();
        nodes[2].send(b"from-c").await.unwrap();
        let expected = [b"from-a".to_vec(), b"from-b".to_vec(), b"from-c".to_vec()];
        for (i, node) in nodes.iter_mut().enumerate() {
            let mut got = vec![node.recv().await.unwrap(), node.recv().await.unwrap()];
            got.sort();
            let mut want: Vec<Vec<u8>> = expected
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            want.sort();
            assert_eq!(got, want, "node {i} must see the other two exactly once");
            let dup = tokio::time::timeout(Duration::from_millis(50), node.recv()).await;
            assert!(dup.is_err(), "no duplicates may be delivered");
        }
    }

    // Two nodes over one duplex: messages cross in both directions through
    // the live type, and each side's own send never comes back to it.
    #[tokio::test]
    async fn pair_exchanges_both_ways_without_echo() {
        let (ab, ba) = duplex(cfg());
        let mut a = gossip(vec![ab]);
        let mut b = gossip(vec![ba]);
        a.send(b"from-a").await.unwrap();
        b.send(b"from-b").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"from-a");
        assert_eq!(a.recv().await.unwrap(), b"from-b");
        let echo = tokio::time::timeout(Duration::from_millis(50), a.recv()).await;
        assert!(echo.is_err(), "a sender must not receive its own broadcast");
    }

    // One channel, one fate: when the peer's whole node goes away, this
    // side's recv reports the channel dead (link death cascades to the hub).
    #[tokio::test]
    async fn recv_reports_dead_after_peer_drops() {
        let (ab, ba) = duplex(cfg());
        let mut a = gossip(vec![ab]);
        let b = gossip(vec![ba]);
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
        let mut a = gossip(vec![ab]);
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
        let mut a = gossip(vec![ab]);
        a.send(b"parting word").await.unwrap();
        a.shutdown().await.unwrap();
        assert_eq!(ba.recv().await.unwrap(), b"parting word");
    }

    // Empty-group semantics mirror the mem group: constructed with zero
    // channels, sends are vacuously Ok and recv reports the channel dead.
    #[tokio::test]
    async fn empty_group_sends_vacuously_and_recv_is_dead() {
        let mut g = gossip(Vec::new());
        g.send(b"into the void").await.unwrap();
        assert!(matches!(g.recv().await, Err(RecvError::Closed)));
    }

    // The local size check runs before any link concern, so it outranks
    // the empty-group vacuous Ok: zero links does not exempt an oversized
    // send.
    #[tokio::test]
    async fn empty_group_still_enforces_max_msg_len() {
        let mut g = gossip(Vec::new()).with_max_msg_len(4);
        assert!(matches!(
            g.send(b"oversized").await,
            Err(SendError::TooLarge { max: 4 })
        ));
    }

    // A simultaneous burst inside the configured bounds converges fully:
    // liveness does not weaken the healthy-path message-set guarantee.
    #[tokio::test]
    async fn simultaneous_bursts_converge_within_the_bounds() {
        let roomy = MemConfig {
            capacity: Some(512),
            ..MemConfig::default()
        };
        let config = GossipConfig {
            queue_capacity: 512,
        };
        let (ab, ba) = duplex(roomy);
        let mut a = gossip_with(vec![ab], config);
        let mut b = gossip_with(vec![ba], config);

        async fn send_burst(node: &mut GossipBroadcast, tag: u8) {
            for i in 0..200u32 {
                let mut msg = vec![tag];
                msg.extend_from_slice(&i.to_be_bytes());
                node.send(&msg).await.unwrap();
            }
        }

        tokio::time::timeout(
            Duration::from_secs(10),
            futures_util::future::join(send_burst(&mut a, b'a'), send_burst(&mut b, b'b')),
        )
        .await
        .expect("both bursts must finish sending without wedging");

        async fn drain(node: &mut GossipBroadcast) -> usize {
            for count in 1..=200 {
                tokio::time::timeout(Duration::from_secs(5), node.recv())
                    .await
                    .unwrap_or_else(|_| panic!("burst stopped after {} messages", count - 1))
                    .unwrap();
            }
            200
        }
        let (ra, rb) = futures_util::future::join(drain(&mut a), drain(&mut b)).await;
        assert_eq!((ra, rb), (200, 200));
    }

    // Saturation cannot masquerade as successful convergence. The bounded
    // hub terminates the group instead of silently discarding a first-seen
    // message and keeping the channel apparently healthy.
    #[tokio::test]
    async fn saturated_burst_fails_explicitly_instead_of_diverging() {
        let (ab, ba) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        let config = GossipConfig { queue_capacity: 1 };
        let mut a = gossip_with(vec![ab], config);
        let _parked = ba;

        let mut observed_failure = false;
        for i in 0..200u32 {
            if a.send(&i.to_be_bytes()).await.is_err() {
                observed_failure = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        if !observed_failure {
            observed_failure = tokio::time::timeout(Duration::from_secs(1), a.recv())
                .await
                .expect("a saturated group must terminate")
                .is_err();
        }
        assert!(observed_failure);
        // No shutdown here: the parked peer never reads, so the drain this
        // node owes it cannot finish — that wait is the caller's to bound,
        // and dropping abandons it, which is what a failed group wants.
    }

    // A slow local consumer is another loss of convergence, not permission
    // to discard messages while keeping the channel apparently healthy.
    #[tokio::test]
    async fn full_consumer_queue_ends_the_group_explicitly() {
        let (ab, mut ba) = duplex(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        let config = GossipConfig { queue_capacity: 1 };
        let mut a = gossip_with(vec![ab], config);

        for message in [b"one".as_slice(), b"two", b"three"] {
            let _ = ba.send(message).await;
            tokio::task::yield_now().await;
        }

        assert_eq!(a.recv().await.unwrap(), b"one");
        assert!(a.recv().await.is_err());
        assert!(matches!(
            a.shutdown().await,
            Err(GossipError::QueueFull {
                output: QueueKind::Consumer
            })
        ));
    }

    // The same ending, with one forward already parked on the wire. A link
    // sitting inside `SendHalf::send` cannot see the command queue close, so
    // it has to be told: a group that ends badly releases its links, and the
    // parked send is dropped rather than waited on. Without that the drain
    // joins a task only the peer could free.
    //
    #[tokio::test]
    async fn a_terminal_group_does_not_leave_shutdown_waiting_on_a_parked_forward() {
        // One slot each way, so the second forward has nowhere to go.
        let (ab, mut ba) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        let mut a = gossip_with(vec![ab], GossipConfig { queue_capacity: 1 });

        // The first forward fills the peer's slot; the second parks in the
        // send, because nothing on this side ever reads `ba`.
        for message in [b"one".as_slice(), b"two"] {
            a.send(message).await.expect("the hub accepts both");
            tokio::task::yield_now().await;
        }

        // Now end the group the way the test above does, by overflowing the
        // consumer queue nobody is draining.
        for message in [b"three".as_slice(), b"four", b"five"] {
            let _ = ba.send(message).await;
            tokio::task::yield_now().await;
        }
        assert!(
            a.recv().await.is_ok() && a.recv().await.is_err(),
            "the group has ended, which is the precondition and not the defect"
        );

        // The group has ended, so the forward parked on the wire is owed to
        // nobody: the link stops waiting on its own and names itself. No
        // clock is involved, and the caller does not have to give up first.
        let mut draining = a.begin_shutdown();
        let ended = tokio::time::timeout(Duration::from_secs(5), draining.finish())
            .await
            .expect("a terminal group releases its links without anyone giving up");

        assert!(
            matches!(ended, Err(GossipError::NotFlushed { link: 0 })),
            "the drain must name the link it left owing its peer, got {ended:?}"
        );
    }

    // The other half of the same hazard, and the one a whole-group run hits:
    // here the hub ends CLEANLY, so nothing is released on its account, and
    // the link learns the group is over only when its own receive half fails
    // to hand a message on. A link in that state has a peer that has stopped
    // talking to it, so waiting for a parked forward waits on the very thing
    // that ended. Two such links, each parked in a send the other would drain,
    // is a cycle with no way out.
    #[tokio::test]
    async fn a_link_whose_receive_half_ended_does_not_wait_on_its_parked_forward() {
        let (ab, mut ba) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        let mut a = gossip_with(vec![ab], GossipConfig { queue_capacity: 4 });

        // The first forward fills the peer's slot, the second parks: nothing
        // on this side ever reads `ba`.
        for message in [b"one".as_slice(), b"two"] {
            a.send(message).await.expect("the hub accepts both");
            tokio::task::yield_now().await;
        }

        // A CLEAN end: dropping the caller's handle, not a failure. The hub
        // exits with Ok, so no link is released on its account.
        let mut draining = a.begin_shutdown();
        tokio::task::yield_now().await;

        // The peer speaks once more. The receive half now has nowhere to hand
        // it, which is how this link learns the group is gone.
        let _ = ba.send(b"from the peer").await;

        let ended = tokio::time::timeout(Duration::from_secs(5), draining.finish())
            .await
            .expect("a half-dead link stops waiting instead of joining forever");
        let _ = ended;
    }

    // The oracle the whole ladder is anchored on: what releases the link is
    // an event, never a clock, and what the peer reads is always whole. A
    // group that ended badly has already reported losing convergence, so it
    // owes that peer nothing more; the complement, that a CLEAN end still
    // flushes, is `shutdown_flushes_pending_sends`.
    #[tokio::test]
    async fn a_terminal_group_releases_its_links_without_tearing_the_stream() {
        let (ab, mut ba) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        let mut a = gossip_with(vec![ab], GossipConfig { queue_capacity: 1 });

        for message in [b"one".as_slice(), b"two"] {
            a.send(message).await.expect("the hub accepts both");
            tokio::task::yield_now().await;
        }
        for message in [b"three".as_slice(), b"four", b"five"] {
            let _ = ba.send(message).await;
            tokio::task::yield_now().await;
        }

        // No clock anywhere: the drain returns because the group ended, and
        // it names the link that was still parked.
        let mut draining = a.begin_shutdown();
        let ended = tokio::time::timeout(Duration::from_secs(5), draining.finish())
            .await
            .expect("an event releases the link, so nothing here waits on time");
        assert!(
            matches!(ended, Err(GossipError::NotFlushed { link: 0 })),
            "the parked forward must be named, got {ended:?}"
        );

        // The peer reads arbitrarily late and gets whole messages: the
        // forward that completed, and then a clean end. Never a fragment of
        // the one that was released.
        assert_eq!(ba.recv().await.unwrap(), b"one");
        assert!(
            ba.recv().await.is_err(),
            "a released link closes cleanly rather than leaving a fragment"
        );
    }

    // Two-phase wiring over the mem transport: B starts (publishing its
    // address), A and C dial with an explicit cadence, B establishes both
    // inbound links — and the three wired nodes gossip to convergence.
    #[tokio::test]
    async fn wiring_builds_a_line_that_converges() {
        use crate::channel::ListenParams;
        use crate::mem::{MemAddr, MemConfig, MemTransport};

        let transport = MemTransport::new(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        let retry = || DialRetry {
            deadline: Some(Duration::from_secs(2)),
            attempt_timeout: Duration::from_secs(1),
            pause: Duration::from_millis(10),
        };
        let (b_wiring, addr) = Wiring::start(
            &transport,
            WireConfig {
                listen: Some(ListenSide {
                    params: ListenParams::new(1),
                    accept: 2,
                }),
                dials: vec![],
                dial_retry: retry(),
                circuit_isolation: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(addr, Some(MemAddr));

        let dial_cfg = || WireConfig {
            listen: None,
            dials: vec![MemAddr],
            dial_retry: retry(),
            circuit_isolation: None,
        };
        let a_cfg = dial_cfg();
        let c_cfg = dial_cfg();
        let (b_chs, a_res, c_res) = tokio::join!(
            b_wiring.establish(),
            async {
                let (w, addr) = Wiring::start(&transport, a_cfg).await.unwrap();
                assert_eq!(addr, None);
                w.establish().await
            },
            async {
                let (w, _) = Wiring::start(&transport, c_cfg).await.unwrap();
                w.establish().await
            },
        );
        let mut b = gossip(b_chs.unwrap());
        let mut a = gossip(a_res.unwrap());
        let mut c = gossip(c_res.unwrap());

        a.send(b"from-a").await.unwrap();
        b.send(b"from-b").await.unwrap();
        c.send(b"from-c").await.unwrap();
        let mut got_a = vec![a.recv().await.unwrap(), a.recv().await.unwrap()];
        let mut got_c = vec![c.recv().await.unwrap(), c.recv().await.unwrap()];
        got_a.sort();
        got_c.sort();
        assert_eq!(got_a, vec![b"from-b".to_vec(), b"from-c".to_vec()]);
        assert_eq!(got_c, vec![b"from-a".to_vec(), b"from-b".to_vec()]);
    }

    // A node may accept and dial in the same membership. Both sides must
    // progress together: running accepts first would wait forever before
    // the dial that supplies the inbound link is ever polled.
    #[tokio::test]
    async fn wiring_with_both_roles_does_not_deadlock() {
        use crate::channel::ListenParams;
        use crate::mem::{MemAddr, MemConfig, MemTransport};

        let transport = MemTransport::new(MemConfig::default());
        let (wiring, addr) = Wiring::start(
            &transport,
            WireConfig {
                listen: Some(ListenSide {
                    params: ListenParams::new(1),
                    accept: 1,
                }),
                dials: vec![MemAddr],
                dial_retry: DialRetry {
                    deadline: Some(Duration::from_secs(1)),
                    attempt_timeout: Duration::from_millis(100),
                    pause: Duration::from_millis(10),
                },
                circuit_isolation: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(addr, Some(MemAddr));

        let channels = tokio::time::timeout(Duration::from_secs(1), wiring.establish())
            .await
            .expect("accept and dial sides must make progress together")
            .unwrap();
        assert_eq!(channels.len(), 2);
    }

    // No deadline means no giving up: against the same permanently blocked
    // transport, the dial that would have expired keeps retrying instead —
    // the shape a caller asks for when only a connected peer will do.
    #[tokio::test(start_paused = true)]
    async fn a_dial_without_a_deadline_never_gives_up() {
        use crate::mem::{MemAddr, MemConfig, MemTransport};

        let transport = MemTransport::new(MemConfig::default());
        let connector = transport.connector();
        let mut fillers = Vec::new();
        for _ in 0..8 {
            fillers.push(connector.connect(&MemAddr).await.unwrap());
        }

        let (wiring, _addr) = Wiring::start(
            &transport,
            WireConfig {
                listen: None,
                dials: vec![MemAddr],
                dial_retry: DialRetry {
                    deadline: None,
                    attempt_timeout: Duration::from_millis(20),
                    pause: Duration::from_millis(10),
                },
                circuit_isolation: None,
            },
        )
        .await
        .unwrap();

        // Far past any budget the bounded variant would have spent.
        assert!(
            tokio::time::timeout(Duration::from_secs(60), wiring.establish())
                .await
                .is_err(),
            "a dial with no deadline must still be trying"
        );
        drop(fillers);
    }

    // A dial attempt that times out must be retried, not treated as fatal:
    // fill the mem transport's inbound queue (capacity 8, no listener ever
    // draining it) so every connect attempt hangs, then confirm establish
    // keeps retrying across several attempt_timeouts and gives up within
    // the overall per-address deadline — never past it.
    #[tokio::test(start_paused = true)]
    async fn establish_retries_a_timed_out_dial_within_the_deadline() {
        use crate::mem::{MemAddr, MemConfig, MemTransport};

        let transport = MemTransport::new(MemConfig::default());
        let connector = transport.connector();
        // Saturate the fixed 8-slot inbound queue; with no listener ever
        // created, nothing drains it and any further connect blocks
        // forever.
        let mut fillers = Vec::new();
        for _ in 0..8 {
            fillers.push(connector.connect(&MemAddr).await.unwrap());
        }

        let (wiring, _addr) = Wiring::start(
            &transport,
            WireConfig {
                listen: None,
                dials: vec![MemAddr],
                dial_retry: DialRetry {
                    deadline: Some(Duration::from_millis(120)),
                    attempt_timeout: Duration::from_millis(20),
                    pause: Duration::from_millis(10),
                },
                circuit_isolation: None,
            },
        )
        .await
        .unwrap();

        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_millis(500), wiring.establish())
            .await
            .expect("a timed-out attempt must not hang past the dial deadline");
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "every attempt hangs, so the dial exhausts its budget"
        );
        // At ~30ms per full attempt (20ms timeout + 10ms pause) against a
        // 120ms deadline, several attempts must have happened. The final one
        // may be shorter because every attempt is capped at the hard deadline.
        assert!(
            elapsed >= Duration::from_millis(90),
            "several attempts must run before giving up: {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(120),
            "must never run past the per-address deadline: {elapsed:?}"
        );
        drop(fillers);
    }
}
