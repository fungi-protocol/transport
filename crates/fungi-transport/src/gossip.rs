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
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::channel::{
    BroadcastChannel, Connector, ListenParams, Listener, RecvHalf, SendHalf, SplitChannel,
    Transport,
};
use crate::error::{ConnectError, RecvError, SendError};
use crate::session::SessionId;

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
    /// caller's job (see [`Wiring`]).
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
    /// Dial on this logical session's isolated circuits
    /// ([`Transport::connector_for`]); `None` uses the shared default
    /// connector. A gossip group serving one protocol session is exactly
    /// what per-session isolation exists for.
    pub session: Option<SessionId>,
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
        let connector = match &cfg.session {
            Some(session) => transport.connector_for(session),
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
                let g = GossipBroadcast::new(chs);
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
        let mut a = GossipBroadcast::new(vec![a_ab]);
        let _b = GossipBroadcast::new(vec![b_ab, b_bc]); // alive, never consumed
        let mut c = GossipBroadcast::new(vec![c_bc]);
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
        let mut a = GossipBroadcast::new(vec![ab]);
        let mut b = GossipBroadcast::new(vec![ba]);
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

    // The local size check runs before any link concern, so it outranks
    // the empty-group vacuous Ok: zero links does not exempt an oversized
    // send.
    #[tokio::test]
    async fn empty_group_still_enforces_max_msg_len() {
        let mut g = GossipBroadcast::new(Vec::<crate::mem::MemChannel>::new()).with_max_msg_len(4);
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
        let mut a = GossipBroadcast::with_config(vec![ab], config);
        let mut b = GossipBroadcast::with_config(vec![ba], config);

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
        let mut a = GossipBroadcast::with_config(vec![ab], config);
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
        let mut a = GossipBroadcast::with_config(vec![ab], config);

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
                session: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(addr, Some(MemAddr));

        let dial_cfg = || WireConfig {
            listen: None,
            dials: vec![MemAddr],
            dial_retry: retry(),
            session: None,
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
        let mut b = GossipBroadcast::new(b_chs.unwrap());
        let mut a = GossipBroadcast::new(a_res.unwrap());
        let mut c = GossipBroadcast::new(c_res.unwrap());

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
                session: None,
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
                session: None,
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
                session: None,
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
