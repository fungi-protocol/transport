//! In-memory pipe implementation of the [`crate::channel`] traits. Two
//! crossed bounded `tokio::sync::mpsc` queues; capacity 1 by default so a
//! slow transport is simulated for free; [`group`] wires `n` members into a
//! broadcast bus the same way.
//!
//! The opening contract is simulated, not provided: both ends live in one
//! process, so there is no real anonymity or authentication here — this
//! backend exists to exercise the trait semantics in tests.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::channel::{Channel, Connector, Listener, RecvHalf, SendHalf, SplitChannel};
use crate::error::{ConnectError, RecvError, SendError};
use crate::isolation::CircuitIsolationId;
use crate::sender::SenderId;

/// What `send` promises in this mock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Delivery {
    /// `send` resolves once the message is in the peer's buffer; a dropped
    /// peer yields [`SendError::Closed`] (mailbox-style positive confirmation).
    #[default]
    Confirmed,
    /// `send` resolves once the transport accepted the message; loss (full
    /// buffer, dead peer, injected drop) is silent — loss = infinite delay.
    BestEffort,
}

/// Knobs for the in-memory pipe.
#[derive(Debug, Clone, Default)]
pub struct MemConfig {
    /// Per-direction buffer capacity; `None` = 1 (slow transport). A `Some(0)`
    /// is clamped to 1 rather than panicking (tokio mpsc rejects a 0 capacity).
    pub capacity: Option<usize>,
    /// Maximum message size; larger sends fail with [`SendError::TooLarge`].
    pub max_msg_len: Option<usize>,
    /// Artificial latency applied before each delivery.
    pub latency: Option<Duration>,
    /// Confirmed-mode sends give up with an error after this internal
    /// deadline. The trait exposes no timeouts; this is strictly
    /// transport-internal.
    pub send_timeout: Option<Duration>,
    /// Delivery semantics of `send`.
    pub delivery: Delivery,
}

/// One end of an in-memory duplex channel.
#[derive(Debug)]
pub struct MemChannel {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    cfg: MemConfig,
    drop_next: AtomicUsize,
    fail_next: AtomicUsize,
}

impl MemChannel {
    /// Silently drop the next `n` sends (best-effort loss injection).
    /// Applies regardless of `Delivery` mode; in `Confirmed` mode a dropped
    /// send still returns Ok(()).
    pub fn drop_next(&self, n: usize) {
        self.drop_next.store(n, Ordering::Relaxed);
    }
    /// Fail the next `n` sends with [`SendError::Transport`]. Mock-specific
    /// tolerance: this pipe stays usable afterwards, but the contract says a
    /// consumer must treat any non-`TooLarge` send error as a dead channel —
    /// do not lean on the tolerance outside fault-injection tests.
    pub fn fail_next(&self, n: usize) {
        self.fail_next.store(n, Ordering::Relaxed);
    }
}

/// Create a connected pair: whatever A sends, B receives, and vice versa.
pub fn duplex(cfg: MemConfig) -> (MemChannel, MemChannel) {
    let cap = cfg.capacity.unwrap_or(1).max(1);
    let (tx_ab, rx_ab) = mpsc::channel(cap);
    let (tx_ba, rx_ba) = mpsc::channel(cap);
    let mk = |tx, rx| MemChannel {
        tx,
        rx,
        cfg: cfg.clone(),
        drop_next: AtomicUsize::new(0),
        fail_next: AtomicUsize::new(0),
    };
    (mk(tx_ab, rx_ba), mk(tx_ba, rx_ab))
}

// Relaxed suffices: `fetch_update` keeps each decrement atomic, and these
// counters guard no other memory, so no cross-thread ordering is needed.
fn take_one(counter: &AtomicUsize) -> bool {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
}

/// Reject an oversized payload before it is ever cloned.
fn sized(cfg: &MemConfig, msg: &[u8]) -> Result<Vec<u8>, usize> {
    match cfg.max_msg_len {
        Some(max) if msg.len() > max => Err(max),
        _ => Ok(msg.to_vec()),
    }
}

/// The whole send path, shared by the unified channel and its sending half
/// so the two can never drift: fault injection, latency, delivery mode and
/// the internal timeout all live here.
async fn send_path(
    tx: &mpsc::Sender<Vec<u8>>,
    cfg: &MemConfig,
    drop_next: &AtomicUsize,
    fail_next: &AtomicUsize,
    msg: Result<Vec<u8>, usize>,
) -> Result<(), SendError> {
    let msg = match msg {
        Ok(msg) => msg,
        Err(max) => return Err(SendError::TooLarge { max }),
    };
    if take_one(fail_next) {
        return Err(SendError::Transport("injected failure".into()));
    }
    if let Some(latency) = cfg.latency {
        tokio::time::sleep(latency).await;
    }
    if take_one(drop_next) {
        return Ok(()); // injected silent loss
    }
    match cfg.delivery {
        Delivery::Confirmed => match cfg.send_timeout {
            Some(deadline) => match tokio::time::timeout(deadline, tx.send(msg)).await {
                Ok(sent) => sent.map_err(|_| SendError::Closed),
                // Deliberately opaque — the trait has no Timeout variant;
                // timing stays transport-internal.
                Err(_) => Err(SendError::Transport("send timed out".into())),
            },
            None => tx.send(msg).await.map_err(|_| SendError::Closed),
        },
        Delivery::BestEffort => {
            let _ = tx.try_send(msg); // full or closed: silent loss
            Ok(())
        }
    }
}

impl Channel for MemChannel {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let msg = sized(&self.cfg, msg);
        send_path(&self.tx, &self.cfg, &self.drop_next, &self.fail_next, msg)
    }

    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        // tokio's mpsc recv is documented cancel-safe: no message is lost
        // when this future is dropped mid-wait.
        self.rx.recv().await.ok_or(RecvError::Closed)
    }
}

/// Sending half of a split [`MemChannel`]: borrows everything the send path
/// reads, so fault injection and limits behave exactly as on the whole
/// channel.
#[derive(Debug)]
pub struct MemSendHalf<'a> {
    tx: &'a mpsc::Sender<Vec<u8>>,
    cfg: &'a MemConfig,
    drop_next: &'a AtomicUsize,
    fail_next: &'a AtomicUsize,
}

/// Receiving half of a split [`MemChannel`].
#[derive(Debug)]
pub struct MemRecvHalf<'a> {
    rx: &'a mut mpsc::Receiver<Vec<u8>>,
}

impl SendHalf for MemSendHalf<'_> {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let msg = sized(self.cfg, msg);
        send_path(self.tx, self.cfg, self.drop_next, self.fail_next, msg)
    }
}

impl RecvHalf for MemRecvHalf<'_> {
    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        self.rx.recv().await.ok_or(RecvError::Closed)
    }
}

impl SplitChannel for MemChannel {
    type SendHalf<'a> = MemSendHalf<'a>;
    type RecvHalf<'a> = MemRecvHalf<'a>;

    fn split(&mut self) -> (MemSendHalf<'_>, MemRecvHalf<'_>) {
        (
            MemSendHalf {
                tx: &self.tx,
                cfg: &self.cfg,
                drop_next: &self.drop_next,
                fail_next: &self.fail_next,
            },
            MemRecvHalf { rx: &mut self.rx },
        )
    }
}

/// Address of an in-memory listener. Only one endpoint exists per
/// [`network`], so this is a unit marker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct MemAddr;

impl std::fmt::Display for MemAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mem")
    }
}

impl std::str::FromStr for MemAddr {
    type Err = std::convert::Infallible;

    /// There is only one in-memory endpoint per network, so any text parses to
    /// the single unit address. This lets a `MemAddr` round-trip through a
    /// transport (e.g. capnp) that carries addresses as text.
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Ok(MemAddr)
    }
}

/// Connector half of an in-memory network: each `connect` produces a fresh
/// channel pair, handing the far end to the paired [`MemListener`].
///
/// `isolation` records which circuit-isolation group this connector serves. There are
/// no real circuits in memory, so isolation here is only observable, not
/// enforced: [`isolation`](MemConnector::isolation) lets a test assert that
/// isolated connectors carry the distinct identity a real backend would
/// isolate on.
#[derive(Debug, Clone)]
pub struct MemConnector {
    cfg: MemConfig,
    to_listener: mpsc::Sender<MemChannel>,
    isolation: Option<CircuitIsolationId>,
}

impl MemConnector {
    /// This connector's circuit-isolation group, or `None` for the
    /// transport's shared default circuit group.
    pub fn isolation(&self) -> Option<CircuitIsolationId> {
        self.isolation
    }
}

/// Listener half of an in-memory network.
#[derive(Debug)]
pub struct MemListener {
    inbound: mpsc::Receiver<MemChannel>,
}

/// Create a connector/listener pair sharing an in-memory "network".
pub fn network(cfg: MemConfig) -> (MemConnector, MemListener) {
    let (to_listener, inbound) = mpsc::channel(8);
    (
        MemConnector {
            cfg,
            to_listener,
            isolation: None,
        },
        MemListener { inbound },
    )
}

/// In-memory [`Transport`](crate::channel::Transport): a factory over one
/// in-memory network. `listen` yields the network's single listener once;
/// further calls are `Unreachable`.
#[derive(Debug)]
pub struct MemTransport {
    connector: MemConnector,
    listener: std::sync::Mutex<Option<MemListener>>,
}

impl MemTransport {
    /// A transport over a fresh in-memory network.
    pub fn new(cfg: MemConfig) -> Self {
        let (connector, listener) = network(cfg);
        Self {
            connector,
            listener: std::sync::Mutex::new(Some(listener)),
        }
    }
}

impl crate::channel::Transport for MemTransport {
    type Addr = MemAddr;
    type Connector = MemConnector;
    type Listener = MemListener;

    fn connector(&self) -> MemConnector {
        self.connector.clone()
    }

    fn isolated_connector(&self, isolation: &CircuitIsolationId) -> MemConnector {
        MemConnector {
            isolation: Some(*isolation),
            ..self.connector.clone()
        }
    }

    async fn listen(
        &self,
        _params: crate::channel::ListenParams,
    ) -> Result<(MemListener, MemAddr), ConnectError> {
        let listener = self
            .listener
            .lock()
            .expect("mem transport listener mutex")
            .take()
            .ok_or(ConnectError::Unreachable)?;
        Ok((listener, MemAddr))
    }
}

impl Connector for MemConnector {
    type Addr = MemAddr;
    type Channel = MemChannel;

    fn connect(
        &self,
        _addr: &MemAddr,
    ) -> impl Future<Output = Result<MemChannel, ConnectError>> + Send {
        let (near, far) = duplex(self.cfg.clone());
        let to_listener = self.to_listener.clone();
        async move {
            to_listener
                .send(far)
                .await
                .map_err(|_| ConnectError::Unreachable)?;
            Ok(near)
        }
    }
}

impl Listener for MemListener {
    type Channel = MemChannel;

    async fn accept(&mut self) -> Result<MemChannel, ConnectError> {
        self.inbound.recv().await.ok_or(ConnectError::Unreachable)
    }
}

/// One member's handle onto an in-memory broadcast group: whatever this
/// member sends lands in every other member's queue; `recv` drains this
/// member's own queue. The same [`MemConfig`] knobs and fault injection as
/// [`MemChannel`] apply, message by message across the whole fan-out (an
/// injected drop or failure covers the entire send, not one recipient).
///
/// Mock-specific departure semantics: a send to a member that already
/// dropped its handle is skipped silently (their loss is their departure);
/// only when EVERY other member is gone does a Confirmed-mode send yield
/// [`SendError::Closed`]. A group of one has no recipients and its sends
/// vacuously succeed.
#[derive(Debug)]
pub struct MemBroadcastChannel {
    txs: Vec<mpsc::Sender<Vec<u8>>>,
    rx: mpsc::Receiver<Vec<u8>>,
    cfg: MemConfig,
    drop_next: AtomicUsize,
    fail_next: AtomicUsize,
}

impl MemBroadcastChannel {
    /// Silently drop the next `n` sends (best-effort loss injection); a
    /// dropped send reaches no member.
    pub fn drop_next(&self, n: usize) {
        self.drop_next.store(n, Ordering::Relaxed);
    }
    /// Fail the next `n` sends with [`SendError::Transport`]. Same
    /// mock-specific tolerance as [`MemChannel::fail_next`].
    pub fn fail_next(&self, n: usize) {
        self.fail_next.store(n, Ordering::Relaxed);
    }
}

/// Create an `n`-member broadcast group sharing one in-memory bus.
pub fn group(n: usize, cfg: MemConfig) -> Vec<MemBroadcastChannel> {
    let cap = cfg.capacity.unwrap_or(1).max(1);
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..n).map(|_| mpsc::channel(cap)).unzip();
    rxs.into_iter()
        .enumerate()
        .map(|(i, rx)| MemBroadcastChannel {
            txs: txs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, tx)| tx.clone())
                .collect(),
            rx,
            cfg: cfg.clone(),
            drop_next: AtomicUsize::new(0),
            fail_next: AtomicUsize::new(0),
        })
        .collect()
}

impl crate::channel::BroadcastChannel for MemBroadcastChannel {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let msg = match self.cfg.max_msg_len {
            Some(max) if msg.len() > max => Err(max),
            _ => Ok(msg.to_vec()),
        };
        async move {
            let msg = match msg {
                Ok(msg) => msg,
                Err(max) => return Err(SendError::TooLarge { max }),
            };
            if take_one(&self.fail_next) {
                return Err(SendError::Transport("injected failure".into()));
            }
            if let Some(latency) = self.cfg.latency {
                tokio::time::sleep(latency).await;
            }
            if take_one(&self.drop_next) {
                return Ok(()); // injected silent loss, group-wide
            }
            if self.txs.is_empty() {
                return Ok(()); // a group of one: vacuous delivery
            }
            match self.cfg.delivery {
                Delivery::Confirmed => {
                    let mut alive = 0usize;
                    for tx in &self.txs {
                        let sent = match self.cfg.send_timeout {
                            Some(deadline) => {
                                match tokio::time::timeout(deadline, tx.send(msg.clone())).await {
                                    Ok(sent) => sent.map_err(|_| ()),
                                    Err(_) => {
                                        return Err(SendError::Transport("send timed out".into()));
                                    }
                                }
                            }
                            None => tx.send(msg.clone()).await.map_err(|_| ()),
                        };
                        if sent.is_ok() {
                            alive += 1;
                        }
                    }
                    if alive == 0 {
                        return Err(SendError::Closed);
                    }
                    Ok(())
                }
                Delivery::BestEffort => {
                    for tx in &self.txs {
                        let _ = tx.try_send(msg.clone()); // full or closed: silent loss
                    }
                    Ok(())
                }
            }
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        // Closes only when every other member dropped its handle (each holds
        // a clone of this member's tx).
        self.rx.recv().await.ok_or(RecvError::Closed)
    }
}

/// Sender identity inside an in-memory group: the member's index. Only
/// meaningful within the group that minted it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemSenderId([u8; 4]);

impl SenderId for MemSenderId {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A [`MemBroadcastChannel`] that also names which member each message came
/// from. Attribution is by construction: the shared bus tags every message
/// with the sending handle's index, so it is trustworthy only within this
/// process — which is the honest reach of this mock.
///
/// This group is always [`Delivery::Confirmed`] with no `send_timeout` and no
/// fault injection; of [`MemConfig`]'s knobs only `capacity`, `max_msg_len`
/// and `latency` apply.
#[derive(Debug)]
pub struct MemAttributableBroadcastChannel {
    me: MemSenderId,
    txs: Vec<mpsc::Sender<(MemSenderId, Vec<u8>)>>,
    rx: mpsc::Receiver<(MemSenderId, Vec<u8>)>,
    cfg: MemConfig,
}

/// Create an `n`-member ATTRIBUTED broadcast group; member `i`'s sender id
/// is its index.
pub fn attributed_group(n: usize, cfg: MemConfig) -> Vec<MemAttributableBroadcastChannel> {
    let cap = cfg.capacity.unwrap_or(1).max(1);
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..n).map(|_| mpsc::channel(cap)).unzip();
    rxs.into_iter()
        .enumerate()
        .map(|(i, rx)| MemAttributableBroadcastChannel {
            me: MemSenderId((i as u32).to_be_bytes()),
            txs: txs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, tx)| tx.clone())
                .collect(),
            rx,
            cfg: cfg.clone(),
        })
        .collect()
}

impl crate::channel::AttributableBroadcastChannel for MemAttributableBroadcastChannel {
    type Sender = MemSenderId;

    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let msg = match self.cfg.max_msg_len {
            Some(max) if msg.len() > max => Err(max),
            _ => Ok(msg.to_vec()),
        };
        async move {
            let msg = match msg {
                Ok(msg) => msg,
                Err(max) => return Err(SendError::TooLarge { max }),
            };
            if let Some(latency) = self.cfg.latency {
                tokio::time::sleep(latency).await;
            }
            if self.txs.is_empty() {
                return Ok(());
            }
            let mut alive = 0usize;
            for tx in &self.txs {
                if tx.send((self.me.clone(), msg.clone())).await.is_ok() {
                    alive += 1;
                }
            }
            if alive == 0 {
                return Err(SendError::Closed);
            }
            Ok(())
        }
    }

    async fn recv(&mut self) -> Result<(MemSenderId, Vec<u8>), RecvError> {
        self.rx.recv().await.ok_or(RecvError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Channel;
    use crate::error::SendError;
    use crate::testkit;
    use std::time::Duration;

    /// A `Some(0)` capacity is clamped to 1, not passed to `mpsc::channel`
    /// (which panics on 0), and yields a usable channel.
    #[tokio::test]
    async fn zero_capacity_is_clamped_not_a_panic() {
        let (mut a, mut b) = duplex(MemConfig {
            capacity: Some(0),
            ..MemConfig::default()
        });
        a.send(b"hi").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"hi");
    }

    // CONFORMANCE (trait contract) — delegated to the generic testkit; the
    // mock is the testkit's first client.
    #[tokio::test]
    async fn roundtrip_both_directions() {
        let (a, b) = duplex(MemConfig {
            capacity: Some(4),
            ..MemConfig::default()
        });
        testkit::roundtrip_both_directions(a, b).await;
    }

    #[tokio::test]
    async fn too_large_is_rejected() {
        let cfg = MemConfig {
            max_msg_len: Some(4),
            ..MemConfig::default()
        };
        let (a, _b) = duplex(cfg);
        testkit::too_large(a, 4).await;
    }

    #[tokio::test]
    async fn too_large_is_recoverable() {
        let cfg = MemConfig {
            capacity: Some(2),
            max_msg_len: Some(16),
            ..MemConfig::default()
        };
        let (a, b) = duplex(cfg);
        testkit::too_large_is_recoverable(a, b, 16).await;
    }

    #[tokio::test]
    async fn recv_after_peer_drop_is_closed() {
        let (a, b) = duplex(MemConfig::default());
        testkit::closed_after_peer_drop(a, b).await;
    }

    #[tokio::test]
    async fn recv_is_cancel_safe() {
        let (a, b) = duplex(MemConfig::default());
        testkit::recv_is_cancel_safe(a, b).await;
    }

    // One slot per direction, so every send after the first waits on the
    // peer: the shape that deadlocks a pair driven through `Channel` alone.
    #[tokio::test]
    async fn mutual_bursts_converge() {
        let cfg = MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        };
        let (a, b) = duplex(cfg);
        testkit::mutual_bursts_converge(a, b, 64).await;
    }

    // MOCK-SPECIFIC (NOT part of the trait contract, NOT inherited by
    // real transports): this pipe happens to be FIFO per direction; bench
    // scenarios rely on it.
    #[tokio::test]
    async fn mock_is_fifo_per_direction() {
        let (mut a, mut b) = duplex(MemConfig {
            capacity: Some(4),
            ..MemConfig::default()
        });
        a.send(b"m1").await.unwrap();
        a.send(b"m2").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"m1");
        assert_eq!(b.recv().await.unwrap(), b"m2");
    }

    // A full peer buffer in Confirmed mode must not hang forever — the
    // transport gives up after its internal deadline and errors. The error
    // is deliberately opaque (Transport, not a dedicated Timeout variant).
    #[tokio::test]
    async fn confirmed_send_times_out_when_peer_buffer_full() {
        let cfg = MemConfig {
            capacity: Some(1),
            send_timeout: Some(Duration::from_millis(10)),
            ..MemConfig::default()
        };
        let (mut a, _b) = duplex(cfg);
        a.send(b"fills the buffer").await.unwrap();
        let err = a.send(b"no room").await;
        assert!(matches!(err, Err(SendError::Transport(_))));
    }

    #[tokio::test]
    async fn confirmed_send_to_dropped_peer_errors_best_effort_does_not() {
        let (mut a, b) = duplex(MemConfig {
            delivery: Delivery::Confirmed,
            ..MemConfig::default()
        });
        drop(b);
        assert!(matches!(a.send(b"x").await, Err(SendError::Closed)));

        let (mut a, b) = duplex(MemConfig {
            delivery: Delivery::BestEffort,
            ..MemConfig::default()
        });
        drop(b);
        assert!(a.send(b"x").await.is_ok()); // loss = infinite delay
    }

    #[tokio::test]
    async fn best_effort_loss_injection() {
        let (mut a, mut b) = duplex(MemConfig {
            delivery: Delivery::BestEffort,
            ..MemConfig::default()
        });
        a.drop_next(1);
        a.send(b"lost").await.unwrap(); // Ok, but silently dropped
        a.send(b"kept").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"kept");
    }

    // `drop_next` applies regardless of delivery mode: even in Confirmed mode
    // (the default), an injected drop returns Ok while the message never
    // reaches the peer — the fault injection deliberately breaks the
    // confirmed guarantee to exercise "Ok is never a delivery promise".
    #[tokio::test]
    async fn drop_next_loses_the_message_even_in_confirmed_mode() {
        let (mut a, mut b) = duplex(MemConfig {
            capacity: Some(2),
            ..MemConfig::default()
        });
        a.drop_next(1);
        a.send(b"lost").await.unwrap(); // Ok despite the injected drop
        a.send(b"kept").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"kept");
    }

    // A zero-length message is a valid datagram and must round-trip intact,
    // distinct from "no message".
    #[tokio::test]
    async fn empty_message_roundtrips() {
        let (mut a, mut b) = duplex(MemConfig {
            capacity: Some(2),
            ..MemConfig::default()
        });
        a.send(b"").await.unwrap();
        a.send(b"after").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"");
        assert_eq!(b.recv().await.unwrap(), b"after");
    }

    // Simulated delivery delay — the mock's stand-in for a slow transport
    // (a cold-start Tor circuit is seconds away from the first message).
    // start_paused: tokio's virtual clock makes this deterministic and
    // instant.
    #[tokio::test(start_paused = true)]
    async fn latency_delays_delivery() {
        let (mut a, mut b) = duplex(MemConfig {
            latency: Some(Duration::from_millis(100)),
            ..MemConfig::default()
        });
        let t0 = tokio::time::Instant::now();
        a.send(b"slow").await.unwrap();
        assert!(t0.elapsed() >= Duration::from_millis(100));
        assert_eq!(b.recv().await.unwrap(), b"slow");
    }

    #[tokio::test]
    async fn transport_failure_injection() {
        let (mut a, _b) = duplex(MemConfig::default());
        a.fail_next(1);
        assert!(matches!(a.send(b"x").await, Err(SendError::Transport(_))));
        assert!(a.send(b"x").await.is_ok());
    }

    // Connection-oriented lifecycle (die → detect → reconnect) — delegated
    // to the generic testkit; the mock is a connection-based transport, so
    // it must pass the shared Connector/Listener conformance.
    #[tokio::test]
    async fn connect_use_drop_reconnect() {
        let (connector, listener) = network(MemConfig::default());
        testkit::connect_use_drop_reconnect(connector, listener, &MemAddr).await;
    }

    // Mock-internal error surface: both sites that emit `Unreachable`.
    #[tokio::test]
    async fn connect_fails_when_listener_is_gone() {
        let (connector, listener) = network(MemConfig::default());
        drop(listener); // no one left to hand the far end to
        assert!(matches!(
            connector.connect(&MemAddr).await,
            Err(ConnectError::Unreachable)
        ));
    }

    #[tokio::test]
    async fn accept_fails_when_all_connectors_are_gone() {
        let (connector, mut listener) = network(MemConfig::default());
        drop(connector); // no one left who could ever connect
        assert!(matches!(
            listener.accept().await,
            Err(ConnectError::Unreachable)
        ));
    }

    #[tokio::test]
    async fn mem_transport_dials_and_accepts() {
        use crate::channel::{Channel, Connector, ListenParams, Listener, Transport};
        let transport = MemTransport::new(MemConfig::default());
        let connector = transport.connector();
        let (mut listener, _addr) = transport.listen(ListenParams::new(1)).await.unwrap();
        let (client, server) =
            futures_util::future::join(connector.connect(&MemAddr), listener.accept()).await;
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        client.send(b"hi").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"hi");
    }

    #[tokio::test]
    async fn mem_transport_listen_is_single_use() {
        use crate::channel::{ListenParams, Transport};
        let transport = MemTransport::new(MemConfig::default());
        let _first = transport.listen(ListenParams::new(1)).await.unwrap();
        assert!(matches!(
            transport.listen(ListenParams::new(1)).await,
            Err(crate::error::ConnectError::Unreachable)
        ));
    }

    // Isolation plumbing (the observable half of isolation, which is all the
    // mock can show): the default connector carries no isolation id; an
    // isolated connector carries exactly the id it was built for, and
    // distinct groups carry distinct ids — the identity a real backend
    // isolates circuits on.
    #[test]
    fn isolated_connector_carries_the_isolation_identity() {
        use crate::channel::Transport;
        use crate::isolation::CircuitIsolationId;
        let transport = MemTransport::new(MemConfig::default());
        assert_eq!(transport.connector().isolation(), None);

        let (s1, s2) = (
            CircuitIsolationId::generate(),
            CircuitIsolationId::generate(),
        );
        assert_eq!(transport.isolated_connector(&s1).isolation(), Some(s1));
        assert_eq!(transport.isolated_connector(&s2).isolation(), Some(s2));
        assert_ne!(
            transport.isolated_connector(&s1).isolation(),
            transport.isolated_connector(&s2).isolation()
        );
        // Same group, two connectors: same identity (a real backend would
        // let these share a circuit).
        assert_eq!(
            transport.isolated_connector(&s1).isolation(),
            transport.isolated_connector(&s1).isolation()
        );
    }

    // A departed member is skipped silently; only when EVERY other member is
    // gone does a Confirmed send report the group dead.
    #[tokio::test]
    async fn group_send_skips_departed_members_until_all_are_gone() {
        use crate::channel::BroadcastChannel;
        let mut g = group(
            3,
            MemConfig {
                capacity: Some(4),
                ..MemConfig::default()
            },
        );
        let c = g.remove(2);
        drop(c);
        g[0].send(b"still delivered").await.unwrap();
        assert_eq!(g[1].recv().await.unwrap(), b"still delivered");
        let b = g.remove(1);
        drop(b);
        assert!(matches!(
            g[0].send(b"nobody left").await,
            Err(SendError::Closed)
        ));
    }

    // CONFORMANCE (broadcast trait contract) — delegated to the testkit; the
    // mock group is the broadcast testkit's first client.
    #[tokio::test]
    async fn broadcast_reaches_all_others() {
        let g = group(
            3,
            MemConfig {
                capacity: Some(4),
                ..MemConfig::default()
            },
        );
        testkit::broadcast_reaches_all_others(g).await;
    }

    #[tokio::test]
    async fn broadcast_recv_is_cancel_safe() {
        let g = group(2, MemConfig::default());
        testkit::broadcast_recv_is_cancel_safe(g).await;
    }

    #[tokio::test]
    async fn broadcast_too_large_is_recoverable() {
        let g = group(
            2,
            MemConfig {
                capacity: Some(2),
                max_msg_len: Some(16),
                ..MemConfig::default()
            },
        );
        testkit::broadcast_too_large_is_recoverable(g, 16).await;
    }

    #[tokio::test]
    async fn broadcast_closed_after_group_drop() {
        let g = group(3, MemConfig::default());
        testkit::closed_after_group_drop(g).await;
    }

    #[tokio::test]
    async fn attribution_matches_sender() {
        let g = attributed_group(
            3,
            MemConfig {
                capacity: Some(4),
                ..MemConfig::default()
            },
        );
        testkit::attribution_matches_sender(g).await;
    }
}
