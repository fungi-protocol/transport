//! In-memory pipe implementation of the v1 traits — the experiment bench
//! and the embryo of fungi#2. Two crossed bounded `tokio::sync::mpsc`
//! queues; capacity 1 by default so a slow transport is simulated for free.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::error::{ConnectError, RecvError, SendError};
use crate::v1::{Channel, Connector, Listener};

/// What `send` promises in this mock — the experiment's second axis.
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
    /// Per-direction buffer capacity; `None` = 1 (slow transport).
    pub capacity: Option<usize>,
    /// Maximum message size; larger sends fail with [`SendError::TooLarge`].
    pub max_msg_len: Option<usize>,
    /// Artificial latency applied before each delivery.
    pub latency: Option<Duration>,
    /// Confirmed-mode sends give up with an error after this internal
    /// deadline. The trait exposes no timeouts; this is
    /// strictly transport-internal — the "with timeouts" half of the
    /// send-semantics experiment.
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
    drop_next: Arc<AtomicUsize>,
    fail_next: Arc<AtomicUsize>,
}

impl MemChannel {
    /// Silently drop the next `n` sends (best-effort loss injection).
    pub fn drop_next(&self, n: usize) {
        self.drop_next.store(n, Ordering::SeqCst);
    }
    /// Fail the next `n` sends with [`SendError::Transport`].
    pub fn fail_next(&self, n: usize) {
        self.fail_next.store(n, Ordering::SeqCst);
    }
}

/// Create a connected pair: whatever A sends, B receives, and vice versa.
pub fn duplex(cfg: MemConfig) -> (MemChannel, MemChannel) {
    let cap = cfg.capacity.unwrap_or(1);
    let (tx_ab, rx_ab) = mpsc::channel(cap);
    let (tx_ba, rx_ba) = mpsc::channel(cap);
    let mk = |tx, rx| MemChannel {
        tx,
        rx,
        cfg: cfg.clone(),
        drop_next: Arc::new(AtomicUsize::new(0)),
        fail_next: Arc::new(AtomicUsize::new(0)),
    };
    (mk(tx_ab, rx_ba), mk(tx_ba, rx_ab))
}

fn take_one(counter: &AtomicUsize) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
}

impl Channel for MemChannel {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let msg = msg.to_vec();
        async move {
            if let Some(max) = self.cfg.max_msg_len
                && msg.len() > max
            {
                return Err(SendError::TooLarge { max });
            }
            if take_one(&self.fail_next) {
                return Err(SendError::Transport("injected failure".into()));
            }
            if let Some(latency) = self.cfg.latency {
                tokio::time::sleep(latency).await;
            }
            if take_one(&self.drop_next) {
                return Ok(()); // injected silent loss
            }
            match self.cfg.delivery {
                Delivery::Confirmed => match self.cfg.send_timeout {
                    Some(deadline) => {
                        match tokio::time::timeout(deadline, self.tx.send(msg)).await {
                            Ok(sent) => sent.map_err(|_| SendError::Closed),
                            // Experiment note: dedicated Timeout variant vs
                            // opaque Transport is decided in Task 13.
                            Err(_) => Err(SendError::Transport("send timed out".into())),
                        }
                    }
                    None => self.tx.send(msg).await.map_err(|_| SendError::Closed),
                },
                Delivery::BestEffort => {
                    let _ = self.tx.try_send(msg); // full or closed: silent loss
                    Ok(())
                }
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
        async move {
            // tokio's mpsc recv is documented cancel-safe: no message is
            // lost when this future is dropped mid-wait.
            self.rx.recv().await.ok_or(RecvError::Closed)
        }
    }
}

/// Address of an in-memory listener. Only one endpoint exists per
/// [`network`], so this is a unit marker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemAddr;

/// Connector half of an in-memory network: each `connect` produces a fresh
/// channel pair, handing the far end to the paired [`MemListener`].
#[derive(Debug)]
pub struct MemConnector {
    cfg: MemConfig,
    to_listener: mpsc::Sender<MemChannel>,
}

/// Listener half of an in-memory network.
#[derive(Debug)]
pub struct MemListener {
    inbound: mpsc::Receiver<MemChannel>,
}

/// Create a connector/listener pair sharing an in-memory "network".
pub fn network(cfg: MemConfig) -> (MemConnector, MemListener) {
    let (to_listener, inbound) = mpsc::channel(8);
    (MemConnector { cfg, to_listener }, MemListener { inbound })
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

    #[allow(clippy::manual_async_fn)]
    fn accept(&mut self) -> impl Future<Output = Result<MemChannel, ConnectError>> + Send {
        async move { self.inbound.recv().await.ok_or(ConnectError::Unreachable) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{RecvError, SendError};
    use crate::v1::{Channel, Connector, Listener};
    use std::time::Duration;

    // CONFORMANCE (trait contract): everything sent arrives intact, both
    // directions. Deliberately does NOT assert arrival order — the trait
    // promises none (an OHTTP mailbox implementation may reorder).
    #[tokio::test]
    async fn roundtrip_both_directions() {
        let (mut a, mut b) = duplex(MemConfig {
            capacity: Some(4),
            ..MemConfig::default()
        });
        a.send(b"m1").await.unwrap();
        a.send(b"m2").await.unwrap();
        let got = [b.recv().await.unwrap(), b.recv().await.unwrap()];
        assert!(got.contains(&b"m1".to_vec()) && got.contains(&b"m2".to_vec()));
        b.send(b"reply").await.unwrap();
        assert_eq!(a.recv().await.unwrap(), b"reply");
    }

    // MOCK-SPECIFIC (NOT part of the trait contract, NOT inherited by
    // fungi#3/#4): this pipe happens to be FIFO per direction; bench
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

    // The "with timeouts" half of the send-semantics experiment: a full
    // peer buffer in Confirmed mode must not hang forever — the transport
    // gives up after its INTERNAL deadline and errors. Whether that error
    // deserves a dedicated SendError variant is a Task 13 table row.
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
    async fn too_large_is_rejected() {
        let cfg = MemConfig {
            max_msg_len: Some(4),
            ..MemConfig::default()
        };
        let (mut a, _b) = duplex(cfg);
        assert!(matches!(
            a.send(b"12345").await,
            Err(SendError::TooLarge { max: 4 })
        ));
    }

    #[tokio::test]
    async fn recv_after_peer_drop_is_closed() {
        let (a, mut b) = duplex(MemConfig::default());
        drop(a);
        assert!(matches!(b.recv().await, Err(RecvError::Closed)));
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

    #[tokio::test]
    async fn transport_failure_injection() {
        let (mut a, _b) = duplex(MemConfig::default());
        a.fail_next(1);
        assert!(matches!(a.send(b"x").await, Err(SendError::Transport(_))));
        assert!(a.send(b"x").await.is_ok());
    }

    #[tokio::test]
    async fn recv_is_cancel_safe() {
        let (mut a, mut b) = duplex(MemConfig::default());
        // Poll-and-abandon recv 10 times; no message exists yet.
        for _ in 0..10 {
            let poll = tokio::time::timeout(Duration::from_millis(5), b.recv()).await;
            assert!(poll.is_err(), "should time out");
        }
        a.send(b"m1").await.unwrap();
        assert_eq!(
            b.recv().await.unwrap(),
            b"m1",
            "no message lost to cancellation"
        );
    }

    #[tokio::test]
    async fn connect_use_drop_reconnect() {
        let (connector, mut listener) = network(MemConfig::default());
        let addr = MemAddr;
        let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        client.send(b"hello").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"hello");
        // The server END dies for real (owned value dropped). The client
        // detects it — confirmed send errors — and reconnects through the
        // same connector: the full die → detect → reconnect cycle.
        drop(server);
        assert!(client.send(b"x").await.is_err());
        let (c2, s2) = tokio::join!(connector.connect(&addr), listener.accept());
        let (mut c2, mut s2) = (c2.unwrap(), s2.unwrap());
        c2.send(b"again").await.unwrap();
        assert_eq!(s2.recv().await.unwrap(), b"again");
    }
}
