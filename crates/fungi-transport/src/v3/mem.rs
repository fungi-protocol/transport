//! In-memory pipe for the v3 traits. The duplex object is just the two
//! halves stapled together; `Into` unstaples them.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll};

use futures_core::Stream;
use tokio::sync::mpsc;

use crate::error::{ConnectError, RecvError, SendError};
use crate::v1::mem::take_one;
pub use crate::v1::mem::{Delivery, MemAddr, MemConfig};
use crate::v3::{Channel, Connector, Listener, Sender};
use std::future::Future;

/// Write half of an in-memory channel.
#[derive(Debug)]
pub struct MemSender {
    tx: mpsc::Sender<Vec<u8>>,
    cfg: MemConfig,
    drop_next: Arc<AtomicUsize>,
    fail_next: Arc<AtomicUsize>,
}

impl MemSender {
    /// Silently drop the next `n` sends (best-effort loss injection).
    pub fn drop_next(&self, n: usize) {
        self.drop_next.store(n, std::sync::atomic::Ordering::SeqCst);
    }
    /// Fail the next `n` sends with [`SendError::Transport`].
    pub fn fail_next(&self, n: usize) {
        self.fail_next.store(n, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Read half of an in-memory channel.
#[derive(Debug)]
pub struct MemReceiver {
    rx: mpsc::Receiver<Vec<u8>>,
}

/// An unsplit in-memory channel: the two halves stapled together.
#[derive(Debug)]
pub struct MemChannel {
    sender: MemSender,
    receiver: MemReceiver,
}

/// Create a connected pair: whatever A sends, B receives, and vice versa.
pub fn duplex(cfg: MemConfig) -> (MemChannel, MemChannel) {
    let cap = cfg.capacity.unwrap_or(1);
    let (tx_ab, rx_ab) = mpsc::channel(cap);
    let (tx_ba, rx_ba) = mpsc::channel(cap);
    let mk = |tx, rx| MemChannel {
        sender: MemSender {
            tx,
            cfg: cfg.clone(),
            drop_next: Arc::new(AtomicUsize::new(0)),
            fail_next: Arc::new(AtomicUsize::new(0)),
        },
        receiver: MemReceiver { rx },
    };
    (mk(tx_ab, rx_ba), mk(tx_ba, rx_ab))
}

impl Sender for MemSender {
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
                return Ok(());
            }
            match self.cfg.delivery {
                Delivery::Confirmed => match self.cfg.send_timeout {
                    Some(deadline) => match tokio::time::timeout(deadline, self.tx.send(msg)).await
                    {
                        Ok(sent) => sent.map_err(|_| SendError::Closed),
                        Err(_) => Err(SendError::Transport("send timed out".into())),
                    },
                    None => self.tx.send(msg).await.map_err(|_| SendError::Closed),
                },
                Delivery::BestEffort => {
                    let _ = self.tx.try_send(msg);
                    Ok(())
                }
            }
        }
    }
}

impl Stream for MemReceiver {
    type Item = Result<Vec<u8>, RecvError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|o| o.map(Ok))
    }
}

impl From<MemChannel> for (MemSender, MemReceiver) {
    fn from(ch: MemChannel) -> Self {
        (ch.sender, ch.receiver)
    }
}

impl Channel for MemChannel {
    type Sender = MemSender;
    type Receiver = MemReceiver;
}

/// Connector half of an in-memory network.
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
    use futures_util::StreamExt;
    use std::time::Duration;

    // Split halves can be moved independently into different tasks.
    #[tokio::test]
    async fn halves_are_independently_owned() {
        let (a, b) = duplex(MemConfig {
            capacity: Some(16),
            ..Default::default()
        });
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, mut b_rx) = b.into();
        let sender = tokio::spawn(async move {
            for i in 0u8..50 {
                a_tx.send(&[i]).await.unwrap();
            }
        });
        for i in 0u8..50 {
            assert_eq!(b_rx.next().await.unwrap().unwrap(), [i]);
        }
        sender.await.unwrap();
    }

    // CONFORMANCE (trait contract): everything sent arrives intact, both
    // directions. Deliberately does NOT assert arrival order — the trait
    // promises none (an OHTTP mailbox implementation may reorder).
    #[tokio::test]
    async fn roundtrip_both_directions() {
        let (a, b) = duplex(MemConfig {
            capacity: Some(4),
            ..MemConfig::default()
        });
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, mut b_rx) = b.into();
        a_tx.send(b"m1").await.unwrap();
        a_tx.send(b"m2").await.unwrap();
        let got = [
            b_rx.next().await.unwrap().unwrap(),
            b_rx.next().await.unwrap().unwrap(),
        ];
        assert!(got.contains(&b"m1".to_vec()) && got.contains(&b"m2".to_vec()));
    }

    // MOCK-SPECIFIC (NOT part of the trait contract, NOT inherited by
    // fungi#3/#4): this pipe happens to be FIFO per direction; bench
    // scenarios rely on it.
    #[tokio::test]
    async fn mock_is_fifo_per_direction() {
        let (a, b) = duplex(MemConfig {
            capacity: Some(4),
            ..MemConfig::default()
        });
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, mut b_rx) = b.into();
        a_tx.send(b"m1").await.unwrap();
        a_tx.send(b"m2").await.unwrap();
        assert_eq!(b_rx.next().await.unwrap().unwrap(), b"m1");
        assert_eq!(b_rx.next().await.unwrap().unwrap(), b"m2");
    }

    #[tokio::test]
    async fn too_large_is_rejected() {
        let cfg = MemConfig {
            max_msg_len: Some(4),
            ..MemConfig::default()
        };
        let (a, _b) = duplex(cfg);
        let (mut a_tx, _a_rx) = a.into();
        assert!(matches!(
            a_tx.send(b"12345").await,
            Err(SendError::TooLarge { max: 4 })
        ));
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
        let (a, _b) = duplex(cfg);
        let (mut a_tx, _a_rx) = a.into();
        a_tx.send(b"fills the buffer").await.unwrap();
        let err = a_tx.send(b"no room").await;
        assert!(matches!(err, Err(SendError::Transport(_))));
    }

    #[tokio::test]
    async fn stream_ends_after_sender_half_drop() {
        let (a, b) = duplex(MemConfig::default());
        let (a_tx, _a_rx) = a.into();
        let (_b_tx, mut b_rx) = b.into();
        drop(a_tx);
        assert!(b_rx.next().await.is_none());
    }

    #[tokio::test]
    async fn confirmed_send_to_dropped_peer_errors_best_effort_does_not() {
        let (a, b) = duplex(MemConfig {
            delivery: Delivery::Confirmed,
            ..MemConfig::default()
        });
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, b_rx) = b.into();
        drop(b_rx);
        assert!(matches!(a_tx.send(b"x").await, Err(SendError::Closed)));

        let (a, b) = duplex(MemConfig {
            delivery: Delivery::BestEffort,
            ..MemConfig::default()
        });
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, b_rx) = b.into();
        drop(b_rx);
        assert!(a_tx.send(b"x").await.is_ok()); // loss = infinite delay
    }

    #[tokio::test]
    async fn best_effort_loss_injection() {
        let (a, b) = duplex(MemConfig {
            delivery: Delivery::BestEffort,
            ..MemConfig::default()
        });
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, mut b_rx) = b.into();
        a_tx.drop_next(1);
        a_tx.send(b"lost").await.unwrap(); // Ok, but silently dropped
        a_tx.send(b"kept").await.unwrap();
        assert_eq!(b_rx.next().await.unwrap().unwrap(), b"kept");
    }

    #[tokio::test]
    async fn transport_failure_injection() {
        let (a, _b) = duplex(MemConfig::default());
        let (mut a_tx, _a_rx) = a.into();
        a_tx.fail_next(1);
        assert!(matches!(
            a_tx.send(b"x").await,
            Err(SendError::Transport(_))
        ));
        assert!(a_tx.send(b"x").await.is_ok());
    }

    #[tokio::test]
    async fn next_is_cancel_safe() {
        let (a, b) = duplex(MemConfig::default());
        let (mut a_tx, _a_rx) = a.into();
        let (_b_tx, mut b_rx) = b.into();
        for _ in 0..10 {
            let poll = tokio::time::timeout(Duration::from_millis(5), b_rx.next()).await;
            assert!(poll.is_err());
        }
        a_tx.send(b"m1").await.unwrap();
        assert_eq!(b_rx.next().await.unwrap().unwrap(), b"m1");
    }

    #[tokio::test]
    async fn connect_use_drop_reconnect() {
        let (connector, mut listener) = network(MemConfig::default());
        let addr = MemAddr;
        let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
        let (client, server) = (client.unwrap(), server.unwrap());
        let (mut client_tx, _client_rx) = client.into();
        let (_server_tx, mut server_rx) = server.into();
        client_tx.send(b"hello").await.unwrap();
        assert_eq!(server_rx.next().await.unwrap().unwrap(), b"hello");
        // The server receiver half dies for real (owned value dropped). The client
        // sender detects it — confirmed send errors — and reconnects through the
        // same connector: the full die → detect → reconnect cycle.
        drop(server_rx);
        assert!(client_tx.send(b"x").await.is_err());
        let (c2, s2) = tokio::join!(connector.connect(&addr), listener.accept());
        let (c2, s2) = (c2.unwrap(), s2.unwrap());
        let (mut c2_tx, _c2_rx) = c2.into();
        let (_s2_tx, mut s2_rx) = s2.into();
        c2_tx.send(b"again").await.unwrap();
        assert_eq!(s2_rx.next().await.unwrap().unwrap(), b"again");
    }
}
