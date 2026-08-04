//! Variant 3 — split halves: a channel converts into an owned
//! `(Sender, Receiver)` pair; the read half is a [`Stream`].
//!
//! Experiment notes recorded against this variant: full duplex works by
//! construction (each half lives in its own task — the std/tokio mpsc
//! shape); the cost is two associated types
//! propagating through consumer signatures and every transport having to
//! provide a split even when unused.

use std::future::Future;

use futures_core::Stream;

use crate::error::{ConnectError, RecvError, SendError};

/// The write half of a datagram channel.
///
/// Same `send` contract as the other variants: `Ok(())` = accepted,
/// best-effort delivery; timeouts internal; [`SendError::TooLarge`] for
/// oversized messages.
pub trait Sender: Send {
    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
}

/// A datagram channel to ONE peer that splits into independently owned
/// halves. Receiving is the [`Stream`] half; channel death is stream end.
/// Dropping the receiver mid-poll must not lose messages (cancel safety).
pub trait Channel: Send + Into<(Self::Sender, Self::Receiver)> {
    /// The write half.
    type Sender: Sender + Send;
    /// The read half: a stream of received messages.
    type Receiver: Stream<Item = Result<Vec<u8>, RecvError>> + Send + Unpin;
}

/// Establishes channels to peers, for connection-oriented transports.
/// See v1's `Connector` docs; identical contract, bound to [`Channel`] (v3).
pub trait Connector: Send {
    /// Transport-native peer address, opaque to consumers.
    type Addr: Send + Sync;
    /// The channel type this connector produces.
    type Channel: Channel;
    /// Open a new channel to the peer at `addr`.
    fn connect(
        &self,
        addr: &Self::Addr,
    ) -> impl Future<Output = Result<Self::Channel, ConnectError>> + Send;
}

/// Accepts inbound channels, for connection-oriented transports.
pub trait Listener: Send {
    /// The channel type this listener produces.
    type Channel: Channel;
    /// Wait for the next inbound channel.
    fn accept(&mut self) -> impl Future<Output = Result<Self::Channel, ConnectError>> + Send;
}

pub mod mem;

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    struct LoopSender(tokio::sync::mpsc::Sender<Vec<u8>>);
    struct Loopback {
        tx: LoopSender,
        rx: tokio_stream_adapter::Recv,
    }
    // Minimal receiver-as-stream over tokio mpsc for the test:
    mod tokio_stream_adapter {
        use super::*;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        #[derive(Debug)]
        pub struct Recv(pub tokio::sync::mpsc::Receiver<Vec<u8>>);
        impl futures_core::Stream for Recv {
            type Item = Result<Vec<u8>, RecvError>;
            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                self.0.poll_recv(cx).map(|o| o.map(Ok))
            }
        }
    }

    impl Sender for LoopSender {
        fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
            let msg = msg.to_vec();
            async move { self.0.send(msg).await.map_err(|_| SendError::Closed) }
        }
    }

    impl From<Loopback> for (LoopSender, tokio_stream_adapter::Recv) {
        fn from(ch: Loopback) -> Self {
            (ch.tx, ch.rx)
        }
    }

    impl Channel for Loopback {
        type Sender = LoopSender;
        type Receiver = tokio_stream_adapter::Recv;
    }

    #[tokio::test]
    async fn split_enables_independently_owned_halves() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let ch = Loopback {
            tx: LoopSender(tx),
            rx: tokio_stream_adapter::Recv(rx),
        };
        let (mut sender, mut receiver) = ch.into();
        let send_task = tokio::spawn(async move {
            sender.send(b"from a task").await.unwrap();
            sender
        });
        assert_eq!(receiver.next().await.unwrap().unwrap(), b"from a task");
        drop(send_task.await.unwrap());
        assert!(receiver.next().await.is_none());
    }
}
