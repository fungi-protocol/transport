//! Variant 1 — methods-only channel: `Stream` does not appear in the
//! interface; [`into_stream`] provides it as an internal-only adapter.
//!
//! Experiment notes recorded against this variant: `&mut self` on both
//! methods means one channel object cannot send and receive concurrently —
//! full-duplex consumers must wrap the channel in a task (see
//! `examples/echo_v1.rs`, scenario 2).

use std::future::Future;

use futures_core::Stream;

use crate::error::{ConnectError, RecvError, SendError};

/// A datagram channel to ONE peer: opaque bytes, one message per call.
///
/// Contract:
/// - `Ok(())` from `send` means the transport accepted the message and will
///   deliver best-effort. It is NOT end-to-end delivery confirmation.
/// - `Err` from `send` means not delivered, or unknown — never "delivered
///   with a caveat". Any give-up timeout is internal to the transport; the
///   trait exposes none.
/// - `recv` resolves with the next available message; the transport buffers
///   internally. Dropping the `recv` future before it resolves must not
///   lose any message (cancel safety).
/// - Messages have arbitrary size; a transport rejects oversized ones with
///   [`SendError::TooLarge`].
/// - No ordering guarantees across channels, no deduplication.
pub trait Channel: Send {
    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
    /// Wait for and return the next message from the peer.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send;
}

/// Establishes channels to peers, for connection-oriented transports.
///
/// Message-based transports (e.g. an OHTTP mailbox) implement only
/// [`Channel`]; connectors are how consumers RE-establish a channel after
/// [`SendError::Closed`]/[`RecvError::Closed`]. Retry cadence is the
/// caller's business, never the connector's.
pub trait Connector: Send {
    /// Transport-native peer address (e.g. an onion address), opaque to
    /// consumers; obtained out of band.
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

/// Adapt any [`Channel`] into a [`Stream`] of received messages ("internal
/// only" Stream). The stream ends after the first error.
pub fn into_stream<C: Channel>(
    channel: C,
) -> impl Stream<Item = Result<Vec<u8>, RecvError>> + Send {
    futures_util::stream::unfold((channel, false), |(mut ch, done)| async move {
        if done {
            return None;
        }
        let item = ch.recv().await;
        let done = item.is_err();
        Some((item, (ch, done)))
    })
}

pub mod mem;

#[cfg(test)]
mod tests {
    use super::*;

    /// Echoes every sent message back on recv. Proves the trait is
    /// implementable with plain async blocks and Send futures.
    struct Loopback(std::collections::VecDeque<Vec<u8>>);

    impl Channel for Loopback {
        fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
            self.0.push_back(msg.to_vec());
            async { Ok(()) }
        }
        fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
            let next = self.0.pop_front();
            async move { next.ok_or(RecvError::Closed) }
        }
    }

    fn assert_send<T: Send>(_: T) {}

    #[tokio::test]
    async fn trait_is_implementable_and_futures_are_send() {
        let mut ch = Loopback(Default::default());
        assert_send(ch.send(b"ping"));
        ch.send(b"ping").await.unwrap();
        assert_send(ch.recv());
        assert_eq!(ch.recv().await.unwrap(), b"ping");
        assert!(matches!(ch.recv().await, Err(RecvError::Closed)));
    }

    #[tokio::test]
    async fn into_stream_yields_messages() {
        use futures_util::StreamExt;
        let mut ch = Loopback(Default::default());
        ch.send(b"a").await.unwrap();
        ch.send(b"b").await.unwrap();
        let stream = into_stream(ch);
        let collected: Vec<_> = stream.take(2).map(|r| r.unwrap()).collect().await;
        assert_eq!(collected, vec![b"a".to_vec(), b"b".to_vec()]);
    }
}
