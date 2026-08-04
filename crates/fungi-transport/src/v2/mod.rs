//! Variant 2 — the read side IS the public interface: `Channel` is a
//! [`Stream`] of received messages with a `send` method on top.
//!
//! Experiment notes recorded against this variant: implementors write
//! `poll_next` by hand (or embed a buffer + task); `futures-core` becomes a
//! mandatory dependency of every transport; consumers need `Unpin` (bound
//! here) or pinning; channel death is `None` (stream end), not an error —
//! the `Closed` variant of `RecvError` is unused on the happy read path.

use std::future::Future;

use futures_core::Stream;

use crate::error::{ConnectError, RecvError, SendError};

/// A datagram channel to ONE peer; receiving is the [`Stream`] itself.
///
/// Same contract as v1 for `send` (best-effort acceptance, no exposed
/// timeouts, [`SendError::TooLarge`] for oversized messages) and the same
/// cancel-safety requirement for the stream: an abandoned `poll_next` must
/// not lose a message. Channel death surfaces as stream end (`None`).
pub trait Channel: Stream<Item = Result<Vec<u8>, RecvError>> + Send + Unpin {
    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
}

/// Establishes channels to peers, for connection-oriented transports.
/// See v1's `Connector` docs; identical contract, bound to [`Channel`] (v2).
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct Loopback(VecDeque<Vec<u8>>);

    impl Stream for Loopback {
        type Item = Result<Vec<u8>, RecvError>;
        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
    }

    impl Channel for Loopback {
        fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
            self.0.push_back(msg.to_vec());
            async { Ok(()) }
        }
    }

    #[tokio::test]
    async fn stream_interface_works() {
        let mut ch = Loopback(VecDeque::new());
        ch.send(b"a").await.unwrap();
        ch.send(b"b").await.unwrap();
        assert_eq!(ch.next().await.unwrap().unwrap(), b"a");
        assert_eq!(ch.next().await.unwrap().unwrap(), b"b");
        assert!(ch.next().await.is_none(), "end of channel is stream end");
    }
}
