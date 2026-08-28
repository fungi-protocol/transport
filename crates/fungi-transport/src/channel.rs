//! The channel abstraction for exchanging opaque messages with a peer.
//! `Stream` does not appear in the trait interface; [`into_stream`] adapts a
//! [`Channel`] into one for consumers who prefer it.
//!
//! `&mut self` on both methods means one channel object cannot send and
//! receive concurrently — full-duplex consumers must wrap the channel in a
//! task (see `examples/echo.rs`, scenario 2).

use std::future::Future;

use futures_core::Stream;

use crate::error::{ConnectError, RecvError, SendError};
use crate::sender::SenderId;
use crate::session::SessionId;

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
/// - `send` is NOT required to be cancel-safe: a `send` future dropped
///   before resolving may or may not have transmitted the message — treat
///   the whole channel as dead after cancelling a send.
/// - Messages have arbitrary size; a transport rejects oversized ones with
///   [`SendError::TooLarge`] — the one RECOVERABLE send error. Any `recv`
///   error, and any other `send` error, means the channel is DEAD (see
///   [`RecvError`]/[`SendError`]); recovery is a NEW channel via the
///   [`Connector`], never this one.
/// - No liveness detection: a silently dead path parks `recv` forever.
///   Callers own timeouts, and any keepalive belongs to a higher layer.
/// - No ordering guarantees — within or across channels, no deduplication.
///
/// # Examples
///
/// A connected pair exchanging messages in both directions, using the
/// in-memory implementation ([`crate::mem`]) that any real transport
/// (SOCKS5h, arti, an OHTTP mailbox) must behave like:
///
/// ```
/// use fungi_transport::Channel;
/// use fungi_transport::mem::{MemConfig, duplex};
///
/// # #[tokio::main]
/// # async fn main() {
/// let (mut a, mut b) = duplex(MemConfig::default());
///
/// a.send(b"hello").await.unwrap();
/// assert_eq!(b.recv().await.unwrap(), b"hello");
///
/// b.send(b"world").await.unwrap();
/// assert_eq!(a.recv().await.unwrap(), b"world");
/// # }
/// ```
pub trait Channel: Send {
    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
    /// Wait for and return the next message from the peer.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send;
}

/// A P2P channel whose peer is AUTHENTICATED: every message on it is from the
/// one known sender, named by [`sender`](AttributableChannel::sender).
///
/// This is the *attributable* half of the anonymous/attributable split. It
/// carries the same opaque-bytes, one-message-per-call contract as [`Channel`]
/// (delivery semantics, cancel-safety, the error taxonomy — all identical);
/// the only addition is the known sender. Because a P2P channel has ONE peer,
/// the sender is exposed ONCE, not per message — per-message attribution is
/// broadcast's shape, and a broadcast channel is a distinct type built later.
///
/// It is deliberately NOT a supertrait of, nor interchangeable with,
/// [`Channel`]: an anonymous channel and an attributable one are different
/// types so the compiler keeps them apart (you cannot pass one where the other
/// is expected). Both are P2P; the broadcast counterparts arrive with the
/// broadcast/gossip layer.
pub trait AttributableChannel: Send {
    /// The sender identity type this channel attributes messages to.
    type Sender: SenderId;

    /// The peer every message on this channel is from.
    fn sender(&self) -> &Self::Sender;

    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
    /// Wait for and return the next message from the peer (from
    /// [`sender`](AttributableChannel::sender)).
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send;
}

/// Establishes channels to peers, for connection-oriented transports.
///
/// Message-based transports (e.g. an OHTTP mailbox) implement only
/// [`Channel`]; connectors are how consumers RE-establish a channel after
/// an error: `connect` again, on the SAME connector, and a fresh channel
/// (a new circuit/stream) to the same address comes back — nothing
/// carries over from the dead one, and the responder's identity is
/// unchanged. Retry cadence is the caller's business, never the
/// connector's.
///
/// Opening contract: dialing is INITIATOR-anonymous — the transport
/// presents no identity of this peer to the responder. The address is what
/// authenticates the RESPONDER: an `Ok` channel talks to the holder of the
/// identity the `Addr` names (for the Tor backends, the onion key), or to
/// no one. How far each guarantee reaches is backend-specific; every
/// backend crate documents its trust base.
pub trait Connector: Send {
    /// Transport-native name of the responder's identity (e.g. an onion
    /// address), opaque to consumers; obtained out of band.
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
///
/// Opening contract: inbound channels are anonymous. `accept` yields only
/// the channel — deliberately: the listener learns nothing about who
/// dialed, and implementations must not expose an initiator identity
/// through any side channel. Attributing senders is a higher layer's
/// business, built on top of these channels.
pub trait Listener: Send {
    /// The channel type this listener produces.
    type Channel: Channel;
    /// Wait for the next inbound channel.
    fn accept(&mut self) -> impl Future<Output = Result<Self::Channel, ConnectError>> + Send;
}

/// Backend-agnostic parameters for creating a listener.
#[derive(Debug, Clone, Default)]
pub struct ListenParams {
    /// The virtual port the onion service listens on.
    pub virt_port: u16,
    /// Identity hint, interpreted per backend. A backend with persistent
    /// identities (arti) loads or creates the identity stored under this
    /// nickname, falling back to a fixed default nickname when `None`. A
    /// backend with only ephemeral identities (the SOCKS5h DiscardPK onion)
    /// ignores the hint and publishes a fresh identity per listener. `None`
    /// therefore does NOT guarantee an ephemeral identity.
    pub nickname: Option<String>,
}

impl ListenParams {
    /// Parameters with no nickname hint on `virt_port` — the backend's
    /// default identity (see [`ListenParams::nickname`]).
    pub fn new(virt_port: u16) -> Self {
        Self {
            virt_port,
            nickname: None,
        }
    }

    /// Attach a nickname for backends with persistent identities; backends
    /// without them ignore it (see [`ListenParams::nickname`]).
    pub fn with_nickname(mut self, nickname: impl Into<String>) -> Self {
        self.nickname = Some(nickname.into());
        self
    }
}

/// A transport factory: opens connectors and creates listeners (publishing an
/// onion identity). Connection initiation and identity creation live here —
/// the surface beyond the per-message [`Channel`].
///
/// The `Addr` returned by [`listen`](Transport::listen) is this peer's
/// authenticatable identity: hand it to peers out of band, and whoever
/// dials it reaches the holder of that identity (see [`Connector`]).
///
/// # Examples
///
/// The factory flow, using the in-memory transport: publish a listener,
/// hand its address out, dial it. The dialer knows who it reached — the
/// address authenticates the responder — while the accepted channel carries
/// no identity of the dialer.
///
/// ```
/// use fungi_transport::mem::{MemConfig, MemTransport};
/// use fungi_transport::{Channel, Connector, ListenParams, Listener, Transport};
///
/// # #[tokio::main]
/// # async fn main() {
/// let transport = MemTransport::new(MemConfig::default());
/// let (mut listener, addr) = transport.listen(ListenParams::new(9735)).await.unwrap();
///
/// let connector = transport.connector();
/// let (dialed, accepted) = tokio::join!(connector.connect(&addr), listener.accept());
/// let (mut dialed, mut accepted) = (dialed.unwrap(), accepted.unwrap());
///
/// dialed.send(b"hello").await.unwrap();
/// assert_eq!(accepted.recv().await.unwrap(), b"hello");
/// # }
/// ```
pub trait Transport: Send {
    /// Transport-native peer address, shared with the connector.
    type Addr: Send + Sync;
    /// The connector this transport produces.
    type Connector: Connector<Addr = Self::Addr>;
    /// The listener this transport produces.
    type Listener: Listener;

    /// A connector for dialing peers on the transport's shared default
    /// session. Use [`connector_for`](Transport::connector_for) to isolate a
    /// logical session onto its own circuits.
    fn connector(&self) -> Self::Connector;

    /// A connector bound to `session`. Channels opened through connectors of
    /// DIFFERENT sessions must not share a transport circuit — so their
    /// streams cannot be correlated by network metadata — while connectors of
    /// the SAME session may share one. Isolation is per transport: the same
    /// [`SessionId`] on another transport (or process) shares nothing. See
    /// [`session`](crate::session).
    fn connector_for(&self, session: &SessionId) -> Self::Connector;

    /// Create and publish a listener, returning it together with the onion
    /// address it was published under (the generated/loaded identity).
    fn listen(
        &self,
        params: ListenParams,
    ) -> impl Future<Output = Result<(Self::Listener, Self::Addr), ConnectError>> + Send;
}

/// Adapt any [`Channel`] into a [`Stream`] of received messages. An adapter
/// for consumers who prefer a `Stream`; `Stream` is deliberately not part of
/// the trait contract. The stream ends after the first error.
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

    /// A minimal `SenderId` for exercising the attributable trait.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestSender(Vec<u8>);
    impl SenderId for TestSender {
        fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// Loopback with a known sender: proves `AttributableChannel` is
    /// implementable with Send futures, and that `sender` names the one peer.
    struct AttributedLoopback {
        sender: TestSender,
        queue: std::collections::VecDeque<Vec<u8>>,
    }

    impl AttributableChannel for AttributedLoopback {
        type Sender = TestSender;
        fn sender(&self) -> &TestSender {
            &self.sender
        }
        fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
            self.queue.push_back(msg.to_vec());
            async { Ok(()) }
        }
        fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
            let next = self.queue.pop_front();
            async move { next.ok_or(RecvError::Closed) }
        }
    }

    #[tokio::test]
    async fn attributable_channel_is_implementable_and_names_its_sender() {
        let mut ch = AttributedLoopback {
            sender: TestSender(b"alice".to_vec()),
            queue: Default::default(),
        };
        // The sender is known once, for the whole channel — not per message.
        assert_eq!(ch.sender().as_bytes(), b"alice");
        assert_send(ch.send(b"hi"));
        ch.send(b"hi").await.unwrap();
        assert_send(ch.recv());
        assert_eq!(ch.recv().await.unwrap(), b"hi");
        assert_eq!(ch.sender().as_bytes(), b"alice");
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

    #[tokio::test]
    async fn into_stream_ends_after_first_error() {
        use futures_util::StreamExt;
        // Loopback yields `Closed` once its queue drains, so the stream sees
        // Ok, Ok, then an error. It must surface that error and then END —
        // if termination were broken, `collect` would loop forever on the
        // repeating error instead of finishing at three items.
        let mut ch = Loopback(Default::default());
        ch.send(b"a").await.unwrap();
        ch.send(b"b").await.unwrap();
        let collected: Vec<_> = into_stream(ch).collect().await;
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].as_ref().unwrap(), b"a");
        assert_eq!(collected[1].as_ref().unwrap(), b"b");
        assert!(matches!(collected[2], Err(RecvError::Closed)));
    }
}
