//! The channel abstraction for exchanging opaque messages with a peer.
//! `Stream` does not appear in the trait interface; [`into_stream`] adapts a
//! [`Channel`] into one for consumers who prefer it.
//!
//! `&mut self` on both methods means one channel object cannot send and
//! receive concurrently. This is deliberate: one object with one fate keeps
//! channel death unambiguous and the plugin surface a single interface. It is
//! not, however, something a consumer can work around on its own: two tasks
//! cannot share one `&mut self` object, and sharing it through a lock makes a
//! pending send starve the receiving side, so two peers under mutual load
//! deadlock. Concurrent full-duplex is therefore a capability the channel
//! must offer — [`SplitChannel`] — not a pattern the consumer can build (see
//! `examples/echo.rs`, scenario 2).

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

/// The sending direction of a [`SplitChannel`]. Same contract as
/// [`Channel::send`], including that it is NOT cancel-safe.
pub trait SendHalf: Send {
    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
}

/// The receiving direction of a [`SplitChannel`]. Same contract as
/// [`Channel::recv`], cancel safety included.
pub trait RecvHalf: Send {
    /// Wait for and return the next message from the peer.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send;
}

/// A [`Channel`] that hands out its two directions as separate borrows, for
/// the consumer that must send and receive CONCURRENTLY.
///
/// Driving a channel through [`Channel`] alone cannot do that: one task
/// awaiting `send` is not polling `recv`, so two peers that each have a
/// send pending stop draining each other and deadlock. There is no fix
/// outside the trait — two tasks cannot share one `&mut self` object, and a
/// lock only moves the starvation onto the guard — so the channel itself
/// has to offer the split.
///
/// The halves BORROW the channel, which keeps everything `&mut self` gave:
/// only one split exists at a time, neither half outlives the object, and
/// the two still share one fate — a channel that either direction kills is
/// dead for both.
///
/// # Examples
///
/// The pattern a relay wants: two loops joined in one task, so a blocked
/// send never stops the receiving that would release it.
///
/// ```
/// use fungi_transport::{RecvHalf, SendHalf, SplitChannel};
/// use fungi_transport::mem::{MemChannel, MemConfig, duplex};
///
/// async fn drive(ch: &mut MemChannel) {
///     let (mut tx, mut rx) = ch.split();
///     let sending = async move {
///         for i in 0..4u8 { tx.send(&[i]).await.unwrap(); }
///     };
///     let receiving = async move {
///         for _ in 0..4 { rx.recv().await.unwrap(); }
///     };
///     futures_util::future::join(sending, receiving).await;
/// }
///
/// # #[tokio::main]
/// # async fn main() {
/// // One slot per direction: the second send blocks until the peer reads.
/// let cfg = MemConfig { capacity: Some(1), ..MemConfig::default() };
/// let (mut a, mut b) = duplex(cfg);
/// // Both peers push and drain at once; neither wedges the other.
/// futures_util::future::join(drive(&mut a), drive(&mut b)).await;
/// # }
/// ```
pub trait SplitChannel: Channel {
    /// The borrowed sending half.
    type SendHalf<'a>: SendHalf
    where
        Self: 'a;
    /// The borrowed receiving half.
    type RecvHalf<'a>: RecvHalf
    where
        Self: 'a;

    /// Borrow the two directions separately.
    fn split(&mut self) -> (Self::SendHalf<'_>, Self::RecvHalf<'_>);
}

/// A P2P channel whose peer is AUTHENTICATED: every message on it is from the
/// one known sender, named by [`sender`](AttributableChannel::sender).
///
/// This is the *attributable* half of the anonymous/attributable split. It
/// carries the same opaque-bytes, one-message-per-call contract as [`Channel`]
/// (delivery semantics, cancel-safety, the error taxonomy — all identical);
/// the only addition is the known sender. Because a P2P channel has ONE peer,
/// the sender is exposed ONCE, not per message — per-message attribution is
/// broadcast's shape — see [`AttributableBroadcastChannel`].
///
/// It is deliberately NOT a supertrait of, nor interchangeable with,
/// [`Channel`]: an anonymous channel and an attributable one are different
/// types so the compiler keeps them apart (you cannot pass one where the other
/// is expected). Both are P2P; [`BroadcastChannel`] and
/// [`AttributableBroadcastChannel`] are the broadcast counterparts.
///
/// The separation is enforced by the type system, not convention. An
/// attributable channel is not accepted where an anonymous [`Channel`] is
/// required:
///
/// ```compile_fail
/// use fungi_transport::{AttributableChannel, Channel};
///
/// fn wants_anonymous(_: impl Channel) {}
///
/// fn misuse(attributable: impl AttributableChannel) {
///     // error[E0277]: the trait bound `impl AttributableChannel: Channel`
///     // is not satisfied — the two channel kinds are distinct types.
///     wants_anonymous(attributable);
/// }
/// ```
///
/// Nor is an anonymous channel accepted where an attributable one is required
/// (it names no sender):
///
/// ```compile_fail
/// use fungi_transport::{AttributableChannel, Channel};
///
/// fn wants_attributable(_: impl AttributableChannel) {}
///
/// fn misuse(anonymous: impl Channel) {
///     // error[E0277]: the trait bound `impl Channel: AttributableChannel`
///     // is not satisfied.
///     wants_attributable(anonymous);
/// }
/// ```
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

/// A datagram channel to a GROUP of peers: opaque bytes, one message per
/// call, and no sender identity on receive — the anonymous broadcast kind.
///
/// # Examples
///
/// A three-member in-memory group ([`crate::mem::group`]): one send reaches
/// both other members, and never echoes back to the sender:
///
/// ```
/// use fungi_transport::BroadcastChannel;
/// use fungi_transport::mem::{MemConfig, group};
///
/// # #[tokio::main]
/// # async fn main() {
/// let mut g = group(3, MemConfig { capacity: Some(4), ..MemConfig::default() });
///
/// g[0].send(b"hello group").await.unwrap();
/// assert_eq!(g[1].recv().await.unwrap(), b"hello group");
/// assert_eq!(g[2].recv().await.unwrap(), b"hello group");
/// # }
/// ```
///
/// The P2P/broadcast axis is enforced by the type system: a broadcast
/// channel is not accepted where a P2P [`Channel`] is required, nor the
/// reverse:
///
/// ```compile_fail
/// use fungi_transport::{BroadcastChannel, Channel};
///
/// fn wants_p2p(_: impl Channel) {}
///
/// fn misuse(broadcast: impl BroadcastChannel) {
///     // error[E0277]: the trait bound `impl BroadcastChannel: Channel`
///     // is not satisfied — the two channel kinds are distinct types.
///     wants_p2p(broadcast);
/// }
/// ```
///
/// ```compile_fail
/// use fungi_transport::{BroadcastChannel, Channel};
///
/// fn wants_broadcast(_: impl BroadcastChannel) {}
///
/// fn misuse(p2p: impl Channel) {
///     // error[E0277]: the trait bound `impl Channel: BroadcastChannel`
///     // is not satisfied.
///     wants_broadcast(p2p);
/// }
/// ```
///
/// Same base contract as [`Channel`], group-wide:
/// - `Ok(())` from `send` means the transport accepted the message for
///   best-effort delivery to every OTHER participant. It is NOT end-to-end
///   confirmation, and the sender does not receive its own message back.
/// - `recv` resolves with the next message from any participant; the
///   transport buffers internally. Dropping the `recv` future before it
///   resolves must not lose any message (cancel safety).
/// - `send` is NOT required to be cancel-safe: treat the whole channel as
///   dead after cancelling a send.
/// - [`SendError::TooLarge`] is the one RECOVERABLE send error. Any `recv`
///   error, and any other `send` error, means the channel is DEAD; recovery
///   is a new channel from the construction layer, never this one.
/// - Buffering is internal and the overflow policy is implementation-
///   defined; a receiver that falls too far behind may find messages
///   dropped, or the channel dead.
/// - No ordering guarantees, no deduplication.
///
/// Propagation is the implementation's job, below this trait: however the
/// implementation reaches the group (gossip over P2P channels, a
/// server-side broadcast API), a consumer only calls `send` and `recv` and
/// cannot tell the difference. Group membership does not appear here —
/// who "every participant" is belongs to the construction layer.
pub trait BroadcastChannel: Send {
    /// Send one opaque message toward every other participant.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
    /// Wait for and return the next message from any participant.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send;
}

/// A broadcast channel whose messages are ATTRIBUTED: every received
/// message names its sender — per message, because a group has many
/// senders (a P2P [`AttributableChannel`] has one peer and names it once).
///
/// Same group-wide contract as [`BroadcastChannel`] (best-effort send to
/// every other participant, no echo, cancel-safe `recv`, the error
/// taxonomy, implementation-defined overflow, membership elsewhere); the
/// only addition is the sender on receive.
///
/// What the sender means is the implementation's promise, and every
/// implementation documents its own mechanism and how far it reaches: a
/// transport that relays through peers can only vouch for its immediate
/// neighbor, never the originator, so attributing the originator takes a
/// backend that can see it or a higher layer that authenticates messages
/// themselves. Implementations that cannot attribute honestly implement
/// [`BroadcastChannel`] instead.
///
/// The anonymous/attributable axis holds within broadcast too:
///
/// ```compile_fail
/// use fungi_transport::{AttributableBroadcastChannel, BroadcastChannel};
///
/// fn wants_anonymous(_: impl BroadcastChannel) {}
///
/// fn misuse(attributable: impl AttributableBroadcastChannel) {
///     // error[E0277]: the trait bound
///     // `impl AttributableBroadcastChannel: BroadcastChannel` is not
///     // satisfied — the two broadcast kinds are distinct types.
///     wants_anonymous(attributable);
/// }
/// ```
///
/// ```compile_fail
/// use fungi_transport::{AttributableBroadcastChannel, BroadcastChannel};
///
/// fn wants_attributable(_: impl AttributableBroadcastChannel) {}
///
/// fn misuse(anonymous: impl BroadcastChannel) {
///     // error[E0277]: the trait bound
///     // `impl BroadcastChannel: AttributableBroadcastChannel` is not
///     // satisfied.
///     wants_attributable(anonymous);
/// }
/// ```
///
/// The P2P/broadcast axis holds on the attributable side too:
///
/// ```compile_fail
/// use fungi_transport::{AttributableBroadcastChannel, AttributableChannel};
///
/// fn wants_attributable_p2p(_: impl AttributableChannel) {}
///
/// fn misuse(broadcast: impl AttributableBroadcastChannel) {
///     // error[E0277]: the trait bound
///     // `impl AttributableBroadcastChannel: AttributableChannel` is not
///     // satisfied — per-channel and per-message attribution are distinct types.
///     wants_attributable_p2p(broadcast);
/// }
/// ```
///
/// ```compile_fail
/// use fungi_transport::{AttributableBroadcastChannel, AttributableChannel};
///
/// fn wants_attributable_broadcast(_: impl AttributableBroadcastChannel) {}
///
/// fn misuse(p2p: impl AttributableChannel) {
///     // error[E0277]: the trait bound
///     // `impl AttributableChannel: AttributableBroadcastChannel` is not
///     // satisfied.
///     wants_attributable_broadcast(p2p);
/// }
/// ```
pub trait AttributableBroadcastChannel: Send {
    /// The sender identity type this channel attributes messages to.
    type Sender: SenderId;

    /// Send one opaque message toward every other participant.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
    /// Wait for and return the next message and the sender it is from.
    fn recv(&mut self) -> impl Future<Output = Result<(Self::Sender, Vec<u8>), RecvError>> + Send;
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

    /// Group-loopback double: every sent message lands in one shared queue
    /// that recv drains. Proves `BroadcastChannel` is implementable with
    /// plain async blocks and Send futures.
    struct BroadcastLoopback(std::collections::VecDeque<Vec<u8>>);

    impl BroadcastChannel for BroadcastLoopback {
        fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
            self.0.push_back(msg.to_vec());
            async { Ok(()) }
        }
        fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
            let next = self.0.pop_front();
            async move { next.ok_or(RecvError::Closed) }
        }
    }

    #[tokio::test]
    async fn broadcast_trait_is_implementable_and_futures_are_send() {
        let mut ch = BroadcastLoopback(Default::default());
        assert_send(ch.send(b"to the group"));
        ch.send(b"to the group").await.unwrap();
        assert_send(ch.recv());
        assert_eq!(ch.recv().await.unwrap(), b"to the group");
        assert!(matches!(ch.recv().await, Err(RecvError::Closed)));
    }

    /// Group loopback with per-message senders: proves the attributable
    /// broadcast trait is implementable and that attribution travels with
    /// each message, not once per channel.
    struct AttributedBroadcastLoopback(std::collections::VecDeque<(TestSender, Vec<u8>)>);

    impl AttributableBroadcastChannel for AttributedBroadcastLoopback {
        type Sender = TestSender;
        fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
            self.0.push_back((TestSender(b"me".to_vec()), msg.to_vec()));
            async { Ok(()) }
        }
        fn recv(
            &mut self,
        ) -> impl Future<Output = Result<(TestSender, Vec<u8>), RecvError>> + Send {
            let next = self.0.pop_front();
            async move { next.ok_or(RecvError::Closed) }
        }
    }

    #[tokio::test]
    async fn attributable_broadcast_attributes_per_message() {
        let mut ch = AttributedBroadcastLoopback(Default::default());
        ch.0.push_back((TestSender(b"alice".to_vec()), b"hi".to_vec()));
        ch.0.push_back((TestSender(b"bob".to_vec()), b"yo".to_vec()));
        let (s1, m1) = ch.recv().await.unwrap();
        let (s2, m2) = ch.recv().await.unwrap();
        assert_eq!((s1.as_bytes(), m1.as_slice()), (&b"alice"[..], &b"hi"[..]));
        assert_eq!((s2.as_bytes(), m2.as_slice()), (&b"bob"[..], &b"yo"[..]));
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
