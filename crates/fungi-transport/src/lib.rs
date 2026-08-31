//! The P2P datagram channel abstraction for the Fungi protocol.
//!
//! A channel is a connection to ONE peer moving opaque byte messages, one
//! message per call. No delivery ordering across channels, no deduplication,
//! no framing, no per-message anonymity semantics — those belong to other
//! layers. The one identity contract this crate does own is at
//! connection-opening: dialing is initiator-anonymous, and the address
//! authenticates the responder (see [`Connector`] and [`Listener`]).
//!
//! The API is [`Channel`] (send/recv one connected peer), [`Connector`]
//! (open new channels) and [`Listener`] (accept inbound ones), plus
//! [`into_stream`] to adapt a `Channel` into a `Stream` where that's more
//! convenient. [`mem`] is an in-memory implementation for tests and for
//! exercising the contract; [`framed`] adapts any byte stream into a
//! `Channel` with length-prefix framing; [`OnionAddr`] is the transport-native
//! address the Tor backends use; [`testkit`] holds the transport-agnostic
//! conformance suite every `Channel` implementation is expected to pass.
//!
//! # Channel kinds
//!
//! Channels are split along two axes so the compiler keeps distinct kinds
//! apart — you can never pass one where another is meant:
//!
//! - **anonymous vs attributable** — whether a received message names its
//!   sender. [`Channel`] is anonymous (the peer is unidentified);
//!   [`AttributableChannel`] names the sender via [`SenderId`]. A P2P
//!   attributable channel has one peer, so the sender is known once, not per
//!   message.
//! - **P2P vs broadcast** — one peer, or a pub-sub group. [`Channel`] and
//!   [`AttributableChannel`] are P2P; [`BroadcastChannel`] and
//!   [`AttributableBroadcastChannel`] are their broadcast counterparts,
//!   where attribution is per message (a group has many senders). A
//!   broadcast implementation reaches the group however it likes — gossip
//!   over P2P channels, a server-side broadcast API — and consumers cannot
//!   tell the difference; [`mem::group`] is the in-memory one.
//!
//! Real transports live in their own crates: `fungi-transport-socks5h`
//! (external tor daemon) and `fungi-transport-arti` (in-process arti).

pub mod addr;
pub mod channel;
pub mod error;
pub mod framed;
pub mod gossip_spike_a;
pub mod gossip_spike_c;
pub mod harness;
pub mod mem;
pub mod sender;
pub mod session;
pub mod testkit;

pub use addr::{OnionAddr, ParseOnionAddrError};
pub use channel::{
    AttributableBroadcastChannel, AttributableChannel, BroadcastChannel, Channel, Connector,
    ListenParams, Listener, Transport, into_stream,
};
pub use error::{BoxError, ConnectError, RecvError, SendError};
pub use harness::{dial_sequence, echo_one_peer};
pub use sender::SenderId;
pub use session::{ParseSessionIdError, SessionId};
