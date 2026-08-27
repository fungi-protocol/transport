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
//! Real transports live in their own crates: `fungi-transport-socks5h`
//! (external tor daemon) and `fungi-transport-arti` (in-process arti).

pub mod addr;
pub mod channel;
pub mod error;
pub mod framed;
pub mod harness;
pub mod mem;
pub mod testkit;

pub use addr::{OnionAddr, ParseOnionAddrError};
pub use channel::{Channel, Connector, ListenParams, Listener, Transport, into_stream};
pub use error::{BoxError, ConnectError, RecvError, SendError};
pub use harness::{dial_sequence, echo_one_peer};
