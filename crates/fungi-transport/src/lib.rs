//! The P2P datagram channel abstraction for the Fungi protocol.
//!
//! A channel is a connection to ONE peer moving opaque byte messages, one
//! message per call. No delivery ordering across channels, no deduplication,
//! no framing, no anonymity semantics — those belong to other layers.

pub mod error;
pub mod v1;
pub mod v2;

pub use error::{BoxError, ConnectError, RecvError, SendError};
