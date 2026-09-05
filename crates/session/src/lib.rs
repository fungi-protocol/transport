//! Connection-local binding of P2P channels to one logical protocol session.
//!
//! Binding confirms that both ends present the same session ID, exact protocol
//! version, and complete canonical-message size limit before the channel is
//! admitted to closed-group gossip. It does not authenticate group membership:
//! [`ProtocolSessionId`] is context, not a secret or credential. Confidentiality
//! and integrity remain requirements of the underlying P2P channel.
//!
//! The identity itself is supplied out of band, with the membership it belongs
//! to — the same channel that names who is in the group names the session they
//! are constructing. Binding only confirms that both ends were told the same
//! thing; it cannot establish it, and a peer presenting a session it was never
//! given is indistinguishable here from one that was.
//!
//! The negotiated limit governs application messages, not frames: a transport
//! still admits whatever its own framing cap allows, so a peer can force an
//! allocation up to that cap before the smaller session limit rejects the
//! message. Pushing the negotiated value down into framing needs it known at
//! dial time, which is one connection earlier than binding can supply it.
//!
//! ```
//! use fungi_session::{
//!     MessageContext, MessageSizeLimit, ProtocolSessionId, ProtocolVersion, SessionContract,
//!     bind,
//! };
//! use fungi_transport::Channel;
//! use fungi_transport::mem::{MemConfig, duplex};
//! use fungi_wire::{Body, CanonicalMessage, Message};
//!
//! # #[tokio::main]
//! # async fn main() {
//! let contract = SessionContract::new(
//!     MessageContext::new(ProtocolSessionId::new([7; 32]), ProtocolVersion::new(1)),
//!     MessageSizeLimit::new(4096).unwrap(),
//! );
//!
//! // Both ends present the same contract, so both sides admit the link.
//! let (left, right) = duplex(MemConfig::default());
//! let (left, right) = tokio::join!(bind(left, contract), bind(right, contract));
//! let (mut left, mut right) = (left.unwrap(), right.unwrap());
//!
//! // Only canonical messages committed to this exact session may cross it.
//! let message = CanonicalMessage::encode(
//!     contract.context(),
//!     &Message::new(Body::Psbt(b"fragment".to_vec())),
//! )
//! .unwrap();
//! left.send(message.as_bytes()).await.unwrap();
//! assert_eq!(right.recv().await.unwrap(), message.as_bytes());
//! # }
//! ```
//!
//! Transport circuit isolation and protocol-session identity are intentionally
//! different types:
//!
//! ```compile_fail
//! use fungi_session::ProtocolSessionId;
//! use fungi_transport::CircuitIsolationId;
//!
//! fn expects_protocol_session(_: ProtocolSessionId) {}
//!
//! let transport_isolation = CircuitIsolationId::generate();
//! expects_protocol_session(transport_isolation);
//! ```

#![forbid(unsafe_code)]

mod channel;
mod contract;
mod error;
mod hello;

pub use channel::{
    SessionBoundChannel, SessionRecvHalf, SessionSendHalf, bind, bind_all, bind_group,
};
pub use contract::{MessageSizeLimit, SessionContract};
pub use error::{InvalidMessageSizeLimit, SessionBindingError};
pub use fungi_wire::{MessageContext, ProtocolSessionId, ProtocolVersion};

#[cfg(test)]
mod tests;
