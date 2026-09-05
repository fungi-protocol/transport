//! Canonical typed application messages and their grow-only replicated set.
//!
//! The transport frame payload is exactly one [`CanonicalMessage`]. Transport
//! framing is deliberately excluded from both canonical bytes and identity.
//! A message's [`MessageContext`] binds those bytes to one protocol session and
//! exact protocol version without identifying its transport or immediate peer.
//! Unknown odd message and extension types remain byte-identical so an older
//! Fungi relay can forward and commit to newer optional application messages.
//!
//! ```
//! use fungi_wire::{
//!     Body, CanonicalMessage, Message, MessageContext, MessageSet, ProtocolSessionId,
//!     ProtocolVersion,
//! };
//!
//! let context = MessageContext::new(ProtocolSessionId::new([7; 32]), ProtocolVersion::new(1));
//! let message =
//!     CanonicalMessage::encode(context, &Message::new(Body::Psbt(b"fragment".to_vec()))).unwrap();
//!
//! // Received bytes are validated, never normalised: bytes that re-encode to
//! // anything else are rejected rather than silently repaired.
//! assert_eq!(
//!     CanonicalMessage::parse(message.as_bytes().to_vec()).unwrap(),
//!     message
//! );
//!
//! // The set is grow-only and keyed by full identity, so re-inserting the same
//! // message leaves the commitment where it was.
//! let mut set = MessageSet::new(context);
//! set.insert(message.clone()).unwrap();
//! let commitment = set.commitment();
//! set.insert(message).unwrap();
//! assert_eq!(set.commitment(), commitment);
//! ```

#![forbid(unsafe_code)]

mod bigsize;
mod context;
mod encoding;
mod error;
mod id;
mod message;
mod set;
#[cfg(test)]
mod tests;
mod tlv;

pub use context::{MessageContext, ProtocolSessionId, ProtocolVersion};
pub use encoding::{CanonicalMessage, MAX_MESSAGE_SIZE};
pub use error::{
    DecodeError, EncodeError, IdentityCollision, InvalidUnknownMessageType, MessageSetError,
};
pub use id::{MESSAGE_ID_TAG, MessageId, MessageSetCommitment, SET_COMMITMENT_TAG};
pub use message::{Body, Message, TYPE_CONFIRMATION, TYPE_PAYMENT, TYPE_PSBT, UnknownBody};
pub use set::MessageSet;
pub use tlv::{Extension, Extensions};
