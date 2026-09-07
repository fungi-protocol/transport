//! Canonical typed application messages and their grow-only replicated set.
//!
//! The transport frame payload is exactly one [`CanonicalMessage`]. Transport
//! framing is deliberately excluded from both canonical bytes and identity.
//! A message's [`MessageContext`] binds those bytes to one protocol session and
//! exact protocol version without identifying its transport or immediate peer.
//! Unknown odd message and extension types remain byte-identical so an older
//! Fungi relay can forward and commit to newer optional application messages.
//!
//! Because the context travels inside the bytes, admission is a property of
//! the message and not of the connection that carried it: [`MessageSet`]
//! refuses anything committed to another session or version. A transport that
//! has a link of its own can confirm the same context once, at the link, and
//! then trust what crosses it; nothing requires one. A message arriving from a
//! store-and-forward service, where there is no peer to handshake with, is
//! admitted or refused by exactly this check and no other.
//! [`CanonicalMessage::validate`] applies it without copying or deriving an
//! identity, for a relay that forwards what it does not keep.
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
//!
//! // Admission is by the message's own context: one committed to another
//! // session is refused here, with no link and no handshake in sight.
//! let elsewhere = MessageContext::new(ProtocolSessionId::new([9; 32]), ProtocolVersion::new(1));
//! let foreign =
//!     CanonicalMessage::encode(elsewhere, &Message::new(Body::Psbt(b"fragment".to_vec()))).unwrap();
//! assert!(set.insert(foreign).is_err());
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
