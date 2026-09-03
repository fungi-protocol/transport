//! Canonical typed application messages and their grow-only replicated set.
//!
//! The transport frame payload is exactly one [`CanonicalMessage`]. Transport
//! framing is deliberately excluded from both canonical bytes and identity.

#![forbid(unsafe_code)]

mod bigsize;
mod encoding;
mod error;
mod id;
mod message;
mod set;
#[cfg(test)]
mod tests;
mod tlv;

pub use encoding::{CanonicalMessage, MAX_MESSAGE_SIZE};
pub use error::{DecodeError, EncodeError, IdentityCollision};
pub use id::{MESSAGE_ID_TAG, MessageId, SET_COMMITMENT_TAG};
pub use message::{Body, Message, TYPE_CONFIRMATION, TYPE_PAYMENT, TYPE_PSBT, UnknownBody};
pub use set::MessageSet;
pub use tlv::{Extension, Extensions};
