//! Transport-independent encoding and logical identity for protocol
//! messages.
//!
//! A message is a typed body plus an extension stream. Its logical
//! identity is a tagged hash of its canonical encoding — a pure function
//! of the bytes, with no author, counter or clock, so two nodes that
//! received the same message agree on its identity without having agreed
//! on anything else.
//!
//! Encoding is canonical: one byte string per logical message, and
//! decoding rejects any other spelling rather than normalizing it. A
//! serializer whose output varies between implementations is a client
//! fingerprint, and identity by hash means a second spelling is a second
//! identity. That is also why a node preserves extension records it does
//! not understand instead of dropping them.

#![forbid(unsafe_code)]

pub mod bigsize;
pub mod encoding;
pub mod error;
pub mod fold;
pub mod id;
pub mod message;
pub mod set;
pub mod tlv;

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod transport_convergence;
pub use encoding::{
    AllTlv, DeterministicCbor, EXT_VALIDITY, Encoding, HeaderTlv, KvPairs, unwrap_block, wrap,
};
pub use error::{DecodeError, EncodeError};
pub use fold::{AppState, Validity, fold_at};
pub use id::{
    MESSAGE_ID_TAG, MessageId, SET_COMMITMENT_TAG, SHORT_ID_TAG, ShortId, message_id, short_id,
};
pub use message::{
    Body, Message, TYPE_BLOCK, TYPE_CONFIRMATION, TYPE_LISTEN_ADVERTISEMENT, TYPE_PAYMENT,
    TYPE_PSBT, TYPE_VALIDITY_PROOF,
};
pub use set::MessageSet;
pub use tlv::{TlvRecord, TlvStream};
