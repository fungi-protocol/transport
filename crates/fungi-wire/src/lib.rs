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

pub use encoding::{EXT_VALIDITY, Encoding, HeaderTlv};
pub use error::{DecodeError, EncodeError};
pub use fold::{AppState, Validity, fold_at};
pub use id::{MESSAGE_ID_TAG, MessageId, SET_COMMITMENT_TAG, message_id};
pub use message::{Body, Message};
pub use set::MessageSet;
pub use tlv::{TlvRecord, TlvStream};

#[cfg(test)]
mod smoke {
    use concurrent_psbt::Join;
    use proptest::prelude::*;

    /// A set under union: the shape every message set here has.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct U8Set(std::collections::BTreeSet<u8>);

    impl Join for U8Set {
        fn join(mut self, other: Self) -> Self {
            self.0.extend(other.0);
            self
        }
    }

    fn any_set() -> impl Strategy<Value = U8Set> {
        proptest::collection::btree_set(any::<u8>(), 0..8).prop_map(U8Set)
    }

    concurrent_psbt::assert_join_laws!(any_set());
}
