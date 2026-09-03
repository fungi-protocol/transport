//! The logical identity of a message.
//!
//! A tagged hash over the message's canonical encoding and nothing else:
//! no author, no counter, no clock. Two nodes holding the same message
//! agree on its identity without having agreed on anything else, and a
//! peer cannot mint two distinct messages sharing one identity — which is
//! precisely what a per-author counter would allow, invisibly.
//!
//! Computed from bytes, never from a parsed message: relaying must be
//! able to recognise a message it cannot understand.

use sha2::{Digest, Sha256};

/// A message's logical identity.
pub type MessageId = [u8; 32];

/// Domain separation for [`message_id`].
pub const MESSAGE_ID_TAG: &str = "fungi/message-id";

/// Domain separation for the delivered-set commitment.
pub const SET_COMMITMENT_TAG: &str = "fungi/message-set";

/// The identity of the message encoded as `bytes`.
pub fn message_id(bytes: &[u8]) -> MessageId {
    tagged_hash(MESSAGE_ID_TAG, &[bytes])
}

/// Tagged hash: the tag's digest twice, then the parts in order.
/// Prefixing with a fixed-width digest of the tag keeps one domain's
/// hashes from ever being reused as another's, and costs nothing at
/// runtime because the prefix is a cacheable midstate.
///
/// Parts are hashed in sequence with no separator, so a caller
/// passing variable-width parts must frame them itself. Both callers
/// here do: the identity takes a single part, and the set commitment
/// commits a count before fixed-width ids.
pub(crate) fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_digest = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_digest);
    hasher.update(tag_digest);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_domain_separated() {
        assert_ne!(message_id(b"x"), tagged_hash(SET_COMMITMENT_TAG, &[b"x"]));
        assert_ne!(message_id(b"x").as_slice(), Sha256::digest(b"x").as_slice());
    }

    #[test]
    fn identity_is_stable_and_distinguishing() {
        assert_eq!(message_id(b"same"), message_id(b"same"));
        assert_ne!(message_id(b"a"), message_id(b"b"));
        assert_ne!(message_id(b""), message_id(b"\x00"));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Identity needs no parsing and no validation: arbitrary
            /// bytes, including bytes that decode to nothing, have one,
            /// and it never panics.
            #[test]
            fn arbitrary_bytes_have_a_stable_identity(
                bytes in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                prop_assert_eq!(message_id(&bytes), message_id(&bytes));
            }
        }
    }
}
