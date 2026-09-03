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

/// A per-session abbreviation of a [`MessageId`].
pub type ShortId = [u8; 8];

/// Domain separation for [`short_id`].
pub const SHORT_ID_TAG: &str = "fungi/short-id";

/// Abbreviate an identity for bulk exchange.
///
/// Salted per session so a collision cannot be produced in advance for
/// every session at once, and tolerant of collisions when they happen: a
/// short id decides only whether to ask for a message, so a collision
/// costs one redundant fetch, never a wrong delivery. The full identity
/// stays the only thing a set is keyed by.
pub fn short_id(salt: &[u8; 32], id: &MessageId) -> ShortId {
    let full = tagged_hash(SHORT_ID_TAG, &[salt, id]);
    full[..8]
        .try_into()
        .expect("a 32-byte digest has eight leading bytes")
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

    #[test]
    fn short_ids_are_salt_dependent() {
        let id = message_id(b"m");
        assert_ne!(short_id(&[0u8; 32], &id), short_id(&[1u8; 32], &id));
    }

    #[test]
    fn short_ids_are_stable_and_separate_distinct_messages() {
        let salt = [7u8; 32];
        assert_eq!(
            short_id(&salt, &message_id(b"a")),
            short_id(&salt, &message_id(b"a"))
        );
        assert_ne!(
            short_id(&salt, &message_id(b"a")),
            short_id(&salt, &message_id(b"b"))
        );
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
