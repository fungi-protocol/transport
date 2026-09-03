//! The delivered message set.
//!
//! Keyed by identity, so inserting a message twice is inserting it once,
//! and ordered, so every node traverses it the same way. The commitment
//! is what lets two nodes confirm they saw exactly the same messages: it
//! depends on the set and not on the order the messages arrived in.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::id::{SET_COMMITMENT_TAG, tagged_hash_iter};
use crate::{MessageId, message_id};

/// The set of messages a node has delivered, keyed by identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageSet(BTreeMap<MessageId, Vec<u8>>);

/// A full message ID was observed with two different byte strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCollision {
    /// Conflicting full identity.
    pub id: MessageId,
}

impl fmt::Display for IdentityCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "different messages share full identity {:02x?}", self.id)
    }
}

impl Error for IdentityCollision {}

impl MessageSet {
    /// Record a message, returning its identity. Inserting the same bytes
    /// again is a no-op; different bytes under the same full ID are an
    /// explicit collision instead of an order-dependent overwrite.
    pub fn insert(&mut self, bytes: Vec<u8>) -> Result<MessageId, IdentityCollision> {
        let id = message_id(&bytes);
        self.insert_at(id, bytes)?;
        Ok(id)
    }

    /// How many distinct messages the set holds.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The messages, in identity order.
    pub fn iter(&self) -> impl Iterator<Item = (&MessageId, &[u8])> {
        self.0.iter().map(|(id, bytes)| (id, bytes.as_slice()))
    }

    /// Join `other` into this grow-only set, detecting full-ID collisions.
    pub fn merge(&mut self, other: Self) -> Result<(), IdentityCollision> {
        for (id, bytes) in &other.0 {
            if self.0.get(id).is_some_and(|existing| existing != bytes) {
                return Err(IdentityCollision { id: *id });
            }
        }
        self.0.extend(other.0);
        Ok(())
    }

    /// Return the union of two grow-only message sets.
    ///
    /// Union is associative, commutative and idempotent, so peers may merge
    /// snapshots in any order and repeat merges without changing the result.
    pub fn union(mut self, other: Self) -> Result<Self, IdentityCollision> {
        self.merge(other)?;
        Ok(self)
    }

    /// A commitment to exactly this set.
    ///
    /// Identities are fixed width and traversed in order, so the digest
    /// is a function of which messages are present and of nothing else —
    /// not of when they arrived, nor of how the set was merged. The fixed
    /// width is also what makes the concatenation injective on its own:
    /// no two different sets share a byte string. The count carries no
    /// share of that and is committed only to keep the property from
    /// resting on the ids' width alone, which a later variable-width
    /// component would silently take away.
    pub fn commitment(&self) -> [u8; 32] {
        let count = u64::try_from(self.0.len())
            .expect("a materialized MessageSet cannot exceed u64::MAX entries")
            .to_be_bytes();
        let parts =
            std::iter::once(count.as_slice()).chain(self.0.keys().map(<[u8; 32]>::as_slice));
        tagged_hash_iter(SET_COMMITMENT_TAG, parts)
    }

    fn insert_at(&mut self, id: MessageId, bytes: Vec<u8>) -> Result<(), IdentityCollision> {
        match self.0.get(&id) {
            Some(existing) if existing != &bytes => Err(IdentityCollision { id }),
            Some(_) => Ok(()),
            None => {
                self.0.insert(id, bytes);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
impl crate::testing::Join for MessageSet {
    fn join(mut self, other: Self) -> Self {
        self.merge(other)
            .expect("SHA-256 collision resistance is a test assumption");
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::encoding::{Encoding, HeaderTlv};
    use crate::message::{Body, Message};
    use crate::testing::Join;
    use proptest::prelude::*;

    pub(crate) fn set_of(payloads: &[&[u8]]) -> MessageSet {
        let mut set = MessageSet::default();
        for p in payloads {
            let msg = Message::new(Body::Psbt(p.to_vec()));
            set.insert(HeaderTlv::encode(&msg).expect("encodable"))
                .unwrap();
        }
        set
    }

    #[test]
    fn inserting_the_same_message_twice_changes_nothing() {
        let mut set = MessageSet::default();
        let msg = Message::new(Body::Psbt(b"x".to_vec()));
        let a = set
            .insert(HeaderTlv::encode(&msg).expect("encodable"))
            .unwrap();
        let b = set
            .insert(HeaderTlv::encode(&msg).expect("encodable"))
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn public_union_merges_without_consuming_the_left_hand_api() {
        let a = set_of(&[b"a", b"b"]);
        let b = set_of(&[b"b", b"c"]);
        let expected = set_of(&[b"a", b"b", b"c"]);

        assert_eq!(a.clone().union(b.clone()), Ok(expected.clone()));
        let mut merged = a;
        merged.merge(b).unwrap();
        assert_eq!(merged, expected);
    }

    #[test]
    fn a_full_id_collision_is_never_resolved_by_arrival_order() {
        let id = [7; 32];
        let mut set = MessageSet::default();
        set.insert_at(id, b"first".to_vec()).unwrap();
        assert_eq!(
            set.insert_at(id, b"second".to_vec()),
            Err(IdentityCollision { id })
        );
        assert_eq!(set.iter().next(), Some((&id, b"first".as_slice())));
    }

    #[test]
    fn merge_is_atomic_when_an_identity_collision_is_detected() {
        let collision_id = [7; 32];
        let mut left = MessageSet::default();
        left.insert_at(collision_id, b"incumbent".to_vec()).unwrap();
        let before = left.clone();

        let mut right = MessageSet::default();
        right.insert(b"accepted".to_vec()).unwrap();
        right
            .insert_at(collision_id, b"conflicting".to_vec())
            .unwrap();

        assert_eq!(
            left.merge(right),
            Err(IdentityCollision { id: collision_id })
        );
        assert_eq!(left, before);
    }

    #[test]
    fn the_commitment_ignores_arrival_order_and_duplication() {
        let forward = set_of(&[b"a", b"b", b"c"]).commitment();
        assert_eq!(forward, set_of(&[b"c", b"b", b"a"]).commitment());
        assert_eq!(
            forward,
            set_of(&[b"b", b"a", b"b", b"c", b"a"]).commitment()
        );
    }

    #[test]
    fn the_commitment_separates_distinct_sets() {
        assert_ne!(set_of(&[b"a"]).commitment(), set_of(&[b"b"]).commitment());
        assert_ne!(
            set_of(&[b"a"]).commitment(),
            set_of(&[b"a", b"b"]).commitment()
        );
        assert_ne!(
            MessageSet::default().commitment(),
            set_of(&[b"a"]).commitment()
        );
    }

    pub(crate) mod properties {
        use super::*;

        pub(crate) fn any_message_set() -> impl Strategy<Value = MessageSet> {
            proptest::collection::vec(crate::testing::any_encodable_message(), 0..6).prop_map(
                |msgs| {
                    let mut set = MessageSet::default();
                    for msg in msgs {
                        set.insert(HeaderTlv::encode(&msg).expect("encodable"))
                            .unwrap();
                    }
                    set
                },
            )
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            #[test]
            fn idempotent(a in any_message_set()) {
                prop_assert_eq!(a.clone().join(a.clone()), a);
            }

            #[test]
            fn commutative(a in any_message_set(), b in any_message_set()) {
                prop_assert_eq!(a.clone().join(b.clone()), b.join(a));
            }

            #[test]
            fn associative(
                a in any_message_set(),
                b in any_message_set(),
                c in any_message_set(),
            ) {
                prop_assert_eq!(
                    a.clone().join(b.clone()).join(c.clone()),
                    a.join(b.join(c)),
                );
            }

            /// Equal sets commit equally, however they were built.
            #[test]
            fn the_commitment_is_a_function_of_the_set(
                a in any_message_set(),
                b in any_message_set(),
            ) {
                let ab = a.clone().join(b.clone());
                let ba = b.join(a);
                prop_assert_eq!(ab.commitment(), ba.commitment());
            }
        }
    }
}
