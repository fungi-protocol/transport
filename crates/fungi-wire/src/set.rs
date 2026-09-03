//! The delivered message set.
//!
//! Keyed by identity, so inserting a message twice is inserting it once,
//! and ordered, so every node traverses it the same way. The commitment
//! is what lets two nodes confirm they saw exactly the same messages: it
//! depends on the set and not on the order the messages arrived in.

use std::collections::BTreeMap;

use crate::id::{SET_COMMITMENT_TAG, tagged_hash};
use crate::{MessageId, message_id};

/// The set of messages a node has delivered, keyed by identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageSet(BTreeMap<MessageId, Vec<u8>>);

impl MessageSet {
    /// Record a message, returning its identity. Inserting the same bytes
    /// again is a no-op: this keeps the incumbent while merging keeps the
    /// newcomer, and the two agree anyway because identity is a hash of
    /// the bytes, so the incumbent and the newcomer are the same bytes.
    pub fn insert(&mut self, bytes: Vec<u8>) -> MessageId {
        let id = message_id(&bytes);
        self.0.entry(id).or_insert(bytes);
        id
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
        let count = (self.0.len() as u64).to_be_bytes();
        let ids: Vec<u8> = self.0.keys().flatten().copied().collect();
        tagged_hash(SET_COMMITMENT_TAG, &[&count, &ids])
    }
}

// The lattice crate is a dev-dependency: the laws are worth checking
// where the lattice is consumed, but the experiment must not make the
// application crate a runtime dependency of the wire format.
#[cfg(test)]
impl concurrent_psbt::Join for MessageSet {
    fn join(mut self, other: Self) -> Self {
        self.0.extend(other.0);
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::encoding::{Encoding, HeaderTlv};
    use crate::message::{Body, Message};
    use concurrent_psbt::Join;
    use proptest::prelude::*;

    pub(crate) fn set_of(payloads: &[&[u8]]) -> MessageSet {
        let mut set = MessageSet::default();
        for p in payloads {
            let msg = Message::new(Body::Psbt(p.to_vec()));
            set.insert(HeaderTlv::encode(&msg).expect("encodable"));
        }
        set
    }

    #[test]
    fn inserting_the_same_message_twice_changes_nothing() {
        let mut set = MessageSet::default();
        let msg = Message::new(Body::Psbt(b"x".to_vec()));
        let a = set.insert(HeaderTlv::encode(&msg).expect("encodable"));
        let b = set.insert(HeaderTlv::encode(&msg).expect("encodable"));
        assert_eq!(a, b);
        assert_eq!(set.len(), 1);
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
                        set.insert(HeaderTlv::encode(&msg).expect("encodable"));
                    }
                    set
                },
            )
        }

        concurrent_psbt::assert_join_laws!(any_message_set());

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

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
