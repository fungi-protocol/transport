use crate::{
    CanonicalMessage, IdentityCollision, MessageId, MessageSetCommitment, SET_COMMITMENT_TAG,
};
use std::collections::BTreeMap;

/// Grow-only set keyed by stable full message identities.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageSet(BTreeMap<MessageId, CanonicalMessage>);
impl MessageSet {
    /// Insert a validated message; identical insertion is a no-op.
    pub fn insert(&mut self, message: CanonicalMessage) -> Result<MessageId, IdentityCollision> {
        let id = message.id();
        self.insert_with_id(id, message)
    }

    fn insert_with_id(
        &mut self,
        id: MessageId,
        message: CanonicalMessage,
    ) -> Result<MessageId, IdentityCollision> {
        match self.0.get(&id) {
            Some(old) if old != &message => return Err(IdentityCollision { id }),
            Some(_) => return Ok(id),
            None => {
                self.0.insert(id, message);
            }
        }
        Ok(id)
    }

    #[cfg(test)]
    pub(crate) fn insert_at(
        &mut self,
        id: MessageId,
        message: CanonicalMessage,
    ) -> Result<MessageId, IdentityCollision> {
        self.insert_with_id(id, message)
    }
    /// Whether a full identity is present.
    pub fn contains(&self, id: &MessageId) -> bool {
        self.0.contains_key(id)
    }
    /// Look up validated bytes by full identity.
    pub fn get(&self, id: &MessageId) -> Option<&CanonicalMessage> {
        self.0.get(id)
    }
    /// Number of distinct identities.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether the set contains no messages.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Iterate in deterministic full-ID order.
    pub fn iter(&self) -> impl Iterator<Item = (&MessageId, &CanonicalMessage)> {
        self.0.iter()
    }
    /// Merge another grow-only set, rejecting a full-ID collision.
    pub fn merge(&mut self, other: Self) -> Result<(), IdentityCollision> {
        for (id, message) in &other.0 {
            if self.0.get(id).is_some_and(|old| old != message) {
                return Err(IdentityCollision { id: *id });
            }
        }
        self.0.extend(other.0);
        Ok(())
    }
    /// Return the checked union of two grow-only sets.
    pub fn union(mut self, other: Self) -> Result<Self, IdentityCollision> {
        self.merge(other)?;
        Ok(self)
    }
    /// Commit to the sorted full identities and cardinality.
    pub fn commitment(&self) -> MessageSetCommitment {
        let count = u64::try_from(self.0.len())
            .expect("a materialized MessageSet cannot exceed u64::MAX entries")
            .to_be_bytes();
        let parts = std::iter::once(count.as_slice())
            .chain(self.0.keys().map(|id| id.as_bytes().as_slice()));
        MessageSetCommitment::from_hash(crate::id::tagged_hash_iter(SET_COMMITMENT_TAG, parts))
    }
}
