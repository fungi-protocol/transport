use crate::{CanonicalMessage, IdentityCollision, MessageId, SET_COMMITMENT_TAG, id::tagged_hash};
use std::collections::BTreeMap;

/// Grow-only set keyed by stable full message identities.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageSet(BTreeMap<MessageId, CanonicalMessage>);
impl MessageSet {
    /// Insert a validated message; identical insertion is a no-op.
    pub fn insert(&mut self, message: CanonicalMessage) -> Result<MessageId, IdentityCollision> {
        let id = message.id();
        match self.0.get(&id) {
            Some(old) if old != &message => return Err(IdentityCollision { id }),
            Some(_) => return Ok(id),
            None => {
                self.0.insert(id, message);
            }
        }
        Ok(id)
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
        for (_, message) in other.0 {
            self.insert(message)?;
        }
        Ok(())
    }
    /// Return the checked union of two grow-only sets.
    pub fn union(mut self, other: Self) -> Result<Self, IdentityCollision> {
        self.merge(other)?;
        Ok(self)
    }
    /// Commit to the sorted full identities and cardinality.
    pub fn commitment(&self) -> [u8; 32] {
        let count = (self.0.len() as u64).to_be_bytes();
        let ids: Vec<u8> = self.0.keys().flatten().copied().collect();
        tagged_hash(SET_COMMITMENT_TAG, &[&count, &ids])
    }
}
