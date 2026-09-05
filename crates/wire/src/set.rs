use crate::{
    CanonicalMessage, IdentityCollision, MessageContext, MessageId, MessageSetCommitment,
    MessageSetError,
};
use std::collections::BTreeMap;

/// Grow-only set keyed by stable full message identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSet {
    context: MessageContext,
    messages: BTreeMap<MessageId, CanonicalMessage>,
}
impl MessageSet {
    /// Construct an empty set for one protocol session and version.
    pub fn new(context: MessageContext) -> Self {
        Self {
            context,
            messages: BTreeMap::new(),
        }
    }

    /// Return the logical context shared by every message in this set.
    pub const fn context(&self) -> MessageContext {
        self.context
    }

    /// Insert a validated message; identical insertion is a no-op.
    pub fn insert(&mut self, message: CanonicalMessage) -> Result<MessageId, MessageSetError> {
        if message.context() != self.context {
            return Err(MessageSetError::ContextMismatch {
                expected: self.context,
                received: message.context(),
            });
        }
        let id = message.id();
        self.insert_with_id(id, message)
    }

    fn insert_with_id(
        &mut self,
        id: MessageId,
        message: CanonicalMessage,
    ) -> Result<MessageId, MessageSetError> {
        match self.messages.get(&id) {
            Some(old) if old != &message => {
                return Err(IdentityCollision { id }.into());
            }
            Some(_) => return Ok(id),
            None => {
                self.messages.insert(id, message);
            }
        }
        Ok(id)
    }

    #[cfg(test)]
    pub(crate) fn insert_at(
        &mut self,
        id: MessageId,
        message: CanonicalMessage,
    ) -> Result<MessageId, MessageSetError> {
        self.insert_with_id(id, message)
    }
    /// Whether a full identity is present.
    pub fn contains(&self, id: &MessageId) -> bool {
        self.messages.contains_key(id)
    }
    /// Look up validated bytes by full identity.
    pub fn get(&self, id: &MessageId) -> Option<&CanonicalMessage> {
        self.messages.get(id)
    }
    /// Number of distinct identities.
    pub fn len(&self) -> usize {
        self.messages.len()
    }
    /// Whether the set contains no messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
    /// Iterate in deterministic full-ID order.
    pub fn iter(&self) -> impl Iterator<Item = (&MessageId, &CanonicalMessage)> {
        self.messages.iter()
    }
    /// Merge another grow-only set, rejecting a full-ID collision.
    pub fn merge(&mut self, other: Self) -> Result<(), MessageSetError> {
        if other.context != self.context {
            return Err(MessageSetError::ContextMismatch {
                expected: self.context,
                received: other.context,
            });
        }
        for (id, message) in &other.messages {
            if self.messages.get(id).is_some_and(|old| old != message) {
                return Err(IdentityCollision { id: *id }.into());
            }
        }
        self.messages.extend(other.messages);
        Ok(())
    }
    /// Return the checked union of two grow-only sets.
    pub fn union(mut self, other: Self) -> Result<Self, MessageSetError> {
        self.merge(other)?;
        Ok(self)
    }
    /// Commit to the sorted full identities and cardinality.
    pub fn commitment(&self) -> MessageSetCommitment {
        let count = u64::try_from(self.messages.len())
            .expect("a materialized MessageSet cannot exceed u64::MAX entries")
            .to_be_bytes();
        let session_id = self.context.session_id();
        let version = self.context.protocol_version().to_be_bytes();
        let parts = std::iter::once(session_id.as_bytes().as_slice())
            .chain(std::iter::once(version.as_slice()))
            .chain(std::iter::once(count.as_slice()))
            .chain(self.messages.keys().map(|id| id.as_bytes().as_slice()));
        MessageSetCommitment::from_hash(crate::id::set_commitment(parts))
    }
}
