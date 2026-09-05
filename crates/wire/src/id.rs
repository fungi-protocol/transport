use sha2::{Digest, Sha256};

/// Full collision-resistant logical message identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// Borrow the full identity bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for MessageId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Collision-resistant commitment to a complete [`crate::MessageSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageSetCommitment([u8; 32]);

impl MessageSetCommitment {
    /// Borrow the full commitment bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_hash(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl AsRef<[u8]> for MessageSetCommitment {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
/// Domain tag for message identities.
pub const MESSAGE_ID_TAG: &str = "fungi/message-id";
/// Domain tag for ordered full-ID set commitments.
pub const SET_COMMITMENT_TAG: &str = "fungi/message-set";

pub(crate) fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    tagged_hash_iter(tag, parts.iter().copied())
}

pub(crate) fn tagged_hash_iter<'a>(
    tag: &str,
    parts: impl IntoIterator<Item = &'a [u8]>,
) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
pub(crate) fn message_id(bytes: &[u8]) -> MessageId {
    MessageId(tagged_hash(MESSAGE_ID_TAG, &[bytes]))
}
