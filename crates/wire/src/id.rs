use std::sync::LazyLock;

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
pub const MESSAGE_ID_TAG: &str = "fungi/v1/message-id";
/// Domain tag for ordered full-ID set commitments.
pub const SET_COMMITMENT_TAG: &str = "fungi/v1/message-set";

/// A hasher primed with one domain's BIP340 prefix.
///
/// `SHA256(tag)` written twice is exactly one 64-byte block, so its
/// compression is identical for every hash in the domain. Priming once and
/// cloning per hash is what earns the doubled tag its bytes: hashing a short
/// message costs one block instead of three, while the tag itself is
/// compressed once for the life of the process.
fn primed(tag: &str) -> Sha256 {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash
}

static MESSAGE_ID_DOMAIN: LazyLock<Sha256> = LazyLock::new(|| primed(MESSAGE_ID_TAG));
static SET_COMMITMENT_DOMAIN: LazyLock<Sha256> = LazyLock::new(|| primed(SET_COMMITMENT_TAG));

pub(crate) fn message_id(bytes: &[u8]) -> MessageId {
    let mut hash = MESSAGE_ID_DOMAIN.clone();
    hash.update(bytes);
    MessageId(hash.finalize().into())
}

pub(crate) fn set_commitment<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hash = SET_COMMITMENT_DOMAIN.clone();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
