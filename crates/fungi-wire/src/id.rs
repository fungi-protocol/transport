use sha2::{Digest, Sha256};

/// Full collision-resistant logical message identity.
pub type MessageId = [u8; 32];
/// Domain tag for message identities.
pub const MESSAGE_ID_TAG: &str = "fungi/message-id/v1";
/// Domain tag for ordered full-ID set commitments.
pub const SET_COMMITMENT_TAG: &str = "fungi/message-set/v1";

pub(crate) fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
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
    tagged_hash(MESSAGE_ID_TAG, &[bytes])
}
