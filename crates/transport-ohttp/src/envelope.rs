use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{HpkePublicKey, LinkSecret, MAX_MESSAGE_SIZE};

const MAGIC: &[u8; 8] = b"FNGOMB01";
pub(crate) const OVERHEAD: usize = 8 + 4 + 32;

fn mac(secret: &LinkSecret, recipient: &HpkePublicKey) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret.0).expect("HMAC accepts any key length");
    mac.update(b"fungi-ohttp-mailbox-v1");
    mac.update(&recipient.to_compressed_bytes());
    mac
}

pub(crate) fn encode(msg: &[u8], secret: &LinkSecret, recipient: &HpkePublicKey) -> Vec<u8> {
    let mut body = Vec::with_capacity(OVERHEAD + msg.len());
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    body.extend_from_slice(msg);
    let mut tag = mac(secret, recipient);
    tag.update(&body);
    body.extend_from_slice(&tag.finalize().into_bytes());
    body
}

// Unauthenticated entries (including old link generations) are ignored. The
// explicit length preserves empty messages and trailing zero byte.
pub(crate) fn decode(
    body: &[u8],
    secret: &LinkSecret,
    recipient: &HpkePublicKey,
) -> Option<Vec<u8>> {
    if body.get(..8)? != MAGIC {
        return None;
    }
    let len = u32::from_be_bytes(body.get(8..12)?.try_into().ok()?) as usize;
    if len > MAX_MESSAGE_SIZE {
        return None;
    }
    let end = 12 + len;
    let mut tag = mac(secret, recipient);
    tag.update(body.get(..end)?);
    tag.verify_slice(body.get(end..end + 32)?).ok()?;
    Some(body[12..end].to_vec())
}
