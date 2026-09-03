//! Differential conformance check using an implementation independent of the
//! production decoder, identity types, and `MessageSet`.

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

#[derive(Deserialize)]
struct Vectors {
    messages: Vec<MessageVector>,
    commitments: Vec<CommitmentVector>,
    invalid_messages: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct MessageVector {
    canonical: String,
    message_id: String,
}

#[derive(Deserialize)]
struct CommitmentVector {
    messages: Vec<String>,
    commitment: String,
}

#[derive(Deserialize)]
struct InvalidVector {
    canonical: String,
}

fn tagged_hash(tag: &str, parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    for part in parts {
        hash.update(part.as_ref());
    }
    hash.finalize().into()
}

fn read_bigsize(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let first = *bytes.get(*cursor)?;
    *cursor += 1;
    let (width, floor) = match first {
        0xfd => (2, 0xfd),
        0xfe => (4, 0x1_0000),
        0xff => (8, 0x1_0000_0000),
        value => return Some(u64::from(value)),
    };
    let field = bytes.get(*cursor..cursor.checked_add(width)?)?;
    *cursor += width;
    let value = field
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    (value >= floor).then_some(value)
}

fn accepts(bytes: &[u8]) -> bool {
    if bytes.len() > MAX_MESSAGE_SIZE || bytes.len() < 3 {
        return false;
    }
    let ty = u16::from_be_bytes([bytes[0], bytes[1]]);
    if !matches!(ty, 1 | 3 | 5) && ty.is_multiple_of(2) {
        return false;
    }

    let mut cursor = 2;
    let Some(payload_len) = read_bigsize(bytes, &mut cursor).and_then(|n| usize::try_from(n).ok())
    else {
        return false;
    };
    let Some(payload_end) = cursor.checked_add(payload_len) else {
        return false;
    };
    if payload_end > bytes.len() {
        return false;
    }
    cursor = payload_end;

    let mut previous = None;
    while cursor < bytes.len() {
        let Some(extension_type) = read_bigsize(bytes, &mut cursor) else {
            return false;
        };
        if extension_type.is_multiple_of(2)
            || previous.is_some_and(|previous| extension_type <= previous)
        {
            return false;
        }
        previous = Some(extension_type);
        let Some(extension_len) =
            read_bigsize(bytes, &mut cursor).and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        let Some(end) = cursor.checked_add(extension_len) else {
            return false;
        };
        if end > bytes.len() {
            return false;
        }
        cursor = end;
    }
    true
}

fn message_id(bytes: &[u8]) -> [u8; 32] {
    tagged_hash("fungi/message-id", [bytes])
}

fn commitment(messages: &[Vec<u8>]) -> [u8; 32] {
    let mut ids: Vec<_> = messages.iter().map(|bytes| message_id(bytes)).collect();
    ids.sort_unstable();
    ids.dedup();
    let count = u64::try_from(ids.len()).unwrap().to_be_bytes();
    tagged_hash(
        "fungi/message-set",
        std::iter::once(count.as_slice()).chain(ids.iter().map(<[u8; 32]>::as_slice)),
    )
}

#[test]
fn independent_reference_agrees_with_all_vectors() {
    let vectors: Vectors = serde_json::from_str(include_str!("vectors.json")).unwrap();

    for vector in vectors.messages {
        let bytes = hex::decode(vector.canonical).unwrap();
        assert!(accepts(&bytes));
        assert_eq!(hex::encode(message_id(&bytes)), vector.message_id);
    }
    for vector in vectors.invalid_messages {
        assert!(!accepts(&hex::decode(vector.canonical).unwrap()));
    }
    for vector in vectors.commitments {
        let messages: Vec<_> = vector
            .messages
            .into_iter()
            .map(|message| hex::decode(message).unwrap())
            .collect();
        assert!(messages.iter().all(|message| accepts(message)));
        assert_eq!(hex::encode(commitment(&messages)), vector.commitment);
    }
}
