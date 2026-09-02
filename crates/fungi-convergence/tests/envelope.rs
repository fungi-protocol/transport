//! Round-trip, identity, and validation behavior of [`Envelope`], exercised
//! through the crate's public API only.

use std::collections::BTreeSet;

use fungi_convergence::{
    AuthorId, Envelope, EnvelopeError, MAX_PAYLOAD_LEN, MessageId, WIRE_OVERHEAD,
};

fn envelope() -> Envelope {
    Envelope::new(AuthorId::new([0xA5; 32]), 42, b"hello".to_vec()).unwrap()
}

#[test]
fn canonical_roundtrip_preserves_fields_and_id() {
    let original = envelope();
    let encoded = original.encode();
    let decoded = Envelope::decode(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.message_id(), original.message_id());
    assert_eq!(encoded.len(), WIRE_OVERHEAD + 5);
}

#[test]
fn encoding_is_stable() {
    let encoded = envelope().encode();
    assert_eq!(&encoded[..4], b"FGCV");
    assert_eq!(&encoded[4..36], &[0xA5; 32]);
    assert_eq!(&encoded[36..44], &42u64.to_be_bytes());
    assert_eq!(&encoded[44..48], &5u32.to_be_bytes());
    assert_eq!(&encoded[48..], b"hello");
}

#[test]
fn identity_changes_with_each_logical_field() {
    let base = envelope().message_id();
    assert_ne!(
        Envelope::new(AuthorId::new([0xB6; 32]), 42, b"hello".to_vec())
            .unwrap()
            .message_id(),
        base
    );
    assert_ne!(
        Envelope::new(AuthorId::new([0xA5; 32]), 43, b"hello".to_vec())
            .unwrap()
            .message_id(),
        base
    );
    assert_ne!(
        Envelope::new(AuthorId::new([0xA5; 32]), 42, b"world".to_vec())
            .unwrap()
            .message_id(),
        base
    );
}

#[test]
fn identical_logical_messages_deduplicate() {
    let a = envelope();
    let b = Envelope::decode(&a.encode()).unwrap();
    let ids = [a.message_id(), b.message_id()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 1);
}

#[test]
fn payload_boundary_is_enforced() {
    assert!(Envelope::new(AuthorId::new([1; 32]), 0, vec![0; MAX_PAYLOAD_LEN]).is_ok());
    assert_eq!(
        Envelope::new(AuthorId::new([1; 32]), 0, vec![0; MAX_PAYLOAD_LEN + 1]),
        Err(EnvelopeError::PayloadTooLarge {
            max: MAX_PAYLOAD_LEN,
            actual: MAX_PAYLOAD_LEN + 1,
        })
    );
}

#[test]
fn malformed_envelopes_are_rejected() {
    assert_eq!(Envelope::decode(b"short"), Err(EnvelopeError::Truncated));

    let mut invalid_magic = envelope().encode();
    invalid_magic[0] ^= 1;
    assert_eq!(
        Envelope::decode(&invalid_magic),
        Err(EnvelopeError::InvalidMagic)
    );

    let mut truncated = envelope().encode();
    truncated.pop();
    assert_eq!(
        Envelope::decode(&truncated),
        Err(EnvelopeError::LengthMismatch {
            declared: 5,
            actual: 4,
        })
    );

    let mut trailing = envelope().encode();
    trailing.push(0);
    assert_eq!(
        Envelope::decode(&trailing),
        Err(EnvelopeError::LengthMismatch {
            declared: 5,
            actual: 6,
        })
    );
}

#[test]
fn message_id_has_stable_display_form() {
    let text = envelope().message_id().to_string();
    assert_eq!(text.len(), MessageId::LEN * 2);
    assert_eq!(
        text,
        "9d3ec73db235eb7c2da3df9b6851b09549eae6b309783c918c721d9869cfbef3"
    );
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}
