use crate::*;
use proptest::prelude::*;

fn canonical(payload: &[u8]) -> CanonicalMessage {
    CanonicalMessage::encode(&Message::new(Body::Payment(payload.to_vec()))).unwrap()
}

#[test]
fn candidate_vector_is_byte_exact() {
    let message = canonical(b"hello");
    assert_eq!(hex::encode(message.as_bytes()), "00030568656c6c6f");
    assert_eq!(
        hex::encode(message.id().as_bytes()),
        "20dba9357befdae2f09f67ccfa65a124a7bfbc886e05154e9720f799c7c3526e"
    );
    assert_eq!(
        CanonicalMessage::parse(message.as_bytes().to_vec()).unwrap(),
        message
    );
}

#[test]
fn every_retained_message_type_has_a_byte_exact_vector() {
    for (body, expected) in [
        (Body::Psbt(Vec::new()), "000100"),
        (Body::Payment(b"hello".to_vec()), "00030568656c6c6f"),
        (Body::Confirmation(vec![0xff]), "000501ff"),
    ] {
        let encoded = CanonicalMessage::encode(&Message::new(body)).unwrap();
        assert_eq!(hex::encode(encoded.as_bytes()), expected);
        assert_eq!(
            CanonicalMessage::parse(hex::decode(expected).unwrap()).unwrap(),
            encoded
        );
    }
}

#[test]
fn set_commitment_vector_is_byte_exact_and_order_independent() {
    let hello = canonical(b"hello");
    let world = canonical(b"world");
    assert_eq!(
        hex::encode(world.id().as_bytes()),
        "e6164c015528e72e8e5564569117331c072edfdd7b3519d3f115f5c3bc542f6e"
    );
    let mut forward = MessageSet::default();
    forward.insert(hello.clone()).unwrap();
    forward.insert(world.clone()).unwrap();
    let mut reverse = MessageSet::default();
    reverse.insert(world).unwrap();
    reverse.insert(hello).unwrap();
    assert_eq!(forward.commitment(), reverse.commitment());
    assert_eq!(
        hex::encode(forward.commitment().as_bytes()),
        "84c1963bb98c0a8f4f60286c489d7fa8d3830e4e8b7d3cb04e875cbe4faca0ec"
    );
}

#[test]
fn empty_and_singleton_commitments_are_byte_exact() {
    let empty = MessageSet::default();
    assert_eq!(
        hex::encode(empty.commitment().as_bytes()),
        "328cabc016c3f0ffae70d63344b34ec8c07d3facb6bf107056225a77e3e80aa3"
    );

    let mut singleton = MessageSet::default();
    singleton.insert(canonical(b"hello")).unwrap();
    assert_eq!(
        hex::encode(singleton.commitment().as_bytes()),
        "9d01f77bdc3af2e60e78fd3f9945e289bdd627e0a949f7c9316cb0c7a40f4371"
    );
}

#[test]
fn extension_message_vector_is_byte_exact() {
    let message = Message {
        body: Body::Payment(b"x".to_vec()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: b"e".to_vec(),
        }])
        .unwrap(),
    };
    let canonical = CanonicalMessage::encode(&message).unwrap();
    assert_eq!(hex::encode(canonical.as_bytes()), "00030178010165");
    assert_eq!(canonical.decode(), message);
}

#[test]
fn unknown_odd_survives_and_unknown_even_fails() {
    let odd = hex::decode("03e9066f7061717565").unwrap();
    assert_eq!(
        CanonicalMessage::parse(odd.clone()).unwrap().as_bytes(),
        odd
    );
    let even = hex::decode("03e8066f7061717565").unwrap();
    assert_eq!(
        CanonicalMessage::parse(even),
        Err(DecodeError::UnknownRequiredMessageType { ty: 1000 })
    );
}

#[test]
fn nonminimal_truncated_and_oversized_inputs_fail() {
    assert_eq!(
        CanonicalMessage::parse(hex::decode("0003fd000568656c6c6f").unwrap()),
        Err(DecodeError::NonMinimalInteger)
    );
    assert_eq!(
        CanonicalMessage::parse(hex::decode("00030568656c6c").unwrap()),
        Err(DecodeError::UnexpectedEof)
    );
    assert!(matches!(
        CanonicalMessage::parse(vec![0; MAX_MESSAGE_SIZE + 1]),
        Err(DecodeError::TooLarge { .. })
    ));
}

#[test]
fn extension_stream_is_strict_and_preserves_unknown_odd_records() {
    let valid = hex::decode("0003000100").unwrap();
    assert_eq!(
        CanonicalMessage::parse(valid.clone()).unwrap().as_bytes(),
        valid
    );
    assert_eq!(
        CanonicalMessage::parse(hex::decode("0003000200").unwrap()),
        Err(DecodeError::UnknownRequiredExtension { ty: 2 })
    );
    assert_eq!(
        CanonicalMessage::parse(hex::decode("00030003000100").unwrap()),
        Err(DecodeError::NonCanonicalExtensions)
    );
    assert_eq!(
        CanonicalMessage::parse(hex::decode("00030001000100").unwrap()),
        Err(DecodeError::NonCanonicalExtensions)
    );
    assert_eq!(
        CanonicalMessage::parse(hex::decode("0003000400").unwrap()),
        Err(DecodeError::UnknownRequiredExtension { ty: 4 })
    );
}

#[test]
fn complete_message_limit_is_enforced_at_the_boundary() {
    // At these payload lengths BigSize occupies five bytes, in addition to the
    // two-byte message type.
    let largest = vec![0; MAX_MESSAGE_SIZE - 7];
    let encoded = canonical(&largest);
    assert_eq!(encoded.as_bytes().len(), MAX_MESSAGE_SIZE);
    assert_eq!(
        CanonicalMessage::parse(encoded.as_bytes().to_vec()).unwrap(),
        encoded
    );

    let one_under = canonical(&vec![0; MAX_MESSAGE_SIZE - 8]);
    assert_eq!(one_under.as_bytes().len(), MAX_MESSAGE_SIZE - 1);

    let too_large = Message::new(Body::Payment(vec![0; MAX_MESSAGE_SIZE - 6]));
    assert_eq!(
        CanonicalMessage::encode(&too_large),
        Err(EncodeError::TooLarge {
            max: MAX_MESSAGE_SIZE,
            actual: MAX_MESSAGE_SIZE + 1,
        })
    );

    let extension_at_limit = Message {
        body: Body::Payment(Vec::new()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: vec![0; MAX_MESSAGE_SIZE - 9],
        }])
        .unwrap(),
    };
    assert_eq!(
        CanonicalMessage::encode(&extension_at_limit)
            .unwrap()
            .as_bytes()
            .len(),
        MAX_MESSAGE_SIZE
    );
    let extension_over_limit = Message {
        body: Body::Payment(Vec::new()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: vec![0; MAX_MESSAGE_SIZE - 8],
        }])
        .unwrap(),
    };
    assert!(matches!(
        CanonicalMessage::encode(&extension_over_limit),
        Err(EncodeError::TooLarge { .. })
    ));
}

#[test]
fn small_set_union_laws_hold_exhaustively() {
    let universe = [canonical(b"a"), canonical(b"b"), canonical(b"c")];
    let sets = (0u8..8)
        .map(|mask| {
            let mut set = MessageSet::default();
            for (bit, message) in universe.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    set.insert(message.clone()).unwrap();
                }
            }
            set
        })
        .collect::<Vec<_>>();

    for a in &sets {
        assert_eq!(a.clone().union(a.clone()).unwrap(), *a);
        for b in &sets {
            assert_eq!(
                a.clone().union(b.clone()).unwrap(),
                b.clone().union(a.clone()).unwrap()
            );
            for c in &sets {
                assert_eq!(
                    a.clone()
                        .union(b.clone())
                        .unwrap()
                        .union(c.clone())
                        .unwrap(),
                    a.clone()
                        .union(b.clone().union(c.clone()).unwrap())
                        .unwrap()
                );
            }
        }
    }
}

#[test]
fn duplicate_insertion_is_idempotent() {
    let mut set = MessageSet::default();
    let msg = canonical(b"same");
    let id = set.insert(msg.clone()).unwrap();
    assert_eq!(set.insert(msg).unwrap(), id);
    assert_eq!(set.len(), 1);
}

#[test]
fn different_bytes_under_one_identity_are_rejected() {
    let first = canonical(b"first");
    let second = canonical(b"second");
    let id = first.id();
    let mut set = MessageSet::default();
    set.insert(first).unwrap();
    assert_eq!(set.insert_at(id, second), Err(IdentityCollision { id }));
}

#[test]
fn merge_is_atomic_when_an_identity_collision_is_detected() {
    let incumbent = canonical(b"incumbent");
    let accepted = canonical(b"accepted");
    let conflicting = canonical(b"conflicting");
    let collision_id = incumbent.id();

    let mut left = MessageSet::default();
    left.insert(incumbent).unwrap();
    let before = left.clone();

    let mut right = MessageSet::default();
    right.insert(accepted).unwrap();
    right
        .insert_at(collision_id, conflicting)
        .expect("the injected id is not present in the right-hand set");

    assert_eq!(
        left.merge(right),
        Err(IdentityCollision { id: collision_id })
    );
    assert_eq!(left, before);
}

fn any_set() -> impl Strategy<Value = MessageSet> {
    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..32), 0..8).prop_map(
        |payloads| {
            let mut set = MessageSet::default();
            for payload in payloads {
                set.insert(canonical(&payload)).unwrap();
            }
            set
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn union_is_idempotent(a in any_set()) {
        prop_assert_eq!(a.clone().union(a.clone()).unwrap(), a);
    }
    #[test]
    fn union_is_commutative(a in any_set(), b in any_set()) {
        prop_assert_eq!(a.clone().union(b.clone()).unwrap(), b.union(a).unwrap());
    }
    #[test]
    fn union_is_associative(a in any_set(), b in any_set(), c in any_set()) {
        prop_assert_eq!(
            a.clone().union(b.clone()).unwrap().union(c.clone()).unwrap(),
            a.union(b.union(c).unwrap()).unwrap()
        );
    }

    #[test]
    fn arbitrary_input_is_canonical_or_rejected(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        if let Ok(message) = CanonicalMessage::parse(bytes.clone()) {
            prop_assert_eq!(message.as_bytes(), bytes.as_slice());
            prop_assert_eq!(
                CanonicalMessage::encode(&message.decode()).unwrap(),
                message,
            );
        }
    }

    #[test]
    fn messages_with_odd_extensions_roundtrip(
        payload in proptest::collection::vec(any::<u8>(), 0..128),
        records in proptest::collection::btree_map(
            (0u64..128).prop_map(|n| n * 2 + 1),
            proptest::collection::vec(any::<u8>(), 0..32),
            0..8,
        ),
    ) {
        let message = Message {
            body: Body::Psbt(payload),
            extensions: Extensions::new(
                records
                    .into_iter()
                    .map(|(ty, value)| Extension { ty, value })
                    .collect(),
            ).unwrap(),
        };
        let canonical = CanonicalMessage::encode(&message).unwrap();
        prop_assert_eq!(crate::encoding::encoded_len(&message).unwrap(), canonical.as_bytes().len());
        prop_assert_eq!(CanonicalMessage::parse(canonical.as_bytes().to_vec()).unwrap(), canonical);
    }
}
