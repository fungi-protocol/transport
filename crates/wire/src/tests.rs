use crate::*;
use proptest::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct ConformanceVectors {
    session_id: String,
    protocol_version: u16,
    messages: Vec<MessageVector>,
    commitments: Vec<CommitmentVector>,
    invalid_messages: Vec<InvalidMessageVector>,
    foreign_context_messages: Vec<InvalidMessageVector>,
}

#[derive(Deserialize)]
struct MessageVector {
    name: String,
    canonical: String,
    message_id: String,
    session_id: Option<String>,
    protocol_version: Option<u16>,
}

#[derive(Deserialize)]
struct CommitmentVector {
    name: String,
    messages: Vec<String>,
    commitment: String,
    session_id: Option<String>,
    protocol_version: Option<u16>,
}

#[derive(Deserialize)]
struct InvalidMessageVector {
    name: String,
    canonical: String,
}

fn declared_context(session_id: &str, protocol_version: u16) -> MessageContext {
    MessageContext::new(
        ProtocolSessionId::new(hex::decode(session_id).unwrap().try_into().unwrap()),
        ProtocolVersion::new(protocol_version),
    )
}

/// A vector either declares its own context in full or inherits the file's;
/// declaring half of one is a mistake in the vectors, not a default.
fn overridden(
    session_id: Option<&str>,
    protocol_version: Option<u16>,
    default: MessageContext,
) -> MessageContext {
    match (session_id, protocol_version) {
        (Some(session), Some(version)) => declared_context(session, version),
        (None, None) => default,
        _ => panic!("a vector overriding its context must declare both halves"),
    }
}

fn conformance_vectors() -> ConformanceVectors {
    serde_json::from_str(include_str!("../tests/vectors.json"))
        .expect("the checked-in conformance vectors must be valid JSON")
}

fn canonical(payload: &[u8]) -> CanonicalMessage {
    CanonicalMessage::encode(context(), &Message::new(Body::Payment(payload.to_vec()))).unwrap()
}

fn context() -> MessageContext {
    context_with(0, 1)
}

fn context_with(session: u8, version: u16) -> MessageContext {
    MessageContext::new(
        ProtocolSessionId::new([session; 32]),
        ProtocolVersion::new(version),
    )
}

fn empty_set() -> MessageSet {
    MessageSet::new(context())
}

fn with_context(message: &str) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&hex::decode(message).unwrap());
    bytes
}

#[test]
fn language_neutral_conformance_vectors_hold() {
    let vectors = conformance_vectors();
    assert_eq!(vectors.session_id, "00".repeat(32));
    assert_eq!(vectors.protocol_version, 1);
    let mut mismatches = Vec::new();

    let default = declared_context(&vectors.session_id, vectors.protocol_version);

    for vector in vectors.messages {
        let bytes = hex::decode(&vector.canonical).unwrap();
        let message = CanonicalMessage::parse(bytes.clone())
            .unwrap_or_else(|error| panic!("message vector {:?} failed: {error}", vector.name));
        assert_eq!(
            message.as_bytes(),
            bytes,
            "message vector {:?}",
            vector.name
        );
        let expected = overridden(
            vector.session_id.as_deref(),
            vector.protocol_version,
            default,
        );
        assert_eq!(
            message.context(),
            expected,
            "message vector {:?}",
            vector.name
        );
        let actual_id = hex::encode(message.id().as_bytes());
        if actual_id != vector.message_id {
            mismatches.push((vector.name.clone(), actual_id, vector.message_id));
        }
        assert_eq!(
            CanonicalMessage::encode(message.context(), &message.decode()).unwrap(),
            message,
            "message vector {:?}",
            vector.name
        );
    }
    assert!(
        mismatches.is_empty(),
        "message ID mismatches: {mismatches:#?}"
    );

    let mut commitment_mismatches = Vec::new();
    for vector in vectors.commitments {
        let mut set = MessageSet::new(overridden(
            vector.session_id.as_deref(),
            vector.protocol_version,
            default,
        ));
        for message in vector.messages {
            set.insert(CanonicalMessage::parse(hex::decode(message).unwrap()).unwrap())
                .unwrap();
        }
        let actual = hex::encode(set.commitment().as_bytes());
        if actual != vector.commitment {
            commitment_mismatches.push((vector.name, actual, vector.commitment));
        }
    }
    assert!(
        commitment_mismatches.is_empty(),
        "set commitment mismatches: {commitment_mismatches:#?}"
    );

    for vector in vectors.invalid_messages {
        assert!(
            CanonicalMessage::parse(hex::decode(&vector.canonical).unwrap()).is_err(),
            "invalid vector {:?} was accepted",
            vector.name
        );
    }

    // Well-formed messages that another session or version produced: valid on
    // their own terms, inadmissible here.
    for vector in vectors.foreign_context_messages {
        let message = CanonicalMessage::parse(hex::decode(&vector.canonical).unwrap())
            .unwrap_or_else(|error| panic!("foreign vector {:?} failed: {error}", vector.name));
        assert_ne!(
            message.context(),
            default,
            "foreign vector {:?}",
            vector.name
        );
        assert!(
            matches!(
                MessageSet::new(default).insert(message),
                Err(MessageSetError::ContextMismatch { .. })
            ),
            "foreign vector {:?} was admitted",
            vector.name
        );
    }
}

#[test]
fn unknown_odd_survives_and_unknown_even_fails() {
    let odd = with_context("03e9066f7061717565");
    assert_eq!(
        CanonicalMessage::parse(odd.clone()).unwrap().as_bytes(),
        odd
    );
    let even = with_context("03e8066f7061717565");
    assert_eq!(
        CanonicalMessage::parse(even),
        Err(DecodeError::UnknownRequiredMessageType { ty: 1000 })
    );
}

#[test]
fn nonminimal_truncated_and_oversized_inputs_fail() {
    assert_eq!(
        CanonicalMessage::parse(with_context("0003fd000568656c6c6f")),
        Err(DecodeError::NonMinimalInteger)
    );
    assert_eq!(
        CanonicalMessage::parse(with_context("00030568656c6c")),
        Err(DecodeError::UnexpectedEof)
    );
    assert!(matches!(
        CanonicalMessage::parse(vec![0; MAX_MESSAGE_SIZE + 1]),
        Err(DecodeError::TooLarge { .. })
    ));
}

#[test]
fn extension_stream_is_strict_and_preserves_unknown_odd_records() {
    let valid = with_context("0003000100");
    assert_eq!(
        CanonicalMessage::parse(valid.clone()).unwrap().as_bytes(),
        valid
    );
    assert_eq!(
        CanonicalMessage::parse(with_context("0003000200")),
        Err(DecodeError::UnknownRequiredExtension { ty: 2 })
    );
    assert_eq!(
        CanonicalMessage::parse(with_context("00030003000100")),
        Err(DecodeError::NonCanonicalExtensions)
    );
    assert_eq!(
        CanonicalMessage::parse(with_context("00030001000100")),
        Err(DecodeError::NonCanonicalExtensions)
    );
    assert_eq!(
        CanonicalMessage::parse(with_context("0003000400")),
        Err(DecodeError::UnknownRequiredExtension { ty: 4 })
    );
}

#[test]
fn complete_message_limit_is_enforced_at_the_boundary() {
    // At these payload lengths BigSize occupies five bytes, in addition to the
    // 34-byte context and two-byte message type.
    let largest = vec![0; MAX_MESSAGE_SIZE - 41];
    let encoded = canonical(&largest);
    assert_eq!(encoded.as_bytes().len(), MAX_MESSAGE_SIZE);
    assert_eq!(
        CanonicalMessage::parse(encoded.as_bytes().to_vec()).unwrap(),
        encoded
    );

    let one_under = canonical(&vec![0; MAX_MESSAGE_SIZE - 42]);
    assert_eq!(one_under.as_bytes().len(), MAX_MESSAGE_SIZE - 1);

    let too_large = Message::new(Body::Payment(vec![0; MAX_MESSAGE_SIZE - 40]));
    assert_eq!(
        CanonicalMessage::encode(context(), &too_large),
        Err(EncodeError::TooLarge {
            max: MAX_MESSAGE_SIZE,
            actual: MAX_MESSAGE_SIZE + 1,
        })
    );

    let extension_at_limit = Message {
        body: Body::Payment(Vec::new()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: vec![0; MAX_MESSAGE_SIZE - 43],
        }])
        .unwrap(),
    };
    assert_eq!(
        CanonicalMessage::encode(context(), &extension_at_limit)
            .unwrap()
            .as_bytes()
            .len(),
        MAX_MESSAGE_SIZE
    );
    let extension_over_limit = Message {
        body: Body::Payment(Vec::new()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: vec![0; MAX_MESSAGE_SIZE - 42],
        }])
        .unwrap(),
    };
    assert!(matches!(
        CanonicalMessage::encode(context(), &extension_over_limit),
        Err(EncodeError::TooLarge { .. })
    ));
}

#[test]
fn small_set_union_laws_hold_exhaustively() {
    let universe = [canonical(b"a"), canonical(b"b"), canonical(b"c")];
    let sets = (0u8..8)
        .map(|mask| {
            let mut set = empty_set();
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
    let mut set = empty_set();
    let msg = canonical(b"same");
    let id = set.insert(msg.clone()).unwrap();
    assert_eq!(set.insert(msg).unwrap(), id);
    assert_eq!(set.len(), 1);
}

#[test]
fn logical_identity_commits_to_session_and_protocol_version() {
    let message = Message::new(Body::Payment(b"same event".to_vec()));
    let original = CanonicalMessage::encode(context_with(1, 1), &message).unwrap();
    let another_session = CanonicalMessage::encode(context_with(2, 1), &message).unwrap();
    let another_version = CanonicalMessage::encode(context_with(1, 2), &message).unwrap();

    assert_ne!(original.as_bytes(), another_session.as_bytes());
    assert_ne!(original.id(), another_session.id());
    assert_ne!(original.as_bytes(), another_version.as_bytes());
    assert_ne!(original.id(), another_version.id());
}

#[test]
fn context_mismatches_are_rejected_without_mutating_the_set() {
    let mut set = MessageSet::new(context_with(1, 1));
    let wrong_session = CanonicalMessage::encode(
        context_with(2, 1),
        &Message::new(Body::Payment(b"wrong session".to_vec())),
    )
    .unwrap();
    let before = set.clone();

    assert_eq!(
        set.insert(wrong_session),
        Err(MessageSetError::ContextMismatch {
            expected: context_with(1, 1),
            received: context_with(2, 1),
        })
    );
    assert_eq!(set, before);

    let other = MessageSet::new(context_with(1, 2));
    assert_eq!(
        set.merge(other),
        Err(MessageSetError::ContextMismatch {
            expected: context_with(1, 1),
            received: context_with(1, 2),
        })
    );
    assert_eq!(set, before);
}

#[test]
fn empty_set_commitment_commits_to_context() {
    let original = MessageSet::new(context_with(1, 1)).commitment();
    assert_ne!(original, MessageSet::new(context_with(2, 1)).commitment());
    assert_ne!(original, MessageSet::new(context_with(1, 2)).commitment());
}

#[test]
fn different_bytes_under_one_identity_are_rejected() {
    let first = canonical(b"first");
    let second = canonical(b"second");
    let id = first.id();
    let mut set = empty_set();
    set.insert(first).unwrap();
    assert_eq!(
        set.insert_at(id, second),
        Err(MessageSetError::IdentityCollision(IdentityCollision { id }))
    );
}

#[test]
fn merge_is_atomic_when_an_identity_collision_is_detected() {
    let incumbent = canonical(b"incumbent");
    let accepted = canonical(b"accepted");
    let conflicting = canonical(b"conflicting");
    let collision_id = incumbent.id();

    let mut left = empty_set();
    left.insert(incumbent).unwrap();
    let before = left.clone();

    let mut right = empty_set();
    right.insert(accepted).unwrap();
    right
        .insert_at(collision_id, conflicting)
        .expect("the injected id is not present in the right-hand set");

    assert_eq!(
        left.merge(right),
        Err(MessageSetError::IdentityCollision(IdentityCollision {
            id: collision_id
        }))
    );
    assert_eq!(left, before);
}

fn any_set() -> impl Strategy<Value = MessageSet> {
    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..32), 0..8).prop_map(
        |payloads| {
            let mut set = empty_set();
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
                CanonicalMessage::encode(message.context(), &message.decode()).unwrap(),
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
        let canonical = CanonicalMessage::encode(context(), &message).unwrap();
        prop_assert_eq!(crate::encoding::encoded_len(&message).unwrap(), canonical.as_bytes().len());
        prop_assert_eq!(CanonicalMessage::parse(canonical.as_bytes().to_vec()).unwrap(), canonical);
    }
}
