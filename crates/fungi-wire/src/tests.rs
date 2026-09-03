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
        CanonicalMessage::parse(message.as_bytes().to_vec()).unwrap(),
        message
    );
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
fn duplicate_insertion_is_idempotent() {
    let mut set = MessageSet::default();
    let msg = canonical(b"same");
    let id = set.insert(msg.clone()).unwrap();
    assert_eq!(set.insert(msg).unwrap(), id);
    assert_eq!(set.len(), 1);
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
}
