//! Test helpers shared across the modules' property suites.
//!
//! Uniform random bytes essentially never reach a canonical decoder — a
//! decoder that accepts one spelling out of many rejects almost every
//! draw — so a property fed on them asserts nothing while appearing to
//! pass. Everything here exists to feed decoders inputs that are VALID
//! encodings under small mutation, and to fail loudly when too few of
//! them get through.

use crate::tlv::{TlvRecord, TlvStream};

/// Apply one mutation to `bytes`: 0 replaces a byte, 1 appends one, 2
/// truncates the tail.
pub(crate) fn mutate(mut bytes: Vec<u8>, idx: usize, val: u8, kind: u8) -> Vec<u8> {
    match kind {
        0 if !bytes.is_empty() => {
            let i = idx % bytes.len();
            bytes[i] = val;
        }
        1 => bytes.push(val),
        _ if !bytes.is_empty() => {
            let i = idx % bytes.len();
            bytes.truncate(i);
        }
        _ => {}
    }
    bytes
}

/// A small deterministic stream derived from `seed`, for the
/// non-vacuity counters (which must not depend on proptest).
pub(crate) fn sample_stream(seed: u64) -> TlvStream {
    let count = seed % 3;
    let records = (0..count)
        .map(|i| TlvRecord {
            ty: 2 * i + 1001 + 2 * (seed % 7),
            value: vec![(seed >> (8 * i)) as u8; (seed as usize >> 3) % 5],
        })
        .collect::<Vec<_>>();
    // The types above are strictly increasing in i, so this holds.
    TlvStream::new(records).expect("generated records are ordered")
}

/// Run `budget` deterministic mutations of `build(seed)` through
/// `accepts`, and report how many NON-EMPTY ones were accepted.
///
/// Empty input never counts. Every decoder here accepts it trivially —
/// an empty buffer is a valid empty stream — and a mutation of empty
/// bytes is frequently no mutation at all, so counting those would let
/// this guard clear its floor while the mutation and decode logic it
/// exists to watch were entirely broken.
pub(crate) fn count_accepted(
    budget: u64,
    accepts: impl Fn(&[u8]) -> bool,
    build: impl Fn(u64) -> Vec<u8>,
) -> u64 {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut reached = 0;
    for seed in 0..budget {
        // xorshift: a fixed generator, so a failure reproduces exactly.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = mutate(
            build(seed),
            state as usize,
            (state >> 32) as u8,
            (state >> 16) as u8 % 3,
        );
        if !bytes.is_empty() && accepts(&bytes) {
            reached += 1;
        }
    }
    reached
}

use crate::encoding::Encoding;
use crate::message::{Body, Message};
use proptest::prelude::Strategy;

/// Test-only join operation used to check semilattice laws without coupling
/// this experiment to an application crate.
pub(crate) trait Join: Sized {
    fn join(self, other: Self) -> Self;
}

/// Messages every candidate encoding can represent: extension types are
/// odd and above every reserved range, so no candidate rejects them and
/// all four are compared over one domain. The reserved-type behaviour is
/// asserted separately, per encoding, where it differs.
pub(crate) fn any_encodable_message() -> impl Strategy<Value = Message> {
    use proptest::prelude::*;
    let bodies = proptest::collection::vec(any::<u8>(), 0..64).prop_flat_map(|p| {
        prop_oneof![
            Just(Body::Psbt(p.clone())),
            Just(Body::Payment(p.clone())),
            Just(Body::Confirmation(p.clone())),
            Just(Body::ListenAdvertisement(p.clone())),
            Just(Body::Block(p.clone())),
            Just(Body::ValidityProof(p)),
        ]
    });
    (
        bodies,
        crate::tlv::tests::properties::any_stream((0u64..500).prop_map(|n| n * 2 + 1001)),
    )
        .prop_map(|(body, extensions)| Message { body, extensions })
}

/// A valid encoding of a message, under one mutation.
pub(crate) fn mutated_encoding<E: Encoding>() -> impl Strategy<Value = Vec<u8>> {
    use proptest::prelude::*;
    (any_encodable_message(), any::<usize>(), any::<u8>(), 0u8..3).prop_map(
        |(msg, idx, val, kind)| {
            let bytes = E::encode(&msg).expect("generated messages are encodable");
            mutate(bytes, idx, val, kind)
        },
    )
}

/// A small deterministic message derived from `seed`, for the
/// non-vacuity counters, which must not depend on proptest.
pub(crate) fn sample_message(seed: u64) -> Message {
    let payload = vec![seed as u8; (seed as usize) % 8];
    let body = match seed % 6 {
        0 => Body::Psbt(payload),
        1 => Body::Payment(payload),
        2 => Body::Confirmation(payload),
        3 => Body::ListenAdvertisement(payload),
        4 => Body::Block(payload),
        _ => Body::ValidityProof(payload),
    };
    Message {
        body,
        extensions: sample_stream(seed),
    }
}
