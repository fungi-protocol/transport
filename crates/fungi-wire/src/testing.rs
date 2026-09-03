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
            ty: 2 * i + 1 + (seed % 7),
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
