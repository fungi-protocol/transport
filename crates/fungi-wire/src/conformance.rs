//! Fixture-driven conformance for the integer and extension codecs.
//!
//! Data transcribed from BOLT #1
//! (<https://github.com/lightning/bolts/blob/master/01-messaging.md>,
//! `01-messaging.md`, fetched 2026-09-03), Appendix A (BigSize) and
//! Appendix B (TLV streams). Kept in one module so the fixtures can be
//! read against their published source without reading the codecs.
//!
//! Appendix C (message extension, i.e. the `init` message's odd/even
//! rule at the message layer) and Appendix D (signed integers) are out
//! of scope: this crate has no message layer yet and no signed-integer
//! codec, so there is nothing in this crate for those appendices to
//! exercise.

#[cfg(test)]
mod tests {
    use crate::bigsize;
    use crate::error::DecodeError;
    use crate::tlv::TlvStream;

    fn fixture(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str.replace(' ', "")).expect("valid fixture hex")
    }

    /// (name, value, hex) — Appendix A, "BigSize Decoding Tests" and
    /// "BigSize Encoding Tests": the shared value/bytes table both
    /// sections round-trip against.
    const BIGSIZE_CANONICAL: &[(&str, u64, &str)] = &[
        ("zero", 0, "00"),
        ("one byte high", 252, "fc"),
        ("two byte low", 253, "fd00fd"),
        ("two byte high", 65535, "fdffff"),
        ("four byte low", 65536, "fe00010000"),
        ("four byte high", 4294967295, "feffffffff"),
        ("eight byte low", 4294967296, "ff0000000100000000"),
        (
            "eight byte high",
            18446744073709551615,
            "ffffffffffffffffff",
        ),
    ];

    /// (name, hex, expected) — Appendix A, "BigSize Decoding Tests"
    /// failure rows: non-canonical encodings, and every truncated-read
    /// depth (no prefix, prefix with zero/partial/all-but-one follow-up
    /// bytes).
    const BIGSIZE_INVALID: &[(&str, &str, DecodeError)] = &[
        (
            "two byte not canonical",
            "fd00fc",
            DecodeError::NonMinimalInteger,
        ),
        (
            "four byte not canonical",
            "fe0000ffff",
            DecodeError::NonMinimalInteger,
        ),
        (
            "eight byte not canonical",
            "ff00000000ffffffff",
            DecodeError::NonMinimalInteger,
        ),
        ("two byte short read", "fd00", DecodeError::UnexpectedEof),
        ("four byte short read", "feffff", DecodeError::UnexpectedEof),
        (
            "eight byte short read",
            "ffffffffff",
            DecodeError::UnexpectedEof,
        ),
        ("one byte no read", "", DecodeError::UnexpectedEof),
        ("two byte no read", "fd", DecodeError::UnexpectedEof),
        ("four byte no read", "fe", DecodeError::UnexpectedEof),
        ("eight byte no read", "ff", DecodeError::UnexpectedEof),
    ];

    /// (name, hex) — Appendix B, "TLV Decoding Successes", the rows
    /// listed under "either namespace" (unknown odd types at every
    /// BigSize width). These are the rows that catch a strict canonical
    /// decoder over-rejecting, which is its characteristic failure mode.
    const TLV_VALID: &[(&str, &str)] = &[
        ("empty", ""),
        ("unknown odd type 33", "21 00"),
        ("unknown odd type 513", "fd0201 00"),
        ("unknown odd type 253", "fd00fd 00"),
        ("unknown odd type 255", "fd00ff 00"),
        ("unknown odd type 33554433", "fe02000001 00"),
        (
            "unknown odd type 144115188075855873",
            "ff0200000000000001 00",
        ),
    ];

    /// (name, hex, expected) — Appendix B, "TLV Decoding Failures" (the
    /// "any namespace" rows: truncated type/length/value and
    /// non-minimal type/length) and "TLV Stream Decoding Failure" (the
    /// ordering and duplicate-type rows). Every row here is testable
    /// without namespace-specific value rules, which is this crate's
    /// scope boundary — see the `not applicable` block below for the
    /// rows that need namespace typing this crate does not have.
    const TLV_INVALID: &[(&str, &str, DecodeError)] = &[
        (
            "type truncated (0xfd, no bytes)",
            "fd",
            DecodeError::UnexpectedEof,
        ),
        (
            "type truncated (0xfd, one byte)",
            "fd01",
            DecodeError::UnexpectedEof,
        ),
        (
            "not minimally encoded type",
            "fd0001 00",
            DecodeError::NonMinimalInteger,
        ),
        ("missing length", "fd0101", DecodeError::UnexpectedEof),
        (
            "length truncated (0xfd, no bytes)",
            "0f fd",
            DecodeError::UnexpectedEof,
        ),
        (
            "length truncated (0xfd, one byte)",
            "0f fd26",
            DecodeError::UnexpectedEof,
        ),
        ("missing value", "0f fd2602", DecodeError::UnexpectedEof),
        (
            "not minimally encoded length",
            "0f fd0001 00",
            DecodeError::NonMinimalInteger,
        ),
        (
            "value truncated",
            concat!(
                "0f fd0201 ",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000",
            ),
            DecodeError::UnexpectedEof,
        ),
        (
            "not in ascending order",
            "0208000000000000022601012a",
            DecodeError::NonCanonicalTlv,
        ),
        (
            "duplicate type",
            "02 08 0000000000000231 02 08 0000000000000451",
            DecodeError::NonCanonicalTlv,
        ),
        (
            "ignorable duplicate type",
            "1f 00 1f 01 2a",
            DecodeError::NonCanonicalTlv,
        ),
        (
            "ignorable out of order",
            "1f 00 0f 01 2a",
            DecodeError::NonCanonicalTlv,
        ),
        (
            "not in ascending order, max-width type first",
            "ffffffffffffffffff 00 00 00",
            DecodeError::NonCanonicalTlv,
        ),
    ];

    // not applicable: the `n1` and `n2` typed namespaces (Appendix B's
    // per-type rows, both decoding-failure and decoding-success), because
    // this crate assigns no record types and so has no per-type value
    // rules to check them against (e.g. `tu64` minimality, point
    // validity, or fixed-width field lengths).
    //
    // not applicable to TlvStream: the four "unknown even type" streams
    // (0x12 00, 0xfd0102 00, 0xfe01000002 00, 0xff0100000000000002 00),
    // and the n1-only row 0x00 00 ("unknown even field for n1's
    // namespace" — even only because n1 leaves type 0 undefined; n2
    // defines it). All five parse fine here and are refused one layer
    // up, where the odd/even rule lives; encoding.rs (not yet written)
    // asserts them.
    //
    // not a concrete vector: Appendix B's "TLV Stream Decoding Failure"
    // section also states two general properties rather than giving
    // byte vectors for them — "any appending of an invalid stream to a
    // valid stream should trigger a decoding failure" and "appending a
    // higher-numbered valid stream to a lower-numbered valid stream
    // should not" — so there is nothing here to transcribe without
    // inventing the streams ourselves.

    #[test]
    fn bigsize_canonical_vectors() {
        for (name, value, hex_str) in BIGSIZE_CANONICAL {
            let bytes = fixture(hex_str);
            let mut out = Vec::new();
            bigsize::encode(*value, &mut out);
            assert_eq!(
                hex::encode(&out),
                hex_str.replace(' ', ""),
                "encoding: {name}"
            );
            assert_eq!(
                bigsize::decode(&bytes).map(|(v, _)| v),
                Ok(*value),
                "decoding: {name}"
            );
        }
    }

    #[test]
    fn bigsize_invalid_vectors() {
        for (name, hex_str, expected) in BIGSIZE_INVALID {
            assert_eq!(
                bigsize::decode(&fixture(hex_str)).as_ref(),
                Err(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn tlv_valid_vectors() {
        for (name, hex_str) in TLV_VALID {
            let bytes = fixture(hex_str);
            let stream = TlvStream::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut out = Vec::new();
            stream.encode(&mut out);
            assert_eq!(out, bytes, "{name} must re-encode verbatim");
        }
    }

    #[test]
    fn tlv_invalid_vectors() {
        for (name, hex_str, expected) in TLV_INVALID {
            assert_eq!(
                TlvStream::decode(&fixture(hex_str)).as_ref(),
                Err(expected),
                "{name}"
            );
        }
    }
}
