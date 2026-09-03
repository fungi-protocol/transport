//! Variable-length integer codec.
//!
//! One, three, five or nine bytes chosen by magnitude, big-endian after a
//! discriminant. Decoding enforces MINIMALITY: a value that would fit in
//! a shorter form is rejected. Without that rule one integer has four
//! spellings, and every structure built on this codec inherits them.

use crate::error::DecodeError;

/// Append the minimal encoding of `value`.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// Decode the integer at the start of `bytes`, returning it and how many
/// bytes it occupied. Rejects non-minimal spellings.
pub fn decode(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    let (&first, rest) = bytes.split_first().ok_or(DecodeError::UnexpectedEof)?;
    // The minimum each width is allowed to carry; anything smaller had a
    // shorter spelling available. Compared directly rather than by
    // re-encoding, because this is the hot path of what gets measured.
    let (value, width, floor) = match first {
        0xfd => (u64::from(u16::from_be_bytes(take(rest)?)), 3, 0xfd),
        0xfe => (u64::from(u32::from_be_bytes(take(rest)?)), 5, 0x1_0000),
        0xff => (u64::from_be_bytes(take(rest)?), 9, 0x1_0000_0000),
        small => return Ok((u64::from(small), 1)),
    };
    if value < floor {
        return Err(DecodeError::NonMinimalInteger);
    }
    Ok((value, width))
}

fn take<const N: usize>(bytes: &[u8]) -> Result<[u8; N], DecodeError> {
    bytes
        .get(..N)
        .ok_or(DecodeError::UnexpectedEof)?
        .try_into()
        .map_err(|_| DecodeError::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vectors_roundtrip() {
        for (value, hex_str) in [
            (0u64, "00"),
            (252, "fc"),
            (253, "fd00fd"),
            (65535, "fdffff"),
            (65536, "fe00010000"),
            (4294967295, "feffffffff"),
            (4294967296, "ff0000000100000000"),
            (18446744073709551615, "ffffffffffffffffff"),
        ] {
            let bytes = hex::decode(hex_str).expect("valid fixture hex");
            let mut out = Vec::new();
            encode(value, &mut out);
            assert_eq!(hex::encode(&out), hex_str, "encoding {value}");
            assert_eq!(
                decode(&bytes),
                Ok((value, bytes.len())),
                "decoding {hex_str}"
            );
        }
    }

    #[test]
    fn non_minimal_encodings_are_rejected() {
        for hex_str in ["fd00fc", "fe0000ffff", "ff00000000ffffffff"] {
            let bytes = hex::decode(hex_str).expect("valid fixture hex");
            assert_eq!(
                decode(&bytes),
                Err(DecodeError::NonMinimalInteger),
                "{hex_str}"
            );
        }
    }

    #[test]
    fn truncated_encodings_are_rejected() {
        for hex_str in ["", "fd00", "feffff", "ffffffffff"] {
            let bytes = hex::decode(hex_str).expect("valid fixture hex");
            assert_eq!(decode(&bytes), Err(DecodeError::UnexpectedEof), "{hex_str}");
        }
    }

    #[test]
    fn decode_reports_only_the_bytes_it_consumed() {
        let mut bytes = hex::decode("fdffff").expect("valid fixture hex");
        bytes.extend_from_slice(b"trailing");
        assert_eq!(decode(&bytes), Ok((65535, 3)));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Every value has exactly one spelling, and it round-trips.
            #[test]
            fn arbitrary_values_roundtrip(value in any::<u64>()) {
                let mut out = Vec::new();
                encode(value, &mut out);
                prop_assert_eq!(decode(&out), Ok((value, out.len())));
            }

            /// Anything that decodes re-encodes to exactly the bytes it
            /// consumed. Uniform bytes are a fine generator HERE — a
            /// leading byte below 0xfd always decodes — but nowhere above
            /// this module; see the encoding suite.
            #[test]
            fn arbitrary_bytes_are_canonical_or_rejected(
                bytes in proptest::collection::vec(any::<u8>(), 0..16),
            ) {
                if let Ok((value, used)) = decode(&bytes) {
                    let mut out = Vec::new();
                    encode(value, &mut out);
                    prop_assert_eq!(&out[..], &bytes[..used]);
                }
            }
        }
    }
}
