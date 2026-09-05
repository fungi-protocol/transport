use crate::DecodeError;

pub(crate) const fn encoded_len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

pub(crate) fn encode(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    let (&first, rest) = bytes.split_first().ok_or(DecodeError::UnexpectedEof)?;
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
    fn bolt_one_canonical_vectors_roundtrip() {
        for (value, encoded) in [
            (0, "00"),
            (252, "fc"),
            (253, "fd00fd"),
            (65_535, "fdffff"),
            (65_536, "fe00010000"),
            (4_294_967_295, "feffffffff"),
            (4_294_967_296, "ff0000000100000000"),
            (u64::MAX, "ffffffffffffffffff"),
        ] {
            let bytes = hex::decode(encoded).expect("valid fixture hex");
            let mut out = Vec::new();
            encode(value, &mut out);
            assert_eq!(out, bytes, "encoding {value}");
            assert_eq!(decode(&bytes), Ok((value, bytes.len())), "decoding {value}");
        }
    }

    #[test]
    fn bolt_one_nonminimal_vectors_fail() {
        for encoded in ["fd00fc", "fe0000ffff", "ff00000000ffffffff"] {
            assert_eq!(
                decode(&hex::decode(encoded).expect("valid fixture hex")),
                Err(DecodeError::NonMinimalInteger),
                "{encoded}"
            );
        }
    }

    #[test]
    fn bolt_one_truncated_vectors_fail() {
        for encoded in ["", "fd", "fd00", "fe", "feffff", "ff", "ffffffffff"] {
            assert_eq!(
                decode(&hex::decode(encoded).expect("valid fixture hex")),
                Err(DecodeError::UnexpectedEof),
                "{encoded}"
            );
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(256))]

        #[test]
        fn every_value_has_one_roundtripping_spelling(value in proptest::prelude::any::<u64>()) {
            let mut bytes = Vec::new();
            encode(value, &mut bytes);
            proptest::prop_assert_eq!(decode(&bytes), Ok((value, bytes.len())));
        }
    }
}
