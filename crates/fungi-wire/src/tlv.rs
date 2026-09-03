use crate::{DecodeError, EncodeError, bigsize};

/// One typed extension record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Extension registry number.
    pub ty: u64,
    /// Opaque encoded value.
    pub value: Vec<u8>,
}

/// Strictly increasing extension stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions(Vec<Extension>);
impl Extensions {
    /// Validate ordering, uniqueness, and required types.
    pub fn new(records: Vec<Extension>) -> Result<Self, DecodeError> {
        if records.windows(2).any(|w| w[0].ty >= w[1].ty) {
            return Err(DecodeError::NonCanonicalExtensions);
        }
        validate(&records)?;
        Ok(Self(records))
    }
    /// Records in canonical type order.
    pub fn records(&self) -> &[Extension] {
        &self.0
    }
    pub(crate) fn encoded_len(&self) -> Result<usize, EncodeError> {
        self.0.iter().try_fold(0usize, |n, r| {
            let len = u64::try_from(r.value.len()).map_err(|_| EncodeError::LengthOverflow)?;
            n.checked_add(bigsize::encoded_len(r.ty))
                .and_then(|n| n.checked_add(bigsize::encoded_len(len)))
                .and_then(|n| n.checked_add(r.value.len()))
                .ok_or(EncodeError::LengthOverflow)
        })
    }
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        for r in &self.0 {
            bigsize::encode(r.ty, out);
            let len = u64::try_from(r.value.len()).map_err(|_| EncodeError::LengthOverflow)?;
            bigsize::encode(len, out);
            out.extend_from_slice(&r.value);
        }
        Ok(())
    }
    pub(crate) fn decode(mut bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut records = Vec::new();
        while !bytes.is_empty() {
            let (ty, n) = bigsize::decode(bytes)?;
            bytes = &bytes[n..];
            let (len, n) = bigsize::decode(bytes)?;
            bytes = &bytes[n..];
            let len = usize::try_from(len).map_err(|_| DecodeError::UnexpectedEof)?;
            let value = bytes.get(..len).ok_or(DecodeError::UnexpectedEof)?.to_vec();
            bytes = &bytes[len..];
            records.push(Extension { ty, value });
        }
        Self::new(records)
    }
}
fn validate(records: &[Extension]) -> Result<(), DecodeError> {
    for r in records {
        if r.ty % 2 == 0 {
            return Err(DecodeError::UnknownRequiredExtension { ty: r.ty });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt_one_unknown_odd_vectors_are_preserved() {
        for encoded in [
            "",
            "2100",
            "fd020100",
            "fd00fd00",
            "fd00ff00",
            "fe0200000100",
            "ff020000000000000100",
        ] {
            let bytes = hex::decode(encoded).expect("valid fixture hex");
            let stream = Extensions::decode(&bytes).expect("unknown odd record is optional");
            let mut out = Vec::new();
            stream.encode(&mut out).unwrap();
            assert_eq!(out, bytes, "{encoded}");
        }
    }

    #[test]
    fn bolt_one_unknown_even_vectors_fail() {
        for encoded in ["1200", "fd010200", "fe0100000200", "ff010000000000000200"] {
            assert!(matches!(
                Extensions::decode(&hex::decode(encoded).expect("valid fixture hex")),
                Err(DecodeError::UnknownRequiredExtension { .. })
            ));
        }
    }

    #[test]
    fn bolt_one_malformed_stream_vectors_fail() {
        for encoded in [
            "fd",
            "fd01",
            "fd000100",
            "fd0101",
            "0ffd",
            "0ffd26",
            "0ffd2602",
            "0ffd000100",
            "0208000000000000022601012a",
            "0208000000000000023102080000000000000451",
            "1f000f012a",
            "1f001f012a",
        ] {
            assert!(
                Extensions::decode(&hex::decode(encoded).expect("valid fixture hex")).is_err(),
                "{encoded}"
            );
        }
    }
}
