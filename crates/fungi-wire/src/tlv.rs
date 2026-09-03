use crate::{DecodeError, EncodeError, bigsize};

/// Validity-window extension: two big-endian `u64`s, `[from, until)`.
pub const EXT_VALIDITY: u64 = 2;

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
    /// Validate ordering, uniqueness, required types and known schemas.
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
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        for r in &self.0 {
            bigsize::encode(r.ty, out);
            bigsize::encode(r.value.len() as u64, out);
            out.extend_from_slice(&r.value);
        }
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
        if r.ty == EXT_VALIDITY {
            let raw: [u8; 16] = r
                .value
                .as_slice()
                .try_into()
                .map_err(|_| DecodeError::BadExtensionValue { ty: r.ty })?;
            if u64::from_be_bytes(raw[..8].try_into().unwrap())
                > u64::from_be_bytes(raw[8..].try_into().unwrap())
            {
                return Err(DecodeError::BadExtensionValue { ty: r.ty });
            }
        } else if r.ty % 2 == 0 {
            return Err(DecodeError::UnknownRequiredExtension { ty: r.ty });
        }
    }
    Ok(())
}
