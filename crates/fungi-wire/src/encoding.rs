use crate::{Body, DecodeError, EncodeError, Extensions, Message, MessageId, bigsize};

/// Maximum complete canonical message size; equal to the default frame payload cap.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Validated canonical `header + payload-length + payload + TLV extensions` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalMessage {
    bytes: Vec<u8>,
    id: MessageId,
}
impl CanonicalMessage {
    /// Encode and validate a typed message.
    pub fn encode(message: &Message) -> Result<Self, EncodeError> {
        let actual = encoded_len(message)?;
        if actual > MAX_MESSAGE_SIZE {
            return Err(EncodeError::TooLarge {
                max: MAX_MESSAGE_SIZE,
                actual,
            });
        }
        let mut bytes = Vec::with_capacity(actual);
        bytes.extend_from_slice(&message.body.wire_type().to_be_bytes());
        let payload_len =
            u64::try_from(message.body.payload().len()).map_err(|_| EncodeError::LengthOverflow)?;
        bigsize::encode(payload_len, &mut bytes);
        bytes.extend_from_slice(message.body.payload());
        message.extensions.encode(&mut bytes)?;
        debug_assert_eq!(bytes.len(), actual);
        Ok(Self::from_validated(bytes))
    }
    /// Validate received bytes without normalizing them.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(DecodeError::TooLarge {
                max: MAX_MESSAGE_SIZE,
                actual: bytes.len(),
            });
        }
        let message = decode(&bytes)?;
        let canonical = Self::encode(&message).map_err(|e| match e {
            EncodeError::TooLarge { max, actual } => DecodeError::TooLarge { max, actual },
            EncodeError::LengthOverflow => DecodeError::TooLarge {
                max: MAX_MESSAGE_SIZE,
                actual: bytes.len(),
            },
        })?;
        if canonical.bytes != bytes {
            return Err(DecodeError::NonCanonicalExtensions);
        }
        Ok(canonical)
    }
    /// Canonical bytes used by transport and identity.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Stable full logical identity.
    pub fn id(&self) -> MessageId {
        self.id
    }
    /// Recover the validated typed representation.
    pub fn decode(&self) -> Message {
        decode(&self.bytes).expect("CanonicalMessage invariant")
    }
    fn from_validated(bytes: Vec<u8>) -> Self {
        let id = crate::id::message_id(&bytes);
        Self { bytes, id }
    }
}

pub(crate) fn encoded_len(message: &Message) -> Result<usize, EncodeError> {
    let payload = message.body.payload().len();
    let payload64 = u64::try_from(payload).map_err(|_| EncodeError::LengthOverflow)?;
    2usize
        .checked_add(bigsize::encoded_len(payload64))
        .and_then(|n| n.checked_add(payload))
        .and_then(|n| message.extensions.encoded_len().ok()?.checked_add(n))
        .ok_or(EncodeError::LengthOverflow)
}

fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
    let ty_bytes: [u8; 2] = bytes
        .get(..2)
        .ok_or(DecodeError::UnexpectedEof)?
        .try_into()
        .map_err(|_| DecodeError::UnexpectedEof)?;
    let ty = u16::from_be_bytes(ty_bytes);
    let rest = &bytes[2..];
    let (len, used) = bigsize::decode(rest)?;
    let rest = &rest[used..];
    let len = usize::try_from(len).map_err(|_| DecodeError::UnexpectedEof)?;
    let payload = rest.get(..len).ok_or(DecodeError::UnexpectedEof)?.to_vec();
    Ok(Message {
        body: Body::decode(ty, payload)?,
        extensions: Extensions::decode(&rest[len..])?,
    })
}
