use crate::{
    Body, DecodeError, EncodeError, Extensions, Message, MessageContext, MessageId,
    ProtocolSessionId, ProtocolVersion, bigsize,
};

const CONTEXT_LEN: usize = 32 + 2;

/// Maximum complete canonical message size; equal to the default frame payload cap.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Validated canonical `context + header + payload + TLV extensions` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalMessage {
    context: MessageContext,
    bytes: Vec<u8>,
    id: MessageId,
}
impl CanonicalMessage {
    /// Encode and validate a typed message.
    pub fn encode(context: MessageContext, message: &Message) -> Result<Self, EncodeError> {
        Ok(Self::from_validated(
            context,
            encode_bytes(context, message)?,
        ))
    }
    /// Validate received bytes without normalizing them.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, DecodeError> {
        let context = check(&bytes)?;
        Ok(Self::from_validated(context, bytes))
    }
    /// Check borrowed bytes against the canonical form, returning only the
    /// context they commit to. Unlike [`parse`](Self::parse) it neither copies
    /// the input nor derives an identity, so a relay that validates every frame
    /// it forwards does not pay for either.
    pub fn validate(bytes: &[u8]) -> Result<MessageContext, DecodeError> {
        check(bytes)
    }
    /// Canonical bytes used by transport and identity.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Stable full logical identity.
    pub fn id(&self) -> MessageId {
        self.id
    }
    /// Logical protocol context covered by the canonical bytes and identity.
    pub const fn context(&self) -> MessageContext {
        self.context
    }
    /// Recover the validated typed representation.
    pub fn decode(&self) -> Message {
        decode(&self.bytes).expect("CanonicalMessage invariant").1
    }
    fn from_validated(context: MessageContext, bytes: Vec<u8>) -> Self {
        let id = crate::id::message_id(&bytes);
        Self { context, bytes, id }
    }
}

fn encode_bytes(context: MessageContext, message: &Message) -> Result<Vec<u8>, EncodeError> {
    let actual = encoded_len(message)?;
    if actual > MAX_MESSAGE_SIZE {
        return Err(EncodeError::TooLarge {
            max: MAX_MESSAGE_SIZE,
            actual,
        });
    }
    let mut bytes = Vec::with_capacity(actual);
    bytes.extend_from_slice(context.session_id().as_bytes());
    bytes.extend_from_slice(&context.protocol_version().to_be_bytes());
    bytes.extend_from_slice(&message.body.wire_type().to_be_bytes());
    let payload_len =
        u64::try_from(message.body.payload().len()).map_err(|_| EncodeError::LengthOverflow)?;
    bigsize::encode(payload_len, &mut bytes);
    bytes.extend_from_slice(message.body.payload());
    message.extensions.encode(&mut bytes)?;
    debug_assert_eq!(bytes.len(), actual);
    Ok(bytes)
}

fn check(bytes: &[u8]) -> Result<MessageContext, DecodeError> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(DecodeError::TooLarge {
            max: MAX_MESSAGE_SIZE,
            actual: bytes.len(),
        });
    }
    let (context, message) = decode(bytes)?;
    let canonical = encode_bytes(context, &message).map_err(|e| match e {
        EncodeError::TooLarge { max, actual } => DecodeError::TooLarge { max, actual },
        EncodeError::LengthOverflow => DecodeError::TooLarge {
            max: MAX_MESSAGE_SIZE,
            actual: bytes.len(),
        },
    })?;
    if canonical != bytes {
        return Err(DecodeError::NonCanonicalExtensions);
    }
    Ok(context)
}

pub(crate) fn encoded_len(message: &Message) -> Result<usize, EncodeError> {
    let payload = message.body.payload().len();
    let payload64 = u64::try_from(payload).map_err(|_| EncodeError::LengthOverflow)?;
    CONTEXT_LEN
        .checked_add(2)
        .and_then(|n| n.checked_add(bigsize::encoded_len(payload64)))
        .and_then(|n| n.checked_add(payload))
        .and_then(|n| message.extensions.encoded_len().ok()?.checked_add(n))
        .ok_or(EncodeError::LengthOverflow)
}

fn decode(bytes: &[u8]) -> Result<(MessageContext, Message), DecodeError> {
    let session_id = ProtocolSessionId::new(
        bytes
            .get(..32)
            .ok_or(DecodeError::UnexpectedEof)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?,
    );
    let version = ProtocolVersion::new(u16::from_be_bytes(
        bytes
            .get(32..CONTEXT_LEN)
            .ok_or(DecodeError::UnexpectedEof)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?,
    ));
    let context = MessageContext::new(session_id, version);
    let ty_bytes: [u8; 2] = bytes
        .get(CONTEXT_LEN..CONTEXT_LEN + 2)
        .ok_or(DecodeError::UnexpectedEof)?
        .try_into()
        .map_err(|_| DecodeError::UnexpectedEof)?;
    let ty = u16::from_be_bytes(ty_bytes);
    let rest = &bytes[CONTEXT_LEN + 2..];
    let (len, used) = bigsize::decode(rest)?;
    let rest = &rest[used..];
    let len = usize::try_from(len).map_err(|_| DecodeError::UnexpectedEof)?;
    let payload = rest.get(..len).ok_or(DecodeError::UnexpectedEof)?.to_vec();
    Ok((
        context,
        Message {
            body: Body::decode(ty, payload)?,
            extensions: Extensions::decode(&rest[len..])?,
        },
    ))
}
