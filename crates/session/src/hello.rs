use fungi_wire::{CanonicalMessage, MessageContext, ProtocolSessionId, ProtocolVersion};

use crate::{MessageSizeLimit, SessionBindingError, SessionContract};

pub(crate) const HELLO_MAGIC: [u8; 16] = *b"fungi/v1/session";
pub(crate) const HELLO_LEN: usize = HELLO_MAGIC.len() + 32 + 2 + 4;

pub(crate) fn encode(contract: SessionContract) -> [u8; HELLO_LEN] {
    let mut bytes = [0; HELLO_LEN];
    let mut cursor = 0;
    bytes[cursor..cursor + HELLO_MAGIC.len()].copy_from_slice(&HELLO_MAGIC);
    cursor += HELLO_MAGIC.len();
    bytes[cursor..cursor + 32].copy_from_slice(contract.context().session_id().as_bytes());
    cursor += 32;
    bytes[cursor..cursor + 2]
        .copy_from_slice(&contract.context().protocol_version().get().to_be_bytes());
    cursor += 2;
    bytes[cursor..].copy_from_slice(&contract.max_message_size().to_be_bytes());
    bytes
}

/// Whether bytes have the shape of a hello. Used only to classify input that
/// is already known not to be an application message.
pub(crate) fn looks_like(bytes: &[u8]) -> bool {
    bytes.len() == HELLO_LEN && bytes.starts_with(&HELLO_MAGIC)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<SessionContract, SessionBindingError> {
    if !looks_like(bytes) {
        return if CanonicalMessage::validate(bytes).is_ok() {
            Err(SessionBindingError::PrematureApplicationMessage)
        } else {
            Err(SessionBindingError::MalformedHandshake)
        };
    }

    let mut cursor = HELLO_MAGIC.len();
    let session_id = ProtocolSessionId::new(
        bytes[cursor..cursor + 32]
            .try_into()
            .expect("the exact hello length was checked"),
    );
    cursor += 32;
    let protocol_version = ProtocolVersion::new(u16::from_be_bytes(
        bytes[cursor..cursor + 2]
            .try_into()
            .expect("the exact hello length was checked"),
    ));
    cursor += 2;
    let limit = MessageSizeLimit::from_be_bytes(
        bytes[cursor..]
            .try_into()
            .expect("the exact hello length was checked"),
    )
    .map_err(|_| SessionBindingError::MalformedHandshake)?;
    Ok(SessionContract::new(
        MessageContext::new(session_id, protocol_version),
        limit,
    ))
}

pub(crate) fn validate(
    expected: SessionContract,
    received: SessionContract,
) -> Result<(), SessionBindingError> {
    if received.context().session_id() != expected.context().session_id() {
        return Err(SessionBindingError::SessionMismatch {
            expected: expected.context().session_id(),
            received: received.context().session_id(),
        });
    }
    if received.context().protocol_version() != expected.context().protocol_version() {
        return Err(SessionBindingError::VersionMismatch {
            expected: expected.context().protocol_version(),
            received: received.context().protocol_version(),
        });
    }
    if received.max_message_size() != expected.max_message_size() {
        return Err(SessionBindingError::MessageSizeLimitMismatch {
            expected: expected.max_message_size(),
            received: received.max_message_size(),
        });
    }
    Ok(())
}
