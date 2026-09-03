//! Protocol-level limits for canonical messages.
//!
//! The canonical message is the frame payload. The transport's four-byte
//! frame prefix is neither part of this limit nor part of message identity.

use crate::{DecodeError, EncodeError, Encoding, Message};

/// Current candidate maximum canonical-message size: one MiB.
///
/// This matches the existing framed transport default and leaves room above
/// the experiment's 64-KiB co-spend sample. A deployment may negotiate a
/// smaller value, but never a value larger than its frame-payload limit.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Encode only if the complete canonical message fits `max`.
pub fn encode_bounded<E: Encoding>(msg: &Message, max: usize) -> Result<Vec<u8>, EncodeError> {
    let actual = E::encoded_len(msg)?;
    if actual > max {
        return Err(EncodeError::TooLarge { max, actual });
    }
    E::encode(msg)
}

/// Reject an oversized frame payload before parsing or allocating its fields.
pub fn decode_bounded<E: Encoding>(bytes: &[u8], max: usize) -> Result<Message, DecodeError> {
    if bytes.len() > max {
        return Err(DecodeError::TooLarge {
            max,
            actual: bytes.len(),
        });
    }
    E::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, HeaderTlv, TlvRecord, TlvStream};

    const _: () = assert!(MAX_MESSAGE_SIZE <= fungi_transport::framed::DEFAULT_MAX_MSG_LEN);

    fn message_with_encoded_len(target: usize) -> Message {
        // These test targets stay below the first BigSize transition, so the
        // header is exactly two type bytes plus one payload-length byte.
        Message::new(Body::Payment(vec![0; target - 3]))
    }

    #[test]
    fn max_minus_one_max_and_max_plus_one_are_distinct() {
        let max = 64;
        for target in [max - 1, max] {
            let msg = message_with_encoded_len(target);
            assert_eq!(
                encode_bounded::<HeaderTlv>(&msg, max).unwrap().len(),
                target
            );
        }
        assert_eq!(
            encode_bounded::<HeaderTlv>(&message_with_encoded_len(max + 1), max),
            Err(EncodeError::TooLarge {
                max,
                actual: max + 1,
            })
        );
    }

    #[test]
    fn extensions_count_toward_the_whole_message_limit() {
        let body = Body::Payment(vec![0; 32]);
        let bare = Message::new(body.clone());
        let extended = Message {
            body,
            extensions: TlvStream::new(vec![TlvRecord {
                ty: 1001,
                value: vec![0; 16],
            }])
            .unwrap(),
        };
        let max = HeaderTlv::encoded_len(&bare).unwrap();
        assert!(encode_bounded::<HeaderTlv>(&bare, max).is_ok());
        assert!(matches!(
            encode_bounded::<HeaderTlv>(&extended, max),
            Err(EncodeError::TooLarge { .. })
        ));
    }

    #[test]
    fn oversized_input_is_rejected_before_structural_parsing() {
        assert_eq!(
            decode_bounded::<HeaderTlv>(&[0; 65], 64),
            Err(DecodeError::TooLarge {
                max: 64,
                actual: 65,
            })
        );
    }
}
