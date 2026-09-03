//! Deterministically encoded CBOR candidate.
//!
//! The data model is deliberately smaller than general CBOR: one fixed map
//! with unsigned integer keys, byte strings, and definite-length arrays.

use super::{Encoding, validate_extensions};
use crate::error::{DecodeError, EncodeError};
use crate::message::{Body, Message};
use crate::tlv::{TlvRecord, TlvStream};

/// A whole-message CBOR map using RFC 8949 core deterministic encoding.
#[derive(Debug)]
pub enum DeterministicCbor {}

impl Encoding for DeterministicCbor {
    const NAME: &'static str = "deterministic-cbor";

    fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        head(5, 3, &mut out); // { 1: type, 2: payload, 3: extensions }
        head(0, 1, &mut out);
        head(0, u64::from(msg.body.wire_type()), &mut out);
        head(0, 2, &mut out);
        bytes(msg.body.payload(), &mut out);
        head(0, 3, &mut out);
        head(4, len(msg.extensions.records().len()), &mut out);
        for record in msg.extensions.records() {
            head(4, 2, &mut out);
            head(0, record.ty, &mut out);
            bytes(&record.value, &mut out);
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let mut input = Input::new(bytes);
        input.exact(5, 3)?;
        input.exact(0, 1)?;
        let ty = u16::try_from(input.unsigned()?).map_err(|_| DecodeError::BadBody)?;
        input.exact(0, 2)?;
        let payload = input.byte_string()?.to_vec();
        input.exact(0, 3)?;
        let count = input.array_len()?;
        let mut records = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            input.exact(4, 2)?;
            records.push(TlvRecord {
                ty: input.unsigned()?,
                value: input.byte_string()?.to_vec(),
            });
        }
        if !input.remaining().is_empty() {
            return Err(DecodeError::BadBody);
        }
        let extensions = TlvStream::new(records)?;
        validate_extensions(&extensions)?;
        Ok(Message {
            body: Body::from_wire_type(ty, payload)?,
            extensions,
        })
    }
}

fn len(value: usize) -> u64 {
    u64::try_from(value).expect("Rust targets cannot address more than u64::MAX bytes")
}

fn bytes(value: &[u8], out: &mut Vec<u8>) {
    head(2, len(value.len()), out);
    out.extend_from_slice(value);
}

fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .at
            .checked_add(count)
            .ok_or(DecodeError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(DecodeError::UnexpectedEof)?;
        self.at = end;
        Ok(value)
    }

    fn head(&mut self) -> Result<(u8, u64), DecodeError> {
        let first = *self.take(1)?.first().ok_or(DecodeError::UnexpectedEof)?;
        let major = first >> 5;
        let additional = first & 0x1f;
        let value = match additional {
            value @ 0..=23 => u64::from(value),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                if value < 24 {
                    return Err(DecodeError::NonMinimalInteger);
                }
                value
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap()));
                if value <= 0xff {
                    return Err(DecodeError::NonMinimalInteger);
                }
                value
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap()));
                if value <= 0xffff {
                    return Err(DecodeError::NonMinimalInteger);
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if value <= 0xffff_ffff {
                    return Err(DecodeError::NonMinimalInteger);
                }
                value
            }
            _ => return Err(DecodeError::BadBody),
        };
        Ok((major, value))
    }

    fn exact(&mut self, major: u8, value: u64) -> Result<(), DecodeError> {
        if self.head()? == (major, value) {
            Ok(())
        } else {
            Err(DecodeError::BadBody)
        }
    }

    fn unsigned(&mut self) -> Result<u64, DecodeError> {
        let (major, value) = self.head()?;
        (major == 0).then_some(value).ok_or(DecodeError::BadBody)
    }

    fn array_len(&mut self) -> Result<usize, DecodeError> {
        let (major, value) = self.head()?;
        if major != 4 {
            return Err(DecodeError::BadBody);
        }
        usize::try_from(value).map_err(|_| DecodeError::BadBody)
    }

    fn byte_string(&mut self) -> Result<&'a [u8], DecodeError> {
        let (major, value) = self.head()?;
        if major != 2 {
            return Err(DecodeError::BadBody);
        }
        let count = usize::try_from(value).map_err(|_| DecodeError::UnexpectedEof)?;
        self.take(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(hex: &str) -> Result<Message, DecodeError> {
        DeterministicCbor::decode(&hex::decode(hex).expect("fixture hex"))
    }

    #[test]
    fn fixed_shape_is_byte_exact() {
        let msg = Message::new(Body::Payment(b"hello".to_vec()));
        assert_eq!(
            hex::encode(DeterministicCbor::encode(&msg).unwrap()),
            "a30103024568656c6c6f0380"
        );
    }

    #[test]
    fn rejects_valid_but_nondeterministic_spellings() {
        // Type 3 is needlessly encoded with an additional byte.
        assert_eq!(
            decode("a3011803024568656c6c6f0380"),
            Err(DecodeError::NonMinimalInteger)
        );
        // Indefinite outer map and an alternative field order.
        assert_eq!(decode("bf010302400380ff"), Err(DecodeError::BadBody));
        assert_eq!(decode("a3024001030380"), Err(DecodeError::BadBody));
    }

    #[test]
    fn rejects_truncated_and_malformed_structure() {
        assert_eq!(
            decode("a30103024568656c6c6f"),
            Err(DecodeError::UnexpectedEof)
        );
        assert_eq!(
            decode("a30103024568656c6c6f038000"),
            Err(DecodeError::BadBody)
        );
        assert_eq!(
            decode("a30103024568656c6c6f038181020140"),
            Err(DecodeError::BadBody)
        );
    }
}
