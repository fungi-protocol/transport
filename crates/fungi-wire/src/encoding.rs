//! Candidate wire encodings.
//!
//! Three shapes behind one trait so the cost of each is measured rather
//! than argued. All are CANONICAL: decoding rejects any spelling other
//! than the one encoding would have produced, because normalizing would
//! give one message two byte strings and identity is a hash of the byte
//! string.

use crate::bigsize;
use crate::error::{DecodeError, EncodeError};
use crate::message::{Body, Message};
use crate::tlv::TlvStream;

/// The one assigned extension type: a validity window, as two big-endian
/// u64s. EVEN, therefore mandatory — a node that ignored it would apply a
/// different replacement rule than its peers and diverge.
pub const EXT_VALIDITY: u64 = 2;

/// Extension record types this build understands.
pub(crate) fn known_extension_type(ty: u64) -> bool {
    ty == EXT_VALIDITY
}

/// The odd/even rule for extension records: an unknown odd record is
/// carried along, an unknown even record is refused. A node that silently
/// dropped either would re-encode a different message.
pub(crate) fn reject_unknown_even(extensions: &TlvStream) -> Result<(), DecodeError> {
    for rec in extensions.records() {
        if rec.ty % 2 == 0 && !known_extension_type(rec.ty) {
            return Err(DecodeError::UnknownEvenExtension { ty: rec.ty });
        }
    }
    Ok(())
}

/// A candidate encoding.
///
/// `encode` is fallible: a shape may be unable to represent every
/// `Message`, and which messages a candidate can carry at all is part of
/// what is being compared.
pub trait Encoding {
    /// Name used in reports.
    const NAME: &'static str;

    /// The message's canonical byte string.
    fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError>;

    /// Decode, rejecting any non-canonical spelling.
    fn decode(bytes: &[u8]) -> Result<Message, DecodeError>;
}

/// A fixed two-byte big-endian type, a length-delimited payload, then the
/// extension stream to the end of the buffer.
///
/// The payload carries its own length so an inner message can be lifted
/// out verbatim, which is what lets one message be another's payload
/// without either being re-encoded.
#[derive(Debug)]
pub enum HeaderTlv {}

impl Encoding for HeaderTlv {
    const NAME: &'static str = "header+tlv";

    fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError> {
        let payload = msg.body.payload();
        let mut out = Vec::with_capacity(payload.len() + 16);
        out.extend_from_slice(&msg.body.wire_type().to_be_bytes());
        bigsize::encode(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        msg.extensions.encode(&mut out);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let header: [u8; 2] = bytes
            .get(..2)
            .ok_or(DecodeError::UnexpectedEof)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?;
        let ty = u16::from_be_bytes(header);
        let rest = &bytes[2..];
        let (len, used) = bigsize::decode(rest)?;
        let rest = &rest[used..];
        let len = usize::try_from(len).map_err(|_| DecodeError::UnexpectedEof)?;
        let payload = rest.get(..len).ok_or(DecodeError::UnexpectedEof)?.to_vec();
        let body = Body::from_wire_type(ty, payload)?;
        let extensions = TlvStream::decode(&rest[len..])?;
        reject_unknown_even(&extensions)?;
        Ok(Message { body, extensions })
    }
}

/// The whole message as one extension stream: record 1 carries the kind,
/// record 2 the payload, everything above 2 is an extension.
///
/// Uniformity costs a namespace — types 1 and 2 are spent on structure
/// and cannot be assigned — and a message with no extensions still pays
/// two record headers.
#[derive(Debug)]
pub enum AllTlv {}

/// Record type carrying the message kind.
const KIND_RECORD: u64 = 1;
/// Record type carrying the payload.
const PAYLOAD_RECORD: u64 = 2;

impl Encoding for AllTlv {
    const NAME: &'static str = "all-tlv";

    fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError> {
        if let Some(rec) = msg
            .extensions
            .records()
            .iter()
            .find(|r| r.ty <= PAYLOAD_RECORD)
        {
            return Err(EncodeError::ReservedExtensionType { ty: rec.ty });
        }
        let mut out = Vec::new();
        bigsize::encode(KIND_RECORD, &mut out);
        bigsize::encode(2, &mut out);
        out.extend_from_slice(&msg.body.wire_type().to_be_bytes());
        let payload = msg.body.payload();
        bigsize::encode(PAYLOAD_RECORD, &mut out);
        bigsize::encode(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        msg.extensions.encode(&mut out);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        // Records are MOVED out, never cloned. Cloning here would charge
        // this format for allocations belonging to the stream type's
        // borrowing API, and the whole point of the comparison is to
        // charge each format only for itself.
        let mut records = TlvStream::decode(bytes)?.into_records();
        if records.len() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let extensions =
            TlvStream::new(records.split_off(2)).expect("a canonical stream's tail is canonical");
        let payload = records.pop().expect("length checked above");
        let kind = records.pop().expect("length checked above");
        if kind.ty != KIND_RECORD || payload.ty != PAYLOAD_RECORD {
            return Err(DecodeError::NonCanonicalTlv);
        }
        let ty: [u8; 2] = kind
            .value
            .as_slice()
            .try_into()
            .map_err(|_| DecodeError::BadBody)?;
        let body = Body::from_wire_type(u16::from_be_bytes(ty), payload.value)?;
        reject_unknown_even(&extensions)?;
        Ok(Message { body, extensions })
    }
}

/// Carry `inner` as the payload of a block, verbatim.
///
/// The inner message is not re-encoded on the way in or out, so its
/// identity is the same whether it travels alone or wrapped. That is what
/// allows a Byzantine layer to arrive as new message kinds instead of as
/// new fields on every existing message.
pub fn wrap<E: Encoding>(inner: &Message) -> Result<Message, EncodeError> {
    Ok(Message::new(Body::Block(E::encode(inner)?)))
}

/// Recover the message a block carries.
pub fn unwrap_block<E: Encoding>(outer: &Message) -> Result<Message, DecodeError> {
    match &outer.body {
        Body::Block(payload) => E::decode(payload),
        _ => Err(DecodeError::BadBody),
    }
}

#[cfg(test)]
pub(crate) mod suite {
    /// The assertions every candidate must satisfy, instantiated once per
    /// encoding inside its own module so the generated test names do not
    /// collide.
    macro_rules! encoding_suite {
        ($mod_name:ident, $enc:ty) => {
            mod $mod_name {
                use proptest::prelude::*;
                use $crate::encoding::Encoding;
                use $crate::error::DecodeError;
                use $crate::message::{Body, Message};
                use $crate::testing;
                use $crate::tlv::{TlvRecord, TlvStream};

                type Enc = $enc;

                fn enc(msg: &Message) -> Vec<u8> {
                    <Enc as Encoding>::encode(msg).expect("suite messages are encodable")
                }

                #[test]
                fn empty_input_is_rejected() {
                    assert!(<Enc as Encoding>::decode(&[]).is_err());
                }

                #[test]
                fn an_unknown_even_extension_is_a_hard_failure() {
                    let msg = Message {
                        body: Body::Psbt(b"x".to_vec()),
                        extensions: TlvStream::new(vec![TlvRecord {
                            ty: 1000,
                            value: b"y".to_vec(),
                        }])
                        .expect("canonical"),
                    };
                    let bytes = enc(&msg);
                    assert_eq!(
                        <Enc as Encoding>::decode(&bytes),
                        Err(DecodeError::UnknownEvenExtension { ty: 1000 })
                    );
                }

                #[test]
                fn an_unknown_odd_extension_survives_verbatim() {
                    let msg = Message {
                        body: Body::Psbt(b"x".to_vec()),
                        extensions: TlvStream::new(vec![TlvRecord {
                            ty: 1001,
                            value: b"y".to_vec(),
                        }])
                        .expect("canonical"),
                    };
                    assert_eq!(<Enc as Encoding>::decode(&enc(&msg)), Ok(msg));
                }

                #[test]
                fn a_wrapped_message_keeps_its_identity() {
                    let inner = Message::new(Body::Psbt(b"inner payload".to_vec()));
                    let inner_bytes = enc(&inner);
                    let outer = $crate::encoding::wrap::<Enc>(&inner)
                        .expect("a block with no extensions is encodable");
                    let recovered = $crate::encoding::unwrap_block::<Enc>(&outer)
                        .expect("the block's payload is an encoded message");
                    assert_eq!(recovered, inner);
                    assert_eq!(
                        $crate::message_id(&enc(&recovered)),
                        $crate::message_id(&inner_bytes)
                    );
                }

                /// The guard against a silently vacuous property: if too
                /// few mutations reach the decoder, the canonicity
                /// assertion below is asserting nothing.
                #[test]
                fn the_canonicity_property_is_not_vacuous() {
                    let reached = testing::count_accepted(
                        4096,
                        |bytes| <Enc as Encoding>::decode(bytes).is_ok(),
                        |seed| enc(&testing::sample_message(seed)),
                    );
                    assert!(reached > 256, "only {reached}/4096 mutations decoded");
                }

                proptest! {
                    #![proptest_config(ProptestConfig::with_cases(128))]

                    /// Decode inverts encode.
                    #[test]
                    fn messages_roundtrip(msg in testing::any_encodable_message()) {
                        prop_assert_eq!(<Enc as Encoding>::decode(&enc(&msg)), Ok(msg));
                    }

                    /// The direction that matters: no second spelling of a
                    /// message survives a decode. Fed from valid encodings
                    /// under mutation — uniform bytes reach these decoders
                    /// 0 times in 200 000, so a property fed on them would
                    /// pass while asserting nothing.
                    #[test]
                    fn mutated_encodings_are_canonical_or_rejected(
                        bytes in testing::mutated_encoding::<Enc>(),
                    ) {
                        if let Ok(msg) = <Enc as Encoding>::decode(&bytes) {
                            prop_assert_eq!(enc(&msg), bytes);
                        }
                    }

                    /// Identity is computable from bytes that never parsed.
                    #[test]
                    fn identity_needs_no_parse(
                        bytes in testing::mutated_encoding::<Enc>(),
                    ) {
                        let id = $crate::message_id(&bytes);
                        if let Ok(msg) = <Enc as Encoding>::decode(&bytes) {
                            prop_assert_eq!($crate::message_id(&enc(&msg)), id);
                        }
                    }

                    /// Nesting is transparent: the inner bytes come back
                    /// byte for byte, at depth one and two.
                    #[test]
                    fn nesting_preserves_the_inner_bytes(
                        inner in testing::any_encodable_message(),
                    ) {
                        let inner_bytes = enc(&inner);
                        let once = $crate::encoding::wrap::<Enc>(&inner).unwrap();
                        let decoded = <Enc as Encoding>::decode(&enc(&once)).unwrap();
                        let recovered =
                            $crate::encoding::unwrap_block::<Enc>(&decoded).unwrap();
                        prop_assert_eq!(enc(&recovered), inner_bytes);

                        let twice = $crate::encoding::wrap::<Enc>(&once).unwrap();
                        let out = $crate::encoding::unwrap_block::<Enc>(
                            &$crate::encoding::unwrap_block::<Enc>(&twice).unwrap(),
                        )
                        .unwrap();
                        prop_assert_eq!(out, inner);
                    }
                }
            }
        };
    }

    encoding_suite!(header_tlv, crate::encoding::HeaderTlv);
    encoding_suite!(all_tlv, crate::encoding::AllTlv);

    /// Where the two shapes genuinely differ: the uniform stream spends
    /// record types on its own structure, so there are messages it cannot
    /// represent and the header shape can. A finding, not a bug — which is
    /// why it is a typed error rather than a panic.
    #[test]
    fn only_the_uniform_shape_reserves_extension_types() {
        use crate::encoding::{AllTlv, Encoding, HeaderTlv};
        use crate::error::EncodeError;
        use crate::message::{Body, Message};
        use crate::tlv::{TlvRecord, TlvStream};

        let msg = Message {
            body: Body::Psbt(b"x".to_vec()),
            extensions: TlvStream::new(vec![TlvRecord {
                ty: 1,
                value: b"y".to_vec(),
            }])
            .expect("canonical"),
        };
        assert!(HeaderTlv::encode(&msg).is_ok());
        assert_eq!(
            AllTlv::encode(&msg),
            Err(EncodeError::ReservedExtensionType { ty: 1 })
        );
    }

    /// The sharper consequence: `EXT_VALIDITY` is 2, exactly the record
    /// type `AllTlv` reserves for its payload, so the uniform shape cannot
    /// carry the protocol's one assigned extension type at all — not just
    /// some hypothetical low-numbered one.
    #[test]
    fn the_uniform_shape_cannot_carry_the_assigned_extension() {
        use crate::encoding::{AllTlv, EXT_VALIDITY, Encoding, HeaderTlv};
        use crate::error::EncodeError;
        use crate::message::{Body, Message};
        use crate::tlv::{TlvRecord, TlvStream};

        let msg = Message {
            body: Body::Psbt(b"x".to_vec()),
            extensions: TlvStream::new(vec![TlvRecord {
                ty: EXT_VALIDITY,
                value: vec![0u8; 16],
            }])
            .expect("canonical"),
        };
        assert!(HeaderTlv::encode(&msg).is_ok());
        assert_eq!(
            AllTlv::encode(&msg),
            Err(EncodeError::ReservedExtensionType { ty: EXT_VALIDITY })
        );
    }
}
