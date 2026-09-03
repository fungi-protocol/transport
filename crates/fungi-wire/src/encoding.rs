//! Candidate wire encodings.
//!
//! Four shapes behind one trait so the cost of each is measured rather
//! than argued. All are CANONICAL: decoding rejects any spelling other
//! than the one encoding would have produced, because normalizing would
//! give one message two byte strings and identity is a hash of the byte
//! string.

use crate::bigsize;
use crate::error::{DecodeError, EncodeError};
use crate::fold::Validity;
use crate::message::{Body, Message};
use crate::tlv::TlvStream;

mod cbor;
pub use cbor::DeterministicCbor;

/// The one assigned extension type: a validity window, as two big-endian
/// u64s. EVEN, therefore mandatory — a node that ignored it would apply a
/// different replacement rule than its peers and diverge.
pub const EXT_VALIDITY: u64 = 2;

/// Extension record types this build understands.
pub(crate) fn known_extension_type(ty: u64) -> bool {
    ty == EXT_VALIDITY
}

/// The two rules an extension stream must satisfy at the message layer.
///
/// The odd/even rule on TYPES: an unknown odd record is carried along, an
/// unknown even record is refused. A node that silently dropped either
/// would re-encode a different message.
///
/// And, for a known even type, its value must parse. Nothing about the
/// odd/even scheme itself can enforce that — the envelope sees a type and
/// an opaque byte string, so a value rule needs a per-type schema, which
/// only a build that knows the type has. Accepting a value it cannot read
/// would put back exactly the divergence the even bit exists to prevent,
/// one level down; for a validity window it would also be the worst
/// available reading, since a window that is dropped rather than refused
/// makes the message unconditionally valid forever.
pub(crate) fn validate_extensions(extensions: &TlvStream) -> Result<(), DecodeError> {
    for rec in extensions.records() {
        if rec.ty % 2 == 0 && !known_extension_type(rec.ty) {
            return Err(DecodeError::UnknownEvenExtension { ty: rec.ty });
        }
        if rec.ty == EXT_VALIDITY {
            let bad = DecodeError::BadExtensionValue { ty: rec.ty };
            let window = Validity::decode(&rec.value).ok_or(bad.clone())?;
            // An inverted window covers no instant at all, so it can only
            // be a mistake or a probe; two builds that each guessed at
            // what it meant would not have to guess the same way.
            if window.from > window.until {
                return Err(bad);
            }
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

    /// Exact number of bytes [`encode`](Self::encode) will produce.
    fn encoded_len(msg: &Message) -> Result<usize, EncodeError>;

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
        // No shape pre-sizes its buffer. Giving one a head start would
        // charge the others for an implementation choice rather than for
        // the format, which is the comparison this crate exists to make.
        let mut out = Vec::new();
        out.extend_from_slice(&msg.body.wire_type().to_be_bytes());
        bigsize::encode(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        msg.extensions.encode(&mut out);
        Ok(out)
    }

    fn encoded_len(msg: &Message) -> Result<usize, EncodeError> {
        let payload_len = msg.body.payload().len();
        let payload_u64 = u64::try_from(payload_len).map_err(|_| EncodeError::LengthOverflow)?;
        2usize
            .checked_add(bigsize::encoded_len(payload_u64))
            .and_then(|n| n.checked_add(payload_len))
            .and_then(|n| msg.extensions.encoded_len().ok()?.checked_add(n))
            .ok_or(EncodeError::LengthOverflow)
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
        validate_extensions(&extensions)?;
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
/// Width of the kind record's value: the wire type is a big-endian u16.
/// Equal to [`PAYLOAD_RECORD`] by coincidence and not by meaning.
const KIND_VALUE_LEN: u64 = 2;

impl Encoding for AllTlv {
    const NAME: &'static str = "all-tlv";

    fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError> {
        reject_reserved_extensions(msg)?;
        let mut out = Vec::new();
        bigsize::encode(KIND_RECORD, &mut out);
        bigsize::encode(KIND_VALUE_LEN, &mut out);
        out.extend_from_slice(&msg.body.wire_type().to_be_bytes());
        let payload = msg.body.payload();
        bigsize::encode(PAYLOAD_RECORD, &mut out);
        bigsize::encode(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        msg.extensions.encode(&mut out);
        Ok(out)
    }

    fn encoded_len(msg: &Message) -> Result<usize, EncodeError> {
        reject_reserved_extensions(msg)?;
        let payload_len = msg.body.payload().len();
        let payload_u64 = u64::try_from(payload_len).map_err(|_| EncodeError::LengthOverflow)?;
        5usize
            .checked_add(bigsize::encoded_len(payload_u64))
            .and_then(|n| n.checked_add(payload_len))
            .and_then(|n| msg.extensions.encoded_len().ok()?.checked_add(n))
            .ok_or(EncodeError::LengthOverflow)
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
        validate_extensions(&extensions)?;
        Ok(Message { body, extensions })
    }
}

/// A magic string, the kind, then key-value pairs sorted by key and
/// terminated by an empty key.
///
/// Keys are explicit rather than positional, which costs bytes per field
/// but makes the format self-describing without a shared schema. Key
/// `0x00` is the payload; an extension of type T has key `0x01` followed
/// by T, so extensions sort after the payload and keep their own order.
#[derive(Debug)]
pub enum KvPairs {}

/// Distinguishes this format from anything else on the wire.
const KV_MAGIC: &[u8; 6] = b"fungi\x00";
/// Key prefix for the body payload.
const KV_KEY_PAYLOAD: u8 = 0x00;
/// Key prefix for an extension record.
const KV_KEY_EXTENSION: u8 = 0x01;

impl Encoding for KvPairs {
    const NAME: &'static str = "kv-pairs";

    fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        out.extend_from_slice(KV_MAGIC);
        out.extend_from_slice(&msg.body.wire_type().to_be_bytes());
        push_pair(&mut out, &[KV_KEY_PAYLOAD], msg.body.payload());
        for rec in msg.extensions.records() {
            let mut key = vec![KV_KEY_EXTENSION];
            bigsize::encode(rec.ty, &mut key);
            push_pair(&mut out, &key, &rec.value);
        }
        // Empty key terminates: the pairs are variable in number, so the
        // buffer's end alone would not distinguish a truncated stream.
        bigsize::encode(0, &mut out);
        Ok(out)
    }

    fn encoded_len(msg: &Message) -> Result<usize, EncodeError> {
        let payload_len = msg.body.payload().len();
        let payload_u64 = u64::try_from(payload_len).map_err(|_| EncodeError::LengthOverflow)?;
        let mut total = 11usize
            .checked_add(bigsize::encoded_len(payload_u64))
            .and_then(|n| n.checked_add(payload_len))
            .ok_or(EncodeError::LengthOverflow)?;
        for rec in msg.extensions.records() {
            let type_width = bigsize::encoded_len(rec.ty);
            let key_len = 1usize
                .checked_add(type_width)
                .ok_or(EncodeError::LengthOverflow)?;
            let key_u64 = u64::try_from(key_len).map_err(|_| EncodeError::LengthOverflow)?;
            let value_u64 =
                u64::try_from(rec.value.len()).map_err(|_| EncodeError::LengthOverflow)?;
            total = total
                .checked_add(bigsize::encoded_len(key_u64))
                .and_then(|n| n.checked_add(key_len))
                .and_then(|n| n.checked_add(bigsize::encoded_len(value_u64)))
                .and_then(|n| n.checked_add(rec.value.len()))
                .ok_or(EncodeError::LengthOverflow)?;
        }
        Ok(total)
    }

    fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let rest = bytes.strip_prefix(KV_MAGIC).ok_or(DecodeError::BadBody)?;
        let ty: [u8; 2] = rest
            .get(..2)
            .ok_or(DecodeError::UnexpectedEof)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?;
        let mut rest = &rest[2..];

        let mut payload: Option<Vec<u8>> = None;
        let mut records = Vec::new();
        // Keys are BORROWED from the input, never copied. Nothing needs a
        // key past the iteration that parses it — it is compared, split,
        // and dropped — so materialising one would charge this format for
        // an allocation the shape does not require, and the comparison
        // between shapes is the whole point.
        let mut last_key: Option<&[u8]> = None;
        loop {
            let (key, value, used) = take_pair(rest)?;
            rest = &rest[used..];
            let Some(key) = key else { break };
            if let Some(prev) = last_key
                && prev >= key
            {
                return Err(DecodeError::NonCanonicalTlv);
            }
            match key.split_first() {
                Some((&KV_KEY_PAYLOAD, [])) => payload = Some(value),
                Some((&KV_KEY_EXTENSION, ty_bytes)) => {
                    let (rec_ty, used) = bigsize::decode(ty_bytes)?;
                    if used != ty_bytes.len() {
                        return Err(DecodeError::NonCanonicalTlv);
                    }
                    records.push(crate::tlv::TlvRecord { ty: rec_ty, value });
                }
                _ => return Err(DecodeError::BadBody),
            }
            last_key = Some(key);
        }
        if !rest.is_empty() {
            return Err(DecodeError::NonCanonicalTlv);
        }
        let body =
            Body::from_wire_type(u16::from_be_bytes(ty), payload.ok_or(DecodeError::BadBody)?)?;
        let extensions = TlvStream::new(records)?;
        validate_extensions(&extensions)?;
        Ok(Message { body, extensions })
    }
}

fn push_pair(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    bigsize::encode(key.len() as u64, out);
    out.extend_from_slice(key);
    bigsize::encode(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn reject_reserved_extensions(msg: &Message) -> Result<(), EncodeError> {
    if let Some(rec) = msg
        .extensions
        .records()
        .iter()
        .find(|r| r.ty <= PAYLOAD_RECORD)
    {
        return Err(EncodeError::ReservedExtensionType { ty: rec.ty });
    }
    Ok(())
}

/// Read one pair, or `None` for the terminating empty key. Returns how
/// many bytes were consumed.
///
/// The key is returned borrowed and the value owned, because that is
/// what each is used for: the key is compared and discarded within one
/// iteration, while the value is kept in the decoded message.
#[allow(clippy::type_complexity)]
fn take_pair(bytes: &[u8]) -> Result<(Option<&[u8]>, Vec<u8>, usize), DecodeError> {
    let (key_len, mut used) = bigsize::decode(bytes)?;
    if key_len == 0 {
        return Ok((None, Vec::new(), used));
    }
    let key_len = usize::try_from(key_len).map_err(|_| DecodeError::UnexpectedEof)?;
    let key_end = used
        .checked_add(key_len)
        .ok_or(DecodeError::UnexpectedEof)?;
    let key = bytes.get(used..key_end).ok_or(DecodeError::UnexpectedEof)?;
    used = key_end;
    let (val_len, n) = bigsize::decode(&bytes[used..])?;
    used += n;
    let val_len = usize::try_from(val_len).map_err(|_| DecodeError::UnexpectedEof)?;
    let value_end = used
        .checked_add(val_len)
        .ok_or(DecodeError::UnexpectedEof)?;
    let value = bytes
        .get(used..value_end)
        .ok_or(DecodeError::UnexpectedEof)?
        .to_vec();
    used = value_end;
    Ok((Some(key), value, used))
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
                fn encoded_len_matches_encoding_at_boundaries() {
                    for payload_len in [0, 23, 24, 252, 253, 255, 256, 65_535, 65_536] {
                        let msg = Message {
                            body: Body::Payment(vec![0; payload_len]),
                            extensions: TlvStream::new(vec![
                                TlvRecord {
                                    ty: 1001,
                                    value: Vec::new(),
                                },
                                TlvRecord {
                                    ty: 1003,
                                    value: vec![0; 24],
                                },
                            ])
                            .expect("canonical"),
                        };
                        assert_eq!(
                            <Enc as Encoding>::encoded_len(&msg),
                            <Enc as Encoding>::encode(&msg).map(|bytes| bytes.len()),
                            "payload length {payload_len}",
                        );
                    }
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

                    #[test]
                    fn encoded_len_is_exact(msg in testing::any_encodable_message()) {
                        prop_assert_eq!(
                            <Enc as Encoding>::encoded_len(&msg),
                            <Enc as Encoding>::encode(&msg).map(|bytes| bytes.len()),
                        );
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
    encoding_suite!(kv_pairs, crate::encoding::KvPairs);
    encoding_suite!(deterministic_cbor, crate::encoding::DeterministicCbor);

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

    /// A validity record whose value is not a window is refused, not
    /// ignored.
    ///
    /// Run over the two shapes that can carry `EXT_VALIDITY` at all; the
    /// uniform shape reserves that record type, so there is no such
    /// message for it to decode.
    fn a_malformed_validity_record_is_refused<E: crate::encoding::Encoding>() {
        use crate::encoding::EXT_VALIDITY;
        use crate::error::DecodeError;
        use crate::message::{Body, Message};
        use crate::tlv::{TlvRecord, TlvStream};

        let mut inverted = 5u64.to_be_bytes().to_vec();
        inverted.extend_from_slice(&1u64.to_be_bytes());
        let mut well_formed = 1u64.to_be_bytes().to_vec();
        well_formed.extend_from_slice(&5u64.to_be_bytes());

        // Encoding does not police values — only decoding does — so these
        // bytes are exactly what a peer sending them would put on the
        // wire.
        for value in [Vec::new(), vec![0u8; 3], vec![0u8; 17], inverted] {
            let msg = Message {
                body: Body::Psbt(b"x".to_vec()),
                extensions: TlvStream::new(vec![TlvRecord {
                    ty: EXT_VALIDITY,
                    value,
                }])
                .expect("canonical"),
            };
            let bytes = E::encode(&msg).expect("the shape can carry the record");
            assert_eq!(
                E::decode(&bytes),
                Err(DecodeError::BadExtensionValue { ty: EXT_VALIDITY }),
                "{}",
                E::NAME
            );
        }

        let msg = Message {
            body: Body::Psbt(b"x".to_vec()),
            extensions: TlvStream::new(vec![TlvRecord {
                ty: EXT_VALIDITY,
                value: well_formed,
            }])
            .expect("canonical"),
        };
        let bytes = E::encode(&msg).expect("the shape can carry the record");
        assert_eq!(E::decode(&bytes), Ok(msg), "{}", E::NAME);
    }

    #[test]
    fn malformed_validity_records_are_refused_by_every_shape_that_carries_them() {
        use crate::encoding::{DeterministicCbor, HeaderTlv, KvPairs};

        a_malformed_validity_record_is_refused::<HeaderTlv>();
        a_malformed_validity_record_is_refused::<KvPairs>();
        a_malformed_validity_record_is_refused::<DeterministicCbor>();
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
