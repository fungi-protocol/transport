//! Extension records: a canonical type-length-value stream.
//!
//! Records are strictly increasing by type, never repeated, each length
//! exactly covering its value and the stream exactly covering its buffer.
//! Decoding preserves every record it parses, including types this build
//! does not understand — a node that dropped unknown records would
//! re-encode a DIFFERENT message with a different identity, and two nodes
//! holding the same message would disagree about which message it was.

use crate::bigsize;
use crate::error::DecodeError;

/// One extension record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord {
    /// The record type. Odd types are ignorable when unknown.
    pub ty: u64,
    /// The record value, exactly as it appeared on the wire.
    pub value: Vec<u8>,
}

/// A canonical extension stream, canonical by construction: an existing
/// value has already passed the ordering and uniqueness checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlvStream(Vec<TlvRecord>);

impl TlvStream {
    /// Build a stream, rejecting records out of order or repeated.
    pub fn new(records: Vec<TlvRecord>) -> Result<Self, DecodeError> {
        if records.windows(2).any(|w| w[0].ty >= w[1].ty) {
            return Err(DecodeError::NonCanonicalTlv);
        }
        Ok(Self(records))
    }

    /// The records, in type order.
    pub fn records(&self) -> &[TlvRecord] {
        &self.0
    }

    /// Consume the stream, yielding its records.
    ///
    /// A decoder that must take records apart moves them out through
    /// this rather than cloning them through [`records`](Self::records).
    /// Without it, a format whose decoder goes through this type would
    /// look costlier than its rivals for reasons belonging to this API
    /// rather than to the format.
    pub fn into_records(self) -> Vec<TlvRecord> {
        self.0
    }

    /// Append the stream's encoding.
    pub fn encode(&self, out: &mut Vec<u8>) {
        for rec in &self.0 {
            bigsize::encode(rec.ty, out);
            bigsize::encode(rec.value.len() as u64, out);
            out.extend_from_slice(&rec.value);
        }
    }

    /// Decode a stream that must cover `bytes` exactly.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut records = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let (ty, used) = bigsize::decode(rest)?;
            rest = &rest[used..];
            let (len, used) = bigsize::decode(rest)?;
            rest = &rest[used..];
            let len = usize::try_from(len).map_err(|_| DecodeError::UnexpectedEof)?;
            let value = rest.get(..len).ok_or(DecodeError::UnexpectedEof)?.to_vec();
            rest = &rest[len..];
            records.push(TlvRecord { ty, value });
        }
        Self::new(records)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn record(ty: u64, value: &[u8]) -> TlvRecord {
        TlvRecord {
            ty,
            value: value.to_vec(),
        }
    }

    #[test]
    fn empty_stream_encodes_to_nothing() {
        let mut out = Vec::new();
        TlvStream::default().encode(&mut out);
        assert!(out.is_empty());
        assert_eq!(TlvStream::decode(&[]), Ok(TlvStream::default()));
    }

    #[test]
    fn records_roundtrip_in_type_order() {
        // type 1, length 1, 'a'; then type 3, length 3, 'bcd'.
        let stream = TlvStream::new(vec![record(1, b"a"), record(3, b"bcd")]).expect("canonical");
        let mut out = Vec::new();
        stream.encode(&mut out);
        assert_eq!(hex::encode(&out), "0101610303626364");
        assert_eq!(TlvStream::decode(&out), Ok(stream));
    }

    #[test]
    fn out_of_order_types_are_rejected() {
        assert_eq!(
            TlvStream::new(vec![record(3, b"a"), record(1, b"b")]),
            Err(DecodeError::NonCanonicalTlv)
        );
    }

    #[test]
    fn duplicate_types_are_rejected() {
        assert_eq!(
            TlvStream::new(vec![record(1, b"a"), record(1, b"b")]),
            Err(DecodeError::NonCanonicalTlv)
        );
    }

    #[test]
    fn a_length_running_past_the_buffer_is_rejected() {
        // type 1, length 8, one byte of value.
        let bytes = hex::decode("010800").expect("valid fixture hex");
        assert_eq!(TlvStream::decode(&bytes), Err(DecodeError::UnexpectedEof));
    }

    #[test]
    fn a_non_minimal_type_is_rejected() {
        // type 1 spelled in three bytes.
        let bytes = hex::decode("fd00010100").expect("valid fixture hex");
        assert_eq!(
            TlvStream::decode(&bytes),
            Err(DecodeError::NonMinimalInteger)
        );
    }

    pub(crate) mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Canonical streams by construction: a sorted map cannot produce
        /// a repeated or out-of-order type, so the generator produces
        /// exactly what the constructor accepts. Restricting in the
        /// generator beats filtering after it — a filter would throw away
        /// most draws and cripple shrinking.
        pub(crate) fn any_stream(
            types: impl Strategy<Value = u64>,
        ) -> impl Strategy<Value = TlvStream> {
            proptest::collection::btree_map(
                types,
                proptest::collection::vec(any::<u8>(), 0..24),
                0..5,
            )
            .prop_map(|records| {
                TlvStream::new(
                    records
                        .into_iter()
                        .map(|(ty, value)| TlvRecord { ty, value })
                        .collect(),
                )
                .expect("a sorted map yields a canonical stream")
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            /// One byte string per stream, in both directions.
            #[test]
            fn streams_roundtrip(stream in any_stream(any::<u64>())) {
                let mut out = Vec::new();
                stream.encode(&mut out);
                prop_assert_eq!(TlvStream::decode(&out), Ok(stream));
            }

            /// Anything that decodes re-encodes to exactly the input.
            /// Fed from valid streams under mutation, not uniform bytes:
            /// uniform bytes reach this decoder about four times in a
            /// thousand, which is not enough for the assertion to mean
            /// anything at the case count above.
            #[test]
            fn mutated_streams_are_canonical_or_rejected(
                bytes in mutated_stream(),
            ) {
                if let Ok(stream) = TlvStream::decode(&bytes) {
                    let mut out = Vec::new();
                    stream.encode(&mut out);
                    prop_assert_eq!(out, bytes);
                }
            }
        }

        /// A valid stream with one byte changed, one byte appended, or a
        /// tail cut off.
        pub(crate) fn mutated_stream() -> impl Strategy<Value = Vec<u8>> {
            (any_stream(0u64..64), any::<usize>(), any::<u8>(), 0u8..3).prop_map(
                |(stream, idx, val, kind)| {
                    let mut bytes = Vec::new();
                    stream.encode(&mut bytes);
                    crate::testing::mutate(bytes, idx, val, kind)
                },
            )
        }

        /// The companion to the property above: it FAILS if too few
        /// mutations reach the decoder, so the property can never quietly
        /// become vacuous.
        #[test]
        fn the_canonicity_property_is_not_vacuous() {
            let reached = crate::testing::count_accepted(
                4096,
                |bytes| TlvStream::decode(bytes).is_ok(),
                |seed| {
                    let mut bytes = Vec::new();
                    crate::testing::sample_stream(seed).encode(&mut bytes);
                    bytes
                },
            );
            assert!(reached > 256, "only {reached}/4096 mutations decoded");
        }
    }
}
