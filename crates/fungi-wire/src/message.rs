//! The messages the protocol carries.
//!
//! Bodies are opaque payloads: this crate owns the envelope and the
//! identity, never the semantics. `Block` and `ValidityProof` exist so a
//! Byzantine layer can arrive as message KINDS whose payload is another
//! encoded message, rather than as new fields on every existing message.
//!
//! Every assigned type number is odd, so a peer that does not know a kind
//! may relay it and carry on — the right default for a network that
//! forwards opaque bytes, and one that forecloses ever making a message
//! mandatory.

use crate::error::DecodeError;
use crate::tlv::TlvStream;

/// Wire type for a partially signed transaction or fragment.
pub const TYPE_PSBT: u16 = 1;
/// Wire type for a payment.
pub const TYPE_PAYMENT: u16 = 3;
/// Wire type for a confirmation.
pub const TYPE_CONFIRMATION: u16 = 5;
/// Wire type for a listen advertisement.
pub const TYPE_LISTEN_ADVERTISEMENT: u16 = 7;
/// Wire type for a block carrying another encoded message.
pub const TYPE_BLOCK: u16 = 9;
/// Wire type for a block-validity proof.
pub const TYPE_VALIDITY_PROOF: u16 = 11;

/// Body of an unassigned odd message, preserved for transparent relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownBody {
    ty: u16,
    payload: Vec<u8>,
}

impl UnknownBody {
    /// Original odd wire type.
    pub fn wire_type(&self) -> u16 {
        self.ty
    }

    /// Original payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A message body using the registry proposed by this experiment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Body {
    /// A partially signed transaction, or a fragment of one.
    Psbt(Vec<u8>),
    /// A payment.
    Payment(Vec<u8>),
    /// A confirmation.
    Confirmation(Vec<u8>),
    /// An advertisement that the sender is accepting offers. Gossiped,
    /// replaceable, and carrying a validity window as an extension.
    ListenAdvertisement(Vec<u8>),
    /// A block whose payload is itself an encoded message.
    Block(Vec<u8>),
    /// A proof that a block is valid.
    ValidityProof(Vec<u8>),
    /// An unassigned odd type preserved for transparent relay.
    Unknown(UnknownBody),
}

impl Body {
    /// The wire type identifying this kind.
    pub fn wire_type(&self) -> u16 {
        match self {
            Body::Psbt(_) => TYPE_PSBT,
            Body::Payment(_) => TYPE_PAYMENT,
            Body::Confirmation(_) => TYPE_CONFIRMATION,
            Body::ListenAdvertisement(_) => TYPE_LISTEN_ADVERTISEMENT,
            Body::Block(_) => TYPE_BLOCK,
            Body::ValidityProof(_) => TYPE_VALIDITY_PROOF,
            Body::Unknown(body) => body.wire_type(),
        }
    }

    /// The payload, whatever the kind.
    pub fn payload(&self) -> &[u8] {
        match self {
            Body::Psbt(p)
            | Body::Payment(p)
            | Body::Confirmation(p)
            | Body::ListenAdvertisement(p)
            | Body::Block(p)
            | Body::ValidityProof(p) => p,
            Body::Unknown(body) => body.payload(),
        }
    }

    /// Rebuild a body from its wire type.
    pub fn from_wire_type(ty: u16, payload: Vec<u8>) -> Result<Body, DecodeError> {
        match ty {
            TYPE_PSBT => Ok(Body::Psbt(payload)),
            TYPE_PAYMENT => Ok(Body::Payment(payload)),
            TYPE_CONFIRMATION => Ok(Body::Confirmation(payload)),
            TYPE_LISTEN_ADVERTISEMENT => Ok(Body::ListenAdvertisement(payload)),
            TYPE_BLOCK => Ok(Body::Block(payload)),
            TYPE_VALIDITY_PROOF => Ok(Body::ValidityProof(payload)),
            odd if odd % 2 == 1 => Ok(Body::Unknown(UnknownBody { ty: odd, payload })),
            even => Err(DecodeError::UnknownRequiredMessageType { ty: even }),
        }
    }
}

/// A message: one body plus the extension records this build may or may
/// not understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The body.
    pub body: Body,
    /// Extension records, canonical by construction.
    pub extensions: TlvStream,
}

impl Message {
    /// A message with no extensions.
    pub fn new(body: Body) -> Self {
        Self {
            body,
            extensions: TlvStream::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_kind() -> Vec<Body> {
        vec![
            Body::Psbt(b"p".to_vec()),
            Body::Payment(b"p".to_vec()),
            Body::Confirmation(b"p".to_vec()),
            Body::ListenAdvertisement(b"p".to_vec()),
            Body::Block(b"p".to_vec()),
            Body::ValidityProof(b"p".to_vec()),
        ]
    }

    #[test]
    fn every_known_kind_round_trips_through_its_number() {
        for body in every_kind() {
            let ty = body.wire_type();
            assert_eq!(Body::from_wire_type(ty, b"p".to_vec()), Ok(body));
        }
    }

    #[test]
    fn known_numbers_are_distinct_and_all_odd() {
        let types: std::collections::BTreeSet<u16> =
            every_kind().iter().map(Body::wire_type).collect();
        assert_eq!(types.len(), 6);
        assert!(
            types.iter().all(|t| t % 2 == 1),
            "every kind must be relayable when unknown"
        );
    }

    #[test]
    fn unknown_odd_types_are_preserved_and_unknown_even_types_fail() {
        assert_eq!(
            Body::from_wire_type(1001, Vec::new()),
            Ok(Body::Unknown(UnknownBody {
                ty: 1001,
                payload: Vec::new(),
            }))
        );
        assert_eq!(
            Body::from_wire_type(1000, Vec::new()),
            Err(DecodeError::UnknownRequiredMessageType { ty: 1000 })
        );
    }
}
