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

/// A message body. Provisional numbers: the assignment is a wire
/// decision this crate does not have the authority to take.
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
}

impl Body {
    /// The wire type identifying this kind.
    pub fn wire_type(&self) -> u16 {
        match self {
            Body::Psbt(_) => 1,
            Body::Payment(_) => 3,
            Body::Confirmation(_) => 5,
            Body::ListenAdvertisement(_) => 7,
            Body::Block(_) => 9,
            Body::ValidityProof(_) => 11,
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
        }
    }

    /// Rebuild a body from its wire type.
    pub fn from_wire_type(ty: u16, payload: Vec<u8>) -> Result<Body, DecodeError> {
        match ty {
            1 => Ok(Body::Psbt(payload)),
            3 => Ok(Body::Payment(payload)),
            5 => Ok(Body::Confirmation(payload)),
            7 => Ok(Body::ListenAdvertisement(payload)),
            9 => Ok(Body::Block(payload)),
            11 => Ok(Body::ValidityProof(payload)),
            odd if odd % 2 == 1 => Err(DecodeError::UnknownIgnorableMessageType { ty: odd }),
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
    fn unknown_types_separate_the_ignorable_from_the_rest() {
        assert_eq!(
            Body::from_wire_type(1001, Vec::new()),
            Err(DecodeError::UnknownIgnorableMessageType { ty: 1001 })
        );
        assert_eq!(
            Body::from_wire_type(1000, Vec::new()),
            Err(DecodeError::UnknownRequiredMessageType { ty: 1000 })
        );
    }
}
