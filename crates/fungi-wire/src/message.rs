use crate::{DecodeError, Extensions};

/// PSBT fragment message type.
pub const TYPE_PSBT: u16 = 1;
/// Payment message type.
pub const TYPE_PAYMENT: u16 = 3;
/// Confirmation message type.
pub const TYPE_CONFIRMATION: u16 = 5;

/// An unassigned odd message retained for transparent relay.
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
    /// Original opaque payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Typed application-message body. Payload semantics belong to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Body {
    /// PSBT fragment.
    Psbt(Vec<u8>),
    /// Payment request or metadata.
    Payment(Vec<u8>),
    /// Confirmation.
    Confirmation(Vec<u8>),
    /// Unknown odd type preserved for relay.
    Unknown(UnknownBody),
}
impl Body {
    /// Registry number.
    pub fn wire_type(&self) -> u16 {
        match self {
            Self::Psbt(_) => TYPE_PSBT,
            Self::Payment(_) => TYPE_PAYMENT,
            Self::Confirmation(_) => TYPE_CONFIRMATION,
            Self::Unknown(v) => v.ty,
        }
    }
    /// Opaque payload bytes.
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Psbt(v) | Self::Payment(v) | Self::Confirmation(v) => v,
            Self::Unknown(v) => &v.payload,
        }
    }
    pub(crate) fn decode(ty: u16, payload: Vec<u8>) -> Result<Self, DecodeError> {
        Ok(match ty {
            TYPE_PSBT => Self::Psbt(payload),
            TYPE_PAYMENT => Self::Payment(payload),
            TYPE_CONFIRMATION => Self::Confirmation(payload),
            odd if odd % 2 == 1 => Self::Unknown(UnknownBody { ty: odd, payload }),
            even => return Err(DecodeError::UnknownRequiredMessageType { ty: even }),
        })
    }
}

/// A typed body and its canonical extension stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Typed body.
    pub body: Body,
    /// Ordered extension records.
    pub extensions: Extensions,
}
impl Message {
    /// Construct a message without extensions.
    pub fn new(body: Body) -> Self {
        Self {
            body,
            extensions: Extensions::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_registry_is_distinct_and_ignorable() {
        let bodies = [
            Body::Psbt(Vec::new()),
            Body::Payment(Vec::new()),
            Body::Confirmation(Vec::new()),
        ];
        let types: std::collections::BTreeSet<_> = bodies.iter().map(Body::wire_type).collect();
        assert_eq!(types.len(), bodies.len());
        assert!(types.iter().all(|ty| ty % 2 == 1));
        for body in bodies {
            assert_eq!(Body::decode(body.wire_type(), Vec::new()), Ok(body));
        }
    }
}
