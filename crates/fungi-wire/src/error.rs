use std::{error::Error, fmt};

/// Failure to parse canonical message bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input exceeds the protocol limit.
    TooLarge {
        /// Maximum accepted size.
        max: usize,
        /// Observed size.
        actual: usize,
    },
    /// The input ended inside a field.
    UnexpectedEof,
    /// A BigSize integer was not minimally encoded.
    NonMinimalInteger,
    /// Extensions were duplicated, unordered, or did not cover the buffer.
    NonCanonicalExtensions,
    /// An unknown even message type cannot be ignored.
    UnknownRequiredMessageType {
        /// Unknown even type.
        ty: u16,
    },
    /// An unknown even extension cannot be ignored.
    UnknownRequiredExtension {
        /// Unknown even type.
        ty: u64,
    },
    /// A known extension carried an invalid value.
    BadExtensionValue {
        /// Known type whose value failed validation.
        ty: u64,
    },
}

/// Failure to encode a typed message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// Computing the encoded size overflowed `usize`.
    LengthOverflow,
    /// The complete canonical message exceeds the protocol limit.
    TooLarge {
        /// Maximum accepted size.
        max: usize,
        /// Computed size.
        actual: usize,
    },
}

/// Different canonical bytes were observed under the same full identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCollision {
    /// Conflicting identity.
    pub id: crate::MessageId,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl fmt::Display for IdentityCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "different messages share full identity ")?;
        for byte in self.id.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl Error for DecodeError {}
impl Error for EncodeError {}
impl Error for IdentityCollision {}
