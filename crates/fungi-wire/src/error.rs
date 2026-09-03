//! Encode and decode failures.
//!
//! Enumerated rather than opaque because callers branch on the variant:
//! the odd/even rule makes an unknown record a decision rather than a
//! failure, and the conformance fixtures assert which rule rejected an
//! input. Every variant here is reachable.

use std::error::Error;
use std::fmt;

/// Failure to decode a message or one of its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The complete canonical message exceeds the protocol boundary.
    TooLarge {
        /// Configured maximum.
        max: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// The input ended inside a field.
    UnexpectedEof,
    /// An integer was spelled longer than necessary.
    NonMinimalInteger,
    /// Extension records were repeated, out of order, or did not exactly
    /// cover their buffer.
    NonCanonicalTlv,
    /// An extension record of an even — therefore non-ignorable — type
    /// this build does not understand.
    UnknownEvenExtension {
        /// The record type.
        ty: u64,
    },
    /// A message type this build does not understand, of even number:
    /// carrying on is not permitted.
    UnknownRequiredMessageType {
        /// The message type.
        ty: u16,
    },
    /// An extension record of a type this build DOES understand carried
    /// a value that does not parse under that type's schema.
    ///
    /// Refused rather than ignored. The even bit exists so that two
    /// nodes cannot diverge over a record one of them cannot handle;
    /// accepting a record whose value is unreadable reinstates that
    /// divergence one level down, and for a validity window it does so
    /// in the worst direction — an ignored window is an unconditionally
    /// valid message.
    BadExtensionValue {
        /// The record type whose value failed.
        ty: u64,
    },
    /// The body's own fields were malformed.
    BadBody,
}

/// Failure to encode a message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// Computing the encoded size overflowed the platform's address space.
    LengthOverflow,
    /// The complete canonical message exceeds the protocol boundary.
    TooLarge {
        /// Configured maximum.
        max: usize,
        /// Computed canonical byte length.
        actual: usize,
    },
    /// The message carries an extension record whose type this encoding
    /// reserves for its own structure, so the shape cannot represent it.
    ReservedExtensionType {
        /// The offending record type.
        ty: u64,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooLarge { max, actual } => {
                write!(f, "message is {actual} bytes, exceeding maximum {max}")
            }
            DecodeError::UnexpectedEof => f.write_str("input ended inside a field"),
            DecodeError::NonMinimalInteger => f.write_str("integer is not minimally encoded"),
            DecodeError::NonCanonicalTlv => f.write_str("extension stream is not canonical"),
            DecodeError::UnknownEvenExtension { ty } => {
                write!(f, "unknown extension record of even type {ty}")
            }
            DecodeError::UnknownRequiredMessageType { ty } => {
                write!(f, "unknown message type {ty}, not safe to ignore")
            }
            DecodeError::BadExtensionValue { ty } => {
                write!(f, "malformed value in extension record of type {ty}")
            }
            DecodeError::BadBody => f.write_str("malformed message body"),
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::LengthOverflow => f.write_str("encoded length overflow"),
            EncodeError::TooLarge { max, actual } => {
                write!(f, "message is {actual} bytes, exceeding maximum {max}")
            }
            EncodeError::ReservedExtensionType { ty } => {
                write!(f, "extension type {ty} is reserved by this encoding")
            }
        }
    }
}

impl Error for DecodeError {}
impl Error for EncodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_actionable() {
        assert_eq!(
            EncodeError::LengthOverflow.to_string(),
            "encoded length overflow"
        );
        assert_eq!(
            DecodeError::NonMinimalInteger.to_string(),
            "integer is not minimally encoded"
        );
        assert_eq!(
            DecodeError::UnknownEvenExtension { ty: 4 }.to_string(),
            "unknown extension record of even type 4"
        );
        assert_eq!(
            DecodeError::BadExtensionValue { ty: 2 }.to_string(),
            "malformed value in extension record of type 2"
        );
        assert_eq!(
            EncodeError::ReservedExtensionType { ty: 1 }.to_string(),
            "extension type 1 is reserved by this encoding"
        );
    }
}
