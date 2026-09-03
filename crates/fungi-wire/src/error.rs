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
    /// A message type this build does not understand, of odd number: a
    /// peer may relay it and carry on.
    UnknownIgnorableMessageType {
        /// The message type.
        ty: u16,
    },
    /// A message type this build does not understand, of even number:
    /// carrying on is not permitted.
    UnknownRequiredMessageType {
        /// The message type.
        ty: u16,
    },
    /// The body's own fields were malformed.
    BadBody,
}

/// Failure to encode a message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
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
            DecodeError::UnexpectedEof => f.write_str("input ended inside a field"),
            DecodeError::NonMinimalInteger => f.write_str("integer is not minimally encoded"),
            DecodeError::NonCanonicalTlv => f.write_str("extension stream is not canonical"),
            DecodeError::UnknownEvenExtension { ty } => {
                write!(f, "unknown extension record of even type {ty}")
            }
            DecodeError::UnknownIgnorableMessageType { ty } => {
                write!(f, "unknown message type {ty}, safe to ignore")
            }
            DecodeError::UnknownRequiredMessageType { ty } => {
                write!(f, "unknown message type {ty}, not safe to ignore")
            }
            DecodeError::BadBody => f.write_str("malformed message body"),
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            DecodeError::NonMinimalInteger.to_string(),
            "integer is not minimally encoded"
        );
        assert_eq!(
            DecodeError::UnknownEvenExtension { ty: 4 }.to_string(),
            "unknown extension record of even type 4"
        );
        assert_eq!(
            EncodeError::ReservedExtensionType { ty: 1 }.to_string(),
            "extension type 1 is reserved by this encoding"
        );
    }
}
