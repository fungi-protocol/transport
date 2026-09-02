//! Transport-independent messages used to converge Fungi peers.
//!
//! Transports move opaque bytes and deliberately promise neither ordering nor
//! deduplication. [`Envelope`] supplies the stable identity needed above that
//! boundary: bridges preserve the encoded envelope, and consumers deduplicate
//! it by [`MessageId`]. Arrival order has no protocol meaning.

use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

/// Maximum application payload accepted by an envelope (4 KiB).
///
/// This conservative limit leaves ample room for HPKE and OHTTP framing in the
/// planned append-only mailbox backend.
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024;

/// Number of bytes added around the application payload on the wire.
pub const WIRE_OVERHEAD: usize = MAGIC.len() + AuthorId::LEN + 8 + 4;

const MAGIC: &[u8; 4] = b"FGCV";
const ID_DOMAIN: &[u8] = b"fungi-convergence-message-id\0";

/// Opaque identity assigned to a message author by the application.
///
/// This value is not authenticated. Applications may use a
/// public-key digest, a random stable identifier, or another 32-byte identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorId([u8; Self::LEN]);

impl AuthorId {
    /// Encoded author identity length.
    pub const LEN: usize = 32;

    /// Construct an author identity from its canonical bytes.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Return the canonical author identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// SHA-256 identity of one canonical encoded envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId([u8; Self::LEN]);

impl MessageId {
    /// Encoded message identity length.
    pub const LEN: usize = 32;

    /// Return the message identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A canonical logical message that keeps the same identity across transports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    author: AuthorId,
    sequence: u64,
    payload: Vec<u8>,
}

impl Envelope {
    /// Construct an envelope.
    ///
    /// Sequence numbers are scoped to `author`. They are diagnostic ordering
    /// hints only: convergence is defined by the set of [`MessageId`] values,
    /// not by sequence or arrival order.
    pub fn new(
        author: AuthorId,
        sequence: u64,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, EnvelopeError> {
        let payload = payload.into();
        validate_payload_len(payload.len())?;
        Ok(Self {
            author,
            sequence,
            payload,
        })
    }

    /// The opaque author identity.
    pub const fn author(&self) -> AuthorId {
        self.author
    }

    /// The author-local sequence number.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The opaque application payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Stable identity derived from the canonical encoding.
    pub fn message_id(&self) -> MessageId {
        let encoded = self.encode();
        let mut hash = Sha256::new();
        hash.update(ID_DOMAIN);
        hash.update(encoded);
        MessageId(hash.finalize().into())
    }

    /// Encode using the canonical wire format.
    ///
    /// Layout: `FGCV | author:[u8;32] | sequence:u64be | payload_len:u32be |
    /// payload`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WIRE_OVERHEAD + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode and validate one canonical envelope.
    pub fn decode(encoded: &[u8]) -> Result<Self, EnvelopeError> {
        if encoded.len() < WIRE_OVERHEAD {
            return Err(EnvelopeError::Truncated);
        }
        if &encoded[..MAGIC.len()] != MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }
        let mut offset = MAGIC.len();
        let author = AuthorId::new(
            encoded[offset..offset + AuthorId::LEN]
                .try_into()
                .expect("slice has exactly AuthorId::LEN bytes: encoded.len() >= WIRE_OVERHEAD was checked above"),
        );
        offset += AuthorId::LEN;
        let sequence =
            u64::from_be_bytes(encoded[offset..offset + 8].try_into().expect(
                "slice has exactly 8 bytes: encoded.len() >= WIRE_OVERHEAD was checked above",
            ));
        offset += 8;
        let payload_len =
            u32::from_be_bytes(encoded[offset..offset + 4].try_into().expect(
                "slice has exactly 4 bytes: encoded.len() >= WIRE_OVERHEAD was checked above",
            )) as usize;
        offset += 4;
        validate_payload_len(payload_len)?;

        let actual = encoded.len() - offset;
        if actual != payload_len {
            return Err(EnvelopeError::LengthMismatch {
                declared: payload_len,
                actual,
            });
        }
        Ok(Self {
            author,
            sequence,
            payload: encoded[offset..].to_vec(),
        })
    }
}

fn validate_payload_len(len: usize) -> Result<(), EnvelopeError> {
    if len > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::PayloadTooLarge {
            max: MAX_PAYLOAD_LEN,
            actual: len,
        });
    }
    Ok(())
}

/// Failure to construct or decode a convergence envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The input is shorter than a complete envelope header.
    Truncated,
    /// The convergence wire-format marker is absent.
    InvalidMagic,
    /// The declared payload length does not equal the remaining bytes.
    LengthMismatch {
        /// Length declared by the wire header.
        declared: usize,
        /// Number of payload bytes actually present.
        actual: usize,
    },
    /// The application payload exceeds the envelope limit.
    PayloadTooLarge {
        /// Maximum payload length accepted by the envelope format.
        max: usize,
        /// Supplied or declared payload length.
        actual: usize,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated convergence envelope"),
            Self::InvalidMagic => f.write_str("invalid convergence envelope marker"),
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "convergence payload length mismatch: declared {declared}, found {actual}"
            ),
            Self::PayloadTooLarge { max, actual } => {
                write!(f, "convergence payload is {actual} bytes, maximum is {max}")
            }
        }
    }
}

impl Error for EnvelopeError {}
