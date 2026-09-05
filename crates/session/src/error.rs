use std::{error::Error, fmt};

use fungi_transport::{RecvError, SendError};
use fungi_wire::{MessageContext, ProtocolSessionId, ProtocolVersion};

use crate::MessageSizeLimit;

/// A configured application-message limit cannot be represented by the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessageSizeLimit {
    /// Rejected number of bytes.
    pub value: usize,
    /// Largest complete canonical message supported by the wire format.
    pub maximum: usize,
}

/// Failure to bind one raw P2P channel to the expected protocol session.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionBindingError {
    /// Sending the local hello failed.
    Send(SendError),
    /// Receiving the remote hello failed.
    Receive(RecvError),
    /// The first peer message was neither the expected hello nor valid
    /// application traffic.
    MalformedHandshake,
    /// Canonical application traffic arrived where the connection-local hello
    /// was required.
    PrematureApplicationMessage,
    /// The peer presented another protocol session.
    SessionMismatch {
        /// Locally configured session.
        expected: ProtocolSessionId,
        /// Session presented by the peer.
        received: ProtocolSessionId,
    },
    /// The peer presented another exact protocol version.
    VersionMismatch {
        /// Locally configured version.
        expected: ProtocolVersion,
        /// Version presented by the peer.
        received: ProtocolVersion,
    },
    /// The peer presented another complete canonical-message limit.
    MessageSizeLimitMismatch {
        /// Locally configured limit.
        expected: MessageSizeLimit,
        /// Limit presented by the peer.
        received: MessageSizeLimit,
    },
}

impl fmt::Display for InvalidMessageSizeLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message-size limit {} is outside 1..={}",
            self.value, self.maximum
        )
    }
}

impl Error for InvalidMessageSizeLimit {}

impl fmt::Display for SessionBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(error) => write!(f, "failed to send session hello: {error}"),
            Self::Receive(error) => write!(f, "failed to receive session hello: {error}"),
            Self::MalformedHandshake => f.write_str("peer sent a malformed session hello"),
            Self::PrematureApplicationMessage => {
                f.write_str("peer sent application traffic before session binding")
            }
            Self::SessionMismatch { expected, received } => write!(
                f,
                "peer session ID {received:?} does not match expected {expected:?}"
            ),
            Self::VersionMismatch { expected, received } => write!(
                f,
                "peer protocol version {received:?} does not match expected {expected:?}"
            ),
            Self::MessageSizeLimitMismatch { expected, received } => write!(
                f,
                "peer message-size limit {received} does not match expected {expected}"
            ),
        }
    }
}

impl Error for SessionBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Send(error) => Some(error),
            Self::Receive(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ApplicationViolation {
    UnexpectedHandshake,
    Malformed(fungi_wire::DecodeError),
    ContextMismatch {
        expected: MessageContext,
        received: MessageContext,
    },
    TooLarge {
        actual: usize,
        max: MessageSizeLimit,
    },
}

impl fmt::Display for ApplicationViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedHandshake => {
                f.write_str("connection-local session hello repeated after binding")
            }
            Self::Malformed(error) => write!(f, "malformed canonical application message: {error}"),
            Self::ContextMismatch { expected, received } => write!(
                f,
                "application message context {received:?} does not match {expected:?}"
            ),
            Self::TooLarge { actual, max } => write!(
                f,
                "application message of {actual} bytes exceeds the session maximum of {max}"
            ),
        }
    }
}

impl Error for ApplicationViolation {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            _ => None,
        }
    }
}
