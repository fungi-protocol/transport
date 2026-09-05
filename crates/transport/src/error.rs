//! Error types for the P2P datagram channel.
//!
//! Concrete enums, not an associated `type Error`: consumers only branch on
//! what changes their behaviour (fragment? reconnect? give up?); backend
//! detail travels opaquely in `Transport`.

use std::error::Error;
use std::fmt;

/// Opaque backend error.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Failure to send one message.
///
/// Taxonomy: [`TooLarge`](SendError::TooLarge) is RECOVERABLE — the message
/// was rejected before touching the transport, and the channel remains
/// usable. Every other send error means the channel must be treated as
/// dead: recovery is a new channel through the
/// [`Connector`](crate::Connector), never resurrection of this one.
#[derive(Debug)]
#[non_exhaustive]
pub enum SendError {
    /// The message exceeds the maximum this transport supports. The limit is
    /// declared by the transport, never by the trait.
    TooLarge {
        /// The transport's maximum message size in bytes.
        max: usize,
    },
    /// The channel is dead; no further messages can be sent on it.
    Closed,
    /// Backend-specific failure, opaque to consumers.
    Transport(BoxError),
}

/// Failure to receive the next message.
///
/// ANY receive error means the channel is dead; the variant is diagnostic,
/// not semantic. Transports cannot uniformly tell a peer's clean departure
/// from a path failure — a Tor stream's teardown, for one, surfaces as
/// [`Transport`](RecvError::Transport) — so consumers must not branch on
/// the variant for correctness: reconnect through the
/// [`Connector`](crate::Connector) either way.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecvError {
    /// The channel is dead; no further messages will arrive on it.
    Closed,
    /// Backend-specific failure, opaque to consumers.
    Transport(BoxError),
}

/// Failure to establish a channel.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The peer address could not be reached.
    Unreachable,
    /// Backend-specific failure, opaque to consumers.
    Transport(BoxError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::TooLarge { max } => {
                write!(f, "message exceeds transport maximum of {max} bytes")
            }
            SendError::Closed => f.write_str("channel closed"),
            SendError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Closed => f.write_str("channel closed"),
            RecvError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::Unreachable => f.write_str("peer unreachable"),
            ConnectError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl Error for SendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SendError::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl Error for RecvError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RecvError::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl Error for ConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConnectError::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_actionable() {
        assert_eq!(
            SendError::TooLarge { max: 1024 }.to_string(),
            "message exceeds transport maximum of 1024 bytes"
        );
        assert_eq!(SendError::Closed.to_string(), "channel closed");
        assert_eq!(RecvError::Closed.to_string(), "channel closed");
        assert_eq!(ConnectError::Unreachable.to_string(), "peer unreachable");
    }

    #[test]
    fn transport_variant_display_wraps_the_backend_message() {
        assert_eq!(
            SendError::Transport("backend exploded".into()).to_string(),
            "transport error: backend exploded"
        );
        assert_eq!(
            RecvError::Transport("backend exploded".into()).to_string(),
            "transport error: backend exploded"
        );
        assert_eq!(
            ConnectError::Transport("backend exploded".into()).to_string(),
            "transport error: backend exploded"
        );
    }

    #[test]
    fn transport_variant_preserves_source() {
        let send = SendError::Transport("backend exploded".into());
        let recv = RecvError::Transport("backend exploded".into());
        let connect = ConnectError::Transport("backend exploded".into());
        for err in [&send as &dyn Error, &recv, &connect] {
            let source = err.source().expect("has source");
            assert_eq!(source.to_string(), "backend exploded");
        }
    }

    #[test]
    fn non_transport_variants_have_no_source() {
        assert!(SendError::TooLarge { max: 1 }.source().is_none());
        assert!(SendError::Closed.source().is_none());
        assert!(RecvError::Closed.source().is_none());
        assert!(ConnectError::Unreachable.source().is_none());
    }
}
