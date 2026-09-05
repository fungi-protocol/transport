//! Mapping from arti errors to the transport-agnostic [`ConnectError`].
//!
//! Only "the peer cannot be reached" becomes [`ConnectError::Unreachable`]
//! (the consumer's cue to retry later); everything else travels opaquely in
//! [`ConnectError::Transport`], source chain preserved.

use arti_client::{Error as ArtiError, ErrorKind, HasKind};
use fungi_transport::ConnectError;

/// Kinds that mean the PEER is unreachable (not that we are broken).
///
/// `OnionServiceConnectionFailed` is the transient "the service is running
/// but we couldn't connect to it" outcome (e.g. its descriptor hasn't
/// propagated yet, or the introduction circuit failed) — it is the
/// consumer's cue to retry later, same as the other kinds here.
pub(crate) fn kind_is_unreachable(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::OnionServiceNotFound
            | ErrorKind::OnionServiceNotRunning
            | ErrorKind::OnionServiceConnectionFailed
            | ErrorKind::RemoteHostNotFound
    )
}

/// Convert an arti error into the trait-level connect error.
pub(crate) fn connect_error(e: ArtiError) -> ConnectError {
    if kind_is_unreachable(e.kind()) {
        ConnectError::Unreachable
    } else {
        ConnectError::Transport(e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arti_client::ErrorKind;

    #[test]
    fn unreachable_kinds_classify_as_unreachable() {
        assert!(kind_is_unreachable(ErrorKind::OnionServiceNotFound));
        assert!(kind_is_unreachable(ErrorKind::OnionServiceNotRunning));
        assert!(kind_is_unreachable(ErrorKind::OnionServiceConnectionFailed));
        assert!(kind_is_unreachable(ErrorKind::RemoteHostNotFound));
    }

    #[test]
    fn other_kinds_classify_as_transport() {
        assert!(!kind_is_unreachable(ErrorKind::TorAccessFailed));
        assert!(!kind_is_unreachable(ErrorKind::BootstrapRequired));
    }
}
