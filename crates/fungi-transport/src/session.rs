//! Logical-session identity for per-session circuit isolation.
//!
//! A [`SessionId`] names one logical session — a multi-party construction in
//! progress, or any grouping the caller decides. Connectors obtained for
//! DIFFERENT sessions ([`Transport::connector_for`](crate::Transport::connector_for))
//! must not share a transport circuit, so the streams they open cannot be
//! correlated by network metadata; connectors for the SAME session may (and
//! should — a circuit is expensive to build). What counts as one session is
//! the caller's business; the transport only keeps them apart.

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque identity of one logical session.
///
/// Two ids are equal iff they name the same session; the value is a lookup
/// key, not something to interpret. [`generate`](SessionId::generate) mints a
/// fresh, unique id.
///
/// Uniqueness, not unpredictability, is what isolation needs: the id only has
/// to differ between sessions that could otherwise share a circuit. It
/// carries the process id so that two processes talking to one shared tor
/// daemon never collide on a SOCKS credential (and thus a circuit); within a
/// process, a monotonic counter separates sessions. It is deliberately NOT a
/// secret — any local process already sits inside the daemon's trust base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    pid: u32,
    seq: u64,
}

impl SessionId {
    /// Mint a fresh session id, unique within this process (and, via the pid,
    /// across the live processes that might share a tor daemon). Named
    /// `generate`, not `new`: each call yields a DISTINCT value, not the one
    /// canonical id a `new`/`Default` would imply.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        Self {
            pid: std::process::id(),
            seq: COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.pid, self.seq)
    }
}

/// Failure to parse a [`SessionId`] from its `pid-seq` text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSessionIdError;

impl fmt::Display for ParseSessionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a session id of the form pid-seq")
    }
}

impl std::error::Error for ParseSessionIdError {}

impl FromStr for SessionId {
    type Err = ParseSessionIdError;

    /// Parse the `pid-seq` text form (the inverse of [`Display`](fmt::Display)),
    /// so a session id can round-trip across a text boundary such as capnp
    /// `Text`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pid, seq) = s.split_once('-').ok_or(ParseSessionIdError)?;
        Ok(Self {
            pid: pid.parse().map_err(|_| ParseSessionIdError)?,
            seq: seq.parse().map_err(|_| ParseSessionIdError)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_new_id_is_distinct() {
        let (a, b, c) = (
            SessionId::generate(),
            SessionId::generate(),
            SessionId::generate(),
        );
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn equal_ids_hash_equally() {
        use std::collections::HashSet;
        let id = SessionId::generate();
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&id));
        assert!(!set.contains(&SessionId::generate()));
    }

    #[test]
    fn display_parse_roundtrip() {
        let id = SessionId::generate();
        assert_eq!(id.to_string().parse::<SessionId>().unwrap(), id);
    }

    #[test]
    fn malformed_text_is_rejected() {
        assert_eq!("noseq".parse::<SessionId>(), Err(ParseSessionIdError));
        assert_eq!("x-1".parse::<SessionId>(), Err(ParseSessionIdError));
        assert_eq!("1-y".parse::<SessionId>(), Err(ParseSessionIdError));
    }
}
