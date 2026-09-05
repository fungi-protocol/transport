//! Transport-local identity for circuit isolation.
//!
//! A [`CircuitIsolationId`] names one caller-defined isolation group.
//! Connectors obtained for DIFFERENT groups
//! ([`Transport::isolated_connector`](crate::Transport::isolated_connector))
//! must not share a transport circuit, so the streams they open cannot be
//! correlated through circuit reuse; connectors for the SAME group may (and
//! should — a circuit is expensive to build). What counts as one isolation
//! group is the caller's business; the transport only keeps groups apart.

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque identity of one transport-local circuit-isolation group.
///
/// Two ids are equal iff they name the same isolation group; the value is a lookup
/// key, not something to interpret. [`generate`](CircuitIsolationId::generate) mints a
/// fresh, unique id.
///
/// Uniqueness, not unpredictability, is what isolation needs: the id only has
/// to differ between groups that could otherwise share a circuit. It
/// carries the process id so that two processes talking to one shared tor
/// daemon never collide on a SOCKS credential (and thus a circuit); within a
/// process, a monotonic counter separates groups. It is deliberately NOT a
/// secret — any local process already sits inside the daemon's trust base.
///
/// Uniqueness holds among CONCURRENTLY-LIVE processes: the counter resets at
/// each start, so a `pid-seq` id is not stable across a restart, and a reused
/// pid could remint an earlier id. Ids are therefore for live isolation, not
/// for persisting and comparing across process lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitIsolationId {
    pid: u32,
    seq: u64,
}

impl CircuitIsolationId {
    /// Mint a fresh isolation id, unique within this process (and, via the pid,
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

impl fmt::Display for CircuitIsolationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.pid, self.seq)
    }
}

/// Failure to parse a [`CircuitIsolationId`] from its `pid-seq` text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCircuitIsolationIdError;

impl fmt::Display for ParseCircuitIsolationIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a circuit-isolation id of the form pid-seq")
    }
}

impl std::error::Error for ParseCircuitIsolationIdError {}

impl FromStr for CircuitIsolationId {
    type Err = ParseCircuitIsolationIdError;

    /// Parse the `pid-seq` text form (the inverse of [`Display`](fmt::Display)),
    /// so an isolation id can round-trip across a text boundary such as capnp
    /// `Text`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pid, seq) = s.split_once('-').ok_or(ParseCircuitIsolationIdError)?;
        Ok(Self {
            pid: pid.parse().map_err(|_| ParseCircuitIsolationIdError)?,
            seq: seq.parse().map_err(|_| ParseCircuitIsolationIdError)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_generated_id_is_distinct() {
        let (a, b, c) = (
            CircuitIsolationId::generate(),
            CircuitIsolationId::generate(),
            CircuitIsolationId::generate(),
        );
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn equal_ids_hash_equally() {
        use std::collections::HashSet;
        let id = CircuitIsolationId::generate();
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&id));
        assert!(!set.contains(&CircuitIsolationId::generate()));
    }

    #[test]
    fn display_parse_roundtrip() {
        let id = CircuitIsolationId::generate();
        assert_eq!(id.to_string().parse::<CircuitIsolationId>().unwrap(), id);
    }

    #[test]
    fn malformed_text_is_rejected() {
        assert_eq!(
            "noseq".parse::<CircuitIsolationId>(),
            Err(ParseCircuitIsolationIdError)
        );
        assert_eq!(
            "x-1".parse::<CircuitIsolationId>(),
            Err(ParseCircuitIsolationIdError)
        );
        assert_eq!(
            "1-y".parse::<CircuitIsolationId>(),
            Err(ParseCircuitIsolationIdError)
        );
    }
}
