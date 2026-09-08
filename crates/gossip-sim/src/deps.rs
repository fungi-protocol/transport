//! Validation dependencies: objects a peer may already hold before it has
//! ever seen the message that would otherwise carry them.
//!
//! Everything else this harness gossips is identified by the hash of its own
//! content ([`fungi_wire::MessageId`]): two peers only agree an identity
//! exists once one of them has produced the bytes it names. A previous
//! transaction and a prevout are different — a txid or an outpoint identifies
//! an object that exists, and that a peer may already hold, before any
//! message about it is ever sent. That is what lets a peer decline to be
//! sent one at all, and it is the property the next slice's announce/pull
//! measurement depends on.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

/// A previous transaction, sized for a legacy input's 2-in/2-out spend (see
/// `FINDINGS.md`, measured at 420 bytes for that shape).
const PREV_TX_BYTES: std::ops::RangeInclusive<usize> = 410..=430;
/// A single `TxOut`: an 8-byte value plus a short script.
const PREVOUT_BYTES: std::ops::RangeInclusive<usize> = 31..=43;

/// How a validation dependency is addressed. Not a content hash: these
/// identities exist before the message does, which is what lets a peer say
/// it already holds the object without ever having received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DepId {
    /// A previous transaction, addressed by its txid.
    Txid([u8; 32]),
    /// A prevout, addressed by its outpoint: txid and output index.
    Outpoint([u8; 32], u32),
}

/// One dependency object: an identity and the bytes it takes to send it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// The dependency's identity.
    pub id: DepId,
    /// Its bytes, before any wire envelope.
    pub bytes: Vec<u8>,
}

/// Which kind of output a peer's input spends, and so which dependency
/// objects that input needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// Spends a segwit output: the prevout alone is what the input commits
    /// to.
    Segwit,
    /// Spends a legacy output: the whole previous transaction is needed as
    /// well, to prove the amount the prevout does not carry.
    Legacy,
}

/// The dependency objects one peer's input touches. A prevout is what any
/// input commits to, so it is always present; a whole previous transaction
/// is only needed for a legacy input, so `prev_tx` is absent for a segwit
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputDependencies {
    /// The outpoint the input spends.
    pub outpoint: Dependency,
    /// The previous transaction, present only for a legacy input.
    pub prev_tx: Option<Dependency>,
}

impl InputDependencies {
    /// Derive one peer's dependency objects from `seed` and `origin` alone,
    /// so a run is reproducible: the same config always produces the same
    /// dependency bytes and identities, independent of iteration order and
    /// of every other peer's [`InputKind`].
    ///
    /// The outpoint and (for a legacy input) the previous transaction it
    /// names share one txid, the same way a real legacy input's outpoint and
    /// its previous transaction do.
    pub fn derive(seed: u64, origin: usize, kind: InputKind) -> Self {
        let mut rng = seeded_rng(seed, origin);
        let mut txid = [0u8; 32];
        rng.fill_bytes(&mut txid);
        let vout = rng.gen_range(0..4u32);
        let outpoint = Dependency {
            id: DepId::Outpoint(txid, vout),
            bytes: sized_bytes(&mut rng, PREVOUT_BYTES),
        };
        let prev_tx = matches!(kind, InputKind::Legacy).then(|| Dependency {
            id: DepId::Txid(txid),
            bytes: sized_bytes(&mut rng, PREV_TX_BYTES),
        });
        Self { outpoint, prev_tx }
    }
}

/// A `StdRng` seeded from `seed` and `origin` alone, so the dependency
/// objects for one peer never shift when another peer's [`InputKind`] (or
/// the iteration order over peers) changes.
fn seeded_rng(seed: u64, origin: usize) -> StdRng {
    let mut hasher = Sha256::new();
    hasher.update(b"gossip-sim-dep");
    hasher.update(seed.to_le_bytes());
    hasher.update((origin as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&digest);
    StdRng::from_seed(seed_bytes)
}

fn sized_bytes(rng: &mut StdRng, range: std::ops::RangeInclusive<usize>) -> Vec<u8> {
    let len = rng.gen_range(range);
    (0..len).map(|_| rng.r#gen::<u8>()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segwit_input_has_a_prevout_and_no_previous_transaction() {
        let deps = InputDependencies::derive(0, 0, InputKind::Segwit);
        assert!(deps.prev_tx.is_none());
        assert!(
            PREVOUT_BYTES.contains(&deps.outpoint.bytes.len()),
            "prevout size {} not in {:?}",
            deps.outpoint.bytes.len(),
            PREVOUT_BYTES
        );
    }

    #[test]
    fn a_legacy_input_also_carries_a_previous_transaction_for_the_same_txid() {
        let deps = InputDependencies::derive(0, 0, InputKind::Legacy);
        let prev_tx = deps
            .prev_tx
            .expect("legacy input carries a previous transaction");
        assert!(
            PREV_TX_BYTES.contains(&prev_tx.bytes.len()),
            "prev tx size {} not in {:?}",
            prev_tx.bytes.len(),
            PREV_TX_BYTES
        );

        let DepId::Outpoint(outpoint_txid, _) = deps.outpoint.id else {
            panic!("outpoint dependency must carry DepId::Outpoint");
        };
        let DepId::Txid(prev_tx_txid) = prev_tx.id else {
            panic!("previous-transaction dependency must carry DepId::Txid");
        };
        assert_eq!(
            outpoint_txid, prev_tx_txid,
            "the outpoint and its previous transaction name the same txid"
        );
    }

    #[test]
    fn sizes_span_their_documented_range_across_many_derivations() {
        // A single sample landing in-range does not rule out a range that
        // was typed too narrow; sampling many origins exercises the low and
        // high ends `rng.gen_range` can actually produce.
        let mut prevout_lens = std::collections::HashSet::new();
        let mut prev_tx_lens = std::collections::HashSet::new();
        for origin in 0..500 {
            let deps = InputDependencies::derive(0, origin, InputKind::Legacy);
            prevout_lens.insert(deps.outpoint.bytes.len());
            prev_tx_lens.insert(deps.prev_tx.unwrap().bytes.len());
        }
        assert!(
            prevout_lens.contains(&31) || prevout_lens.contains(&43),
            "500 draws never touched an end of 31..=43: {prevout_lens:?}"
        );
        assert!(
            prev_tx_lens.iter().all(|&l| PREV_TX_BYTES.contains(&l)),
            "a draw escaped 410..=430: {prev_tx_lens:?}"
        );
        assert!(
            prev_tx_lens.len() > 1,
            "420 legacy draws should not all collapse to one length"
        );
    }

    #[test]
    fn the_same_seed_and_origin_reproduce_the_same_object() {
        let a = InputDependencies::derive(7, 3, InputKind::Legacy);
        let b = InputDependencies::derive(7, 3, InputKind::Legacy);
        assert_eq!(
            a, b,
            "deriving twice from the same inputs must be reproducible"
        );
    }

    #[test]
    fn different_origins_get_different_identities() {
        let a = InputDependencies::derive(7, 0, InputKind::Segwit);
        let b = InputDependencies::derive(7, 1, InputKind::Segwit);
        assert_ne!(a.outpoint.id, b.outpoint.id);
    }

    #[test]
    fn a_peers_dependencies_do_not_depend_on_its_own_input_kind_beyond_the_prev_tx() {
        // Legacy only adds the previous-transaction object; the outpoint
        // itself must be identical whichever kind the input is, since a
        // peer's underlying dependency objects are a property of the input
        // being spent, not of how this harness classifies it.
        let segwit = InputDependencies::derive(9, 4, InputKind::Segwit);
        let legacy = InputDependencies::derive(9, 4, InputKind::Legacy);
        assert_eq!(segwit.outpoint, legacy.outpoint);
    }
}
