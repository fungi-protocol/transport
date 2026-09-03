//! From a delivered message set to application state.
//!
//! The fold must COMMUTE with union: two nodes that received the same
//! messages reach the same state regardless of the order they arrived in,
//! how often, or how the sets were merged along the way. Delay,
//! duplication, reordering and merges of divergent copies are exactly the
//! closure properties of that union, which is why this single property is
//! the whole convergence argument.
//!
//! The fold takes a clock, and that is a real cost rather than a
//! convenience: validity windows make state depend on WHEN it is
//! computed, which set convergence alone does not. For a fixed instant
//! the fold is still a homomorphism; across two instants, two nodes
//! holding identical sets may differ.

use std::collections::BTreeSet;

use crate::encoding::{EXT_VALIDITY, Encoding};
use crate::message::Body;
use crate::set::MessageSet;

/// A validity window, carried as extension record [`EXT_VALIDITY`]:
/// two big-endian u64s, inclusive of `from` and exclusive of `until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// First instant the message applies.
    pub from: u64,
    /// First instant it no longer applies.
    pub until: u64,
}

impl Validity {
    /// Read a window from a record value, or `None` if it is not one.
    pub fn decode(value: &[u8]) -> Option<Validity> {
        let raw: [u8; 16] = value.try_into().ok()?;
        let (from, until) = raw.split_at(8);
        Some(Validity {
            from: u64::from_be_bytes(from.try_into().ok()?),
            until: u64::from_be_bytes(until.try_into().ok()?),
        })
    }

    /// Whether `now` falls inside the window.
    pub fn covers(&self, now: u64) -> bool {
        self.from <= now && now < self.until
    }
}

/// A stand-in for application state: rich enough to be broken by a fold
/// that does not commute with union, small enough to carry no protocol
/// meaning. The real fold replaces it; the property it must satisfy does
/// not change.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppState {
    /// Every payload observed, under union.
    pub payloads: BTreeSet<Vec<u8>>,
    /// The greatest confirmation observed, under max.
    pub highest_confirmation: Option<Vec<u8>>,
}

#[cfg(test)]
impl concurrent_psbt::Join for AppState {
    fn join(mut self, other: Self) -> Self {
        self.payloads.extend(other.payloads);
        self.highest_confirmation = self.highest_confirmation.max(other.highest_confirmation);
        self
    }
}

/// Fold a message set into application state as of `now`.
///
/// Every message contributes independently and each contribution is
/// itself a join, which is what makes the whole fold commute with union.
/// Messages that do not decode contribute nothing: a node must reach the
/// same state as its peers even when it cannot read part of what it
/// relayed. Messages outside their validity window contribute nothing
/// either — an elementwise test, so the property survives it.
pub fn fold_at<E: Encoding>(now: u64, set: &MessageSet) -> AppState {
    let mut state = AppState::default();
    for (_, bytes) in set.iter() {
        let Ok(msg) = E::decode(bytes) else { continue };
        let window = msg
            .extensions
            .records()
            .iter()
            .find(|r| r.ty == EXT_VALIDITY)
            .and_then(|r| Validity::decode(&r.value));
        if window.is_some_and(|w| !w.covers(now)) {
            continue;
        }
        let payload = msg.body.payload().to_vec();
        if matches!(msg.body, Body::Confirmation(_)) {
            state.highest_confirmation = state.highest_confirmation.max(Some(payload.clone()));
        }
        state.payloads.insert(payload);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::HeaderTlv;
    use crate::message::Message;
    use crate::set::tests::set_of;
    use crate::tlv::{TlvRecord, TlvStream};
    use concurrent_psbt::Join;
    use proptest::prelude::*;

    /// A fold that is NOT a homomorphism, kept so the passing property is
    /// known to have teeth: `min` is a join of the OPPOSITE order, so
    /// combining folds disagrees with folding the combination.
    fn broken_fold(set: &MessageSet) -> AppState {
        let mut state = AppState::default();
        for (_, bytes) in set.iter() {
            let Ok(msg) = HeaderTlv::decode(bytes) else {
                continue;
            };
            let payload = msg.body.payload().to_vec();
            state.highest_confirmation = match state.highest_confirmation.take() {
                Some(prev) => Some(prev.min(payload.clone())),
                None => Some(payload.clone()),
            };
            state.payloads.insert(payload);
        }
        state
    }

    #[test]
    fn the_broken_fold_fails_the_law_the_real_one_passes() {
        let a = set_of(&[b"a"]);
        let b = set_of(&[b"z"]);
        let combined = broken_fold(&a.clone().join(b.clone()));
        let joined = broken_fold(&a).join(broken_fold(&b));
        assert_ne!(
            combined, joined,
            "the counterexample must actually break, or it proves nothing"
        );
    }

    #[test]
    fn delivery_order_does_not_change_the_state() {
        let forward = fold_at::<HeaderTlv>(0, &set_of(&[b"a", b"b", b"c"]));
        assert_eq!(
            forward,
            fold_at::<HeaderTlv>(0, &set_of(&[b"c", b"b", b"a"]))
        );
        assert_eq!(
            forward,
            fold_at::<HeaderTlv>(0, &set_of(&[b"b", b"a", b"b", b"c"]))
        );
    }

    #[test]
    fn a_validity_window_makes_the_state_depend_on_the_clock() {
        let mut value = 100u64.to_be_bytes().to_vec();
        value.extend_from_slice(&200u64.to_be_bytes());
        let msg = Message {
            body: Body::ListenAdvertisement(b"addr".to_vec()),
            extensions: TlvStream::new(vec![TlvRecord {
                ty: EXT_VALIDITY,
                value,
            }])
            .expect("canonical"),
        };
        let mut set = MessageSet::default();
        set.insert(HeaderTlv::encode(&msg).expect("encodable"));

        assert!(
            fold_at::<HeaderTlv>(150, &set)
                .payloads
                .contains(b"addr".as_slice())
        );
        assert!(fold_at::<HeaderTlv>(50, &set).payloads.is_empty());
        assert!(fold_at::<HeaderTlv>(250, &set).payloads.is_empty());
    }

    mod properties {
        use super::*;
        use crate::set::tests::properties::any_message_set;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            /// The homomorphism, at a fixed instant.
            #[test]
            fn fold_commutes_with_union(
                now in any::<u64>(),
                a in any_message_set(),
                b in any_message_set(),
            ) {
                prop_assert_eq!(
                    fold_at::<HeaderTlv>(now, &a.clone().join(b.clone())),
                    fold_at::<HeaderTlv>(now, &a).join(fold_at::<HeaderTlv>(now, &b)),
                );
            }

            /// Merging a set into itself is a no-op at the state level too.
            #[test]
            fn folding_is_idempotent_under_merge(
                now in any::<u64>(),
                a in any_message_set(),
            ) {
                prop_assert_eq!(
                    fold_at::<HeaderTlv>(now, &a.clone().join(a.clone())),
                    fold_at::<HeaderTlv>(now, &a),
                );
            }
        }
    }
}
