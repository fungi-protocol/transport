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
use crate::message::{Body, Message};
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

/// The validity window a message carries, if it carries one.
///
/// A decoded message's window is always well formed: a malformed value
/// under the assigned type is refused at decode, so this cannot silently
/// turn a broken record into "no window" and promote the message to
/// permanently valid.
fn window_of(msg: &Message) -> Option<Validity> {
    msg.extensions
        .records()
        .iter()
        .find(|r| r.ty == EXT_VALIDITY)
        .and_then(|r| Validity::decode(&r.value))
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
impl crate::testing::Join for AppState {
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
        if window_of(&msg).is_some_and(|w| !w.covers(now)) {
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
    use crate::testing::Join;
    use crate::tlv::{TlvRecord, TlvStream};
    use proptest::prelude::*;

    /// A fold that is NOT a homomorphism, kept so the passing property is
    /// known to have teeth.
    ///
    /// It differs from [`fold_at`] in exactly one respect — `min` where
    /// the real fold uses `max`, a join of the OPPOSITE order — so what
    /// the counterexample below demonstrates is the order of that join
    /// and nothing else. A copy that also differed in which bodies it
    /// accumulated would fail the law too, without saying which of the
    /// two differences did it.
    fn broken_fold(now: u64, set: &MessageSet) -> AppState {
        let mut state = AppState::default();
        for (_, bytes) in set.iter() {
            let Ok(msg) = HeaderTlv::decode(bytes) else {
                continue;
            };
            if window_of(&msg).is_some_and(|w| !w.covers(now)) {
                continue;
            }
            let payload = msg.body.payload().to_vec();
            if matches!(msg.body, Body::Confirmation(_)) {
                state.highest_confirmation = match state.highest_confirmation.take() {
                    Some(prev) => Some(prev.min(payload.clone())),
                    None => Some(payload.clone()),
                };
            }
            state.payloads.insert(payload);
        }
        state
    }

    /// Confirmations, so the field the broken fold mishandles is reached.
    fn confirmations_of(payloads: &[&[u8]]) -> MessageSet {
        let mut set = MessageSet::default();
        for p in payloads {
            let msg = Message::new(Body::Confirmation(p.to_vec()));
            set.insert(HeaderTlv::encode(&msg).expect("encodable"));
        }
        set
    }

    #[test]
    fn the_broken_fold_fails_the_law_the_real_one_passes() {
        let a = confirmations_of(&[b"a"]);
        let b = confirmations_of(&[b"z"]);
        assert_ne!(
            broken_fold(0, &a.clone().join(b.clone())),
            broken_fold(0, &a).join(broken_fold(0, &b)),
            "the counterexample must actually break, or it proves nothing"
        );
        assert_eq!(
            fold_at::<HeaderTlv>(0, &a.clone().join(b.clone())),
            fold_at::<HeaderTlv>(0, &a).join(fold_at::<HeaderTlv>(0, &b)),
            "and the real fold must survive the input that breaks it"
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
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;

        /// A clock and two sets whose messages carry validity windows
        /// positioned against that clock, drawn together so windows that
        /// cover it, windows that closed before it and windows that have
        /// not opened all occur.
        ///
        /// Local to this module by necessity. The shared message
        /// generator's extension types are all odd and far above every
        /// reserved range, because the encoding suite compares four
        /// candidates over one domain and the uniform shape reserves
        /// record type 2 — which is exactly `EXT_VALIDITY`. Widening the
        /// shared generator to emit windows would make its messages
        /// unencodable by one of the candidates. The homomorphism is
        /// stated over a single encoding, so it can carry records the
        /// shared domain cannot.
        fn clocked_sets() -> impl Strategy<Value = (u64, MessageSet, MessageSet)> {
            // `u64::MAX` is left out of the clock: covering it needs
            // `now < until` and following it needs `from > now`, so two
            // of the three positions are unreachable at that one value.
            (0u64..u64::MAX).prop_flat_map(|now| (Just(now), any_set_at(now), any_set_at(now)))
        }

        fn any_set_at(now: u64) -> impl Strategy<Value = MessageSet> {
            proptest::collection::vec(any_message_at(now), 0..6).prop_map(|msgs| {
                let mut set = MessageSet::default();
                for msg in msgs {
                    set.insert(HeaderTlv::encode(&msg).expect("encodable"));
                }
                set
            })
        }

        /// A message that carries a window against `now` about half the
        /// time, and none the rest.
        fn any_message_at(now: u64) -> impl Strategy<Value = Message> {
            (
                crate::testing::any_encodable_message(),
                proptest::option::of((0u8..3u8, any::<u64>(), any::<u64>())),
            )
                .prop_map(move |(msg, window)| match window {
                    None => msg,
                    Some((position, a, b)) => with_window(msg, window_for(now, position, a, b)),
                })
        }

        /// A window placed relative to `now`: covering it, closed before
        /// it, or not yet open. Saturating throughout, so every draw
        /// yields `from <= until` and the intended position holds for
        /// every clock the strategy above can produce.
        fn window_for(now: u64, position: u8, a: u64, b: u64) -> Validity {
            match position {
                0 => Validity {
                    from: now.saturating_sub(a),
                    until: (now + 1).saturating_add(b),
                },
                1 => {
                    let until = now.saturating_sub(a);
                    Validity {
                        from: until.saturating_sub(b),
                        until,
                    }
                }
                _ => {
                    let from = (now + 1).saturating_add(a);
                    Validity {
                        from,
                        until: from.saturating_add(b),
                    }
                }
            }
        }

        /// Prepend the window as record [`EXT_VALIDITY`]. Type 2 sorts
        /// below every type the shared generator emits, so the stream
        /// stays canonical without re-sorting.
        fn with_window(msg: Message, window: Validity) -> Message {
            let mut value = window.from.to_be_bytes().to_vec();
            value.extend_from_slice(&window.until.to_be_bytes());
            let mut records = vec![TlvRecord {
                ty: EXT_VALIDITY,
                value,
            }];
            records.extend(msg.extensions.into_records());
            Message {
                body: msg.body,
                extensions: TlvStream::new(records).expect("type 2 sorts below the rest"),
            }
        }

        /// The guard against a silently vacuous property: the laws below
        /// only say anything about validity if the sets they draw carry
        /// windows, and only exercise the skip branch if some of those
        /// windows exclude the clock. Counted over draws from the very
        /// strategy the properties use, because the failure this catches
        /// is a generator that does not reach the branch its property
        /// claims to cover.
        #[test]
        fn the_homomorphism_properties_are_not_vacuous() {
            let strategy = clocked_sets();
            let mut runner = TestRunner::deterministic();
            let (mut messages, mut covering, mut closed, mut unopened) = (0u32, 0u32, 0u32, 0u32);
            for _ in 0..256 {
                let (now, a, b) = strategy
                    .new_tree(&mut runner)
                    .expect("the strategy filters nothing out")
                    .current();
                for set in [&a, &b] {
                    for (_, bytes) in set.iter() {
                        messages += 1;
                        let msg = HeaderTlv::decode(bytes).expect("generated messages decode");
                        let Some(window) = window_of(&msg) else {
                            continue;
                        };
                        if window.covers(now) {
                            covering += 1;
                        } else if window.until <= now {
                            closed += 1;
                        } else {
                            unopened += 1;
                        }
                    }
                }
            }
            let windowed = covering + closed + unopened;
            assert!(
                windowed * 4 > messages,
                "only {windowed}/{messages} generated messages carry a validity window"
            );
            assert!(
                covering > 64 && closed > 64 && unopened > 64,
                "window positions relative to the clock: {covering} covering, \
                 {closed} closed, {unopened} not yet open"
            );
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            /// The homomorphism, at a fixed instant. The clock is drawn
            /// with the sets rather than beside them: a window is only a
            /// test of the skip branch if it is positioned against the
            /// instant the fold is taken at.
            #[test]
            fn fold_commutes_with_union((now, a, b) in clocked_sets()) {
                prop_assert_eq!(
                    fold_at::<HeaderTlv>(now, &a.clone().join(b.clone())),
                    fold_at::<HeaderTlv>(now, &a).join(fold_at::<HeaderTlv>(now, &b)),
                );
            }

            /// Merging a set into itself is a no-op at the state level too.
            #[test]
            fn folding_is_idempotent_under_merge((now, a, _b) in clocked_sets()) {
                prop_assert_eq!(
                    fold_at::<HeaderTlv>(now, &a.clone().join(a.clone())),
                    fold_at::<HeaderTlv>(now, &a),
                );
            }
        }
    }
}
