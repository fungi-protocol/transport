//! Counting wrapper for a P2P link.
//!
//! Wrapping is the only way to see what a link carried: the gossip engine
//! consumes the channels it is given and never names them, so link identity is
//! assigned here, by whoever wraps.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fungi_transport::{
    Channel, RecvError, RecvHalf, SendError, SendHalf, SessionBound, SplitChannel,
};
use sha2::{Digest, Sha256};

/// Which link an event happened on. Assigned by the caller that wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub u32);

/// Which node recorded an event: the endpoint that owns this side of the
/// link, not the link itself. Two nodes share a `LinkId`; only `NodeId`
/// distinguishes which of them a `Sent` or `Received` event belongs to.
/// Assigned by the caller that wraps, same as `LinkId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub usize);

/// Identity of one frame, so a receipt can be matched to what was sent and
/// duplicates can be counted. Truncated SHA-256 of the frame bytes: not a
/// protocol identity, just enough to tell frames apart in one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameId([u8; 16]);

impl FrameId {
    /// The identity a frame's bytes hash to. Two frames with the same bytes
    /// get the same identity; this is also how a `Publication`'s bytes are
    /// turned into the identity its events carry, for reductions that need
    /// to match a frame back to the workload that produced it.
    pub fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }

    /// The identity's bytes, for putting it in a frame.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Rebuild an identity taken off a frame.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// A distinguishable identity for tests that need frames without bytes.
    #[cfg(test)]
    pub fn for_test(tag: u8) -> Self {
        Self([tag; 16])
    }
}

/// The direction a frame crossed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Handed to the transport by this end.
    Sent,
    /// Returned from the transport at this end.
    Received,
}

/// One frame crossing one link, in one direction, at one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Which node recorded this event: the endpoint this side of the link
    /// belongs to.
    pub node: NodeId,
    /// Which link.
    pub link: LinkId,
    /// Which direction.
    pub dir: Dir,
    /// Which frame.
    pub frame: FrameId,
    /// Application bytes. Wire bytes add the framing prefix, and the report
    /// adds it, not the meter.
    pub bytes: usize,
}

/// Shared sink for events. A mutex and a push: no await, so wrapping adds no
/// scheduling point and cannot change how tasks interleave.
#[derive(Debug, Default)]
pub struct Recorder {
    events: Mutex<Vec<Event>>,
    /// Sends that reached the transport and failed. Counted, never folded
    /// into `events`: a failed send put nothing on the wire, so it has no
    /// frame or byte count worth recording, only its occurrence.
    failed_sends: AtomicUsize,
}

impl Recorder {
    /// Append one event.
    pub fn record(&self, event: Event) {
        self.events
            .lock()
            .expect("recorder mutex poisoned")
            .push(event);
    }

    /// Every event so far, in the order they were recorded, leaving the log
    /// in place. Copies it, so the process holds two of them at once — use
    /// [`Self::take_events`] at the end of a run, where the copy is pure
    /// cost. This one exists for tests that assert on a log the run is still
    /// using.
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("recorder mutex poisoned").clone()
    }

    /// Every event so far, leaving the log EMPTY. The log is the largest
    /// thing a run holds — roughly forty bytes for each of the
    /// `2 x messages x (k + (n-1)(k-1))` frames a flooded run generates, so
    /// hundreds of megabytes on a dense graph at a hundred peers — and
    /// copying it out doubles that at exactly the moment it is biggest.
    /// Call once, when nothing will record again.
    pub fn take_events(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().expect("recorder mutex poisoned"))
    }

    /// Count one failed send.
    pub fn record_failed_send(&self) {
        self.failed_sends.fetch_add(1, Ordering::Relaxed);
    }

    /// Sends that failed so far.
    pub fn failed_sends(&self) -> usize {
        self.failed_sends.load(Ordering::Relaxed)
    }
}

/// A link that records what crosses it.
///
/// Only successful operations are recorded: a `send` that failed put nothing
/// on the wire, and counting it would overstate the cost of every scheme that
/// fails a link.
#[derive(Debug)]
pub struct Metered<C> {
    inner: C,
    node: NodeId,
    link: LinkId,
    log: Arc<Recorder>,
}

impl<C> Metered<C> {
    /// Wrap `inner`, labelling everything it carries with `node` (this
    /// endpoint) and `link` (the edge it sits on).
    pub fn new(inner: C, node: NodeId, link: LinkId, log: Arc<Recorder>) -> Self {
        Self {
            inner,
            node,
            link,
            log,
        }
    }
}

impl<C: Channel> Channel for Metered<C> {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let event = Event {
            node: self.node,
            link: self.link,
            dir: Dir::Sent,
            frame: FrameId::of(msg),
            bytes: msg.len(),
        };
        async move {
            let outcome = self.inner.send(msg).await;
            match outcome {
                Ok(()) => self.log.record(event),
                Err(_) => self.log.record_failed_send(),
            }
            outcome
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        let outcome = self.inner.recv().await;
        if let Ok(bytes) = &outcome {
            self.log.record(Event {
                node: self.node,
                link: self.link,
                dir: Dir::Received,
                frame: FrameId::of(bytes),
                bytes: bytes.len(),
            });
        }
        outcome
    }
}

/// The sending half of a [`Metered`], recording on the same node and link.
#[derive(Debug)]
pub struct MeteredSend<'a, C: SplitChannel + 'a> {
    inner: C::SendHalf<'a>,
    node: NodeId,
    link: LinkId,
    log: Arc<Recorder>,
}

/// The receiving half of a [`Metered`], recording on the same node and link.
#[derive(Debug)]
pub struct MeteredRecv<'a, C: SplitChannel + 'a> {
    inner: C::RecvHalf<'a>,
    node: NodeId,
    link: LinkId,
    log: Arc<Recorder>,
}

impl<C: SplitChannel> SendHalf for MeteredSend<'_, C> {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let event = Event {
            node: self.node,
            link: self.link,
            dir: Dir::Sent,
            frame: FrameId::of(msg),
            bytes: msg.len(),
        };
        async move {
            let outcome = self.inner.send(msg).await;
            match outcome {
                Ok(()) => self.log.record(event),
                Err(_) => self.log.record_failed_send(),
            }
            outcome
        }
    }
}

impl<C: SplitChannel> RecvHalf for MeteredRecv<'_, C> {
    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        let outcome = self.inner.recv().await;
        if let Ok(bytes) = &outcome {
            self.log.record(Event {
                node: self.node,
                link: self.link,
                dir: Dir::Received,
                frame: FrameId::of(bytes),
                bytes: bytes.len(),
            });
        }
        outcome
    }
}

impl<C: SplitChannel> SplitChannel for Metered<C> {
    type SendHalf<'a>
        = MeteredSend<'a, C>
    where
        Self: 'a;
    type RecvHalf<'a>
        = MeteredRecv<'a, C>
    where
        Self: 'a;

    fn split(&mut self) -> (Self::SendHalf<'_>, Self::RecvHalf<'_>) {
        let (send, recv) = self.inner.split();
        (
            MeteredSend {
                inner: send,
                node: self.node,
                link: self.link,
                log: self.log.clone(),
            },
            MeteredRecv {
                inner: recv,
                node: self.node,
                link: self.link,
                log: self.log.clone(),
            },
        )
    }
}

// Wrapping an admitted link does not unadmit it: the marker travels with the
// channel it describes.
impl<C: SessionBound> SessionBound for Metered<C> {}

#[cfg(test)]
mod tests {
    use super::*;
    use fungi_transport::Channel;
    use fungi_transport::mem::{MemConfig, duplex};
    use fungi_transport::{
        AssumeSessionBound, BroadcastChannel, GossipBroadcast, RecvHalf, SendHalf, SplitChannel,
    };

    #[test]
    fn taking_the_log_hands_over_the_same_events_and_leaves_it_empty() {
        let log = Recorder::default();
        for tag in 0..3u8 {
            log.record(Event {
                node: NodeId(usize::from(tag)),
                link: LinkId(u32::from(tag)),
                dir: Dir::Sent,
                frame: FrameId::for_test(tag),
                bytes: usize::from(tag) + 1,
            });
        }
        let copied = log.events();

        let taken = log.take_events();

        assert_eq!(taken, copied, "taking must not alter what is handed back");
        assert!(
            log.events().is_empty(),
            "the log must be empty afterwards, or the saving is not real"
        );
    }

    #[tokio::test]
    async fn a_frame_is_recorded_once_on_each_end_with_the_same_identity() {
        let log = Arc::new(Recorder::default());
        let (a, b) = duplex(MemConfig::default());
        let mut a = Metered::new(a, NodeId(0), LinkId(7), log.clone());
        let mut b = Metered::new(b, NodeId(1), LinkId(7), log.clone());

        a.send(b"fragment").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"fragment");

        let events = log.events();
        assert_eq!(events.len(), 2, "one send and one receive: {events:?}");
        assert_eq!(events[0].dir, Dir::Sent);
        assert_eq!(events[1].dir, Dir::Received);
        assert_eq!(
            events[0].frame, events[1].frame,
            "same bytes, same identity"
        );
        assert_eq!(events[0].bytes, 8);
        assert!(events.iter().all(|e| e.link == LinkId(7)));
        assert_eq!(events[0].node, NodeId(0), "the sender is node 0");
        assert_eq!(events[1].node, NodeId(1), "the receiver is node 1");
    }

    #[tokio::test]
    async fn distinct_payloads_get_distinct_identities() {
        let log = Arc::new(Recorder::default());
        let (a, _b) = duplex(MemConfig {
            capacity: Some(4),
            ..MemConfig::default()
        });
        let mut a = Metered::new(a, NodeId(0), LinkId(1), log.clone());

        a.send(b"one").await.unwrap();
        a.send(b"two").await.unwrap();

        let events = log.events();
        assert_ne!(events[0].frame, events[1].frame);
    }

    #[tokio::test]
    async fn the_two_halves_record_the_same_link_and_their_own_node() {
        let log = Arc::new(Recorder::default());
        let (a, b) = duplex(MemConfig {
            capacity: Some(2),
            ..MemConfig::default()
        });
        let mut a = Metered::new(a, NodeId(10), LinkId(3), log.clone());
        let mut b = Metered::new(b, NodeId(11), LinkId(3), log.clone());

        let (mut tx, _rx) = a.split();
        let (_tx, mut rx) = b.split();
        tx.send(b"halved").await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), b"halved");

        let events = log.events();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.link == LinkId(3)));
        assert_eq!(events[0].frame, events[1].frame);
        assert_eq!(events[0].node, NodeId(10), "sent from node 10's half");
        assert_eq!(events[1].node, NodeId(11), "received on node 11's half");
    }

    #[tokio::test]
    async fn a_failed_send_is_counted_but_not_logged_as_an_event() {
        let log = Arc::new(Recorder::default());
        let (a, b) = duplex(MemConfig {
            capacity: Some(1),
            max_msg_len: Some(4),
            ..MemConfig::default()
        });
        let mut a = Metered::new(a, NodeId(0), LinkId(0), log.clone());
        let _b = Metered::new(b, NodeId(1), LinkId(0), log.clone());

        assert!(a.send(b"way too long").await.is_err());

        assert_eq!(log.failed_sends(), 1);
        assert!(
            log.events().is_empty(),
            "a failed send put nothing on the wire, so it logs no event"
        );
    }

    #[tokio::test]
    async fn a_metered_link_can_form_a_gossip_group() {
        let log = Arc::new(Recorder::default());
        let (a, b) = duplex(MemConfig {
            capacity: Some(2),
            ..MemConfig::default()
        });
        let a = Metered::new(AssumeSessionBound(a), NodeId(0), LinkId(0), log.clone());
        let b = Metered::new(AssumeSessionBound(b), NodeId(1), LinkId(0), log.clone());

        let mut left = GossipBroadcast::new(vec![a]);
        let mut right = GossipBroadcast::new(vec![b]);
        left.send(b"across").await.unwrap();
        assert_eq!(right.recv().await.unwrap(), b"across");

        assert!(log.events().iter().any(|e| e.dir == Dir::Received));
    }

    /// Runs the `testkit` items that apply to a bare `Channel`/`SplitChannel`
    /// wrapper. `connect_use_drop_reconnect` is a `Connector`/`Listener`
    /// item and `Metered` is neither; the `broadcast_*` items take a
    /// `BroadcastChannel` group, which `a_metered_link_can_form_a_gossip_group`
    /// above already exercises through the real engine. Neither applies here.
    #[tokio::test]
    async fn conformance_holds_through_the_meter() {
        let log = Arc::new(Recorder::default());

        // Two back-to-back sends before either side reads: needs room for
        // both, unlike the burst check below where send and recv run
        // concurrently.
        let (a, b) = duplex(MemConfig {
            capacity: Some(2),
            ..MemConfig::default()
        });
        fungi_transport::testkit::roundtrip_both_directions(
            Metered::new(a, NodeId(0), LinkId(1), log.clone()),
            Metered::new(b, NodeId(1), LinkId(2), log.clone()),
        )
        .await;

        let (a, b) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        fungi_transport::testkit::mutual_bursts_converge(
            Metered::new(a, NodeId(0), LinkId(3), log.clone()),
            Metered::new(b, NodeId(1), LinkId(4), log.clone()),
            8,
        )
        .await;

        // No sends happen before the drop, so capacity 1 is enough.
        let (a, b) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        fungi_transport::testkit::closed_after_peer_drop(
            Metered::new(a, NodeId(0), LinkId(5), log.clone()),
            Metered::new(b, NodeId(1), LinkId(5), log.clone()),
        )
        .await;

        // Only one send follows the cancelled polls, so capacity 1 holds it.
        // This is the item that matters most here: the gossip link task
        // selects over the receiving half exactly the way this item cancels
        // `recv`, so it is what would catch a wrapper that broke
        // cancel-safety.
        let (a, b) = duplex(MemConfig {
            capacity: Some(1),
            ..MemConfig::default()
        });
        fungi_transport::testkit::recv_is_cancel_safe(
            Metered::new(a, NodeId(0), LinkId(6), log.clone()),
            Metered::new(b, NodeId(1), LinkId(6), log.clone()),
        )
        .await;

        // The recovery send after `TooLarge` is the second send on this
        // link; capacity 1 is enough because nothing else is queued ahead of
        // it.
        let (a, b) = duplex(MemConfig {
            capacity: Some(1),
            max_msg_len: Some(16),
            ..MemConfig::default()
        });
        fungi_transport::testkit::too_large_is_recoverable(
            Metered::new(a, NodeId(0), LinkId(7), log.clone()),
            Metered::new(b, NodeId(1), LinkId(7), log.clone()),
            16,
        )
        .await;
    }
}
