//! Conformance suite for [`Channel`] and [`BroadcastChannel`] implementations.
//! Any transport (in-memory, SOCKS5h, arti, OHTTP mailbox) must pass these;
//! each test takes a freshly connected pair. Ordering is deliberately NOT
//! asserted — the trait promises none.

use crate::channel::{
    AttributableBroadcastChannel, BroadcastChannel, Channel, Connector, Listener, RecvHalf,
    SendHalf, SplitChannel,
};
use crate::error::{RecvError, SendError};

/// Everything sent arrives intact, both directions. No order assertion.
pub async fn roundtrip_both_directions<C: Channel>(mut a: C, mut b: C) {
    a.send(b"m1").await.unwrap();
    a.send(b"m2").await.unwrap();
    let got = [b.recv().await.unwrap(), b.recv().await.unwrap()];
    assert!(got.contains(&b"m1".to_vec()) && got.contains(&b"m2".to_vec()));
    b.send(b"reply").await.unwrap();
    assert_eq!(a.recv().await.unwrap(), b"reply");
}

/// A dropped peer surfaces as `Closed`.
pub async fn closed_after_peer_drop<C: Channel>(a: C, mut b: C) {
    drop(a);
    assert!(matches!(b.recv().await, Err(RecvError::Closed)));
}

/// An abandoned recv future must not lose messages.
pub async fn recv_is_cancel_safe<C: Channel>(mut a: C, mut b: C) {
    for _ in 0..10 {
        let poll = tokio::time::timeout(std::time::Duration::from_millis(5), b.recv()).await;
        assert!(poll.is_err());
    }
    a.send(b"m1").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"m1");
}

/// A message larger than the transport's declared maximum is rejected with
/// [`SendError::TooLarge`], never silently truncated or accepted.
pub async fn too_large<C: Channel>(mut a: C, max: usize) {
    let oversized = vec![0u8; max + 1];
    assert!(matches!(
        a.send(&oversized).await,
        Err(SendError::TooLarge { max: m }) if m == max
    ));
}

/// `TooLarge` is a RECOVERABLE rejection: the oversized message never
/// touches the wire, so the channel stays usable — the next within-limit
/// send round-trips.
pub async fn too_large_is_recoverable<C: Channel>(mut a: C, mut b: C, max: usize) {
    let oversized = vec![0u8; max + 1];
    assert!(matches!(
        a.send(&oversized).await,
        Err(SendError::TooLarge { .. })
    ));
    a.send(b"still alive")
        .await
        .expect("channel survives TooLarge");
    assert_eq!(b.recv().await.unwrap(), b"still alive");
}

/// Two peers under MUTUAL load converge: each pushes a burst while draining
/// the other, over links narrow enough that every send after the first waits
/// on the peer. Driven through [`SplitChannel`], where the sending and
/// receiving halves progress together — the same exchange through
/// [`Channel`] alone deadlocks, because a task awaiting `send` is not
/// polling `recv`.
pub async fn mutual_bursts_converge<C: SplitChannel>(mut a: C, mut b: C, burst: usize) {
    async fn drive<C: SplitChannel>(ch: &mut C, tag: u8, burst: usize) -> (usize, usize) {
        let (mut tx, mut rx) = ch.split();
        let sending = async move {
            let mut sent = 0;
            for i in 0..burst {
                if tx.send(&[tag, i as u8]).await.is_err() {
                    break;
                }
                sent += 1;
            }
            sent
        };
        let receiving = async move {
            let mut got = 0;
            while got < burst {
                if rx.recv().await.is_err() {
                    break;
                }
                got += 1;
            }
            got
        };
        futures_util::future::join(sending, receiving).await
    }

    let both = futures_util::future::join(drive(&mut a, b'a', burst), drive(&mut b, b'b', burst));
    let (a_counts, b_counts) = tokio::time::timeout(std::time::Duration::from_secs(30), both)
        .await
        .expect("peers under mutual load must not wedge each other");
    assert_eq!(a_counts, (burst, burst), "peer a must send and receive all");
    assert_eq!(b_counts, (burst, burst), "peer b must send and receive all");
}

/// The connection-oriented lifecycle: connect, exchange a message, lose the
/// peer for real, detect it, then RE-establish through the same connector.
/// Only for [`Connector`]/[`Listener`] transports; message-based ones (a
/// mailbox) never open or drop a connection.
pub async fn connect_use_drop_reconnect<Co, L>(connector: Co, mut listener: L, addr: &Co::Addr)
where
    Co: Connector,
    L: Listener,
{
    // Round 1: connect and accept concurrently, exchange one message.
    let (client, server) =
        futures_util::future::join(connector.connect(addr), listener.accept()).await;
    let (mut client, mut server) = (client.expect("connect"), server.expect("accept"));
    client.send(b"hello").await.unwrap();
    assert_eq!(server.recv().await.unwrap(), b"hello");

    // The peer dies for real. `recv` is the reliable detector across
    // transports: in-memory surfaces `Closed` instantly, and a byte-stream
    // transport sees the peer's close (EOF) as soon as it propagates — unlike
    // `send`, which can keep buffering into a socket for a while first. The
    // timeout guards against a transport that wrongly hangs instead.
    drop(server);
    let detected = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv())
        .await
        .expect("a dropped peer must be detected, not hang");
    assert!(detected.is_err(), "a dropped peer must surface as an error");

    // Reconnect through the SAME connector and exchange again.
    let (client2, server2) =
        futures_util::future::join(connector.connect(addr), listener.accept()).await;
    let (mut client2, mut server2) = (client2.expect("reconnect"), server2.expect("re-accept"));
    client2.send(b"again").await.unwrap();
    assert_eq!(server2.recv().await.unwrap(), b"again");
}

/// One send reaches every other member intact, and the sender does NOT
/// receive its own message (no echo).
pub async fn broadcast_reaches_all_others<B: BroadcastChannel>(mut group: Vec<B>) {
    assert!(group.len() >= 3, "needs a group of at least 3");
    group[0].send(b"to everyone else").await.unwrap();
    for member in group.iter_mut().skip(1) {
        assert_eq!(member.recv().await.unwrap(), b"to everyone else");
    }
    let echo = tokio::time::timeout(std::time::Duration::from_millis(50), group[0].recv()).await;
    assert!(echo.is_err(), "a sender must not receive its own broadcast");
}

/// An abandoned broadcast recv future must not lose messages.
pub async fn broadcast_recv_is_cancel_safe<B: BroadcastChannel>(mut group: Vec<B>) {
    assert!(group.len() >= 2, "needs a group of at least 2");
    for _ in 0..10 {
        let poll = tokio::time::timeout(std::time::Duration::from_millis(5), group[1].recv()).await;
        assert!(poll.is_err());
    }
    group[0].send(b"m1").await.unwrap();
    assert_eq!(group[1].recv().await.unwrap(), b"m1");
}

/// `TooLarge` is RECOVERABLE on a broadcast channel too: the oversized
/// message reaches no one and the channel stays usable.
pub async fn broadcast_too_large_is_recoverable<B: BroadcastChannel>(
    mut group: Vec<B>,
    max: usize,
) {
    assert!(group.len() >= 2, "needs a group of at least 2");
    let oversized = vec![0u8; max + 1];
    assert!(matches!(
        group[0].send(&oversized).await,
        Err(SendError::TooLarge { max: m }) if m == max
    ));
    group[0]
        .send(b"still alive")
        .await
        .expect("channel survives TooLarge");
    assert_eq!(group[1].recv().await.unwrap(), b"still alive");
}

/// Once every other member is gone, the last member's recv reports the
/// channel dead.
pub async fn closed_after_group_drop<B: BroadcastChannel>(mut group: Vec<B>) {
    let mut last = group.pop().expect("non-empty group");
    drop(group);
    assert!(
        last.recv().await.is_err(),
        "an abandoned member must see a dead channel"
    );
}

/// Every message arrives attributed to the member that sent it: two members
/// send, a third receives both, the senders are distinct, and re-sends from
/// the same member carry an equal sender.
pub async fn attribution_matches_sender<B: AttributableBroadcastChannel>(mut group: Vec<B>) {
    assert!(group.len() >= 3, "needs a group of at least 3");
    group[0].send(b"first").await.unwrap();
    group[1].send(b"second").await.unwrap();
    group[0].send(b"first again").await.unwrap();
    let mut by_msg = std::collections::HashMap::new();
    for _ in 0..3 {
        let (sender, msg) = group[2].recv().await.unwrap();
        by_msg.insert(msg, sender);
    }
    let a = by_msg.get(b"first".as_slice()).expect("got first");
    let b = by_msg.get(b"second".as_slice()).expect("got second");
    let a2 = by_msg
        .get(b"first again".as_slice())
        .expect("got first again");
    // Plain comparisons: `SenderId` guarantees Eq but not Debug.
    assert!(a != b, "distinct members must compare distinct");
    assert!(
        a == a2,
        "the same member must compare equal across messages"
    );
}
