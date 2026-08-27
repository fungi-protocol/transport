//! Conformance suite for [`Channel`] implementations. Any transport
//! (in-memory, SOCKS5h, arti, OHTTP mailbox) must pass these; each test
//! takes a freshly connected pair. Ordering is deliberately NOT asserted —
//! the trait promises none.

use crate::channel::{Channel, Connector, Listener};
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
