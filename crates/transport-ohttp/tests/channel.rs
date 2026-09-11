//! Channel behavior.

use super::*;

/// Checks bidirectional delivery and the shared transport receive-cancellation contract against the real PoC directory.
#[tokio::test]
async fn conforms_to_message_contract() {
    let fixture = Fixture::new().await;
    let (a, b) = fixture.pair();
    tokio::time::timeout(
        Duration::from_secs(5),
        testkit::roundtrip_both_directions(a, b),
    )
    .await
    .unwrap();
    let fixture = Fixture::new().await;
    let (a, b) = fixture.pair();
    testkit::recv_is_cancel_safe(a, b).await;
}

/// Publishes before the receiver channel exists, then constructs it from its
/// out-of-band link material and retrieves the retained message.
#[tokio::test]
async fn receiver_can_start_after_publication() {
    let fixture = Fixture::new().await;
    let mut sender = OhttpChannel::new(fixture.config(true), fixture.client()).unwrap();

    sender.send(b"stored while offline").await.unwrap();
    drop(sender);

    let mut receiver = OhttpChannel::new(fixture.config(false), fixture.client()).unwrap();
    assert_eq!(receiver.recv().await.unwrap(), b"stored while offline");
}

/// Sends and receives 20 messages in both directions concurrently to detect split-channel deadlocks across pages.
#[tokio::test]
async fn concurrent_bursts_cross_page_boundaries() {
    let fixture = Fixture::new().await;
    let (a, b) = fixture.pair();
    testkit::mutual_bursts_converge(a, b, 20).await;
}

/// Preserves empty messages, trailing zeros and the largest allowed payload; rejects oversized messages before HTTP without killing the channel.
#[tokio::test]
async fn exact_bytes_and_size_limit() {
    let fixture = Fixture::new().await;
    let (mut a, mut b) = fixture.pair();
    assert!(matches!(
        a.send(&vec![0; MAX_MESSAGE_SIZE + 1]).await,
        Err(SendError::TooLarge {
            max: MAX_MESSAGE_SIZE
        })
    ));
    assert_eq!(a.common.http.controls.calls.load(Ordering::SeqCst), 0);
    for message in [Vec::new(), vec![0, 1, 0, 0], vec![0xab; MAX_MESSAGE_SIZE]] {
        a.send(&message).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), message);
    }
}
