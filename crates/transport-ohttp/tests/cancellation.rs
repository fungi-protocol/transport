//! Cancellation behavior.

use super::*;

/// Cancels a receive after the server responds but before the client commits the page, then verifies both messages can still be read.
#[tokio::test]
async fn cancelling_received_http_page_does_not_advance_cursor_or_lose_messages() {
    let fixture = Fixture::new().await;
    let (mut a, mut b) = fixture.pair();
    a.send(b"one").await.unwrap();
    a.send(b"two").await.unwrap();
    let controls = b.common.http.controls.clone();
    controls.next.store(2, Ordering::SeqCst);
    {
        let recv = b.recv();
        tokio::pin!(recv);
        tokio::select! {
            _ = controls.parked.notified() => {},
            _ = &mut recv => panic!("response must park"),
        }
    }
    assert_eq!(b.receive.cursor, 0);
    assert_eq!(b.recv().await.unwrap(), b"one");
    assert_eq!(b.recv().await.unwrap(), b"two");
    assert_eq!(controls.calls.load(Ordering::SeqCst), 2);
}

/// Injects a send failure while receive is parked; verifies receive wakes with Closed and future sends fail.
#[tokio::test]
async fn send_failure_wakes_parked_receiver_and_kills_both_halves() {
    let fixture = Fixture::new().await;
    let (mut a, mut b) = fixture.pair();
    a.send(b"waiting").await.unwrap();
    let controls = b.common.http.controls.clone();
    controls.next.store(2, Ordering::SeqCst);
    let (mut tx, mut rx) = b.split();
    let receive = rx.recv();
    tokio::pin!(receive);
    tokio::select! {
        _ = controls.parked.notified() => {},
        _ = &mut receive => panic!("response must park"),
    }
    controls.next.store(1, Ordering::SeqCst);
    assert!(matches!(
        tx.send(b"failure").await,
        Err(SendError::Transport(_))
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), &mut receive)
            .await
            .unwrap(),
        Err(RecvError::Closed)
    ));
    assert!(matches!(tx.send(b"dead").await, Err(SendError::Closed)));
}

/// Cancels a send after the server accepts it; verifies the peer gets the message, the sender channel dies, and no retry occurs.
#[tokio::test]
async fn cancelled_send_is_ambiguous_and_poisoned() {
    let fixture = Fixture::new().await;
    let (mut a, mut b) = fixture.pair();
    let controls = a.common.http.controls.clone();
    controls.next.store(2, Ordering::SeqCst);
    {
        let send = a.send(b"accepted but response abandoned");
        tokio::pin!(send);
        tokio::select! {
            _ = controls.parked.notified() => {},
            _ = &mut send => panic!("response must park"),
        }
    }
    assert!(matches!(a.send(b"dead").await, Err(SendError::Closed)));
    assert!(matches!(a.recv().await, Err(RecvError::Closed)));
    assert_eq!(b.recv().await.unwrap(), b"accepted but response abandoned");
    assert_eq!(controls.calls.load(Ordering::SeqCst), 1); // No retry of ambiguous append.
}

/// Injects an HTTP receive failure and verifies the sending direction becomes unusable too.
#[tokio::test]
async fn receive_error_kills_sender() {
    let fixture = Fixture::new().await;
    let (_, mut b) = fixture.pair();
    b.common.http.controls.next.store(1, Ordering::SeqCst);
    assert!(matches!(b.recv().await, Err(RecvError::Transport(_))));
    assert!(matches!(b.send(b"dead").await, Err(SendError::Closed)));
}
