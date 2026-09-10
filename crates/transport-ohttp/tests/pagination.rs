//! Pagination behavior.

use super::*;

/// Advances the cursor over all 40 mixed-recipient frames, checks page request counts, and receives new appends after reaching the tail.
#[tokio::test]
async fn pages_advance_over_other_recipients_and_resume_at_tail() {
    let fixture = Fixture::new().await;
    let (mut a, mut b) = fixture.pair();
    for n in 0..20u8 {
        a.send(&[n]).await.unwrap();
        b.send(&[n + 40]).await.unwrap();
    }
    for n in 0..20u8 {
        assert_eq!(b.recv().await.unwrap(), [n]);
    }
    assert_eq!(b.receive.cursor, 40);
    assert_eq!(b.common.http.controls.calls.load(Ordering::SeqCst), 23); // 20 posts + 3 pages
    assert!(
        tokio::time::timeout(Duration::from_millis(70), b.recv())
            .await
            .is_err()
    );
    assert!(!*b.common.dead.borrow());
    a.send(b"after end").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"after end");
    assert_eq!(b.receive.cursor, 41);
}
