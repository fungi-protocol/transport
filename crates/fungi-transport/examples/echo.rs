//! Five scenarios exercising the channel abstraction end to end: ping-pong,
//! full duplex, multiplexing, reconnect, and cancellation.

use fungi_transport::RecvError;
use fungi_transport::mem::{Delivery, MemAddr, MemChannel, MemConfig, duplex, network};
use fungi_transport::{
    Channel, Connector, Listener, RecvHalf, SendHalf, SplitChannel, into_stream,
};
use futures_util::StreamExt;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    scenario_1_ping_pong().await;
    scenario_2_full_duplex().await;
    scenario_3_multiplex().await;
    scenario_4_reconnect().await;
    scenario_5_cancellation().await;
}

/// 1. Sequential ping-pong — the ergonomics baseline.
async fn scenario_1_ping_pong() {
    let (mut a, mut b) = duplex(MemConfig::default());
    for i in 0u8..3 {
        a.send(&[i]).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), [i]);
        b.send(&[i, i]).await.unwrap();
        assert_eq!(a.recv().await.unwrap(), [i, i]);
    }
    println!("scenario 1: ok");
}

/// 2. Full duplex — both directions at once on ONE channel end.
///
/// `SplitChannel` borrows the two directions separately, so a blocked send
/// never stops the receive that would release its peer.
async fn scenario_2_full_duplex() {
    async fn drive(ch: &mut MemChannel, tag: u8) -> Vec<Vec<u8>> {
        let (mut tx, mut rx) = ch.split();
        let sending = async move {
            for i in 0u8..50 {
                tx.send(&[tag, i]).await.unwrap();
            }
        };
        let receiving = async move {
            let mut messages = Vec::with_capacity(50);
            for _ in 0..50 {
                messages.push(rx.recv().await.unwrap());
            }
            messages
        };
        let ((), messages) = futures_util::future::join(sending, receiving).await;
        messages
    }

    // With one slot per direction, each peer's second send waits until the
    // other peer reads. Both peers must therefore keep receiving while they
    // push their bursts.
    let (mut a, mut b) = duplex(MemConfig {
        capacity: Some(1),
        ..Default::default()
    });
    let (from_b, from_a) =
        futures_util::future::join(drive(&mut a, b'a'), drive(&mut b, b'b')).await;
    assert!(from_b.iter().all(|msg| msg[0] == b'b'));
    assert!(from_a.iter().all(|msg| msg[0] == b'a'));
    println!("scenario 2: ok");
}

/// 3. Multiplex N channels — one consumer serving several peers.
async fn scenario_3_multiplex() {
    let mut pairs: Vec<_> = (0..4u8).map(|_| duplex(MemConfig::default())).collect();
    for (i, (a, _)) in pairs.iter_mut().enumerate() {
        a.send(&[i as u8]).await.unwrap();
    }
    // Adapt each receiving end to a Stream, then select_all.
    let streams = pairs
        .into_iter()
        .map(|(_a, b)| Box::pin(into_stream(b)))
        .collect::<Vec<_>>();
    let mut merged = futures_util::stream::select_all(streams);
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < 4 {
        // _a ends dropped above => streams end after buffered messages;
        // only count the payloads.
        match merged.next().await {
            Some(Ok(msg)) => {
                seen.insert(msg[0]);
            }
            Some(Err(RecvError::Closed)) | None => {}
            Some(Err(e)) => panic!("unexpected: {e}"),
        }
    }
    println!("scenario 3: ok");
}

/// 4. Death and reconnection via the connector.
async fn scenario_4_reconnect() {
    let (connector, mut listener) = network(MemConfig::default());
    let (client, server) = tokio::join!(connector.connect(&MemAddr), listener.accept());
    let (mut client, server) = (client.unwrap(), server.unwrap());
    drop(server); // circuit dies
    let err = client.send(b"x").await;
    assert!(
        err.is_err(),
        "send on dead channel must error (Confirmed mode)"
    );
    // consumer's move: reconnect through the same connector
    let (client2, server2) = tokio::join!(connector.connect(&MemAddr), listener.accept());
    let (mut client2, mut server2) = (client2.unwrap(), server2.unwrap());
    client2.send(b"back").await.unwrap();
    assert_eq!(server2.recv().await.unwrap(), b"back");
    println!("scenario 4: ok");
}

/// 5. Cancellation — recv in select! against another branch; no loss.
async fn scenario_5_cancellation() {
    let (mut a, mut b) = duplex(MemConfig {
        delivery: Delivery::BestEffort,
        ..Default::default()
    });
    let mut ticks = 0u32;
    let mut got = None;
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(1));
    while got.is_none() {
        tokio::select! {
            _ = interval.tick() => {
                ticks += 1;
                if ticks == 3 {
                    a.send(b"late").await.unwrap();
                }
            }
            msg = b.recv() => got = Some(msg.unwrap()),
        }
    }
    assert_eq!(got.unwrap(), b"late");
    println!("scenario 5: ok");
}
