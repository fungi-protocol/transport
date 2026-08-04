//! The comparison bench consumer, v3 flavour. Five scenarios, identical
//! across variants; differences in line count and contortions are the
//! experiment's data.

use fungi_transport::v3::mem::{
    Delivery, MemAddr, MemConfig, MemReceiver, MemSender, duplex, network,
};
use fungi_transport::v3::{Connector, Listener, Sender};
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
    let (a, b) = duplex(MemConfig::default());
    let (mut a_tx, mut a_rx) = a.into();
    let (mut b_tx, mut b_rx) = b.into();
    for i in 0u8..3 {
        a_tx.send(&[i]).await.unwrap();
        assert_eq!(b_rx.next().await.unwrap().unwrap(), [i]);
        b_tx.send(&[i, i]).await.unwrap();
        assert_eq!(a_rx.next().await.unwrap().unwrap(), [i, i]);
    }
    println!("scenario 1: ok");
}

/// 2. Full duplex — both directions at once on ONE channel end.
///
/// v3 fixes full duplex by construction: `into()` gives independently
/// owned halves, so peer A's sender loop and receive loop simply live in
/// different places (a spawned task and the caller) with no pump task or
/// extra mpsc queues standing in for a split.
async fn scenario_2_full_duplex() {
    let (a, b) = duplex(MemConfig {
        capacity: Some(16),
        ..Default::default()
    });

    // Peer B: split; a spawned task forwards rx payloads straight into tx.
    let (mut b_tx, mut b_rx) = b.into();
    tokio::spawn(async move {
        while let Some(Ok(msg)) = b_rx.next().await {
            if b_tx.send(&msg).await.is_err() {
                break;
            }
        }
    });

    // Peer A: split; the sender loop owns tx in its own task, the receive
    // loop runs inline on rx. No pump task needed.
    let (mut a_tx, mut a_rx) = a.into();
    let sender = tokio::spawn(async move {
        for i in 0u8..50 {
            a_tx.send(&[i]).await.unwrap();
        }
    });
    let mut echoed = 0;
    while echoed < 50 {
        a_rx.next().await.unwrap().unwrap();
        echoed += 1;
    }
    sender.await.unwrap();
    println!("scenario 2: ok");
}

/// 3. Multiplex N channels — one consumer serving several peers.
async fn scenario_3_multiplex() {
    let mut pairs: Vec<_> = (0..4u8)
        .map(|_| {
            let (a, b) = duplex(MemConfig::default());
            let (a_tx, _a_rx) = a.into();
            (a_tx, b)
        })
        .collect();
    for (i, (a_tx, _)) in pairs.iter_mut().enumerate() {
        a_tx.send(&[i as u8]).await.unwrap();
    }
    // v3: the "a" sends already happened through split senders above;
    // select_all needs the b halves as streams — extract each Receiver via
    // `.into()`.
    let mut merged = futures_util::stream::select_all(
        pairs
            .into_iter()
            .map(|(_a, b)| <(MemSender, MemReceiver)>::from(b).1),
    );
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < 4 {
        // _a senders dropped above => streams end (None) after buffered
        // messages; only count the payloads.
        match merged.next().await {
            Some(Ok(msg)) => {
                seen.insert(msg[0]);
            }
            Some(Err(e)) => panic!("unexpected: {e}"),
            None => {}
        }
    }
    println!("scenario 3: ok");
}

/// 4. Death and reconnection via the connector.
async fn scenario_4_reconnect() {
    let (connector, mut listener) = network(MemConfig::default());
    let (client, server) = tokio::join!(connector.connect(&MemAddr), listener.accept());
    let (client, server) = (client.unwrap(), server.unwrap());
    let (mut client_tx, _client_rx) = client.into();
    drop(server); // circuit dies
    let err = client_tx.send(b"x").await;
    assert!(
        err.is_err(),
        "send on dead channel must error (Confirmed mode)"
    );
    // consumer's move: reconnect through the same connector
    let (client2, server2) = tokio::join!(connector.connect(&MemAddr), listener.accept());
    let (client2, server2) = (client2.unwrap(), server2.unwrap());
    let (mut client2_tx, _client2_rx) = client2.into();
    let (_server2_tx, mut server2_rx) = server2.into();
    client2_tx.send(b"back").await.unwrap();
    assert_eq!(server2_rx.next().await.unwrap().unwrap(), b"back");
    println!("scenario 4: ok");
}

/// 5. Cancellation — recv in select! against another branch; no loss.
async fn scenario_5_cancellation() {
    let (a, b) = duplex(MemConfig {
        delivery: Delivery::BestEffort,
        ..Default::default()
    });
    let (mut a_tx, _a_rx) = a.into();
    let (_b_tx, mut b_rx) = b.into();
    let mut ticks = 0u32;
    let mut got = None;
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(1));
    while got.is_none() {
        tokio::select! {
            _ = interval.tick() => {
                ticks += 1;
                if ticks == 3 {
                    a_tx.send(b"late").await.unwrap();
                }
            }
            msg = b_rx.next() => got = Some(msg.unwrap().unwrap()),
        }
    }
    assert_eq!(got.unwrap(), b"late");
    println!("scenario 5: ok");
}
