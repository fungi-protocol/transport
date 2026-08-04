//! The comparison bench consumer, v2 flavour. Five scenarios, identical
//! across variants; differences in line count and contortions are the
//! experiment's data.

use fungi_transport::v2::mem::{Delivery, MemAddr, MemConfig, duplex, network};
use fungi_transport::v2::{Channel, Connector, Listener};
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
        assert_eq!(b.next().await.unwrap().unwrap(), [i]);
        b.send(&[i, i]).await.unwrap();
        assert_eq!(a.next().await.unwrap().unwrap(), [i, i]);
    }
    println!("scenario 1: ok");
}

/// 2. Full duplex — both directions at once on ONE channel end.
///
/// v2 does NOT fix full duplex: `send` still takes `&mut self` while `next`
/// (the `Stream` impl) also borrows mutably, so one end still cannot do
/// both concurrently. Same workaround as v1: a task owns the end; two mpsc
/// queues expose the halves. This boilerplate is the measurement.
async fn scenario_2_full_duplex() {
    let (a, mut b) = duplex(MemConfig {
        capacity: Some(16),
        ..Default::default()
    });

    // Peer B: plain echo loop in its own task.
    tokio::spawn(async move {
        while let Some(Ok(msg)) = b.next().await {
            if b.send(&msg).await.is_err() {
                break;
            }
        }
    });

    // Peer A: manual split — the channel lives in a pump task.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    tokio::spawn(async move {
        let mut a = a;
        loop {
            tokio::select! {
                outgoing = out_rx.recv() => match outgoing {
                    Some(msg) => { if a.send(&msg).await.is_err() { break } }
                    None => break,
                },
                incoming = a.next() => match incoming {
                    Some(Ok(msg)) => { if in_tx.send(msg).await.is_err() { break } }
                    Some(Err(_)) => break,
                    None => break,
                },
            }
        }
    });

    let sender = tokio::spawn(async move {
        for i in 0u8..50 {
            out_tx.send(vec![i]).await.unwrap();
        }
        out_tx
    });
    let mut echoed = 0;
    while echoed < 50 {
        in_rx.recv().await.unwrap();
        echoed += 1;
    }
    drop(sender.await.unwrap());
    println!("scenario 2: ok");
}

/// 3. Multiplex N channels — one consumer serving several peers.
async fn scenario_3_multiplex() {
    let mut pairs: Vec<_> = (0..4u8).map(|_| duplex(MemConfig::default())).collect();
    for (i, (a, _)) in pairs.iter_mut().enumerate() {
        a.send(&[i as u8]).await.unwrap();
    }
    // v2 payoff: channels ARE streams — select_all directly, no into_stream
    // adapter, no Box::pin (MemChannel: Unpin, per the Channel bound).
    let mut merged = futures_util::stream::select_all(pairs.into_iter().map(|(_a, b)| b));
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < 4 {
        // _a ends dropped above => streams end (None) after buffered
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
    let (mut client, server) = (client.unwrap(), server.unwrap());
    drop(server); // circuit dies
    // v2 surfaces death on the READ side as stream end (None), not an
    // error; the send side is unchanged from v1 — Confirmed send to a
    // dropped peer still errors.
    let err = client.send(b"x").await;
    assert!(
        err.is_err(),
        "send on dead channel must error (Confirmed mode)"
    );
    // consumer's move: reconnect through the same connector
    let (client2, server2) = tokio::join!(connector.connect(&MemAddr), listener.accept());
    let (mut client2, mut server2) = (client2.unwrap(), server2.unwrap());
    client2.send(b"back").await.unwrap();
    assert_eq!(server2.next().await.unwrap().unwrap(), b"back");
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
            msg = b.next() => got = Some(msg.unwrap().unwrap()),
        }
    }
    assert_eq!(got.unwrap(), b"late");
    println!("scenario 5: ok");
}
