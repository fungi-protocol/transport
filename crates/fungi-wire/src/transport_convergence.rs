//! End-to-end checks from typed messages through distinct broadcast
//! implementations into the same logical message set.

use fungi_transport::mem::{MemConfig, duplex, group};
use fungi_transport::{BroadcastChannel, GossipBroadcast};

use crate::{Body, Encoding, HeaderTlv, Message, MessageSet};

fn messages() -> Vec<Vec<u8>> {
    [
        Body::Payment(b"payment".to_vec()),
        Body::Psbt(b"fragment".to_vec()),
        Body::Confirmation(b"confirmation".to_vec()),
    ]
    .into_iter()
    .map(|body| HeaderTlv::encode(&Message::new(body)).expect("messages are encodable"))
    .collect()
}

async fn converge<C: BroadcastChannel>(nodes: &mut [C]) -> Vec<MessageSet> {
    let messages = messages();
    let mut sets: Vec<MessageSet> = messages
        .iter()
        .cloned()
        .map(|own| {
            let mut set = MessageSet::default();
            set.insert(own).unwrap();
            set
        })
        .collect();

    // A replay is harmless: one backend may forward it and another may
    // suppress it, but neither changes logical membership.
    nodes[0].send(&messages[0]).await.expect("send");
    nodes[0].send(&messages[0]).await.expect("replay");
    nodes[2].send(&messages[2]).await.expect("send");
    nodes[1].send(&messages[1]).await.expect("send");

    for (node, set) in nodes.iter_mut().zip(&mut sets) {
        while set.len() != messages.len() {
            let bytes = tokio::time::timeout(std::time::Duration::from_secs(3), node.recv())
                .await
                .expect("connected broadcast converges")
                .expect("broadcast stays alive");
            set.insert(bytes).unwrap();
        }
    }
    sets
}

#[tokio::test]
async fn server_style_broadcast_and_p2p_gossip_converge_on_the_same_set() {
    let cfg = MemConfig {
        capacity: Some(16),
        ..MemConfig::default()
    };
    let mut server_style = group(3, cfg.clone());
    let server_sets = converge(&mut server_style).await;

    // A--B--C: unlike the in-memory group above, A and C only communicate
    // through B's gossip forwarding.
    let (ab, ba) = duplex(cfg.clone());
    let (bc, cb) = duplex(cfg);
    let mut gossip = vec![
        GossipBroadcast::new(vec![ab]),
        GossipBroadcast::new(vec![ba, bc]),
        GossipBroadcast::new(vec![cb]),
    ];
    let gossip_sets = converge(&mut gossip).await;

    let expected = server_sets[0].commitment();
    assert!(server_sets.iter().all(|set| set.commitment() == expected));
    assert!(gossip_sets.iter().all(|set| set.commitment() == expected));
}
