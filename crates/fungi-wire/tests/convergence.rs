//! Typed-message convergence across server-style broadcast and framed gossip.

use fungi_transport::framed::{DEFAULT_MAX_MSG_LEN, FramedChannel};
use fungi_transport::mem::{MemConfig, group};
use fungi_transport::{BroadcastChannel, GossipBroadcast};
use fungi_wire::{Body, CanonicalMessage, Message, MessageSet};

const DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

fn messages() -> Vec<CanonicalMessage> {
    [
        Body::Payment(b"payment".to_vec()),
        Body::Psbt(b"fragment".to_vec()),
        Body::Confirmation(b"confirmation".to_vec()),
    ]
    .into_iter()
    .map(|body| CanonicalMessage::encode(&Message::new(body)).unwrap())
    .collect()
}

async fn converge<C: BroadcastChannel>(nodes: &mut [C]) -> Vec<MessageSet> {
    let messages = messages();
    let mut sets: Vec<_> = messages
        .iter()
        .cloned()
        .map(|message| {
            let mut set = MessageSet::default();
            set.insert(message).unwrap();
            set
        })
        .collect();

    async fn publish<C: BroadcastChannel>(node: &mut C, message: &CanonicalMessage) {
        tokio::time::timeout(DEADLINE, node.send(message.as_bytes()))
            .await
            .expect("publication does not deadlock")
            .expect("publication succeeds");
    }
    publish(&mut nodes[2], &messages[2]).await;
    publish(&mut nodes[0], &messages[0]).await;
    publish(&mut nodes[0], &messages[0]).await;
    publish(&mut nodes[1], &messages[1]).await;

    for (node, set) in nodes.iter_mut().zip(&mut sets) {
        while set.len() != messages.len() {
            let bytes = tokio::time::timeout(DEADLINE, node.recv())
                .await
                .expect("broadcast converges")
                .expect("channel remains live");
            set.insert(CanonicalMessage::parse(bytes).expect("canonical transport bytes"))
                .unwrap();
        }
    }
    sets
}

#[tokio::test]
async fn mem_and_framed_gossip_converge_on_the_same_message_set() {
    let mut server = group(
        3,
        MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        },
    );
    let server_sets = converge(&mut server).await;

    let (ab, ba) = tokio::io::duplex(4096);
    let (bc, cb) = tokio::io::duplex(4096);
    let framed = |stream| FramedChannel::new(stream, DEFAULT_MAX_MSG_LEN);
    let mut gossip = vec![
        GossipBroadcast::new(vec![framed(ab)]),
        GossipBroadcast::new(vec![framed(ba), framed(bc)]),
        GossipBroadcast::new(vec![framed(cb)]),
    ];
    let gossip_sets = converge(&mut gossip).await;

    let expected = server_sets[0].commitment();
    assert!(server_sets.iter().all(|set| set.commitment() == expected));
    assert!(gossip_sets.iter().all(|set| set.commitment() == expected));
    assert!(
        server_sets
            .iter()
            .chain(&gossip_sets)
            .all(|set| set.len() == 3)
    );
}
