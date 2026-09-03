//! Typed-message convergence across server-style broadcast and framed gossip.

use fungi_transport::framed::{DEFAULT_MAX_MSG_LEN, FramedChannel};
use fungi_transport::mem::{MemConfig, group};
use fungi_transport::{BroadcastChannel, Channel, GossipBroadcast};
use fungi_wire::{
    Body, CanonicalMessage, Extension, Extensions, MAX_MESSAGE_SIZE, Message, MessageSet,
};

const DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
const _: () = assert!(MAX_MESSAGE_SIZE <= DEFAULT_MAX_MSG_LEN);

fn messages() -> Vec<CanonicalMessage> {
    let extended = Message {
        body: Body::Psbt(b"fragment".to_vec()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: b"optional".to_vec(),
        }])
        .unwrap(),
    };
    [
        Message::new(Body::Payment(b"payment".to_vec())),
        extended,
        Message::new(Body::Confirmation(b"confirmation".to_vec())),
    ]
    .iter()
    .map(|message| CanonicalMessage::encode(message).unwrap())
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
async fn framed_boundary_message_is_admitted_but_invalid_bytes_are_not() {
    let payload = vec![0; MAX_MESSAGE_SIZE - 7];
    let boundary = CanonicalMessage::encode(&Message::new(Body::Payment(payload))).unwrap();
    assert_eq!(boundary.as_bytes().len(), MAX_MESSAGE_SIZE);

    let (left, right) = tokio::io::duplex(64 * 1024);
    let mut sender = FramedChannel::new(left, DEFAULT_MAX_MSG_LEN);
    let mut receiver = FramedChannel::new(right, DEFAULT_MAX_MSG_LEN);
    let (sent, received) = tokio::join!(sender.send(boundary.as_bytes()), receiver.recv());
    sent.unwrap();
    let received = CanonicalMessage::parse(received.unwrap()).unwrap();
    assert_eq!(received.id(), boundary.id());

    let invalid = hex::decode("0003fd000568656c6c6f").unwrap();
    let (sent, received) = tokio::join!(sender.send(&invalid), receiver.recv());
    sent.unwrap();
    let set = MessageSet::default();
    assert!(CanonicalMessage::parse(received.unwrap()).is_err());
    assert!(set.is_empty());
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
