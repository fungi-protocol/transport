use std::time::Duration;

use fungi_transport::framing::FramedChannel;
use fungi_transport::mem::{MemChannel, MemConfig, duplex};
use fungi_transport::{BroadcastChannel, Channel, GossipBroadcast, SplitChannel};
use fungi_wire::{
    Body, CanonicalMessage, Message, MessageContext, ProtocolSessionId, ProtocolVersion,
};

use crate::{
    MessageSizeLimit, SessionBindingError, SessionBoundChannel, SessionContract, bind, bind_all,
    hello,
};

const DEADLINE: Duration = Duration::from_secs(3);

fn contract(session: u8, version: u16, limit: usize) -> SessionContract {
    SessionContract::new(
        MessageContext::new(
            ProtocolSessionId::new([session; 32]),
            ProtocolVersion::new(version),
        ),
        MessageSizeLimit::new(limit).unwrap(),
    )
}

fn canonical(contract: SessionContract, payload: &[u8]) -> CanonicalMessage {
    CanonicalMessage::encode(
        contract.context(),
        &Message::new(Body::Payment(payload.to_vec())),
    )
    .unwrap()
}

async fn bound_pair(
    contract: SessionContract,
) -> (
    SessionBoundChannel<MemChannel>,
    SessionBoundChannel<MemChannel>,
) {
    let (left, right) = duplex(MemConfig {
        capacity: Some(1),
        ..MemConfig::default()
    });
    let (left, right) = tokio::join!(bind(left, contract), bind(right, contract));
    (left.unwrap(), right.unwrap())
}

/// Bind one side against a peer that stays raw, so a test can put bytes on the
/// wire that a bound channel would never emit.
async fn bind_against_raw<C>(
    left: C,
    mut right: C,
    contract: SessionContract,
) -> (SessionBoundChannel<C>, C)
where
    C: Channel + SplitChannel,
{
    let peer = async {
        assert_eq!(right.recv().await.unwrap(), hello::encode(contract));
        right.send(&hello::encode(contract)).await.unwrap();
        right
    };
    let (bound, right) = tokio::join!(bind(left, contract), peer);
    (bound.unwrap(), right)
}

async fn bind_with_raw_peer(
    contract: SessionContract,
) -> (SessionBoundChannel<MemChannel>, MemChannel) {
    let (left, right) = duplex(MemConfig {
        capacity: Some(1),
        ..MemConfig::default()
    });
    bind_against_raw(left, right, contract).await
}

fn framed_pair() -> (
    FramedChannel<tokio::io::DuplexStream>,
    FramedChannel<tokio::io::DuplexStream>,
) {
    let (left, right) = tokio::io::duplex(4096);
    (
        FramedChannel::new(left, 4096),
        FramedChannel::new(right, 4096),
    )
}

#[test]
fn message_size_limit_rejects_zero_and_values_above_the_wire_cap() {
    assert!(MessageSizeLimit::new(0).is_err());
    assert!(MessageSizeLimit::new(fungi_wire::MAX_MESSAGE_SIZE + 1).is_err());
    assert_eq!(
        MessageSizeLimit::new(fungi_wire::MAX_MESSAGE_SIZE)
            .unwrap()
            .get(),
        fungi_wire::MAX_MESSAGE_SIZE
    );
}

#[test]
fn hello_roundtrips_and_rejects_malformed_encodings() {
    let expected = contract(1, 2, 4096);
    assert_eq!(hello::decode(&hello::encode(expected)).unwrap(), expected);
    assert!(matches!(
        hello::decode(&hello::encode(expected)[..hello::HELLO_LEN - 1]),
        Err(SessionBindingError::MalformedHandshake)
    ));
    let mut trailing = hello::encode(expected).to_vec();
    trailing.push(0);
    assert!(matches!(
        hello::decode(&trailing),
        Err(SessionBindingError::MalformedHandshake)
    ));
    let mut wrong_magic = hello::encode(expected);
    wrong_magic[0] ^= 1;
    assert!(matches!(
        hello::decode(&wrong_magic),
        Err(SessionBindingError::MalformedHandshake)
    ));
    let mut zero_limit = hello::encode(expected);
    zero_limit[hello::HELLO_LEN - 4..].fill(0);
    assert!(matches!(
        hello::decode(&zero_limit),
        Err(SessionBindingError::MalformedHandshake)
    ));
    let mut excessive_limit = hello::encode(expected);
    let excessive = u32::try_from(fungi_wire::MAX_MESSAGE_SIZE + 1)
        .unwrap()
        .to_be_bytes();
    excessive_limit[hello::HELLO_LEN - 4..].copy_from_slice(&excessive);
    assert!(matches!(
        hello::decode(&excessive_limit),
        Err(SessionBindingError::MalformedHandshake)
    ));
}

#[tokio::test]
async fn simultaneous_binding_with_one_message_buffers_makes_progress() {
    let expected = contract(1, 1, 4096);
    let (mut left, mut right) = tokio::time::timeout(DEADLINE, bound_pair(expected))
        .await
        .expect("binding does not deadlock");
    let message = canonical(expected, b"bound");
    left.send(message.as_bytes()).await.unwrap();
    assert_eq!(right.recv().await.unwrap(), message.as_bytes());
}

#[tokio::test]
async fn each_parameter_mismatch_is_reported_separately() {
    async fn mismatch(
        left: SessionContract,
        right: SessionContract,
    ) -> (SessionBindingError, SessionBindingError) {
        let (a, b) = duplex(MemConfig::default());
        let (a, b) = tokio::join!(bind(a, left), bind(b, right));
        (a.unwrap_err(), b.unwrap_err())
    }

    let base = contract(1, 1, 4096);
    let (left, right) = mismatch(base, contract(2, 1, 4096)).await;
    assert!(matches!(left, SessionBindingError::SessionMismatch { .. }));
    assert!(matches!(right, SessionBindingError::SessionMismatch { .. }));

    let (left, right) = mismatch(base, contract(1, 2, 4096)).await;
    assert!(matches!(left, SessionBindingError::VersionMismatch { .. }));
    assert!(matches!(right, SessionBindingError::VersionMismatch { .. }));

    let (left, right) = mismatch(base, contract(1, 1, 2048)).await;
    assert!(matches!(
        left,
        SessionBindingError::MessageSizeLimitMismatch { .. }
    ));
    assert!(matches!(
        right,
        SessionBindingError::MessageSizeLimitMismatch { .. }
    ));
}

#[tokio::test]
async fn canonical_application_traffic_cannot_replace_the_hello() {
    let expected = contract(1, 1, 4096);
    let (left, mut right) = duplex(MemConfig::default());
    let message = canonical(expected, b"too early");
    let peer = async {
        right.recv().await.unwrap();
        right.send(message.as_bytes()).await.unwrap();
    };
    let (bound, ()) = tokio::join!(bind(left, expected), peer);
    assert!(matches!(
        bound.unwrap_err(),
        SessionBindingError::PrematureApplicationMessage
    ));
}

#[tokio::test]
async fn invalid_post_binding_traffic_is_rejected_before_gossip() {
    let expected = contract(1, 1, 4096);
    let (bound, mut malicious) = bind_with_raw_peer(expected).await;
    let mut gossip = GossipBroadcast::new(vec![bound]).with_max_msg_len(4096);

    malicious.send(b"not canonical").await.unwrap();
    assert!(gossip.recv().await.is_err());
}

#[tokio::test]
async fn invalid_input_at_a_relay_never_reaches_the_next_peer() {
    let expected = contract(1, 1, 4096);
    let (bound_from_a, mut malicious_a) = bind_with_raw_peer(expected).await;
    let (bound_to_c, bound_c) = bound_pair(expected).await;
    let mut relay = GossipBroadcast::new(vec![bound_from_a, bound_to_c]);
    let mut c = GossipBroadcast::new(vec![bound_c]);

    malicious_a.send(b"not canonical").await.unwrap();
    assert!(relay.recv().await.is_err());
    let at_c = tokio::time::timeout(Duration::from_millis(50), c.recv()).await;
    assert!(
        !matches!(at_c, Ok(Ok(_))),
        "invalid bytes crossed the session-bound relay"
    );
}

#[tokio::test]
async fn cross_context_and_repeated_hello_traffic_kill_the_bound_channel() {
    let expected = contract(1, 1, 4096);

    let (mut bound, mut malicious) = bind_with_raw_peer(expected).await;
    let wrong = canonical(contract(2, 1, 4096), b"wrong session");
    malicious.send(wrong.as_bytes()).await.unwrap();
    assert!(bound.recv().await.is_err());
    assert!(matches!(
        bound.send(wrong.as_bytes()).await,
        Err(fungi_transport::SendError::Closed)
    ));

    let (mut bound, mut malicious) = bind_with_raw_peer(expected).await;
    malicious.send(&hello::encode(expected)).await.unwrap();
    assert!(bound.recv().await.is_err());
}

#[tokio::test]
async fn oversize_is_recoverable_on_send_and_fatal_on_receive() {
    let expected = contract(1, 1, 64);
    let (mut left, mut right) = bound_pair(expected).await;
    let oversized = canonical(contract(1, 1, 4096), &[0; 64]);
    assert!(matches!(
        left.send(oversized.as_bytes()).await,
        Err(fungi_transport::SendError::TooLarge { max: 64 })
    ));
    let valid = canonical(expected, b"still alive");
    left.send(valid.as_bytes()).await.unwrap();
    assert_eq!(right.recv().await.unwrap(), valid.as_bytes());

    let (mut bound, mut malicious) = bind_with_raw_peer(expected).await;
    malicious.send(oversized.as_bytes()).await.unwrap();
    assert!(bound.recv().await.is_err());
}

#[tokio::test]
async fn bind_all_returns_no_partial_group_after_one_mismatch() {
    let expected = contract(1, 1, 4096);
    let (left_a, right_a) = duplex(MemConfig::default());
    let (left_b, right_b) = duplex(MemConfig::default());
    let peers = async {
        let (_, _) = tokio::join!(bind(right_a, expected), bind(right_b, contract(2, 1, 4096)));
    };
    let (group, ()) = tokio::join!(bind_all(vec![left_a, left_b], expected), peers);
    assert!(matches!(
        group.unwrap_err(),
        SessionBindingError::SessionMismatch { .. }
    ));
}

#[tokio::test]
async fn binding_carries_traffic_and_rejects_violations_over_framing() {
    let expected = contract(1, 1, 4096);
    let (left, right) = framed_pair();
    let (left, right) = tokio::join!(bind(left, expected), bind(right, expected));
    let (mut left, mut right) = (left.unwrap(), right.unwrap());
    let message = canonical(expected, b"framed");
    left.send(message.as_bytes()).await.unwrap();
    assert_eq!(right.recv().await.unwrap(), message.as_bytes());

    let (left, right) = framed_pair();
    let (mut bound, mut malicious) = bind_against_raw(left, right, expected).await;
    let wrong = canonical(contract(2, 1, 4096), b"wrong session");
    malicious.send(wrong.as_bytes()).await.unwrap();
    assert!(bound.recv().await.is_err());
}

#[tokio::test]
async fn the_negotiated_limit_governs_both_directions_over_framing() {
    let expected = contract(1, 1, 64);
    let (left, right) = framed_pair();
    let (mut bound, mut malicious) = bind_against_raw(left, right, expected).await;

    // The frame cap is 4096; the session admits 64, and it is the session that
    // governs what the application may put on this link.
    let oversized = canonical(contract(1, 1, 4096), &[0; 64]);
    assert!(matches!(
        bound.send(oversized.as_bytes()).await,
        Err(fungi_transport::SendError::TooLarge { max: 64 })
    ));

    malicious.send(oversized.as_bytes()).await.unwrap();
    assert!(bound.recv().await.is_err());
    let cause = bound.failure().expect("the cause is kept");
    assert!(cause.contains("64"), "{cause}");
}

#[tokio::test]
async fn a_message_this_node_refuses_leaves_the_link_usable() {
    let expected = contract(1, 1, 4096);
    let (mut left, mut right) = bound_pair(expected).await;

    // Nothing reached the wire, so the caller's error is the caller's to fix.
    assert!(left.send(b"not canonical").await.is_err());
    let wrong = canonical(contract(2, 1, 4096), b"wrong session");
    assert!(left.send(wrong.as_bytes()).await.is_err());

    let valid = canonical(expected, b"still alive");
    left.send(valid.as_bytes()).await.unwrap();
    assert_eq!(right.recv().await.unwrap(), valid.as_bytes());
}

#[tokio::test]
async fn the_cause_of_death_outlives_the_call_that_saw_it() {
    let expected = contract(1, 1, 4096);
    let (mut bound, mut malicious) = bind_with_raw_peer(expected).await;
    assert!(bound.failure().is_none());

    let wrong = canonical(contract(2, 1, 4096), b"wrong session");
    malicious.send(wrong.as_bytes()).await.unwrap();
    // The observing call reports the violation itself...
    let observed = bound.recv().await.unwrap_err().to_string();
    assert!(observed.contains("context"), "{observed}");

    // ...later calls report only that the channel is dead, the signal every
    // layer above knows how to act on, while the diagnosis stays reachable.
    assert!(matches!(
        bound.recv().await,
        Err(fungi_transport::RecvError::Closed)
    ));
    assert!(matches!(
        bound.send(canonical(expected, b"x").as_bytes()).await,
        Err(fungi_transport::SendError::Closed)
    ));
    let cause = bound.failure().expect("the cause is kept");
    assert!(cause.contains("context"), "{cause}");
}

#[tokio::test]
async fn an_oversize_message_from_a_peer_names_both_sizes() {
    let expected = contract(1, 1, 64);
    let (mut bound, mut malicious) = bind_with_raw_peer(expected).await;
    malicious
        .send(canonical(contract(1, 1, 4096), &[0; 64]).as_bytes())
        .await
        .unwrap();
    assert!(bound.recv().await.is_err());
    let cause = bound.failure().expect("the cause is kept");
    assert!(cause.contains("101") && cause.contains("64"), "{cause}");
}

#[tokio::test]
async fn application_traffic_shaped_like_a_hello_is_still_application_traffic() {
    let mut session = [0; 32];
    session[..hello::HELLO_MAGIC.len()].copy_from_slice(&hello::HELLO_MAGIC);
    let expected = SessionContract::new(
        MessageContext::new(ProtocolSessionId::new(session), ProtocolVersion::new(1)),
        MessageSizeLimit::new(4096).unwrap(),
    );
    // 32 + 2 context, 2 type, 1 length: a 17-byte payload lands exactly on the
    // hello's length, under a session ID that opens with the hello's magic.
    let message = canonical(expected, &[b'p'; 17]);
    assert_eq!(message.as_bytes().len(), hello::HELLO_LEN);
    assert!(hello::looks_like(message.as_bytes()));

    let (mut left, mut right) = bound_pair(expected).await;
    left.send(message.as_bytes()).await.unwrap();
    assert_eq!(right.recv().await.unwrap(), message.as_bytes());
}

#[test]
fn a_session_bound_channel_still_implements_split_channel() {
    fn requires_split<T: SplitChannel>() {}
    requires_split::<SessionBoundChannel<MemChannel>>();
}
