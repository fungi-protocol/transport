//! Proves the plugin layer across a REAL process boundary: a [`connect_plugin`]
//! harness drives the `mem-plugin` child binary, which serves an in-memory
//! [`MemTransport`] over its own stdin/stdout. `connector`/`listen`/`connect`/
//! `accept`/`send`/`recv` all traverse capnp-rpc over the child's pipes, and the
//! whole mem network lives inside the child.

use std::time::Duration;

use fungi_session::{MessageSizeLimit, SessionBindingError, SessionContract, bind};
use fungi_transport::mem::MemAddr;
use fungi_transport::testkit;
use fungi_transport::{Channel, Connector, ListenParams, Listener, Transport};
use fungi_transport_capnp::{CapnpTransport, connect_plugin};
use fungi_wire::{
    Body, CanonicalMessage, Extension, Extensions, MAX_MESSAGE_SIZE, Message, MessageContext,
    MessageSet, ProtocolSessionId, ProtocolVersion,
};

/// The child plugin binary, built by cargo before this integration test.
const MEM_PLUGIN: &str = env!("CARGO_BIN_EXE_mem-plugin");

fn context() -> MessageContext {
    MessageContext::new(ProtocolSessionId::new([0; 32]), ProtocolVersion::new(1))
}

fn session_contract() -> SessionContract {
    SessionContract::new(context(), MessageSizeLimit::new(MAX_MESSAGE_SIZE).unwrap())
}

/// Spawn the `mem-plugin` child and connect a `CapnpTransport` to it over the
/// child's stdio.
fn wire() -> CapnpTransport<MemAddr> {
    connect_plugin(tokio::process::Command::new(MEM_PLUGIN))
}

/// BASIC: build a connector and a listener through the subprocess plugin, then
/// connect and accept concurrently and exchange a message in both directions —
/// every hop crossing capnp over the child's pipes.
#[tokio::test]
async fn subprocess_roundtrip() {
    let transport = wire();

    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();

    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let (mut client, mut server) = (client.unwrap(), server.unwrap());

    client.send(b"ping").await.unwrap();
    assert_eq!(server.recv().await.unwrap(), b"ping");
    server.send(b"pong").await.unwrap();
    assert_eq!(client.recv().await.unwrap(), b"pong");
}

/// TYPED MESSAGES: canonical application messages retain their logical
/// identities across the subprocess boundary. Receiving the same event twice
/// and inserting events in different orders converges to the same MessageSet.
#[tokio::test]
async fn subprocess_typed_messages_converge() {
    let transport = wire();
    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();

    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let payment = CanonicalMessage::encode(
        context(),
        &Message {
            body: Body::Payment(b"payment".to_vec()),
            extensions: Extensions::new(vec![Extension {
                ty: 1,
                value: b"optional".to_vec(),
            }])
            .unwrap(),
        },
    )
    .unwrap();
    let psbt = CanonicalMessage::encode(context(), &Message::new(Body::Psbt(b"fragment".to_vec())))
        .unwrap();
    let boundary = CanonicalMessage::encode(
        context(),
        &Message::new(Body::Confirmation(vec![0; MAX_MESSAGE_SIZE - 41])),
    )
    .unwrap();
    assert_eq!(boundary.as_bytes().len(), MAX_MESSAGE_SIZE);
    let mut invalid = vec![0; 32];
    invalid.extend_from_slice(&1u16.to_be_bytes());
    invalid.extend_from_slice(&hex::decode("0003fd000568656c6c6f").unwrap());

    client.send(payment.as_bytes()).await.unwrap();
    client.send(payment.as_bytes()).await.unwrap();
    client.send(boundary.as_bytes()).await.unwrap();
    server.send(psbt.as_bytes()).await.unwrap();
    server.send(&invalid).await.unwrap();

    let mut client_set = MessageSet::new(context());
    client_set.insert(payment.clone()).unwrap();
    client_set.insert(boundary.clone()).unwrap();
    client_set
        .insert(CanonicalMessage::parse(client.recv().await.unwrap()).unwrap())
        .unwrap();
    assert!(CanonicalMessage::parse(client.recv().await.unwrap()).is_err());

    let mut server_set = MessageSet::new(context());
    server_set.insert(psbt.clone()).unwrap();
    for _ in 0..3 {
        server_set
            .insert(CanonicalMessage::parse(server.recv().await.unwrap()).unwrap())
            .unwrap();
    }
    assert_eq!(client_set.len(), 3);
    assert_eq!(server_set.len(), 3);
    assert_eq!(client_set.commitment(), server_set.commitment());
    assert_eq!(
        client_set.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        server_set.iter().map(|(id, _)| id).collect::<Vec<_>>()
    );
}

/// SESSION BINDING: both directions exchange the connection-local session
/// hello through capnp-rpc before canonical application traffic is accepted.
#[tokio::test]
async fn subprocess_session_binding_precedes_application_traffic() {
    let transport = wire();
    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();
    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let contract = session_contract();
    let (client, server) = tokio::join!(
        bind(client.unwrap(), contract),
        bind(server.unwrap(), contract)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let message =
        CanonicalMessage::encode(context(), &Message::new(Body::Psbt(b"bound".to_vec()))).unwrap();

    client.send(message.as_bytes()).await.unwrap();
    assert_eq!(server.recv().await.unwrap(), message.as_bytes());
}

/// SESSION BINDING: the size limit agreed in the handshake, not the plugin's
/// own frame cap, is what governs application traffic across the boundary.
#[tokio::test]
async fn subprocess_traffic_is_governed_by_the_negotiated_size_limit() {
    let transport = wire();
    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();
    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let contract = SessionContract::new(context(), MessageSizeLimit::new(64).unwrap());
    let (client, server) = tokio::join!(
        bind(client.unwrap(), contract),
        bind(server.unwrap(), contract)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());

    let oversized =
        CanonicalMessage::encode(context(), &Message::new(Body::Psbt(vec![0; 64]))).unwrap();
    assert!(oversized.as_bytes().len() > 64);
    assert!(matches!(
        client.send(oversized.as_bytes()).await,
        Err(fungi_transport::SendError::TooLarge { max: 64 })
    ));

    // Refusing it left the link alive.
    let fits =
        CanonicalMessage::encode(context(), &Message::new(Body::Psbt(b"ok".to_vec()))).unwrap();
    client.send(fits.as_bytes()).await.unwrap();
    assert_eq!(server.recv().await.unwrap(), fits.as_bytes());
}

/// SESSION BINDING: a peer presenting another exact protocol version is
/// refused at the handshake, across the plugin boundary, before either side
/// could construct gossip.
#[tokio::test]
async fn subprocess_binding_refuses_a_mismatched_protocol_version() {
    let transport = wire();
    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();
    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let theirs = SessionContract::new(
        MessageContext::new(ProtocolSessionId::new([0; 32]), ProtocolVersion::new(2)),
        MessageSizeLimit::new(MAX_MESSAGE_SIZE).unwrap(),
    );
    let (client, server) = tokio::join!(
        bind(client.unwrap(), session_contract()),
        bind(server.unwrap(), theirs)
    );
    assert!(matches!(
        client.unwrap_err(),
        SessionBindingError::VersionMismatch { .. }
    ));
    assert!(matches!(
        server.unwrap_err(),
        SessionBindingError::VersionMismatch { .. }
    ));
}

/// SESSION BINDING: application traffic sent where the hello was required is
/// rejected as premature, not parsed as a handshake.
#[tokio::test]
async fn subprocess_binding_rejects_premature_application_traffic() {
    let transport = wire();
    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();
    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let message =
        CanonicalMessage::encode(context(), &Message::new(Body::Psbt(b"early".to_vec()))).unwrap();
    let unbound = async {
        let mut server = server.unwrap();
        server.send(message.as_bytes()).await.unwrap();
        server
    };
    let (client, _server) = tokio::join!(bind(client.unwrap(), session_contract()), unbound);
    assert!(matches!(
        client.unwrap_err(),
        SessionBindingError::PrematureApplicationMessage
    ));
}

/// CONFORMANCE: run the connection-oriented lifecycle suite through the
/// subprocess plugin (connect → accept → roundtrip → drop → detect → reconnect
/// → re-accept → roundtrip). `MemTransport::listen` is single-use, so it is
/// called ONCE and the helper accepts twice on the one listener.
#[tokio::test]
async fn subprocess_conformance() {
    // `_transport` is held for the whole test so the actor thread and the child
    // process stay alive while its connector/listener are exercised.
    let _transport = wire();
    let connector = _transport.connector();
    let (listener, addr) = _transport.listen(ListenParams::new(1)).await.unwrap();

    testkit::connect_use_drop_reconnect(connector, listener, &addr).await;
}

/// LIFECYCLE: a plugin that dies before the capnp handshake must surface as
/// `ConnectError::Unreachable` on the first transport operation — not a hang and
/// not a panic. The `mem-plugin` exits immediately when given any argument.
#[tokio::test]
async fn plugin_crash_is_unreachable() {
    let mut command = tokio::process::Command::new(MEM_PLUGIN);
    command.arg("crash");
    let transport: CapnpTransport<MemAddr> = connect_plugin(command);

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        transport.listen(ListenParams::new(1)),
    )
    .await
    .expect("a crashed plugin must be detected, not hang");

    assert!(
        matches!(result, Err(fungi_transport::ConnectError::Unreachable)),
        "expected Unreachable, got {result:?}"
    );
}

/// LIFECYCLE: a plugin program that cannot even be spawned (non-existent path)
/// must also surface as `ConnectError::Unreachable` on the first transport
/// operation — exercising the `command.spawn()`-`Err` path, distinct from the
/// EOF-after-spawn crash above.
#[tokio::test]
async fn spawn_failure_is_unreachable() {
    let command = tokio::process::Command::new("/nonexistent/fungi-mem-plugin-does-not-exist-xyz");
    let transport: CapnpTransport<MemAddr> = connect_plugin(command);

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        transport.listen(ListenParams::new(1)),
    )
    .await
    .expect("an unspawnable plugin must be detected, not hang");

    assert!(
        matches!(result, Err(fungi_transport::ConnectError::Unreachable)),
        "expected Unreachable, got {result:?}"
    );
}
