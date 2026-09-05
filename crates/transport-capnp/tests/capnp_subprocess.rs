//! Proves the plugin layer across a REAL process boundary: a [`connect_plugin`]
//! harness drives the `mem-plugin` child binary, which serves an in-memory
//! [`MemTransport`] over its own stdin/stdout. `connector`/`listen`/`connect`/
//! `accept`/`send`/`recv` all traverse capnp-rpc over the child's pipes, and the
//! whole mem network lives inside the child.

use std::time::Duration;

use fungi_transport::mem::MemAddr;
use fungi_transport::testkit;
use fungi_transport::{Channel, Connector, ListenParams, Listener, Transport};
use fungi_transport_capnp::{CapnpTransport, connect_plugin};
use fungi_wire::{
    Body, CanonicalMessage, Extension, Extensions, MAX_MESSAGE_SIZE, Message, MessageSet,
};

/// The child plugin binary, built by cargo before this integration test.
const MEM_PLUGIN: &str = env!("CARGO_BIN_EXE_mem-plugin");

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
    let payment = CanonicalMessage::encode(&Message {
        body: Body::Payment(b"payment".to_vec()),
        extensions: Extensions::new(vec![Extension {
            ty: 1,
            value: b"optional".to_vec(),
        }])
        .unwrap(),
    })
    .unwrap();
    let psbt = CanonicalMessage::encode(&Message::new(Body::Psbt(b"fragment".to_vec()))).unwrap();
    let boundary = CanonicalMessage::encode(&Message::new(Body::Confirmation(vec![
        0;
        MAX_MESSAGE_SIZE
            - 7
    ])))
    .unwrap();
    assert_eq!(boundary.as_bytes().len(), MAX_MESSAGE_SIZE);
    let invalid = hex::decode("0003fd000568656c6c6f").unwrap();

    client.send(payment.as_bytes()).await.unwrap();
    client.send(payment.as_bytes()).await.unwrap();
    client.send(boundary.as_bytes()).await.unwrap();
    server.send(psbt.as_bytes()).await.unwrap();
    server.send(&invalid).await.unwrap();

    let mut client_set = MessageSet::default();
    client_set.insert(payment.clone()).unwrap();
    client_set.insert(boundary.clone()).unwrap();
    client_set
        .insert(CanonicalMessage::parse(client.recv().await.unwrap()).unwrap())
        .unwrap();
    assert!(CanonicalMessage::parse(client.recv().await.unwrap()).is_err());

    let mut server_set = MessageSet::default();
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
