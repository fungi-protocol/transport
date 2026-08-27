//! Proves the whole [`fungi_transport::Transport`] factory graph over
//! capnp-rpc, in-process: a [`CapnpTransport`] client wired to a
//! [`serve_plugin`] server wrapping an in-memory [`MemTransport`] backend.
//! `connector`/`listen`/`connect`/`accept`/`send`/`recv` all traverse capnp on
//! every hop, and the factory futures are shown `Send` at compile time.

use std::sync::{Arc, Mutex};

use fungi_transport::mem::{MemAddr, MemConfig, MemTransport};
use fungi_transport::testkit;
use fungi_transport::{Channel, Connector, ListenParams, Listener, Transport};
use fungi_transport_capnp::{CapnpTransport, PluginFixtures, serve_plugin, serve_plugin_with};

/// Compile-time proof that a value is `Send`.
fn assert_send<T: Send>(_: &T) {}

/// Wire a `CapnpTransport` client to a plugin server wrapping a fresh
/// `MemTransport`. The server thread handle is detached (it lives until its
/// stream closes) and dropped here.
fn wire() -> CapnpTransport<MemAddr> {
    // Capacity > 1 so queued sends do not block before the peer drains.
    let cfg = MemConfig {
        capacity: Some(8),
        ..MemConfig::default()
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    // `serve_plugin` is `!Send`, so run it on its own `current_thread` runtime +
    // `LocalSet`; the thread lives until the duplex closes and is detached here.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the server runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let (reader, writer) = tokio::io::split(server_io);
            serve_plugin(MemTransport::new(cfg), reader, writer).await;
        });
    });
    CapnpTransport::connect(client_io)
}

/// BASIC: build a connector and a listener through the graph, then connect and
/// accept concurrently and exchange a message in both directions — every hop
/// crossing capnp. Also proves the factory futures are `Send`.
#[tokio::test]
async fn factory_roundtrip_over_capnp() {
    let transport = wire();

    // The factory futures returned across the trait must be `Send`.
    assert_send(&transport.listen(ListenParams::new(1)));

    let connector = transport.connector();
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();

    assert_send(&connector);
    assert_send(&connector.connect(&addr));
    assert_send(&listener.accept());

    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let (mut client, mut server) = (client.unwrap(), server.unwrap());

    client.send(b"ping").await.unwrap();
    assert_eq!(server.recv().await.unwrap(), b"ping");
    server.send(b"pong").await.unwrap();
    assert_eq!(client.recv().await.unwrap(), b"pong");
}

/// SESSION: a session-bound connector traverses `connectorFor` across capnp
/// and dials end to end, exactly like the default connector — proving the
/// session id crosses the plugin boundary and the remote method is wired.
/// (The mem backend cannot show real circuit isolation; the socks5h/arti
/// crates prove the credential/token derivation.)
#[tokio::test]
async fn connector_for_roundtrip_over_capnp() {
    use fungi_transport::SessionId;

    let transport = wire();
    let connector = transport.connector_for(&SessionId::generate());
    let (mut listener, addr) = transport.listen(ListenParams::new(1)).await.unwrap();

    assert_send(&connector);
    let (client, server) = tokio::join!(connector.connect(&addr), listener.accept());
    let (mut client, mut server) = (client.unwrap(), server.unwrap());

    client.send(b"ping").await.unwrap();
    assert_eq!(server.recv().await.unwrap(), b"ping");
}

/// CONFORMANCE: run the connection-oriented lifecycle suite
/// (connect → accept → roundtrip → drop → detect → reconnect → re-accept →
/// roundtrip) through the whole capnp graph. `MemTransport::listen` is
/// single-use, so it is called ONCE and the helper accepts twice on the one
/// listener. This proves the factory graph is a faithful `Transport` over
/// capnp, not just a one-shot pipe.
#[tokio::test]
async fn connect_use_drop_reconnect_over_capnp() {
    // `_transport` is held for the whole test so the actor thread and the
    // stored `Transport` capability stay alive while its connector/listener are
    // exercised.
    let _transport = wire();
    let connector = _transport.connector();
    let (listener, addr) = _transport.listen(ListenParams::new(1)).await.unwrap();

    testkit::connect_use_drop_reconnect(connector, listener, &addr).await;
}

/// FIXTURES: the test-only tier, distinct from the primary transport API. A
/// `configure_private_net` on the client reaches the backend's `PluginFixtures`
/// impl across capnp — the same wire path arti's plugin uses to install a
/// private network before its bootstrap. Proven deterministically in-process.
#[tokio::test]
async fn configure_private_net_reaches_the_fixtures_over_capnp() {
    /// Records the last configured descriptor, so the test can assert the bytes
    /// crossed the capnp boundary intact.
    struct Recording {
        got: Arc<Mutex<Option<Vec<u8>>>>,
    }
    impl PluginFixtures for Recording {
        fn configure_private_net(&self, net_file: &[u8]) -> Result<(), String> {
            *self.got.lock().unwrap() = Some(net_file.to_vec());
            Ok(())
        }
    }

    let got = Arc::new(Mutex::new(None));
    let got_server = got.clone();
    let cfg = MemConfig {
        capacity: Some(8),
        ..MemConfig::default()
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the server runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let (reader, writer) = tokio::io::split(server_io);
            serve_plugin_with(
                MemTransport::new(cfg),
                Recording { got: got_server },
                reader,
                writer,
            )
            .await;
        });
    });

    let transport: CapnpTransport<MemAddr> = CapnpTransport::connect(client_io);
    // The call resolves only after the server ran the fixture, so the record is
    // in place by the time this returns.
    transport
        .configure_private_net(b"private-net-bytes")
        .await
        .unwrap();
    assert_eq!(
        got.lock().unwrap().as_deref(),
        Some(&b"private-net-bytes"[..])
    );
}
