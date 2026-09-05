//! Proves the Send bridge: a [`CapnpChannel`] driven through the
//! [`fungi_transport::Channel`] trait, with its `send`/`recv` futures shown to
//! be `Send` at compile time.

use fungi_transport::Channel;
use fungi_transport::mem::{MemConfig, duplex};
use fungi_transport::testkit;
use fungi_transport_capnp::{CapnpChannel, serve_backend, serve_loopback};

/// Compile-time proof that a value is `Send`.
fn assert_send<T: Send>(_: &T) {}

/// MINIMUM: send/recv survive the round trip through the Send bridge + capnp,
/// preserving FIFO order, and the futures are `Send`.
#[tokio::test]
async fn loopback_roundtrip_over_capnp() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let _server = serve_loopback(server_io);
    let mut channel = CapnpChannel::connect(client_io);

    // The futures returned by the trait must be `Send`.
    assert_send(&channel.send(b"probe"));
    assert_send(&channel.recv());

    channel.send(b"a").await.unwrap();
    channel.send(b"b").await.unwrap();
    assert_eq!(channel.recv().await.unwrap(), b"a");
    assert_eq!(channel.recv().await.unwrap(), b"b");
}

/// Build two `CapnpChannel`s, each bridging one end of an in-memory duplex pair
/// through a `serve_backend` server. A full both-directions exchange therefore
/// traverses capnp-rpc on every hop, so the pair can be fed to the generic
/// same-type conformance functions. The server thread handles are detached
/// (they live until their stream closes) and dropped here.
fn crossed_capnp_pair(capacity: usize) -> (CapnpChannel, CapnpChannel) {
    let cfg = MemConfig {
        capacity: Some(capacity),
        ..MemConfig::default()
    };
    let (mem_a, mem_b) = duplex(cfg);

    let (client_a_io, server_a_io) = tokio::io::duplex(64 * 1024);
    let (client_b_io, server_b_io) = tokio::io::duplex(64 * 1024);
    serve_backend(server_a_io, mem_a);
    serve_backend(server_b_io, mem_b);

    (
        CapnpChannel::connect(client_a_io),
        CapnpChannel::connect(client_b_io),
    )
}

/// STRETCH: real conformance over capnp. Exercising both directions proves the
/// bridge is a faithful `Channel`, not just a one-shot pipe.
#[tokio::test]
async fn conformance_over_capnp() {
    let (capnp_a, capnp_b) = crossed_capnp_pair(8);
    testkit::roundtrip_both_directions(capnp_a, capnp_b).await;
}

/// The server bridge must preserve the backend's full-duplex capability: with
/// one slot per direction, both peers have to keep receiving while their
/// outbound bursts apply backpressure.
#[tokio::test]
async fn mutual_bursts_converge_over_capnp() {
    let (capnp_a, capnp_b) = crossed_capnp_pair(1);
    testkit::mutual_bursts_converge(capnp_a, capnp_b, 64).await;
}

/// Proves the C1 fix: a dropped `recv` future loses no message across the Send
/// bridge — the actor's front-buffer holds a message pulled for an abandoned
/// caller until the next `recv` claims it.
#[tokio::test]
async fn cancel_safe_over_capnp() {
    let (capnp_a, capnp_b) = crossed_capnp_pair(8);
    testkit::recv_is_cancel_safe(capnp_a, capnp_b).await;
}

/// Proves the I3 fix: a backend/peer `Closed` propagates through capnp as
/// `Closed` (server maps it to a `Disconnected` capnp error, which the client
/// maps back to `RecvError::Closed`), not as an opaque `Transport` error.
#[tokio::test]
async fn closed_propagates_over_capnp() {
    let (capnp_a, capnp_b) = crossed_capnp_pair(8);
    testkit::closed_after_peer_drop(capnp_a, capnp_b).await;
}

/// Proves the adapter's local size check: a message larger than the channel's
/// declared maximum is rejected with `SendError::TooLarge { max }` by the
/// adapter itself, before any RPC — so the server never needs to see it. The
/// loopback server is present only so the channel is otherwise usable.
#[tokio::test]
async fn too_large_rejected_locally_over_capnp() {
    const MAX: usize = 4;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let _server = serve_loopback(server_io);
    let channel = CapnpChannel::connect_with(client_io, MAX);

    testkit::too_large(channel, MAX).await;
}

/// Proves the I2 fix: dropping a `CapnpChannel` while a `recv` is parked on an
/// empty backend still terminates the actor thread AND the server thread,
/// rather than leaking them forever. The peer end of the mem pair is kept
/// alive (never sends), so the backend recv genuinely blocks; the drop must be
/// what unblocks the shutdown, and the server's stream must then hit EOF.
#[tokio::test]
async fn drop_with_recv_parked_terminates_server() {
    use std::time::Duration;

    let cfg = MemConfig {
        capacity: Some(8),
        ..MemConfig::default()
    };
    // `_peer` is held for the whole test so the backend recv blocks (not
    // `Closed`); dropping it early would defeat the point of the test.
    let (backend, _peer) = duplex(cfg);

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = serve_backend(server_io, backend);
    let mut channel = CapnpChannel::connect(client_io);

    // Park a recv inside the actor (command dispatched, backend recv blocking),
    // then abandon the future.
    let parked = tokio::time::timeout(Duration::from_millis(100), channel.recv()).await;
    assert!(
        parked.is_err(),
        "recv must block: the backend has no message"
    );

    // Drop the handle: this must break the actor loop out of the in-flight
    // recv, close the client stream, and let the server thread finish on EOF.
    drop(channel);

    let terminated = tokio::time::timeout(Duration::from_secs(5), async {
        while !server.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        terminated.is_ok(),
        "actor + server threads must terminate after drop, not hang"
    );
}
