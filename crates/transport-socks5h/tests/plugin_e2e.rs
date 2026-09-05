//! Proves a REAL backend over the whole capnp plugin stack, deterministically:
//! the SOCKS5h `TorTransport` runs inside the plugin subprocess, driven from
//! here through [`connect_plugin`] over the child's stdio, with the tor daemon
//! replaced by in-test fakes.
//!
//! The fakes stand in for a daemon: a fake control port answers AUTHENTICATE
//! and ADD_ONION (holding the connection open so the onion service "lives"),
//! and a fake SOCKS proxy does the server side of the handshake and splices the
//! stream to the listener's local port. The proxy learns that local port from
//! the ADD_ONION command the plugin issues — the same port tor itself would
//! forward inbound onion connections to — so no address needs to be known in
//! advance.

use std::net::SocketAddr;

use fungi_transport::testkit;
use fungi_transport::{Connector, ListenParams, Listener, OnionAddr, Transport};
use fungi_transport_capnp::{CapnpTransport, connect_plugin};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// The plugin binary, built by cargo before this integration test.
const PLUGIN: &str = env!("CARGO_BIN_EXE_fungi-socks5h-plugin");

/// Fake tor control port good for one ADD_ONION. Answers AUTHENTICATE and
/// ADD_ONION with a fixed `service_id`, and reports the local port carried in
/// the ADD_ONION command (`...127.0.0.1:<port>`) over `port_tx` so the fake
/// SOCKS proxy knows where to forward. Holds the connection open afterwards,
/// so the onion service lives until the plugin drops it.
async fn fake_control_once(
    listener: TcpListener,
    service_id: String,
    port_tx: oneshot::Sender<u16>,
) {
    let (sock, _) = listener.accept().await.unwrap();
    let mut sock = BufReader::new(sock);
    let mut line = String::new();
    sock.read_line(&mut line).await.unwrap(); // AUTHENTICATE
    sock.get_mut().write_all(b"250 OK\r\n").await.unwrap();

    line.clear();
    sock.read_line(&mut line).await.unwrap(); // ADD_ONION ... 127.0.0.1:<port>
    let local_port: u16 = line
        .trim_end()
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .expect("ADD_ONION carries a forwarding port");
    let _ = port_tx.send(local_port);

    sock.get_mut()
        .write_all(format!("250-ServiceID={service_id}\r\n250 OK\r\n").as_bytes())
        .await
        .unwrap();
    let mut hold = String::new();
    let _ = sock.read_line(&mut hold).await; // park until the plugin drops it
}

/// Fake SOCKS5 forwarding proxy: once the listener's local port is known, serve
/// every inbound client — do the server side of the handshake (no byte
/// assertions; the socks5h crate owns those) and splice it to a fresh
/// connection to `127.0.0.1:<local_port>`.
async fn fake_socks_forwarding(listener: TcpListener, port_rx: oneshot::Receiver<u16>) {
    let local_port = port_rx
        .await
        .expect("the control port reports a local port");
    let forward_to = SocketAddr::from(([127, 0, 0, 1], local_port));
    loop {
        let Ok((mut client, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            if client.read_exact(&mut greeting).await.is_err() {
                return;
            }
            let _ = client.write_all(&[0x05, 0x00]).await;
            let mut head = [0u8; 5];
            if client.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut name = vec![0u8; head[4] as usize];
            let _ = client.read_exact(&mut name).await;
            let mut port = [0u8; 2];
            let _ = client.read_exact(&mut port).await;
            let _ = client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            if let Ok(mut upstream) = TcpStream::connect(forward_to).await {
                tokio::io::copy_bidirectional(&mut client, &mut upstream)
                    .await
                    .ok();
            }
        });
    }
}

/// The crown-jewel test: connector -> fake SOCKS (forwarding) -> the plugin's
/// own onion-service local port, with the whole SOCKS5h `TorTransport` living
/// inside the subprocess and every hop crossing capnp over its stdio.
#[tokio::test]
async fn socks5h_plugin_roundtrip_through_fakes() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();

    let (port_tx, port_rx) = oneshot::channel();
    let service_id = format!("{:a<56}", "e2epluginservice");
    tokio::spawn(fake_control_once(control, service_id.clone(), port_tx));
    tokio::spawn(fake_socks_forwarding(proxy, port_rx));

    let mut command = tokio::process::Command::new(PLUGIN);
    command.env("FUNGI_SOCKS_ADDR", proxy_addr.to_string());
    command.env("FUNGI_CONTROL_ADDR", control_addr.to_string());
    let transport: CapnpTransport<OnionAddr> = connect_plugin(command);

    let (mut listener, onion) = transport.listen(ListenParams::new(9735)).await.unwrap();
    assert_eq!(onion.host(), format!("{service_id}.onion"));

    let connector = transport.connector();
    let (outbound, inbound) = tokio::join!(connector.connect(&onion), listener.accept());
    testkit::roundtrip_both_directions(outbound.unwrap(), inbound.unwrap()).await;
}
