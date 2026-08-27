//! Channel backend over an external tor daemon.
//!
//! The daemon does all Tor work; this crate speaks two local protocols to
//! it: SOCKS5h on the socks port to open streams to `.onion` peers (the
//! proxy resolves the hostname — resolving locally would fail and leak the
//! address to DNS), and the control port to publish an onion service that
//! forwards inbound connections to a local TCP listener.
//!
//! Neither handshake carries an internal deadline: a wedged daemon blocks
//! `connect`/`bind` indefinitely. Callers own the timeout — wrap the future
//! in `tokio::time::timeout` (or similar); cancelling by drop is safe and
//! discards the whole connection attempt.
//!
//! Trust base for the opening contract: the daemon is part of it. It is the
//! daemon — not this crate — that verifies the onion key behind a dialed
//! address and keeps the dialer anonymous, so whoever controls the SOCKS
//! and control ports controls those guarantees. The crate assumes a
//! trusted daemon on localhost; the local forward port of a listener is
//! likewise reachable by any local process.

mod control;
mod socks5;

pub use control::ControlAuth;

use fungi_transport::OnionAddr;

use std::future::Future;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use fungi_transport::ConnectError;
use fungi_transport::Connector;
use fungi_transport::ListenParams;
use fungi_transport::Transport;
use fungi_transport::framed::{DEFAULT_MAX_MSG_LEN, FramedChannel};

/// Knobs for the tor-daemon backend. Defaults match a stock daemon on
/// localhost.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// The daemon's SOCKS port.
    pub socks_addr: SocketAddr,
    /// The daemon's control port.
    pub control_addr: SocketAddr,
    /// Maximum framed message size, both directions.
    pub max_msg_len: usize,
    /// Control-port authentication mode.
    pub auth: ControlAuth,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            control_addr: SocketAddr::from(([127, 0, 0, 1], 9051)),
            max_msg_len: DEFAULT_MAX_MSG_LEN,
            auth: ControlAuth::Null,
        }
    }
}

/// Opens channels to `.onion` peers through the daemon's SOCKS5h proxy.
#[derive(Debug)]
pub struct TorConnector {
    cfg: TorConfig,
}

impl TorConnector {
    /// A connector talking to the daemon described by `cfg`.
    pub fn new(cfg: TorConfig) -> Self {
        Self { cfg }
    }
}

impl Connector for TorConnector {
    type Addr = OnionAddr;
    type Channel = FramedChannel<TcpStream>;

    fn connect(
        &self,
        addr: &OnionAddr,
    ) -> impl Future<Output = Result<Self::Channel, ConnectError>> + Send {
        let socks_addr = self.cfg.socks_addr;
        let max = self.cfg.max_msg_len;
        let host = addr.host().to_owned();
        let port = addr.port();
        async move {
            let stream = socks5::connect(socks_addr, &host, port).await?;
            Ok(FramedChannel::new(stream, max))
        }
    }
}

/// A [`Transport`] over a tor daemon: SOCKS5h connectors and ephemeral onion
/// listeners.
#[derive(Debug, Clone)]
pub struct TorTransport {
    cfg: TorConfig,
}

impl TorTransport {
    /// A transport talking to the daemon described by `cfg`.
    pub fn new(cfg: TorConfig) -> Self {
        Self { cfg }
    }
}

impl Transport for TorTransport {
    type Addr = OnionAddr;
    type Connector = TorConnector;
    type Listener = TorListener;

    fn connector(&self) -> TorConnector {
        TorConnector::new(self.cfg.clone())
    }

    fn listen(
        &self,
        params: ListenParams,
    ) -> impl std::future::Future<Output = Result<(TorListener, OnionAddr), ConnectError>> + Send
    {
        let cfg = self.cfg.clone();
        async move {
            // SOCKS5h onions are ephemeral (DiscardPK); the nickname hint is unused.
            let listener = TorListener::bind(&cfg, params.virt_port).await?;
            let addr = listener.onion_addr().clone();
            Ok((listener, addr))
        }
    }
}

use tokio::net::TcpListener;

use fungi_transport::Listener;

/// Accepts inbound channels arriving through this peer's onion service.
///
/// The onion service is published on [`bind`](TorListener::bind) and lives
/// exactly as long as this listener: dropping it closes the control
/// connection and the daemon removes the service.
#[derive(Debug)]
pub struct TorListener {
    local: TcpListener,
    addr: OnionAddr,
    max_msg_len: usize,
    // Held only for its lifetime: the onion service dies with it.
    _service: control::OnionService,
}

impl TorListener {
    /// Publish an onion service on `virt_port` and listen for connections
    /// the daemon forwards to a local ephemeral port.
    pub async fn bind(cfg: &TorConfig, virt_port: u16) -> Result<Self, ConnectError> {
        let local = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| ConnectError::Transport(e.into()))?;
        let local_port = local
            .local_addr()
            .map_err(|e| ConnectError::Transport(e.into()))?
            .port();
        let service =
            control::create_onion(cfg.control_addr, &cfg.auth, virt_port, local_port).await?;
        let addr = OnionAddr::new(format!("{}.onion", service.service_id), virt_port)
            .map_err(|e| ConnectError::Transport(e.into()))?;
        Ok(Self {
            local,
            addr,
            max_msg_len: cfg.max_msg_len,
            _service: service,
        })
    }

    /// This peer's address, to hand to peers out of band.
    pub fn onion_addr(&self) -> &OnionAddr {
        &self.addr
    }

    /// The local TCP port the daemon forwards inbound connections to.
    /// Exposed for tests; real peers only ever see the onion address.
    pub fn local_port(&self) -> u16 {
        self.local
            .local_addr()
            .expect("bound listener has an addr")
            .port()
    }
}

impl Listener for TorListener {
    type Channel = FramedChannel<TcpStream>;

    async fn accept(&mut self) -> Result<Self::Channel, ConnectError> {
        let (sock, _) = self
            .local
            .accept()
            .await
            .map_err(|e| ConnectError::Transport(e.into()))?;
        Ok(FramedChannel::new(sock, self.max_msg_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fungi_transport::Channel as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Fake SOCKS proxy: accept one client, do the server side of the
    /// handshake (no byte assertions — socks5.rs tests own those), then
    /// splice the client to a fresh TCP connection to `forward_to`.
    async fn fake_socks_forwarding(listener: TcpListener, forward_to: std::net::SocketAddr) {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        client.read_exact(&mut greeting).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();
        let mut head = [0u8; 5];
        client.read_exact(&mut head).await.unwrap();
        let mut name = vec![0u8; head[4] as usize];
        client.read_exact(&mut name).await.unwrap();
        let mut port = [0u8; 2];
        client.read_exact(&mut port).await.unwrap();
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut upstream = tokio::net::TcpStream::connect(forward_to).await.unwrap();
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .ok();
    }

    #[tokio::test]
    async fn connector_yields_a_framed_channel_through_the_proxy() {
        // "Peer": a plain TCP listener speaking the framed protocol.
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let peer_task = tokio::spawn(async move {
            let (sock, _) = peer.accept().await.unwrap();
            let mut ch = fungi_transport::framed::FramedChannel::new(
                sock,
                fungi_transport::framed::DEFAULT_MAX_MSG_LEN,
            );
            let msg = ch.recv().await.unwrap();
            ch.send(&msg).await.unwrap(); // echo
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(fake_socks_forwarding(proxy, peer_addr));

        let connector = TorConnector::new(TorConfig {
            socks_addr: proxy_addr,
            ..TorConfig::default()
        });
        let addr = OnionAddr::new(format!("{}.onion", svc_id("peer")), 9735).unwrap();
        let mut ch = connector.connect(&addr).await.unwrap();
        ch.send(b"ping").await.unwrap();
        assert_eq!(ch.recv().await.unwrap(), b"ping");
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn connector_maps_proxy_absence_to_transport_error() {
        // Nothing listens on this port: TCP connect to the proxy fails.
        let connector = TorConnector::new(TorConfig {
            socks_addr: "127.0.0.1:1".parse().unwrap(),
            ..TorConfig::default()
        });
        let err = connector
            .connect(&OnionAddr::new(format!("{}.onion", svc_id("x")), 1).unwrap())
            .await;
        assert!(matches!(
            err,
            Err(fungi_transport::ConnectError::Transport(_))
        ));
    }

    use tokio::io::AsyncBufReadExt;
    use tokio::io::BufReader;

    /// A valid v3-form service id: a readable prefix padded to 56 base32
    /// chars.
    fn svc_id(prefix: &str) -> String {
        format!("{prefix:a<56}")
    }

    /// Fake control port good for one ADD_ONION (same protocol as the
    /// control.rs fakes; no byte assertions — control.rs owns those).
    async fn fake_control_once(listener: TcpListener, service_id: String) {
        let (sock, _) = listener.accept().await.unwrap();
        let mut sock = BufReader::new(sock);
        let mut line = String::new();
        sock.read_line(&mut line).await.unwrap(); // AUTHENTICATE
        sock.get_mut().write_all(b"250 OK\r\n").await.unwrap();
        line.clear();
        sock.read_line(&mut line).await.unwrap(); // ADD_ONION
        sock.get_mut()
            .write_all(format!("250-ServiceID={service_id}\r\n250 OK\r\n").as_bytes())
            .await
            .unwrap();
        let mut hold = String::new();
        let _ = sock.read_line(&mut hold).await; // park until client drops
    }

    #[tokio::test]
    async fn listener_publishes_onion_and_accepts_framed_channels() {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control.local_addr().unwrap();
        tokio::spawn(fake_control_once(control, svc_id("fungiservicexyz")));

        let cfg = TorConfig {
            control_addr,
            ..TorConfig::default()
        };
        let mut listener = TorListener::bind(&cfg, 9735).await.unwrap();
        assert_eq!(
            listener.onion_addr().host(),
            format!("{}.onion", svc_id("fungiservicexyz"))
        );
        assert_eq!(listener.onion_addr().port(), 9735);

        // The fake daemon "forwards" an inbound connection: in reality tor
        // dials our local port; here the test dials it directly.
        let local = listener.local_port();
        let dial = tokio::spawn(async move {
            let sock = tokio::net::TcpStream::connect(("127.0.0.1", local))
                .await
                .unwrap();
            let mut ch = fungi_transport::framed::FramedChannel::new(sock, DEFAULT_MAX_MSG_LEN);
            ch.send(b"hi from tor").await.unwrap();
            assert_eq!(ch.recv().await.unwrap(), b"pong");
        });
        let mut inbound = listener.accept().await.unwrap();
        assert_eq!(inbound.recv().await.unwrap(), b"hi from tor");
        inbound.send(b"pong").await.unwrap();
        dial.await.unwrap();
    }

    /// The crown-jewel test: connector -> fake SOCKS (forwarding) ->
    /// listener local port, full conformance roundtrip across the chain.
    #[tokio::test]
    async fn end_to_end_connector_to_listener_through_fakes() {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control.local_addr().unwrap();
        tokio::spawn(fake_control_once(control, svc_id("endtoendservice")));

        let cfg = TorConfig {
            control_addr,
            ..TorConfig::default()
        };
        let mut listener = TorListener::bind(&cfg, 9735).await.unwrap();
        let onion = listener.onion_addr().clone();

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_port()));
        tokio::spawn(fake_socks_forwarding(proxy, local));

        let connector = TorConnector::new(TorConfig {
            socks_addr: proxy_addr,
            ..TorConfig::default()
        });
        let (outbound, inbound) = tokio::join!(connector.connect(&onion), listener.accept());
        fungi_transport::testkit::roundtrip_both_directions(outbound.unwrap(), inbound.unwrap())
            .await;
    }

    /// Like `fake_socks_forwarding` but serves EVERY inbound client — the
    /// reconnect conformance opens two sessions — each spliced to a fresh
    /// upstream connection to `forward_to`.
    async fn fake_socks_forwarding_multi(listener: TcpListener, forward_to: std::net::SocketAddr) {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let mut greeting = [0u8; 3];
            if client.read_exact(&mut greeting).await.is_err() {
                continue;
            }
            let _ = client.write_all(&[0x05, 0x00]).await;
            let mut head = [0u8; 5];
            if client.read_exact(&mut head).await.is_err() {
                continue;
            }
            let mut name = vec![0u8; head[4] as usize];
            let _ = client.read_exact(&mut name).await;
            let mut port = [0u8; 2];
            let _ = client.read_exact(&mut port).await;
            let _ = client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            tokio::spawn(async move {
                if let Ok(mut upstream) = tokio::net::TcpStream::connect(forward_to).await {
                    tokio::io::copy_bidirectional(&mut client, &mut upstream)
                        .await
                        .ok();
                }
            });
        }
    }

    /// The connection-oriented reconnect conformance, deterministically:
    /// a real `TorListener` (fake control) reached through a multi-session
    /// fake SOCKS proxy, driven by the shared testkit.
    #[tokio::test]
    async fn connect_use_drop_reconnect_through_fakes() {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control.local_addr().unwrap();
        tokio::spawn(fake_control_once(control, svc_id("reconnectservice")));

        let cfg = TorConfig {
            control_addr,
            ..TorConfig::default()
        };
        let listener = TorListener::bind(&cfg, 9735).await.unwrap();
        let onion = listener.onion_addr().clone();

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_port()));
        tokio::spawn(fake_socks_forwarding_multi(proxy, local));

        let connector = TorConnector::new(TorConfig {
            socks_addr: proxy_addr,
            ..TorConfig::default()
        });
        fungi_transport::testkit::connect_use_drop_reconnect(connector, listener, &onion).await;
    }

    #[tokio::test]
    async fn transport_roundtrips_through_fakes() {
        use fungi_transport::{Connector, ListenParams, Transport};

        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control.local_addr().unwrap();
        tokio::spawn(fake_control_once(control, svc_id("transportservice")));

        let transport = TorTransport::new(TorConfig {
            control_addr,
            ..TorConfig::default()
        });
        let (mut listener, onion) = transport.listen(ListenParams::new(9735)).await.unwrap();
        assert_eq!(
            onion.host(),
            format!("{}.onion", svc_id("transportservice"))
        );

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_port()));
        tokio::spawn(fake_socks_forwarding(proxy, local));

        let connector = TorTransport::new(TorConfig {
            socks_addr: proxy_addr,
            ..TorConfig::default()
        })
        .connector();
        let (outbound, inbound) = tokio::join!(connector.connect(&onion), listener.accept());
        fungi_transport::testkit::roundtrip_both_directions(outbound.unwrap(), inbound.unwrap())
            .await;
    }
}
