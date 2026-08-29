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
//!
//! Per-session isolation is likewise the daemon's: a session-bound connector
//! dials with the session's SOCKS username, and the daemon separates circuits
//! by credential only under `IsolateSOCKSAuth` (its default). A daemon with
//! that turned off would collapse the isolation silently, so a session-bound
//! connector reads the daemon's `SocksPort` configuration over the control
//! port before its first dial and fails loudly if the flag is disabled. That
//! turns an honest misconfiguration into an error; a daemon that lies about
//! its configuration already controls every guarantee here. Isolation covers
//! the dialing side; inbound rendezvous circuits at a listener are the
//! daemon's to place.

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
///
/// A connector bound to a session (via
/// [`fungi_transport::Transport::connector_for`])
/// dials with a SOCKS credential derived from the session id, so the daemon
/// isolates its circuits from other sessions'. The default connector carries
/// none.
#[derive(Debug)]
pub struct TorConnector {
    cfg: TorConfig,
    /// SOCKS username for circuit isolation; `None` uses no-auth.
    credential: Option<String>,
    /// Set once the daemon's isolation config has been verified over the
    /// control port. Only credentialed connects consult it; a failed check
    /// leaves it empty, so the next connect retries instead of caching the
    /// failure.
    isolation_verified: std::sync::Arc<tokio::sync::OnceCell<()>>,
}

impl TorConnector {
    /// A connector talking to the daemon described by `cfg`, on the shared
    /// default circuits (no isolation credential).
    pub fn new(cfg: TorConfig) -> Self {
        Self {
            cfg,
            credential: None,
            isolation_verified: Default::default(),
        }
    }

    /// A connector whose streams carry `credential` as the SOCKS username,
    /// isolating them onto their own circuits. The first connect verifies,
    /// over the control port, that the daemon has not disabled
    /// per-credential isolation, and fails instead of dialing on a daemon
    /// that would silently collapse the sessions onto shared circuits.
    pub fn with_credential(cfg: TorConfig, credential: String) -> Self {
        Self {
            cfg,
            credential: Some(credential),
            isolation_verified: Default::default(),
        }
    }

    #[cfg(test)]
    fn credential(&self) -> Option<&str> {
        self.credential.as_deref()
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
        let control_addr = self.cfg.control_addr;
        let auth = self.cfg.auth.clone();
        let max = self.cfg.max_msg_len;
        let host = addr.host().to_owned();
        let port = addr.port();
        let credential = self.credential.clone();
        let isolation_verified = self.isolation_verified.clone();
        async move {
            if credential.is_some() {
                isolation_verified
                    .get_or_try_init(|| control::verify_isolate_socks_auth(control_addr, &auth))
                    .await?;
            }
            let stream = socks5::connect(socks_addr, &host, port, credential.as_deref()).await?;
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

    fn connector_for(&self, session: &fungi_transport::SessionId) -> TorConnector {
        // The session id's text form becomes the SOCKS username, so the
        // daemon (IsolateSOCKSAuth) gives this session its own circuits.
        TorConnector::with_credential(self.cfg.clone(), session.to_string())
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

    /// The local TCP port the daemon forwards inbound connections to. Only
    /// tests need it — real peers see the onion address — so it is compiled out
    /// of release builds, keeping its one `expect` off the production path.
    #[cfg(test)]
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
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Control fake that serves the isolation check on every connection,
    /// answering `GETCONF SocksPort` with `reply` and counting connections.
    async fn fake_control_isolation(
        listener: TcpListener,
        reply: &'static str,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut sock = tokio::io::BufReader::new(sock);
            let mut line = String::new();
            sock.read_line(&mut line).await.unwrap();
            sock.get_mut().write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            sock.read_line(&mut line).await.unwrap();
            sock.get_mut().write_all(reply.as_bytes()).await.unwrap();
        }
    }

    /// Fake SOCKS proxy requiring username/password: complete the handshake
    /// on every connection (no byte assertions; socks5.rs tests own those),
    /// report each username on `users`, and hold the tunnel open.
    async fn fake_socks_authed(
        listener: TcpListener,
        users: tokio::sync::mpsc::UnboundedSender<String>,
    ) {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let mut head = [0u8; 2];
            client.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            client.write_all(&[0x05, 0x02]).await.unwrap();
            let mut vu = [0u8; 2];
            client.read_exact(&mut vu).await.unwrap();
            let mut uname = vec![0u8; vu[1] as usize];
            client.read_exact(&mut uname).await.unwrap();
            let mut plen = [0u8; 1];
            client.read_exact(&mut plen).await.unwrap();
            let mut passwd = vec![0u8; plen[0] as usize];
            client.read_exact(&mut passwd).await.unwrap();
            client.write_all(&[0x01, 0x00]).await.unwrap();
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
            users.send(String::from_utf8(uname).unwrap()).unwrap();
            tokio::spawn(async move {
                let mut byte = [0u8; 1];
                let _ = client.read_exact(&mut byte).await;
            });
        }
    }

    /// A bound-then-dropped listener's address: connecting to it is refused,
    /// so any code path that touches it turns into a visible error.
    async fn refused_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    /// A credentialed connect verifies the daemon's isolation config over
    /// the control port exactly once per connector, then dials with the
    /// session credential as usual.
    #[tokio::test]
    async fn session_connect_verifies_isolation_once_then_dials() {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(fake_control_isolation(
            control,
            "250 SocksPort=9050\r\n",
            hits.clone(),
        ));
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks.local_addr().unwrap();
        let (users_tx, mut users_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(fake_socks_authed(socks, users_tx));

        let session = fungi_transport::SessionId::generate();
        let connector = TorTransport::new(TorConfig {
            socks_addr,
            control_addr,
            ..TorConfig::default()
        })
        .connector_for(&session);
        let addr = OnionAddr::new(format!("{:a<56}.onion", "x"), 9735).unwrap();
        let _c1 = connector.connect(&addr).await.unwrap();
        let _c2 = connector.connect(&addr).await.unwrap();

        assert_eq!(users_rx.recv().await.unwrap(), session.to_string());
        assert_eq!(users_rx.recv().await.unwrap(), session.to_string());
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the isolation config is verified once per connector, not per dial"
        );
    }

    /// A daemon that disables per-credential isolation fails the credentialed
    /// connect with an error naming the flag, instead of silently dialing
    /// onto shared circuits.
    #[tokio::test]
    async fn session_connect_fails_fast_when_daemon_disables_isolation() {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control.local_addr().unwrap();
        tokio::spawn(fake_control_isolation(
            control,
            "250 SocksPort=9050 NoIsolateSOCKSAuth\r\n",
            Default::default(),
        ));

        let connector = TorTransport::new(TorConfig {
            socks_addr: refused_addr().await,
            control_addr,
            ..TorConfig::default()
        })
        .connector_for(&fungi_transport::SessionId::generate());
        let addr = OnionAddr::new(format!("{:a<56}.onion", "x"), 9735).unwrap();
        let err = connector.connect(&addr).await.unwrap_err();
        assert!(
            err.to_string().contains("NoIsolateSOCKSAuth"),
            "the check must fail before the dial, got: {err}"
        );
    }

    /// The default connector carries no credential, so it never touches the
    /// control port: with the control address refusing connections, the dial
    /// still goes through.
    #[tokio::test]
    async fn default_connector_dials_without_touching_the_control_port() {
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client, _) = socks.accept().await.unwrap();
            let mut greet = [0u8; 2];
            client.read_exact(&mut greet).await.unwrap();
            let mut methods = vec![0u8; greet[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
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
            let mut byte = [0u8; 1];
            let _ = client.read_exact(&mut byte).await;
        });

        let connector = TorTransport::new(TorConfig {
            socks_addr,
            control_addr: refused_addr().await,
            ..TorConfig::default()
        })
        .connector();
        let addr = OnionAddr::new(format!("{:a<56}.onion", "x"), 9735).unwrap();
        connector.connect(&addr).await.unwrap();
    }

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

    /// `connector_for` derives the isolation credential from the session:
    /// distinct sessions get distinct usernames (distinct circuits), the same
    /// session gets the same one, and the default connector carries none.
    #[test]
    fn per_session_connectors_derive_distinct_credentials() {
        use fungi_transport::{SessionId, Transport};
        let transport = TorTransport::new(TorConfig::default());
        assert_eq!(transport.connector().credential(), None);

        let (s1, s2) = (SessionId::generate(), SessionId::generate());
        let c1 = transport.connector_for(&s1);
        let c2 = transport.connector_for(&s2);
        assert_eq!(c1.credential(), Some(s1.to_string().as_str()));
        assert_ne!(c1.credential(), c2.credential());
        assert_eq!(
            transport.connector_for(&s1).credential(),
            c1.credential(),
            "same session, same credential"
        );
    }
}
