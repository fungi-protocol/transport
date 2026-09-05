//! Minimal SOCKS5h client: CONNECT with the hostname sent to the proxy
//! (ATYP=domain), per RFC 1928. "h" = the proxy resolves the name; a
//! `.onion` has no DNS entry, and resolving locally would leak it.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use fungi_transport::ConnectError;

fn io_err(e: std::io::Error) -> ConnectError {
    ConnectError::Transport(e.into())
}

/// RFC 1929 username/password subnegotiation. The username carries the
/// isolation credential (bounded to 255 bytes by the isolation id's short text
/// form); the password is a fixed placeholder — tor isolates on the pair, and
/// varying the username alone already separates circuits.
async fn authenticate(stream: &mut TcpStream, username: &str) -> Result<(), ConnectError> {
    let user = username.as_bytes();
    if user.len() > 255 {
        return Err(ConnectError::Transport(
            "SOCKS5 username longer than the 255-byte limit".into(),
        ));
    }
    // VER(0x01), ULEN, uname, PLEN(0), no password bytes.
    let mut req = Vec::with_capacity(3 + user.len());
    req.extend_from_slice(&[0x01, user.len() as u8]);
    req.extend_from_slice(user);
    req.push(0x00);
    stream.write_all(&req).await.map_err(io_err)?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(io_err)?;
    // Subnegotiation version is 0x01; status 0x00 is success.
    if reply[0] != 0x01 || reply[1] != 0x00 {
        return Err(ConnectError::Transport(
            "SOCKS5 username/password auth rejected".into(),
        ));
    }
    Ok(())
}

/// Classify a SOCKS5 CONNECT reply code (RFC 1928 reply field). `Ok(())` is
/// success. General server failure (`0x01`) and the network/host-unreachable
/// and connection-refused codes (`0x03`-`0x05`) become
/// [`ConnectError::Unreachable`]: through tor these mean the peer could not be
/// reached (`0x01` covers a failed onion descriptor lookup or rendezvous), the
/// consumer's cue to retry later. This matches the arti backend's classifier,
/// so retry semantics do not depend on which backend is plugged. The remaining
/// codes are genuine protocol/policy failures and stay opaque.
fn classify_connect_reply(code: u8) -> Result<(), ConnectError> {
    match code {
        0x00 => Ok(()),
        0x01 | 0x03..=0x05 => Err(ConnectError::Unreachable),
        code => Err(ConnectError::Transport(
            format!("SOCKS5 CONNECT failed with reply code {code}").into(),
        )),
    }
}

/// Open a TCP stream to `host:port` through the SOCKS5 proxy at `proxy`.
/// The hostname travels to the proxy unresolved (SOCKS5h).
///
/// `credential`, when set, drives username/password auth (RFC 1929) with that
/// username (and a fixed password). Its only purpose is circuit isolation:
/// tor's `IsolateSOCKSAuth` (on by default) gives streams with distinct SOCKS
/// credentials distinct circuits. `None` uses no-auth, sharing the daemon's
/// default circuits.
pub(crate) async fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    credential: Option<&str>,
) -> Result<TcpStream, ConnectError> {
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(ConnectError::Transport(
            "hostname longer than SOCKS5's 255-byte limit".into(),
        ));
    }
    let mut stream = TcpStream::connect(proxy).await.map_err(io_err)?;

    // Greeting: a credentialed connect offers ONLY username/password (0x02), so
    // a proxy that will not isolate answers 0xFF and we fail loudly rather than
    // silently riding shared circuits. An unisolated connect offers no-auth.
    match credential {
        None => stream.write_all(&[0x05, 0x01, 0x00]).await,
        Some(_) => stream.write_all(&[0x05, 0x01, 0x02]).await,
    }
    .map_err(io_err)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.map_err(io_err)?;
    if chosen[0] != 0x05 {
        return Err(ConnectError::Transport(
            "SOCKS5 greeting reply with wrong version byte".into(),
        ));
    }
    match (chosen[1], credential) {
        // no-auth selected on an unisolated connect: nothing more to do
        (0x00, None) => {}
        // no-auth on a credentialed connect would ride the daemon's shared
        // circuits, silently losing the per-group isolation the credential
        // exists to provide. We never offer no-auth when credentialed, so a
        // conformant proxy cannot reach this; refuse rather than lose isolation.
        (0x00, Some(_)) => {
            return Err(ConnectError::Transport(
                "SOCKS5 proxy selected no-auth for an isolated connection, which would \
                 collapse per-group circuit isolation"
                    .into(),
            ));
        }
        // username/password selected and we offered it: authenticate
        (0x02, Some(cred)) => authenticate(&mut stream, cred).await?,
        // username/password selected though only a credentialed connect
        // offers it — a conformant proxy cannot reach this; refuse rather
        // than authenticate with an empty credential we never intended.
        (0x02, None) => {
            return Err(ConnectError::Transport(
                "SOCKS5 proxy selected an auth method that was not offered".into(),
            ));
        }
        _ => {
            return Err(ConnectError::Transport(
                "SOCKS5 proxy selected no acceptable auth method".into(),
            ));
        }
    }

    // CONNECT request: ATYP 0x03 (domain name), then len-prefixed name.
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.map_err(io_err)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != 0x05 {
        return Err(ConnectError::Transport(
            "SOCKS5 reply with wrong version byte".into(),
        ));
    }
    classify_connect_reply(head[1])?;
    // Consume the bound address so the stream starts at tunnel byte 0.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await.map_err(io_err)?;
            l[0] as usize
        }
        other => {
            return Err(ConnectError::Transport(
                format!("SOCKS5 reply with unknown address type {other}").into(),
            ));
        }
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await.map_err(io_err)?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::connect;
    use fungi_transport::ConnectError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serve one SOCKS5 connection: assert the exact handshake bytes for
    /// `host:port`, answer with `reply_code`, then (on success) echo one
    /// test byte so callers can prove the returned stream is the tunnel.
    async fn serve_one(listener: TcpListener, host: &str, port: u16, reply_code: u8) {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        s.read_exact(&mut greeting).await.unwrap();
        assert_eq!(
            greeting,
            [0x05, 0x01, 0x00],
            "greeting: ver 5, 1 method, no-auth"
        );
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut head = [0u8; 5];
        s.read_exact(&mut head).await.unwrap();
        // The .onion MUST travel as ATYP=domain so the proxy resolves it.
        assert_eq!(
            &head[..4],
            &[0x05, 0x01, 0x00, 0x03],
            "CONNECT with ATYP=domain"
        );
        let mut name = vec![0u8; head[4] as usize];
        s.read_exact(&mut name).await.unwrap();
        assert_eq!(name, host.as_bytes());
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        assert_eq!(u16::from_be_bytes(p), port);
        // Reply: code + bound address (0.0.0.0:0).
        s.write_all(&[0x05, reply_code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        if reply_code == 0x00 {
            let mut byte = [0u8; 1];
            s.read_exact(&mut byte).await.unwrap();
            s.write_all(&byte).await.unwrap();
        }
    }

    /// Serve one SOCKS5 connection that REQUIRES username/password: assert the
    /// greeting offers method 0x02, select it, read the RFC 1929
    /// subnegotiation and hand the username back to the caller over `user_tx`,
    /// then complete a CONNECT for `host:port`.
    async fn serve_one_authed(
        listener: TcpListener,
        host: &str,
        port: u16,
        user_tx: tokio::sync::oneshot::Sender<String>,
    ) {
        let (mut s, _) = listener.accept().await.unwrap();
        // Greeting: VER, NMETHODS, then the methods.
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05);
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        assert!(
            methods.contains(&0x02),
            "client must offer username/password auth: {methods:?}"
        );
        s.write_all(&[0x05, 0x02]).await.unwrap(); // select username/password

        // RFC 1929: VER(0x01), ULEN, uname, PLEN, passwd.
        let mut vu = [0u8; 2];
        s.read_exact(&mut vu).await.unwrap();
        assert_eq!(vu[0], 0x01, "auth subnegotiation version");
        let mut uname = vec![0u8; vu[1] as usize];
        s.read_exact(&mut uname).await.unwrap();
        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await.unwrap();
        let mut passwd = vec![0u8; plen[0] as usize];
        s.read_exact(&mut passwd).await.unwrap();
        s.write_all(&[0x01, 0x00]).await.unwrap(); // auth success
        user_tx.send(String::from_utf8(uname).unwrap()).unwrap();

        // CONNECT.
        let mut req = [0u8; 5];
        s.read_exact(&mut req).await.unwrap();
        assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x03]);
        let mut name = vec![0u8; req[4] as usize];
        s.read_exact(&mut name).await.unwrap();
        assert_eq!(name, host.as_bytes());
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        assert_eq!(u16::from_be_bytes(p), port);
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    }

    /// A credential drives RFC 1929 auth and arrives at the proxy verbatim as
    /// the username — the isolation identity the daemon separates circuits on.
    #[tokio::test]
    async fn credential_is_sent_as_the_socks_username() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let (user_tx, user_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_one_authed(listener, "peer.onion", 9735, user_tx));
        connect(proxy, "peer.onion", 9735, Some("1234-7"))
            .await
            .unwrap();
        assert_eq!(user_rx.await.unwrap(), "1234-7");
        server.await.unwrap();
    }

    /// A credentialed connect must fail if the proxy selects no-auth: proceeding
    /// would ride the daemon's shared circuits and silently lose isolation.
    #[tokio::test]
    async fn no_auth_on_a_credentialed_connect_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            // Misbehave: select no-auth though only user/pass was offered.
            s.write_all(&[0x05, 0x00]).await.unwrap();
        });
        let err = connect(proxy, "peer.onion", 9735, Some("1234-7")).await;
        assert!(matches!(err, Err(ConnectError::Transport(_))));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_success_yields_the_tunnel_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, "abcdefghijklmnop.onion", 9735, 0x00));
        let mut stream = connect(proxy, "abcdefghijklmnop.onion", 9735, None)
            .await
            .unwrap();
        stream.write_all(&[0x42]).await.unwrap();
        let mut echoed = [0u8; 1];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, [0x42]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn host_unreachable_maps_to_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, "dead.onion", 1, 0x04));
        let err = connect(proxy, "dead.onion", 1, None).await;
        assert!(matches!(err, Err(ConnectError::Unreachable)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn general_failure_maps_to_unreachable() {
        // Through tor, a general server failure on CONNECT is a failed onion
        // lookup/rendezvous — a reachability condition, same as arti reports.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, "sad.onion", 1, 0x01));
        let err = connect(proxy, "sad.onion", 1, None).await;
        assert!(matches!(err, Err(ConnectError::Unreachable)));
        server.await.unwrap();
    }

    #[test]
    fn connect_reply_classification() {
        use super::classify_connect_reply;
        assert!(classify_connect_reply(0x00).is_ok());
        for code in [0x01, 0x03, 0x04, 0x05] {
            assert!(
                matches!(classify_connect_reply(code), Err(ConnectError::Unreachable)),
                "reply code {code:#04x} should be Unreachable"
            );
        }
        for code in [0x02, 0x06, 0x07, 0x08] {
            assert!(
                matches!(
                    classify_connect_reply(code),
                    Err(ConnectError::Transport(_))
                ),
                "reply code {code:#04x} should be Transport"
            );
        }
    }

    /// The 255-byte hostname guard fires before the proxy is ever dialed.
    /// The proxy here is a bound listener that never answers, so only the
    /// pre-I/O guard message can come back — had the code dialed, it would
    /// have stalled in the handshake and produced a different error.
    #[tokio::test]
    async fn hostname_over_255_bytes_is_rejected_before_any_io() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let host = "a".repeat(256);
        let err = connect(proxy, &host, 1, None)
            .await
            .expect_err("an overlong hostname must be rejected");
        assert!(
            err.to_string().contains("255-byte limit"),
            "expected the pre-I/O guard error, got: {err}"
        );
        drop(listener);
    }

    mod properties {
        use super::super::connect;
        use super::serve_one;
        use proptest::prelude::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building the proptest runtime")
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(16))]

            /// The CONNECT encoding round-trips for any legal hostname up to
            /// the 255-byte limit: the proxy sees exactly the requested host
            /// and port, and the returned stream is the tunnel.
            #[test]
            fn handshake_roundtrips_any_legal_hostname(
                host in "[a-z0-9.]{1,255}",
                port in 1u16..,
            ) {
                rt().block_on(async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let proxy = listener.local_addr().unwrap();
                    let served = host.clone();
                    let server = tokio::spawn(async move {
                        serve_one(listener, &served, port, 0x00).await;
                    });
                    let mut stream = connect(proxy, &host, port, None).await.unwrap();
                    stream.write_all(&[0x42]).await.unwrap();
                    let mut echoed = [0u8; 1];
                    stream.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(echoed, [0x42]);
                    server.await.unwrap();
                });
            }
        }
    }

    /// A reply whose VER byte isn't 0x05 is a malformed/mismatched proxy
    /// reply and must error before the reply code is even inspected —
    /// otherwise a garbled version byte could be misread as a valid code.
    #[tokio::test]
    async fn wrong_version_byte_in_reply_maps_to_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            let mut name = vec![0u8; head[4] as usize];
            s.read_exact(&mut name).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
            // Reply with VER=0x04 (wrong) instead of 0x05.
            s.write_all(&[0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = connect(proxy, "wrongver.onion", 1, None).await;
        assert!(matches!(err, Err(ConnectError::Transport(_))));
        server.await.unwrap();
    }
}
