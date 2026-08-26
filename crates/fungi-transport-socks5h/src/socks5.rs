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

/// Open a TCP stream to `host:port` through the SOCKS5 proxy at `proxy`.
/// The hostname travels to the proxy unresolved (SOCKS5h).
pub(crate) async fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> Result<TcpStream, ConnectError> {
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(ConnectError::Transport(
            "hostname longer than SOCKS5's 255-byte limit".into(),
        ));
    }
    let mut stream = TcpStream::connect(proxy).await.map_err(io_err)?;

    // Greeting: version 5, one auth method, 0x00 = no authentication.
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(io_err)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.map_err(io_err)?;
    if chosen != [0x05, 0x00] {
        return Err(ConnectError::Transport(
            "SOCKS5 proxy refused no-auth method".into(),
        ));
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
    match head[1] {
        0x00 => {}
        // network unreachable / host unreachable / connection refused: the
        // peer cannot be reached — the consumer's cue to try later.
        0x03..=0x05 => return Err(ConnectError::Unreachable),
        code => {
            return Err(ConnectError::Transport(
                format!("SOCKS5 CONNECT failed with reply code {code}").into(),
            ));
        }
    }
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

    #[tokio::test]
    async fn connect_success_yields_the_tunnel_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, "abcdefghijklmnop.onion", 9735, 0x00));
        let mut stream = connect(proxy, "abcdefghijklmnop.onion", 9735)
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
        let err = connect(proxy, "dead.onion", 1).await;
        assert!(matches!(err, Err(ConnectError::Unreachable)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn general_failure_maps_to_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, "sad.onion", 1, 0x01));
        let err = connect(proxy, "sad.onion", 1).await;
        assert!(matches!(err, Err(ConnectError::Transport(_))));
        server.await.unwrap();
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
        let err = connect(proxy, &host, 1)
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
                    let mut stream = connect(proxy, &host, port).await.unwrap();
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
        let err = connect(proxy, "wrongver.onion", 1).await;
        assert!(matches!(err, Err(ConnectError::Transport(_))));
        server.await.unwrap();
    }
}
