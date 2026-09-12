//! Minimal tor control-port client: authenticate, publish one onion
//! service. The service lives as long as the control connection — dropping
//! it is the cleanup (no DEL_ONION needed).

use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use fungi_transport::ConnectError;

/// How to authenticate on the daemon's control port.
#[derive(Debug, Clone)]
pub enum ControlAuth {
    /// No authentication configured on the daemon.
    Null,
    /// Cookie authentication: send the hex of this file's contents.
    CookieFile(PathBuf),
}

/// A published onion service. `service_id` has no `.onion` suffix. The
/// daemon removes the service when `conn` drops.
pub(crate) struct OnionService {
    pub(crate) service_id: String,
    /// Held for side effects only: the service dies when the connection closes.
    #[allow(dead_code)]
    pub(crate) conn: BufReader<TcpStream>,
}

impl std::fmt::Debug for OnionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionService")
            .field("service_id", &self.service_id)
            .finish_non_exhaustive()
    }
}

fn io_err(e: std::io::Error) -> ConnectError {
    ConnectError::Transport(e.into())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02X}");
    }
    s
}

async fn read_reply_line(conn: &mut BufReader<TcpStream>) -> Result<String, ConnectError> {
    let mut line = String::new();
    let n = conn.read_line(&mut line).await.map_err(io_err)?;
    if n == 0 {
        return Err(ConnectError::Transport(
            "control connection closed by daemon".into(),
        ));
    }
    Ok(line.trim_end().to_owned())
}

/// One classified line of a control-port reply. Per the control-spec reply
/// grammar, `250-<text>` is a continuation line and `250 <text>` is the final
/// line; anything else — a non-250 code, or a bare `250` with no separator — is
/// unexpected, so callers treat it as an error (fail-closed). This is the single
/// place that grammar is parsed; each caller decides what a continuation, or a
/// given final payload, means for its command.
enum ReplyLine<'a> {
    /// A `250-` continuation line, carrying the text after the prefix.
    Continuation(&'a str),
    /// The final `250 ` line, carrying the text after the prefix.
    Final(&'a str),
    /// A non-250 code or otherwise unexpected line. The caller reports the full
    /// line it already holds, so no payload is carried here.
    Other,
}

fn classify_reply_line(line: &str) -> ReplyLine<'_> {
    if let Some(rest) = line.strip_prefix("250-") {
        ReplyLine::Continuation(rest)
    } else if let Some(rest) = line.strip_prefix("250 ") {
        ReplyLine::Final(rest)
    } else {
        // A bare `250` (no separator) is malformed per the control-spec reply
        // grammar; classifying it as Other keeps the isolation check fail-closed.
        ReplyLine::Other
    }
}

/// Expect a single-line `250 OK`-style success reply. A `250-` continuation
/// line here means the reply is multi-line where we expected exactly one —
/// that is a protocol desync, not success, so it errors rather than being
/// mistaken for a `250`-prefixed success.
async fn expect_ok(conn: &mut BufReader<TcpStream>) -> Result<(), ConnectError> {
    let line = read_reply_line(conn).await?;
    match classify_reply_line(&line) {
        ReplyLine::Final(_) => Ok(()),
        ReplyLine::Continuation(rest) => Err(ConnectError::Transport(
            format!(
                "control port desynchronized: expected a single-line reply but got a \
                 continuation line: 250-{rest}"
            )
            .into(),
        )),
        ReplyLine::Other => Err(ConnectError::Transport(
            format!("control port replied: {line}").into(),
        )),
    }
}

/// Open a control connection and authenticate on it.
async fn open_authenticated(
    control: SocketAddr,
    auth: &ControlAuth,
) -> Result<BufReader<TcpStream>, ConnectError> {
    let stream = TcpStream::connect(control).await.map_err(io_err)?;
    let mut conn = BufReader::new(stream);
    let auth_line = match auth {
        ControlAuth::Null => "AUTHENTICATE\r\n".to_owned(),
        ControlAuth::CookieFile(path) => {
            let cookie = tokio::fs::read(path).await.map_err(io_err)?;
            format!("AUTHENTICATE {}\r\n", hex(&cookie))
        }
    };
    conn.get_mut()
        .write_all(auth_line.as_bytes())
        .await
        .map_err(io_err)?;
    expect_ok(&mut conn).await?;
    Ok(conn)
}

/// Verify the daemon separates circuits by SOCKS credential: read its
/// `SocksPort` configuration and error if any line carries the
/// `NoIsolateSOCKSAuth` flag. The flag's absence means the daemon default
/// (`IsolateSOCKSAuth` on) applies, which is what per-group isolation
/// relies on; a daemon with it disabled would collapse all groups onto
/// shared circuits without any observable failure.
pub(crate) async fn verify_isolate_socks_auth(
    control: SocketAddr,
    auth: &ControlAuth,
) -> Result<(), ConnectError> {
    let mut conn = open_authenticated(control, auth).await?;
    conn.get_mut()
        .write_all(b"GETCONF SocksPort\r\n")
        .await
        .map_err(io_err)?;
    // One reply line per configured SocksPort value: `250-` continuations,
    // then a final `250 `-prefixed line. Flags appear inside the value as
    // written in the configuration, so every line is scanned.
    loop {
        let line = read_reply_line(&mut conn).await?;
        let (payload, last) = match classify_reply_line(&line) {
            ReplyLine::Continuation(rest) => (rest, false),
            ReplyLine::Final(rest) => (rest, true),
            ReplyLine::Other => {
                return Err(ConnectError::Transport(
                    format!("GETCONF SocksPort failed: {line}").into(),
                ));
            }
        };
        // Values may arrive as a QuotedString, so quotes are stripped from
        // each token before comparing.
        if payload.split(['=', ' ', '\t']).any(|token| {
            token
                .trim_matches('"')
                .eq_ignore_ascii_case("NoIsolateSOCKSAuth")
        }) {
            return Err(ConnectError::Transport(
                "the daemon's SocksPort sets NoIsolateSOCKSAuth, which disables the \
                 per-credential circuit isolation that per-group isolation relies on; \
                 remove the flag (the daemon default is isolation on)"
                    .into(),
            ));
        }
        if last {
            return Ok(());
        }
    }
}

/// Authenticate and publish an ephemeral v3 onion service forwarding
/// `virt_port` to `127.0.0.1:local_port`.
pub(crate) async fn create_onion(
    control: SocketAddr,
    auth: &ControlAuth,
    virt_port: u16,
    local_port: u16,
) -> Result<OnionService, ConnectError> {
    let mut conn = open_authenticated(control, auth).await?;

    // DiscardPK: the identity is ephemeral by design — a fresh onion
    // address per listener; we never reuse the key.
    let cmd = format!(
        "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={virt_port},127.0.0.1:{local_port}\r\n"
    );
    conn.get_mut()
        .write_all(cmd.as_bytes())
        .await
        .map_err(io_err)?;

    // Per the control-spec reply grammar, `250-` marks a continuation line
    // and `250 ` (space) marks the final line of the reply. Any line other
    // than a `250-` continuation or the final `250 OK` — including another
    // `250 <something>` final line, or a non-250 code — is an error; reading
    // one more line for it would block forever, since the daemon has
    // already sent its whole reply.
    let mut service_id = None;
    loop {
        let line = read_reply_line(&mut conn).await?;
        match classify_reply_line(&line) {
            // The ServiceID continuation carries the onion identity; other
            // continuation lines (e.g. PrivateKey) are ignored.
            ReplyLine::Continuation(rest) => {
                if let Some(id) = rest.strip_prefix("ServiceID=") {
                    service_id = Some(id.to_owned());
                }
            }
            // Only `250 OK` ends the reply; any other final line or non-250
            // code is a failure (reading another line would block forever).
            ReplyLine::Final("OK") => break,
            _ => {
                return Err(ConnectError::Transport(
                    format!("ADD_ONION failed: {line}").into(),
                ));
            }
        }
    }
    let service_id = service_id
        .ok_or_else(|| ConnectError::Transport("ADD_ONION reply carried no ServiceID".into()))?;

    Ok(OnionService { service_id, conn })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// One-connection fake control port. Asserts the AUTHENTICATE line
    /// equals `expect_auth`, then answers ADD_ONION with `service_id`.
    async fn fake_control(listener: TcpListener, expect_auth: String, service_id: &str) {
        let (sock, _) = listener.accept().await.unwrap();
        let mut sock = BufReader::new(sock);
        let mut line = String::new();
        sock.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim_end(), expect_auth);
        sock.get_mut().write_all(b"250 OK\r\n").await.unwrap();
        line.clear();
        sock.read_line(&mut line).await.unwrap();
        let line = line.trim_end();
        assert!(
            line.starts_with("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port="),
            "unexpected command: {line}"
        );
        sock.get_mut()
            .write_all(format!("250-ServiceID={service_id}\r\n250 OK\r\n").as_bytes())
            .await
            .unwrap();
        // Hold the connection open until the client drops it (the service's
        // lifetime is the connection's lifetime).
        let mut rest = String::new();
        let _ = sock.read_line(&mut rest).await;
    }

    /// One-connection fake for the isolation check: null-auth, then answers
    /// `GETCONF SocksPort` with `reply` verbatim.
    async fn fake_control_getconf(listener: TcpListener, reply: &'static str) {
        let (sock, _) = listener.accept().await.unwrap();
        let mut sock = BufReader::new(sock);
        let mut line = String::new();
        sock.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim_end(), "AUTHENTICATE");
        sock.get_mut().write_all(b"250 OK\r\n").await.unwrap();
        line.clear();
        sock.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim_end(), "GETCONF SocksPort");
        sock.get_mut().write_all(reply.as_bytes()).await.unwrap();
    }

    async fn check_against(reply: &'static str) -> Result<(), ConnectError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = listener.local_addr().unwrap();
        tokio::spawn(fake_control_getconf(listener, reply));
        verify_isolate_socks_auth(control, &ControlAuth::Null).await
    }

    #[tokio::test]
    async fn isolation_check_accepts_the_default_config() {
        check_against("250 SocksPort=9050\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn isolation_check_rejects_no_isolate_socks_auth() {
        let err = check_against("250 SocksPort=9050 NoIsolateSOCKSAuth\r\n")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("NoIsolateSOCKSAuth"),
            "the error must name the offending flag, got: {err}"
        );
    }

    /// Every configured SocksPort line is scanned, not only the first.
    #[tokio::test]
    async fn isolation_check_scans_every_config_line() {
        check_against("250-SocksPort=9050\r\n250 SocksPort=9051 NoIsolateSOCKSAuth\r\n")
            .await
            .unwrap_err();
    }

    /// The daemon accepts its option names in any case, so the check must too.
    #[tokio::test]
    async fn isolation_check_is_case_insensitive() {
        check_against("250 SocksPort=9050 noisolatesocksauth\r\n")
            .await
            .unwrap_err();
    }

    /// The reply value may arrive as a QuotedString; the flag is still found.
    #[tokio::test]
    async fn isolation_check_sees_through_quoted_values() {
        check_against("250 SocksPort=\"9050 NoIsolateSOCKSAuth\"\r\n")
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn isolation_check_surfaces_daemon_errors() {
        let err = check_against("552 Unrecognized configuration key\r\n")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("552"), "got: {err}");
    }

    #[tokio::test]
    async fn null_auth_creates_onion() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = listener.local_addr().unwrap();
        tokio::spawn(fake_control(
            listener,
            "AUTHENTICATE".into(),
            "fungi000service0id",
        ));
        let svc = create_onion(control, &ControlAuth::Null, 9735, 40001)
            .await
            .unwrap();
        assert_eq!(svc.service_id, "fungi000service0id");
    }

    #[tokio::test]
    async fn cookie_auth_sends_hex_of_cookie_file() {
        let cookie_path =
            std::env::temp_dir().join(format!("fungi-test-cookie-{}", std::process::id()));
        std::fs::write(&cookie_path, [0xde, 0xad, 0xbe, 0xef]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = listener.local_addr().unwrap();
        tokio::spawn(fake_control(
            listener,
            "AUTHENTICATE DEADBEEF".into(),
            "cookieauthedid",
        ));
        let svc = create_onion(control, &ControlAuth::CookieFile(cookie_path.clone()), 1, 2)
            .await
            .unwrap();
        assert_eq!(svc.service_id, "cookieauthedid");
        std::fs::remove_file(cookie_path).ok();
    }

    #[tokio::test]
    async fn error_reply_maps_to_transport_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = BufReader::new(sock);
            let mut line = String::new();
            sock.read_line(&mut line).await.unwrap();
            sock.get_mut()
                .write_all(b"515 Authentication failed\r\n")
                .await
                .unwrap();
        });
        let err = create_onion(control, &ControlAuth::Null, 1, 2).await;
        assert!(matches!(
            err,
            Err(fungi_transport::ConnectError::Transport(_))
        ));
    }

    /// A `250-` continuation followed by a final line that isn't `250 OK`
    /// (e.g. `250 DONE`) must error immediately, not hang waiting for a
    /// line the daemon will never send. Regression test for the reply-loop
    /// hang: `Err` within the timeout, not a wedged read.
    #[tokio::test]
    async fn non_ok_final_line_errors_instead_of_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = BufReader::new(sock);
            let mut line = String::new();
            sock.read_line(&mut line).await.unwrap(); // AUTHENTICATE
            sock.get_mut().write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            sock.read_line(&mut line).await.unwrap(); // ADD_ONION
            sock.get_mut()
                .write_all(b"250-ServiceID=x\r\n250 DONE\r\n")
                .await
                .unwrap();
            // Hold the connection open; if the client is hung reading, this
            // keeps the test from succeeding by accident on EOF.
            let mut rest = String::new();
            let _ = sock.read_line(&mut rest).await;
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            create_onion(control, &ControlAuth::Null, 1, 2),
        )
        .await
        .expect("create_onion hung instead of returning an error");
        assert!(matches!(result, Err(ConnectError::Transport(_))));
    }
}
