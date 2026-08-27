//! Generic integration-driver primitives: drive a [`Channel`]
//! peer through an echo loop or a fixed message sequence. Generic over the
//! trait so the in-memory mock exercises them; real transports reuse them
//! unchanged (the e2e binary, the capnp plugin harness).

use crate::channel::Channel;

/// The dial side's message sequence: distinct sizes incl. empty and multi-KiB.
fn sequence() -> Vec<Vec<u8>> {
    vec![
        b"hello over tor".to_vec(),
        Vec::new(),
        vec![0xAB; 64 * 1024],
        b"last".to_vec(),
    ]
}

/// Echo every message from one accepted channel until the peer departs.
/// The peer closing ends the loop cleanly, whether it surfaces as
/// [`RecvError::Closed`](crate::error::RecvError::Closed) (a graceful EOF, as
/// on a plain TCP/SOCKS stream) or as
/// [`RecvError::Transport`](crate::error::RecvError::Transport): a real Tor
/// onion stream is torn down with an END
/// cell, which the arti backend reports as a transport error (e.g. END reason
/// MISC maps to `io::ErrorKind::Other`) rather than a clean EOF. Either way the
/// peer is gone. Data correctness is the dialer's job ([`dial_sequence`] checks
/// every echo), so the echo server only has to serve one peer until it leaves.
pub async fn echo_one_peer<C: Channel>(mut ch: C) -> Result<(), String> {
    loop {
        match ch.recv().await {
            Ok(msg) => ch.send(&msg).await.map_err(|e| e.to_string())?,
            Err(_) => return Ok(()), // peer went away: end of session
        }
    }
}

/// Send the sequence, assert each echo matches.
pub async fn dial_sequence<C: Channel>(mut ch: C) -> Result<(), String> {
    for (i, msg) in sequence().into_iter().enumerate() {
        ch.send(&msg).await.map_err(|e| format!("send {i}: {e}"))?;
        let back = ch.recv().await.map_err(|e| format!("recv {i}: {e}"))?;
        if back != msg {
            return Err(format!(
                "echo {i} mismatch: {} vs {} bytes",
                back.len(),
                msg.len()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RecvError;
    use crate::mem::{MemConfig, duplex};

    #[tokio::test]
    async fn echo_then_dial_sequence_roundtrips_over_mem() {
        let (a, b) = duplex(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        let echo = tokio::spawn(echo_one_peer(a));
        dial_sequence(b)
            .await
            .expect("sequence should pass against echo");
        echo.await.unwrap().expect("echo side clean");
    }

    #[tokio::test]
    async fn dial_sequence_fails_on_wrong_echo() {
        let (a, b) = duplex(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        // A "broken" peer: receives but answers garbage once, then echoes.
        let broken = tokio::spawn(async move {
            let mut b = b;
            let _ = b.recv().await.unwrap();
            b.send(b"wrong").await.unwrap();
            while let Ok(m) = b.recv().await {
                if b.send(&m).await.is_err() {
                    break;
                }
            }
        });
        assert!(dial_sequence(a).await.is_err());
        broken.abort();
    }

    /// A one-shot test double: `recv` yields one message, then a
    /// `RecvError::Transport` (never `Closed`) — models a peer departing via a
    /// transport-level close (as a real onion stream's END cell does).
    struct OneThenTransportError {
        first: Option<Vec<u8>>,
    }

    impl Channel for OneThenTransportError {
        async fn send(&mut self, _msg: &[u8]) -> Result<(), crate::error::SendError> {
            Ok(())
        }

        async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
            match self.first.take() {
                Some(msg) => Ok(msg),
                None => Err(RecvError::Transport("boom".into())),
            }
        }
    }

    #[tokio::test]
    async fn echo_one_peer_ends_cleanly_when_peer_departs() {
        let ch = OneThenTransportError {
            first: Some(b"hi".to_vec()),
        };
        // A transport-level close after the exchange is the peer departing, not
        // a failure — a real onion stream's END cell arrives this way.
        echo_one_peer(ch)
            .await
            .expect("peer departure is a clean end");
    }
}
