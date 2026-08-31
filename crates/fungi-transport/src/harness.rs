//! Generic integration-driver primitives: drive a [`Channel`]
//! peer through an echo loop or a fixed message sequence. Generic over the
//! trait so the in-memory mock exercises them; real transports reuse them
//! unchanged (the e2e binary, the capnp plugin harness).

use std::collections::BTreeSet;

use tokio::sync::mpsc;

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

/// Naive gossip over a fixed set of P2P channels: send `own`, forward every
/// first-seen message on the other channels, and return once `expect`
/// distinct messages (own included) are held. The channels must form a
/// connected graph over the participants or convergence never happens —
/// wiring the graph is the caller's job. Termination is by count alone;
/// callers own any wall-clock bound. Every participant must be called with
/// the same `expect` — the total number of distinct messages across the
/// whole graph, not just what one node sees directly — or a mismatched
/// participant can wait forever for a count that never arrives.
pub async fn gossip_until<C: Channel + 'static>(
    channels: Vec<C>,
    own: Vec<u8>,
    expect: usize,
) -> Result<BTreeSet<Vec<u8>>, String> {
    let (to_hub, mut from_links) = mpsc::channel::<(usize, Vec<u8>)>(64);
    let mut link_cmds = Vec::with_capacity(channels.len());
    let mut links = Vec::with_capacity(channels.len());
    for (i, mut ch) in channels.into_iter().enumerate() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(64);
        link_cmds.push(cmd_tx);
        let to_hub = to_hub.clone();
        links.push(tokio::spawn(async move {
            // The select! resolves to a plain value first, so both branch
            // futures are dropped before the channel is used again.
            enum Event {
                Forward(Option<Vec<u8>>),
                In(Result<Vec<u8>, crate::error::RecvError>),
            }
            loop {
                let event = tokio::select! {
                    cmd = cmd_rx.recv() => Event::Forward(cmd),
                    // Cancel-safe by the Channel contract, so losing the
                    // race to the cmd arm drops no message.
                    got = ch.recv() => Event::In(got),
                };
                match event {
                    Event::Forward(Some(msg)) => {
                        if ch.send(&msg).await.is_err() {
                            return;
                        }
                    }
                    Event::Forward(None) => return,
                    Event::In(Ok(msg)) => {
                        if to_hub.send((i, msg)).await.is_err() {
                            // The hub already moved on to draining (see
                            // below); anything still queued in cmd_rx is a
                            // forward this link owes its peer, so deliver it
                            // before exiting rather than dropping it.
                            while let Some(msg) = cmd_rx.recv().await {
                                if ch.send(&msg).await.is_err() {
                                    break;
                                }
                            }
                            return;
                        }
                    }
                    Event::In(Err(_)) => return,
                }
            }
        }));
    }
    drop(to_hub);

    let mut set = BTreeSet::new();
    set.insert(own.clone());
    for cmd in &link_cmds {
        let _ = cmd.send(own.clone()).await;
    }
    while set.len() < expect {
        let Some((from, msg)) = from_links.recv().await else {
            return Err(format!(
                "links closed holding {}/{expect} messages",
                set.len()
            ));
        };
        if set.insert(msg.clone()) {
            for (j, cmd) in link_cmds.iter().enumerate() {
                if j != from {
                    let _ = cmd.send(msg.clone()).await;
                }
            }
        }
    }
    // Everything a node owes its peers was queued at insert time. Dropping
    // from_links unblocks a link task mid-send to the hub, but that task
    // then drains its own cmd_rx before returning (see the In(Ok) arm
    // above), so nothing queued there is lost. Aborting could kill an
    // in-flight forward a peer still needs, and cancelling a send violates
    // the channel's cancel-safety contract.
    drop(from_links); // unblocks any link task mid-send to the hub
    drop(link_cmds); // each cmd_rx.recv() now yields None, ending the loop
    for link in links {
        let _ = link.await;
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RecvError;
    use crate::mem::{MemConfig, duplex};

    fn gossip_cfg() -> MemConfig {
        MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        }
    }

    // Line topology A—B—C: A's message reaches C only if B forwards it —
    // the case plain multicast cannot serve.
    #[tokio::test]
    async fn line_topology_converges() {
        let (a_ab, b_ab) = duplex(gossip_cfg());
        let (b_bc, c_bc) = duplex(gossip_cfg());
        let (ra, rb, rc) = tokio::join!(
            gossip_until(vec![a_ab], b"from-a".to_vec(), 3),
            gossip_until(vec![b_ab, b_bc], b"from-b".to_vec(), 3),
            gossip_until(vec![c_bc], b"from-c".to_vec(), 3),
        );
        let expected: BTreeSet<Vec<u8>> =
            [b"from-a".to_vec(), b"from-b".to_vec(), b"from-c".to_vec()].into();
        assert_eq!(ra.unwrap(), expected);
        assert_eq!(rb.unwrap(), expected);
        assert_eq!(rc.unwrap(), expected);
    }

    // Triangle: duplicates arrive and are forwarded only on first sight.
    #[tokio::test]
    async fn triangle_topology_converges() {
        let (a_ab, b_ab) = duplex(gossip_cfg());
        let (a_ac, c_ac) = duplex(gossip_cfg());
        let (b_bc, c_bc) = duplex(gossip_cfg());
        let (ra, rb, rc) = tokio::join!(
            gossip_until(vec![a_ab, a_ac], b"from-a".to_vec(), 3),
            gossip_until(vec![b_ab, b_bc], b"from-b".to_vec(), 3),
            gossip_until(vec![c_ac, c_bc], b"from-c".to_vec(), 3),
        );
        let expected: BTreeSet<Vec<u8>> =
            [b"from-a".to_vec(), b"from-b".to_vec(), b"from-c".to_vec()].into();
        assert_eq!(ra.unwrap(), expected);
        assert_eq!(rb.unwrap(), expected);
        assert_eq!(rc.unwrap(), expected);
    }

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
