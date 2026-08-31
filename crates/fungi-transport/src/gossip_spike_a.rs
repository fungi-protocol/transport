//! Shape-A probe: naive gossip written against the unified `Channel` trait
//! (one object, send + recv behind `&mut self`). The experiment measures
//! what this shape costs the consumer; see the branch notes.

use std::collections::BTreeSet;

use tokio::sync::mpsc;

use crate::channel::Channel;

/// Run naive gossip over the given P2P channels until `expect` distinct
/// messages (own included) are held, then return the converged set.
///
/// Shape-A cost on display: `send` and `recv` share `&mut self`, so each
/// channel needs a wrapper task multiplexing "forward a message out" against
/// "receive from the peer" with `select!`; a hub task owns the message set.
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
            // futures are dropped before the channel is used again — the
            // shape's send/recv multiplexing cannot touch `ch` inside a
            // handler while the recv future still borrows it.
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
    // Join, not abort: aborting a task can cancel a send future in flight,
    // and a cancelled send may or may not have transmitted — exactly the
    // message that just completed the set. Dropping the command senders
    // instead lets each link drain its already-queued forwards (including
    // that last one) before its task returns on its own.
    drop(link_cmds);
    for link in links {
        let _ = link.await;
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::{MemConfig, duplex};

    fn cfg() -> MemConfig {
        MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        }
    }

    // Line topology A—B—C: A's message reaches C only if B forwards it.
    // This is exactly the case plain multicast cannot serve.
    #[tokio::test]
    async fn line_topology_converges() {
        let (a_ab, b_ab) = duplex(cfg());
        let (b_bc, c_bc) = duplex(cfg());
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

    // Triangle: every pair connected; duplicates arrive and must be
    // forwarded only on first sight, or the nodes never terminate.
    #[tokio::test]
    async fn triangle_topology_converges() {
        let (a_ab, b_ab) = duplex(cfg());
        let (a_ac, c_ac) = duplex(cfg());
        let (b_bc, c_bc) = duplex(cfg());
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
}
