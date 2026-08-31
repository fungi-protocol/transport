//! Shape-C probe: the same naive gossip against split send/receive halves.
//! Each half is a smaller trait; a link needs no `select!` multiplexing —
//! the receive half and the send half live in separate tasks. The
//! experiment measures what the split buys and what shared-fate questions
//! it opens; see the branch notes.

use std::collections::BTreeSet;
use std::future::Future;

use tokio::sync::mpsc;

use crate::error::{RecvError, SendError};
use crate::mem::MemConfig;

/// The send half of a P2P channel.
pub trait ChannelSender: Send {
    /// Send one opaque message to the peer.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send;
}

/// The receive half of a P2P channel.
pub trait ChannelReceiver: Send {
    /// Wait for and return the next message from the peer.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send;
}

/// Send half of an in-memory pipe end.
#[derive(Debug)]
pub struct MemSendHalf {
    tx: mpsc::Sender<Vec<u8>>,
    max_msg_len: Option<usize>,
}

/// Receive half of an in-memory pipe end.
#[derive(Debug)]
pub struct MemRecvHalf {
    rx: mpsc::Receiver<Vec<u8>>,
}

/// A connected pair of SPLIT ends: `((a_send, a_recv), (b_send, b_recv))`,
/// where whatever A sends B receives and vice versa.
pub fn split_duplex(cfg: MemConfig) -> ((MemSendHalf, MemRecvHalf), (MemSendHalf, MemRecvHalf)) {
    let cap = cfg.capacity.unwrap_or(1).max(1);
    let (tx_ab, rx_ab) = mpsc::channel(cap);
    let (tx_ba, rx_ba) = mpsc::channel(cap);
    let mk_s = |tx| MemSendHalf {
        tx,
        max_msg_len: cfg.max_msg_len,
    };
    (
        (mk_s(tx_ab), MemRecvHalf { rx: rx_ba }),
        (mk_s(tx_ba), MemRecvHalf { rx: rx_ab }),
    )
}

impl ChannelSender for MemSendHalf {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        let msg = match self.max_msg_len {
            Some(max) if msg.len() > max => Err(max),
            _ => Ok(msg.to_vec()),
        };
        async move {
            match msg {
                Ok(msg) => self.tx.send(msg).await.map_err(|_| SendError::Closed),
                Err(max) => Err(SendError::TooLarge { max }),
            }
        }
    }
}

impl ChannelReceiver for MemRecvHalf {
    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        self.rx.recv().await.ok_or(RecvError::Closed)
    }
}

/// The same naive gossip as the shape-A probe, over split halves: one
/// receive task and one send task per link, no `select!`, no multiplexing.
pub async fn gossip_until<S, R>(
    links: Vec<(S, R)>,
    own: Vec<u8>,
    expect: usize,
) -> Result<BTreeSet<Vec<u8>>, String>
where
    S: ChannelSender + 'static,
    R: ChannelReceiver + 'static,
{
    let (to_hub, mut from_links) = mpsc::channel::<(usize, Vec<u8>)>(64);
    let mut link_cmds = Vec::with_capacity(links.len());
    let mut recv_tasks = Vec::with_capacity(links.len());
    let mut send_tasks = Vec::with_capacity(links.len());
    for (i, (mut send_half, mut recv_half)) in links.into_iter().enumerate() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(64);
        link_cmds.push(cmd_tx);
        let to_hub = to_hub.clone();
        recv_tasks.push(tokio::spawn(async move {
            while let Ok(msg) = recv_half.recv().await {
                if to_hub.send((i, msg)).await.is_err() {
                    return;
                }
            }
        }));
        send_tasks.push(tokio::spawn(async move {
            while let Some(msg) = cmd_rx.recv().await {
                if send_half.send(&msg).await.is_err() {
                    return;
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
    // The split makes the cancel-safety asymmetry directly actionable: recv
    // is cancel-safe by the Channel contract, so aborting the receive tasks
    // loses no message. A send future is NOT cancel-safe, so the send tasks
    // are joined instead — dropping the command senders lets each queued
    // forward (including the one that just completed the set) drain first.
    for task in &recv_tasks {
        task.abort();
    }
    drop(link_cmds);
    for task in send_tasks {
        let _ = task.await;
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MemConfig {
        MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        }
    }

    #[tokio::test]
    async fn line_topology_converges() {
        let (a_ab, b_ab) = split_duplex(cfg());
        let (b_bc, c_bc) = split_duplex(cfg());
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

    #[tokio::test]
    async fn triangle_topology_converges() {
        let (a_ab, b_ab) = split_duplex(cfg());
        let (a_ac, c_ac) = split_duplex(cfg());
        let (b_bc, c_bc) = split_duplex(cfg());
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

    // The type-state claim shape A cannot make: a pure relay that provably
    // cannot originate on a link it only receives from — it never holds
    // that link's send half.
    #[tokio::test]
    async fn a_receive_only_relay_is_expressible() {
        let ((mut a_s, _a_r), (b_s_unused, mut b_r)) = split_duplex(cfg());
        let ((mut relay_out_s, _), (_, mut c_r)) = split_duplex(cfg());
        drop(b_s_unused); // the relay provably cannot send back toward A
        let relay = tokio::spawn(async move {
            while let Ok(msg) = b_r.recv().await {
                if relay_out_s.send(&msg).await.is_err() {
                    return;
                }
            }
        });
        a_s.send(b"through").await.unwrap();
        assert_eq!(c_r.recv().await.unwrap(), b"through");
        relay.abort();
    }
}
