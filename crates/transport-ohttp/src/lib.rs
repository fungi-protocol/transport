//! P2P channels over the append-only mailbox.
//!
//! Construction is out of band: both peers need mailbox IDs, distinct HPKE
//! keys, and a fresh shared [`LinkSecret`] for each channel generation. The
//! secret authenticates the link, not a public sender identity. Mailbox reads
//! are non-destructive; unrelated entries are skipped and accepted messages
//! retain their exact bytes. No ordering, deduplication, durable cursor, or
//! peer-close detection is promised. Reopening requires fresh link material;
//! do not reuse a previous generation's secret with session binding.
//!
//! This backend implements [`Channel`] and [`SplitChannel`]. HPKE hides
//! payloads from the gateway, while OHTTP splits network metadata between relay
//! and gateway. Their non-collusion and traffic-analysis limitations still
//! apply; a stable mailbox is visible to the gateway.
//!
//! ```no_run
//! use std::time::Duration;
//! use fungi_transport::{BoxError, Channel};
//! use fungi_transport_ohttp::{MailboxConfig, OhttpChannel, RelayClient};
//!
//! async fn exchange(config: MailboxConfig) -> Result<Vec<u8>, BoxError> {
//!     let http = RelayClient::new(Duration::from_secs(45))?;
//!     let mut channel = OhttpChannel::new(config, http)?;
//!     channel.send(b"hello").await?;
//!     Ok(channel.recv().await?)
//! }
//! ```

#![forbid(unsafe_code)]

mod envelope;
mod http;

#[cfg(test)]
#[path = "../tests/mod.rs"]
mod tests;

use std::{collections::VecDeque, fmt, time::Duration};

use fungi_transport::{BoxError, Channel, RecvError, SendError, SplitChannel};
use payjoin::append_mailbox;
use payjoin::directory::{MAX_FRAMES_PER_RESPONSE, PADDED_MESSAGE_BYTES};
use rand::RngCore;
use tokio::{sync::watch, time::Instant};

pub use http::{HttpClient, RelayClient};
pub use payjoin::{HpkeKeyPair, HpkePublicKey, OhttpKeys, Url, directory::ShortId};

/// Maximum opaque message size in one frame, after HPKE and our envelope.
/// The pinned PoC uses 64-byte EllSwift, 33-byte reply key and 16-byte AEAD tag.
pub const MAX_MESSAGE_SIZE: usize = PADDED_MESSAGE_BYTES - 64 - 33 - 16 - envelope::OVERHEAD;

/// A per-link, per-generation shared authentication secret.
/// Exchange confidentially out of band with exactly one peer. Never reuse for
/// a newly bound channel, even if mailbox IDs and HPKE keys remain the same.
#[derive(Clone)]
pub struct LinkSecret([u8; 32]);

impl LinkSecret {
    /// Generate fresh link material using the operating system RNG.
    pub fn generate() -> Self {
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Import a uniformly random secret exchanged confidentially out of band.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Export for confidential out-of-band exchange with the other endpoint.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkSecret([REDACTED])")
    }
}

/// Explicit configuration of one endpoint of a mailbox link.
/// Peers swap `incoming`/`outgoing` IDs and their local/peer HPKE keys, sharing
/// the same fresh link secret. The two IDs may also name one shared mailbox.
pub struct MailboxConfig {
    /// Directory base URL, without query or fragment and with a trailing slash.
    pub directory: Url,
    /// OHTTP relay origin URL (root path). The PoC appends the directory authority.
    pub relay: Url,
    /// Gateway public key configuration obtained through trusted provisioning.
    pub ohttp_keys: OhttpKeys,
    /// Mailbox scanned by this endpoint, starting at frame zero.
    pub incoming: ShortId,
    /// Mailbox to which this endpoint appends messages for its peer.
    pub outgoing: ShortId,
    /// Local recipient keypair, unique to this link where possible.
    pub local_keys: HpkeKeyPair,
    /// The other endpoint's distinct recipient public key.
    pub peer_key: HpkePublicKey,
    /// Fresh shared secret that separates this channel from retained history.
    pub link_secret: LinkSecret,
    /// Delay after reaching the current mailbox end, or finding no mailbox.
    pub poll_interval: Duration,
}

impl fmt::Debug for MailboxConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // URLs and mailbox IDs are also deliberately omitted from logs.
        f.debug_struct("MailboxConfig")
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

struct Common<H> {
    config: MailboxConfig,
    http: H,
    dead: watch::Sender<bool>,
}

#[derive(Default)]
struct ReceiveState {
    cursor: usize,
    buffered: VecDeque<Vec<u8>>,
    next_poll: Option<Instant>,
}

/// A single-peer mailbox channel, with bounded page buffering.
pub struct OhttpChannel<H = RelayClient> {
    common: Common<H>,
    receive: ReceiveState,
}

impl<H> fmt::Debug for OhttpChannel<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OhttpChannel")
            .field("dead", &*self.common.dead.borrow())
            .finish_non_exhaustive()
    }
}

impl<H: HttpClient> OhttpChannel<H> {
    /// Construct without network I/O. All reads go through the supplied relay
    /// client. Supply fresh link material on every reconstruction; historical
    /// frames are scanned but cannot authenticate under the new secret.
    pub fn new(config: MailboxConfig, http: H) -> Result<Self, BoxError> {
        let directory = reqwest::Url::parse(config.directory.as_str())?;
        let relay = reqwest::Url::parse(config.relay.as_str())?;
        for url in [&directory, &relay] {
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(
                    "mailbox URLs must be HTTP(S) bases without credentials, query or fragment"
                        .into(),
                );
            }
        }
        if !directory.path().ends_with('/') {
            return Err("directory base URL must end with '/'".into());
        }
        if relay.path() != "/" {
            return Err(
                "relay URL must have a root path; the PoC supplies its routing path".into(),
            );
        }
        if config.local_keys.public_key() == &config.peer_key {
            return Err("the two endpoints must use distinct HPKE keys".into());
        }
        if config.poll_interval.is_zero()
            || Instant::now().checked_add(config.poll_interval).is_none()
        {
            return Err("poll interval must be nonzero and fit the monotonic clock".into());
        }
        Ok(Self {
            common: Common {
                config,
                http,
                dead: watch::channel(false).0,
            },
            receive: ReceiveState::default(),
        })
    }
}

// Dropping an in-flight send kills BOTH directions, including a parked recv.
struct SendGuard<'a> {
    dead: &'a watch::Sender<bool>,
    armed: bool,
}

impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.dead.send_replace(true);
        }
    }
}

impl<H: HttpClient> Common<H> {
    async fn send(&self, msg: &[u8]) -> Result<(), SendError> {
        let mut death = self.dead.subscribe();
        if *death.borrow() {
            return Err(SendError::Closed);
        }
        if msg.len() > MAX_MESSAGE_SIZE {
            return Err(SendError::TooLarge {
                max: MAX_MESSAGE_SIZE,
            });
        }
        let mut guard = SendGuard {
            dead: &self.dead,
            armed: true,
        };
        let operation = async {
            let c = &self.config;
            let body = envelope::encode(msg, &c.link_secret, &c.peer_key);
            let (request, context) = append_mailbox::append_request(
                &c.ohttp_keys,
                &c.directory,
                c.relay.as_str(),
                &c.outgoing,
                &body,
                c.local_keys.public_key(),
                &c.peer_key,
            )
            .map_err(|e| -> BoxError { Box::new(e) })?;
            let response = self.http.post(request).await?;
            append_mailbox::process_append_response(&response, context)
                .map_err(|e| -> BoxError { Box::new(e) })
        };
        let result = tokio::select! {
            biased;
            _ = death.changed() => Err(SendError::Closed),
            result = operation => result.map_err(SendError::Transport),
        };
        guard.armed = result.is_err();
        result
    }

    async fn recv(&self, state: &mut ReceiveState) -> Result<Vec<u8>, RecvError> {
        let mut death = self.dead.subscribe();
        if *death.borrow() {
            return Err(RecvError::Closed);
        }
        let result = tokio::select! {
            biased;
            _ = death.changed() => Err(RecvError::Closed),
            result = self.receive(state) => result.map_err(RecvError::Transport),
        };
        if result.is_err() {
            self.dead.send_replace(true);
        }
        result
    }

    async fn receive(&self, state: &mut ReceiveState) -> Result<Vec<u8>, BoxError> {
        loop {
            if let Some(msg) = state.buffered.pop_front() {
                return Ok(msg);
            }
            if let Some(deadline) = state.next_poll {
                tokio::time::sleep_until(deadline).await;
            }
            let c = &self.config;
            let (request, context) = append_mailbox::read_page_request(
                &c.ohttp_keys,
                &c.directory,
                c.relay.as_str(),
                &c.incoming,
                state.cursor,
                MAX_FRAMES_PER_RESPONSE,
            )?;
            let response = self.http.post(request).await?;
            let page =
                append_mailbox::process_read_page_response(&response, context, &c.local_keys)?;
            // There is no await between consuming a response and committing all
            // its messages and cursor. Cancelling HTTP simply re-reads this page.
            match page {
                Some(page) => {
                    if page.count == 0 && !page.end {
                        return Err("mailbox returned a non-progressing page".into());
                    }
                    state.cursor = page
                        .first
                        .checked_add(page.count)
                        .ok_or("cursor overflow")?;
                    state
                        .buffered
                        .extend(page.messages.into_iter().filter_map(|msg| {
                            envelope::decode(
                                &msg.plaintext,
                                &c.link_secret,
                                c.local_keys.public_key(),
                            )
                        }));
                    state.next_poll = page.end.then(|| Instant::now() + c.poll_interval);
                }
                None => state.next_poll = Some(Instant::now() + c.poll_interval),
            }
            // Bound executor work while scanning pages of unrelated frames.
            if state.buffered.is_empty() {
                tokio::task::yield_now().await;
            }
        }
    }
}

impl<H: HttpClient> Channel for OhttpChannel<H> {
    async fn send(&mut self, msg: &[u8]) -> Result<(), SendError> {
        self.common.send(msg).await
    }
    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        self.common.recv(&mut self.receive).await
    }
}

/// Borrowed sending direction; a fatal error ends both halves.
pub struct OhttpSendHalf<'a, H>(&'a Common<H>);
/// Borrowed receiving direction; cancelling a receive preserves unread data.
pub struct OhttpRecvHalf<'a, H>(&'a Common<H>, &'a mut ReceiveState);

impl<H> fmt::Debug for OhttpSendHalf<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OhttpSendHalf { .. }")
    }
}
impl<H> fmt::Debug for OhttpRecvHalf<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OhttpRecvHalf { .. }")
    }
}
impl<H: HttpClient> fungi_transport::SendHalf for OhttpSendHalf<'_, H> {
    async fn send(&mut self, msg: &[u8]) -> Result<(), SendError> {
        self.0.send(msg).await
    }
}
impl<H: HttpClient> fungi_transport::RecvHalf for OhttpRecvHalf<'_, H> {
    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        self.0.recv(self.1).await
    }
}
impl<H: HttpClient> SplitChannel for OhttpChannel<H> {
    type SendHalf<'a>
        = OhttpSendHalf<'a, H>
    where
        Self: 'a;
    type RecvHalf<'a>
        = OhttpRecvHalf<'a, H>
    where
        Self: 'a;
    fn split(&mut self) -> (Self::SendHalf<'_>, Self::RecvHalf<'_>) {
        (
            OhttpSendHalf(&self.common),
            OhttpRecvHalf(&self.common, &mut self.receive),
        )
    }
}
