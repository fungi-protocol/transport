//! A [`Transport`] that defers arti's bootstrap to first use.
//!
//! The capnp plugin exposes a transport *and* a test-fixtures capability. arti's
//! directory authorities must be fixed before its single bootstrap, so the
//! plugin cannot bootstrap eagerly: the harness first drives
//! `configurePrivateNet` (which lands on [`LazyArtiTransport::configure_private_net`]),
//! then the first transport operation triggers the one bootstrap with whatever
//! network was configured. In production (no such call) the first
//! `connector`/`listen` simply bootstraps onto the public network.
//!
//! This module holds no capnp: the plugin binary wraps [`LazyArtiTransport`] in
//! a `PluginFixtures` that forwards to [`LazyArtiTransport::configure_private_net`],
//! keeping the library free of the plugin layer.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fungi_transport::{ConnectError, Connector, ListenParams, OnionAddr, SessionId, Transport};
use tokio::sync::OnceCell;

use crate::{ArtiConfig, ArtiConnector, ArtiListener, ArtiTransport, PrivateNet};

/// The private-network descriptor to apply at bootstrap, plus a latch that
/// closes once a bootstrap has begun. Both live under one lock so the
/// "reject a late configure" check and the "read the descriptor" step cannot
/// interleave: once `get` latches `reserved`, a racing `configure_private_net`
/// is refused instead of setting a descriptor the one bootstrap already read
/// past and would silently ignore.
#[derive(Default)]
struct Pending {
    /// The descriptor to apply, or `None` to bootstrap onto the public network.
    net: Option<String>,
    /// Set when a bootstrap has begun; `configure_private_net` then fails.
    reserved: bool,
}

/// Boot state shared by the lazy transport, its connectors, and the fixtures.
struct LazyInner {
    /// The bootstrapped transport, built at most once on first use.
    booted: OnceCell<ArtiTransport>,
    /// The pending private-network descriptor and its bootstrap latch, set
    /// through [`LazyArtiTransport::configure_private_net`].
    pending: Mutex<Pending>,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    max_msg_len: usize,
}

impl LazyInner {
    /// Bootstrap once (public or private, per `pending`) and return the client.
    async fn get(&self) -> Result<&ArtiTransport, ConnectError> {
        self.booted
            .get_or_try_init(|| async {
                // Latch the bootstrap and read the descriptor under one lock,
                // then drop the guard before any await: it never crosses a
                // suspension point, so this future stays `Send`. Cloning (not
                // taking) the descriptor keeps it for a retry if bootstrap
                // fails and this closure runs again.
                let pending = {
                    let mut p = self.pending.lock().expect("arti lazy pending mutex");
                    p.reserved = true;
                    p.net.clone()
                };
                match pending {
                    Some(text) => {
                        let cfg = PrivateNet::parse(&text)
                            .map_err(|e| ConnectError::Transport(e.into()))?
                            .build_config(&self.state_dir, &self.cache_dir)
                            .map_err(|e| ConnectError::Transport(e.into()))?;
                        ArtiTransport::bootstrap_with(cfg, self.max_msg_len).await
                    }
                    None => {
                        ArtiTransport::bootstrap(ArtiConfig {
                            state_dir: self.state_dir.clone(),
                            cache_dir: self.cache_dir.clone(),
                            max_msg_len: self.max_msg_len,
                        })
                        .await
                    }
                }
            })
            .await
    }
}

/// An arti [`Transport`] whose bootstrap is deferred to first use, so a private
/// test network can be installed through [`configure_private_net`] beforehand.
///
/// [`configure_private_net`]: LazyArtiTransport::configure_private_net
#[derive(Clone)]
pub struct LazyArtiTransport {
    inner: Arc<LazyInner>,
}

impl std::fmt::Debug for LazyArtiTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyArtiTransport").finish_non_exhaustive()
    }
}

impl LazyArtiTransport {
    /// A lazy transport storing arti state/cache under the given directories.
    pub fn new(state_dir: PathBuf, cache_dir: PathBuf, max_msg_len: usize) -> Self {
        Self {
            inner: Arc::new(LazyInner {
                booted: OnceCell::new(),
                pending: Mutex::new(Pending::default()),
                state_dir,
                cache_dir,
                max_msg_len,
            }),
        }
    }

    /// Install a private-network descriptor to apply before the one bootstrap.
    /// Must precede the first `connector`/`listen`; errors if the descriptor is
    /// invalid or if a bootstrap has already begun. The latch is set at
    /// bootstrap START, not success, so the descriptor cannot be swapped in
    /// after a failed bootstrap either — the first bootstrap commits the
    /// network. This is the seam the plugin's `TestFixtures.configurePrivateNet`
    /// drives.
    pub fn configure_private_net(&self, net_file: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(net_file)
            .map_err(|e| format!("private-net descriptor is not UTF-8: {e}"))?
            .to_owned();
        // Validate eagerly so a bad descriptor fails the fixture call, not the
        // later bootstrap.
        PrivateNet::parse(&text)?;
        // Reject under the same lock the bootstrap latches: if a bootstrap has
        // already begun, this descriptor would be ignored, so fail instead of
        // silently accepting it.
        let mut pending = self.inner.pending.lock().expect("arti lazy pending mutex");
        if pending.reserved {
            return Err("configure_private_net called after arti bootstrapped".into());
        }
        pending.net = Some(text);
        Ok(())
    }
}

impl Transport for LazyArtiTransport {
    type Addr = OnionAddr;
    type Connector = LazyArtiConnector;
    type Listener = ArtiListener;

    fn connector(&self) -> LazyArtiConnector {
        LazyArtiConnector {
            inner: self.inner.clone(),
            session: None,
        }
    }

    fn connector_for(&self, session: &SessionId) -> LazyArtiConnector {
        LazyArtiConnector {
            inner: self.inner.clone(),
            session: Some(*session),
        }
    }

    fn listen(
        &self,
        params: ListenParams,
    ) -> impl Future<Output = Result<(ArtiListener, OnionAddr), ConnectError>> + Send {
        let inner = self.inner.clone();
        // Call the trait `listen`, not arti's inherent `listen(&str, u16)`.
        async move { <ArtiTransport as Transport>::listen(inner.get().await?, params).await }
    }
}

/// The connector half of [`LazyArtiTransport`]: bootstraps on its first
/// `connect`, then delegates to the real [`ArtiConnector`].
#[derive(Clone)]
pub struct LazyArtiConnector {
    inner: Arc<LazyInner>,
    /// Session this connector is bound to; `None` dials on the shared default.
    /// The session's isolation token lives on the bootstrapped transport, so
    /// it can only be resolved after the one bootstrap, inside `connect`.
    session: Option<SessionId>,
}

impl std::fmt::Debug for LazyArtiConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyArtiConnector").finish_non_exhaustive()
    }
}

impl Connector for LazyArtiConnector {
    type Addr = OnionAddr;
    type Channel = <ArtiConnector as Connector>::Channel;

    fn connect(
        &self,
        addr: &OnionAddr,
    ) -> impl Future<Output = Result<Self::Channel, ConnectError>> + Send {
        let inner = self.inner.clone();
        let addr = addr.clone();
        let session = self.session;
        async move {
            let transport = inner.get().await?;
            let connector = match &session {
                Some(session) => transport.connector_for(session),
                None => transport.connector(),
            };
            connector.connect(&addr).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lazy() -> LazyArtiTransport {
        let base = std::env::temp_dir().join(format!("fungi-arti-lazy-{}", std::process::id()));
        LazyArtiTransport::new(base.join("state"), base.join("cache"), 64 * 1024)
    }

    /// A valid descriptor (an authority and a fallback) is accepted and stored;
    /// no bootstrap and no network are involved.
    #[test]
    fn configure_private_net_accepts_a_valid_descriptor() {
        let t = lazy();
        let net = "authority testda 27102BC123E7AF1D4741AE047E160C91ADC76B21\n\
                   fallback 27102BC123E7AF1D4741AE047E160C91ADC76B21 \
                   xGYRXQ2b1SDpLoNjKilDNzrqAX2XCEBEyYlVmIGSjTo 192.168.1.11:9001\n";
        assert!(t.configure_private_net(net.as_bytes()).is_ok());
        assert!(t.inner.pending.lock().unwrap().net.is_some());
    }

    /// Once a bootstrap has begun (which `get` latches before it awaits), a
    /// late `configure_private_net` is refused rather than silently setting a
    /// descriptor the one bootstrap has already read past.
    #[test]
    fn configure_after_bootstrap_latch_is_rejected() {
        let t = lazy();
        t.inner.pending.lock().unwrap().reserved = true;
        let net = "authority testda 27102BC123E7AF1D4741AE047E160C91ADC76B21\n\
                   fallback 27102BC123E7AF1D4741AE047E160C91ADC76B21 \
                   xGYRXQ2b1SDpLoNjKilDNzrqAX2XCEBEyYlVmIGSjTo 192.168.1.11:9001\n";
        assert!(t.configure_private_net(net.as_bytes()).is_err());
    }

    /// A non-UTF-8 descriptor is rejected at the fixture call, not deferred.
    #[test]
    fn configure_private_net_rejects_non_utf8() {
        let t = lazy();
        assert!(t.configure_private_net(&[0xff, 0xfe]).is_err());
    }

    /// A malformed descriptor is rejected eagerly by parsing.
    #[test]
    fn configure_private_net_rejects_a_malformed_descriptor() {
        let t = lazy();
        assert!(t.configure_private_net(b"not a valid line").is_err());
    }

    /// The session→connector plumbing: the default connector is unbound,
    /// session-bound connectors carry their session, and distinct sessions
    /// stay distinct. Resolving the session to an isolation token is the
    /// bootstrapped transport's job, pinned by its own tests; no bootstrap
    /// and no network are involved here.
    #[test]
    fn connector_for_carries_the_session() {
        let t = lazy();
        let (s1, s2) = (SessionId::generate(), SessionId::generate());
        assert_eq!(t.connector().session, None);
        assert_eq!(t.connector_for(&s1).session, Some(s1));
        assert_ne!(t.connector_for(&s1).session, t.connector_for(&s2).session);
    }

    fn assert_send<T: Send>(_: T) {}

    /// The lazy transport and its connector are `Send`, and their factory
    /// futures are `Send` — the trait contract the plugin server relies on.
    #[test]
    fn lazy_transport_is_send() {
        let t = lazy();
        assert_send(&t);
        assert_send(t.connector());
        assert_send(t.listen(ListenParams::new(1)));
        let c = t.connector_for(&SessionId::generate());
        assert_send(c.connect(&OnionAddr::new(format!("{:a<56}.onion", "x"), 1).unwrap()));
    }
}
