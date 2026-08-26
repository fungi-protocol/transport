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

use fungi_transport::{ConnectError, Connector, ListenParams, OnionAddr, Transport};
use tokio::sync::OnceCell;

use crate::{ArtiConfig, ArtiConnector, ArtiListener, ArtiTransport, PrivateNet};

/// Boot state shared by the lazy transport, its connectors, and the fixtures.
struct LazyInner {
    /// The bootstrapped transport, built at most once on first use.
    booted: OnceCell<ArtiTransport>,
    /// A private-network descriptor to apply before bootstrap, set through
    /// [`LazyArtiTransport::configure_private_net`]. `None` bootstraps onto the
    /// public network.
    pending: Mutex<Option<String>>,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    max_msg_len: usize,
}

impl LazyInner {
    /// Bootstrap once (public or private, per `pending`) and return the client.
    async fn get(&self) -> Result<&ArtiTransport, ConnectError> {
        self.booted
            .get_or_try_init(|| async {
                // Brief lock, cloned out before any await: the guard never
                // crosses a suspension point, so this future stays `Send`.
                let pending = self.pending.lock().unwrap().clone();
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
                pending: Mutex::new(None),
                state_dir,
                cache_dir,
                max_msg_len,
            }),
        }
    }

    /// Install a private-network descriptor to apply before the one bootstrap.
    /// Must precede the first `connector`/`listen`; errors if arti has already
    /// booted or the descriptor is invalid. This is the seam the plugin's
    /// `TestFixtures.configurePrivateNet` drives.
    pub fn configure_private_net(&self, net_file: &[u8]) -> Result<(), String> {
        if self.inner.booted.initialized() {
            return Err("configure_private_net called after arti bootstrapped".into());
        }
        let text = std::str::from_utf8(net_file)
            .map_err(|e| format!("private-net descriptor is not UTF-8: {e}"))?
            .to_owned();
        // Validate eagerly so a bad descriptor fails the fixture call, not the
        // later bootstrap.
        PrivateNet::parse(&text)?;
        *self.inner.pending.lock().unwrap() = Some(text);
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
        async move { inner.get().await?.connector().connect(&addr).await }
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
        let net = "authority testda AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                   fallback RSAHEX EDBASE64 192.168.1.11:9001\n";
        assert!(t.configure_private_net(net.as_bytes()).is_ok());
        assert!(t.inner.pending.lock().unwrap().is_some());
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

    fn assert_send<T: Send>(_: T) {}

    /// The lazy transport and its connector are `Send`, and their factory
    /// futures are `Send` — the trait contract the plugin server relies on.
    #[test]
    fn lazy_transport_is_send() {
        let t = lazy();
        assert_send(&t);
        assert_send(t.connector());
        assert_send(t.listen(ListenParams::new(1)));
        let c = t.connector();
        assert_send(c.connect(&OnionAddr::new(format!("{:a<56}.onion", "x"), 1).unwrap()));
    }
}
