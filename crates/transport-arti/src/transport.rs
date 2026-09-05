//! Shared arti bootstrap: one [`TorClient`] per peer, handed to both the
//! connector and listener halves.
//!
//! Bootstrap costs a Tor circuit cold start (~26 round trips, seconds) —
//! never pay it twice. No internal deadlines anywhere in this crate: callers
//! own timeouts (`tokio::time::timeout`); cancelling by drop is safe and
//! discards the attempt.

use std::path::PathBuf;
use std::sync::Arc;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{IsolationToken, TorClient, TorClientConfig};
use fungi_transport::ConnectError;
use fungi_transport::framing::DEFAULT_MAX_MSG_LEN;
use tor_rtcompat::PreferredRuntime;

use crate::error::connect_error;

/// Knobs for the in-process arti backend.
#[derive(Debug, Clone)]
pub struct ArtiConfig {
    /// Directory for arti's persistent state (incl. onion-service keys —
    /// identity persists per nickname; point at a throwaway dir for an
    /// ephemeral identity).
    pub state_dir: PathBuf,
    /// Directory for arti's network-directory cache.
    pub cache_dir: PathBuf,
    /// Maximum framed message size, both directions.
    pub max_msg_len: usize,
}

impl ArtiConfig {
    /// A config with the default message-size limit.
    pub fn new(state_dir: impl Into<PathBuf>, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            cache_dir: cache_dir.into(),
            max_msg_len: DEFAULT_MAX_MSG_LEN,
        }
    }
}

/// Map an [`ArtiConfig`] onto arti's own config type. fs-mistrust (arti's
/// filesystem permission guard, which protects onion-service keys) stays on:
/// the VM path relaxes it out of band by setting
/// `FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS` on the plugin process, so production
/// stays strict by default.
pub(crate) fn tor_config(cfg: &ArtiConfig) -> Result<TorClientConfig, ConnectError> {
    TorClientConfigBuilder::from_directories(&cfg.state_dir, &cfg.cache_dir)
        .build()
        .map_err(|e| ConnectError::Transport(e.into()))
}

/// Like [`tor_config`], but with arti's fs-mistrust guard relaxed on this one
/// config — for tests whose sandbox/CI temp dirs the guard would reject.
/// Relaxing per-config is thread-safe, unlike mutating the global environment.
#[cfg(test)]
pub(crate) fn test_config(cfg: &ArtiConfig) -> TorClientConfig {
    let mut b = TorClientConfigBuilder::from_directories(&cfg.state_dir, &cfg.cache_dir);
    b.storage().permissions().dangerously_trust_everyone();
    b.build().expect("building the test tor config")
}

/// A bootstrapped in-process Tor client, source of both channel halves.
pub struct ArtiTransport {
    pub(crate) client: Arc<TorClient<PreferredRuntime>>,
    pub(crate) max_msg_len: usize,
    /// One token per circuit-isolation group, so repeated `isolated_connector`
    /// calls with the same id reuse a token (and thus a circuit group)
    /// while distinct ids never do. The map is inherent to that guarantee:
    /// an `IsolationToken` is a fresh unique value, not derivable from the
    /// id, so it has to be remembered. It grows one small entry per
    /// distinct group and is never evicted — evicting a live group would
    /// remint a different token and split its circuit group. It therefore stays
    /// bounded only while ids track long-lived isolation groups, not
    /// ephemeral per-dial values.
    isolations: std::sync::Mutex<
        std::collections::HashMap<fungi_transport::CircuitIsolationId, IsolationToken>,
    >,
}

impl std::fmt::Debug for ArtiTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtiTransport")
            .field("max_msg_len", &self.max_msg_len)
            .finish_non_exhaustive()
    }
}

impl ArtiTransport {
    /// Bootstrap onto the Tor network. Expensive (seconds); do it once per
    /// peer and share the result.
    ///
    /// Requires a rustls `CryptoProvider` to be installed as the process
    /// default. rustls normally auto-installs one the first time it's
    /// needed, but auto-install only works when exactly one crypto-provider
    /// feature (`ring` or `aws-lc-rs`) is enabled across the dependency
    /// graph. If a consumer's other dependencies pull in both, rustls
    /// cannot pick one and this function panics with "CryptoProvider not
    /// installed". The fix is to install one explicitly before calling
    /// `bootstrap`, e.g. `rustls::crypto::ring::default_provider().install_default()`
    /// (or the `aws_lc_rs` equivalent).
    pub async fn bootstrap(cfg: ArtiConfig) -> Result<Self, ConnectError> {
        Self::bootstrap_with(tor_config(&cfg)?, cfg.max_msg_len).await
    }

    /// Bootstrap with a caller-built [`TorClientConfig`] (e.g. a private
    /// test network's authorities); `max_msg_len` as in [`ArtiConfig`].
    pub async fn bootstrap_with(
        tor_cfg: TorClientConfig,
        max_msg_len: usize,
    ) -> Result<Self, ConnectError> {
        let client = TorClient::create_bootstrapped(tor_cfg)
            .await
            .map_err(connect_error)?;
        Ok(Self::from_client(client, max_msg_len))
    }

    /// Wrap an existing client (deterministic tests use an unbootstrapped
    /// Manual client here).
    pub(crate) fn from_client(
        client: Arc<TorClient<PreferredRuntime>>,
        max_msg_len: usize,
    ) -> Self {
        Self {
            client,
            max_msg_len,
            isolations: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The isolation token for `isolation`, minting and storing a fresh one the
    /// first time — so every connector in a group shares one token.
    fn isolation_for(&self, isolation: &fungi_transport::CircuitIsolationId) -> IsolationToken {
        // The guard never crosses an await (this whole method is sync).
        *self
            .isolations
            .lock()
            .expect("arti isolation map mutex")
            .entry(*isolation)
            .or_insert_with(IsolationToken::new)
    }

    /// Build a connector from the shared client with the given isolation.
    fn make_connector(&self, isolation: Option<IsolationToken>) -> crate::ArtiConnector {
        crate::ArtiConnector {
            client: self.client.clone(),
            max_msg_len: self.max_msg_len,
            isolation,
        }
    }

    /// The connector half, sharing this transport's client.
    pub fn connector(&self) -> crate::ArtiConnector {
        self.make_connector(None)
    }
}

impl fungi_transport::Transport for ArtiTransport {
    type Addr = fungi_transport::OnionAddr;
    type Connector = crate::ArtiConnector;
    type Listener = crate::ArtiListener;

    fn connector(&self) -> crate::ArtiConnector {
        // Same as the inherent `connector`; that one stays for direct callers.
        self.make_connector(None)
    }

    fn isolated_connector(
        &self,
        isolation: &fungi_transport::CircuitIsolationId,
    ) -> crate::ArtiConnector {
        // Same group -> same token -> shared circuit group; distinct groups ->
        // distinct tokens -> isolated circuits.
        self.make_connector(Some(self.isolation_for(isolation)))
    }

    fn listen(
        &self,
        params: fungi_transport::ListenParams,
    ) -> impl std::future::Future<
        Output = Result<
            (crate::ArtiListener, fungi_transport::OnionAddr),
            fungi_transport::ConnectError,
        >,
    > + Send {
        // arti identity is persistent per nickname; default when unspecified.
        let nickname = params.nickname.unwrap_or_else(|| "fungi".to_string());
        async move {
            let listener = self.listen(&nickname, params.virt_port).await?;
            let addr = listener.onion_addr().clone();
            Ok((listener, addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fungi_transport::framing::DEFAULT_MAX_MSG_LEN;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fungi-arti-{}-{}", name, std::process::id()))
    }

    #[test]
    fn config_defaults_max_msg_len() {
        let cfg = ArtiConfig::new(tmp("s1"), tmp("c1"));
        assert_eq!(cfg.max_msg_len, DEFAULT_MAX_MSG_LEN);
    }

    #[test]
    fn tor_config_builds_from_directories() {
        let cfg = ArtiConfig::new(tmp("s2"), tmp("c2"));
        assert!(tor_config(&cfg).is_ok());
    }

    /// No network: an unbootstrapped Manual client can be constructed, which
    /// is the seam the deterministic connector tests use.
    #[tokio::test]
    async fn unbootstrapped_client_constructs_without_network() {
        use arti_client::{BootstrapBehavior, TorClient};
        use rustls::crypto::ring::default_provider;

        let _ = default_provider().install_default();
        let cfg = ArtiConfig::new(tmp("s3"), tmp("c3"));
        let client = TorClient::builder()
            .config(test_config(&cfg))
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped();
        assert!(client.is_ok());
        let transport = ArtiTransport::from_client(client.unwrap(), cfg.max_msg_len);
        let _ = format!("{transport:?}");
    }

    /// Compile-time contract: ArtiTransport implements the factory trait with the
    /// arti connector/listener and the shared onion address. Compiling is the
    /// assertion.
    #[allow(dead_code)]
    fn arti_is_transport()
    where
        ArtiTransport: fungi_transport::Transport<
                Addr = fungi_transport::OnionAddr,
                Connector = crate::ArtiConnector,
                Listener = crate::ArtiListener,
            > + Send,
    {
    }

    #[test]
    fn transport_contract_holds() {
        // arti_is_transport compiling IS the assertion.
    }

    /// The isolation-id→token map: the default connector has no isolation; an
    /// isolated connector has one; the SAME group reuses its token (shared
    /// circuit group) while DISTINCT groups get distinct tokens
    /// (isolated circuits). No network — only the token wiring is exercised.
    #[tokio::test]
    async fn isolated_connector_maps_groups_to_isolation_tokens() {
        use fungi_transport::{CircuitIsolationId, Transport};
        use rustls::crypto::ring::default_provider;

        let _ = default_provider().install_default();
        let cfg = ArtiConfig::new(tmp("iso-s"), tmp("iso-c"));
        let client = arti_client::TorClient::builder()
            .config(test_config(&cfg))
            .bootstrap_behavior(arti_client::BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();
        let transport = ArtiTransport::from_client(client, cfg.max_msg_len);

        assert_eq!(transport.connector().isolation(), None);

        let (s1, s2) = (
            CircuitIsolationId::generate(),
            CircuitIsolationId::generate(),
        );
        let t1 = transport.isolated_connector(&s1).isolation().unwrap();
        let t2 = transport.isolated_connector(&s2).isolation().unwrap();
        assert_ne!(t1, t2, "distinct groups get distinct tokens");
        assert_eq!(
            transport.isolated_connector(&s1).isolation().unwrap(),
            t1,
            "same group reuses its token"
        );
    }
}
