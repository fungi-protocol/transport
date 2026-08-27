//! The [`Connector`] half: open framed channels to peer onion services.

use std::future::Future;

use arti_client::{DataStream, IsolationToken, StreamPrefs, TorClient};
use fungi_transport::framed::FramedChannel;
use fungi_transport::{ConnectError, Connector, OnionAddr};
use tor_rtcompat::PreferredRuntime;

use crate::error::connect_error;

/// Opens channels to `.onion` peers through the in-process Tor client.
/// Obtained from [`crate::ArtiTransport::connector`].
#[derive(Clone)]
pub struct ArtiConnector {
    pub(crate) client: std::sync::Arc<TorClient<PreferredRuntime>>,
    pub(crate) max_msg_len: usize,
    /// Isolation token for this session; `None` shares the client's default
    /// circuits. All connectors of one session hold the SAME token, so their
    /// streams may share a circuit while other sessions' cannot.
    pub(crate) isolation: Option<IsolationToken>,
}

impl std::fmt::Debug for ArtiConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtiConnector")
            .field("max_msg_len", &self.max_msg_len)
            .finish_non_exhaustive()
    }
}

impl ArtiConnector {
    #[cfg(test)]
    pub(crate) fn isolation(&self) -> Option<IsolationToken> {
        self.isolation
    }
}

impl Connector for ArtiConnector {
    type Addr = OnionAddr;
    type Channel = FramedChannel<DataStream>;

    fn connect(
        &self,
        addr: &OnionAddr,
    ) -> impl Future<Output = Result<Self::Channel, ConnectError>> + Send {
        let client = self.client.clone();
        let max = self.max_msg_len;
        let host = addr.host().to_owned();
        let port = addr.port();
        let isolation = self.isolation;
        async move {
            let mut prefs = StreamPrefs::new();
            if let Some(token) = isolation {
                prefs.set_isolation(token);
            }
            let stream = client
                .connect_with_prefs((host.as_str(), port), &prefs)
                .await
                .map_err(connect_error)?;
            Ok(FramedChannel::new(stream, max))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ArtiConfig, ArtiTransport, test_config};
    use arti_client::BootstrapBehavior;

    fn unbootstrapped() -> ArtiTransport {
        use rustls::crypto::ring::default_provider;
        let _ = default_provider().install_default();
        let base = std::env::temp_dir().join(format!("fungi-arti-conn-{}", std::process::id()));
        let cfg = ArtiConfig::new(base.join("state"), base.join("cache"));
        let client = TorClient::builder()
            .config(test_config(&cfg))
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();
        ArtiTransport::from_client(client, cfg.max_msg_len)
    }

    fn assert_send<T: Send>(_: T) {}

    /// The Connector impl exists, its future is Send, and connecting on an
    /// unbootstrapped Manual client fails deterministically — no network.
    #[tokio::test]
    async fn connect_on_unbootstrapped_client_errors_deterministically() {
        let connector = unbootstrapped().connector();
        let addr =
            fungi_transport::OnionAddr::new(format!("{:a<56}.onion", "nonexistent"), 1).unwrap();
        let fut = connector.connect(&addr);
        assert_send(fut);
        assert!(connector.connect(&addr).await.is_err());
    }
}
