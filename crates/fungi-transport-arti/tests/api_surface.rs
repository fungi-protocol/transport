//! Compile-time probe of the arti API surface this crate depends on.
//! No test here touches the network. If arti renames something, this file
//! breaks first — fix it to the real API and reconcile the adapter code.

use arti_client::config::TorClientConfigBuilder;
use arti_client::{BootstrapBehavior, DataStream, TorClient, TorClientConfig};
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::PreferredRuntime;

/// DataStream must satisfy FramedChannel's bounds.
#[allow(dead_code)]
fn framed_accepts_datastream()
where
    DataStream: AsyncRead + AsyncWrite + Send + Unpin,
{
}

/// The client API names used by transport.rs / connector.rs.
#[allow(dead_code)]
async fn client_surface(cfg: TorClientConfig) {
    // Bootstrap-once entry point (transport.rs):
    let _ = TorClient::create_bootstrapped(cfg.clone()).await;
    // Unbootstrapped construction for deterministic tests (transport.rs):
    let client = TorClient::builder()
        .config(cfg)
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .unwrap();
    // Connect signature (connector.rs):
    let _ = client.connect(("example.onion", 1_u16)).await;
}

/// Config construction from directories (transport.rs).
#[allow(dead_code)]
fn config_surface() {
    let _ = TorClientConfigBuilder::from_directories("/tmp/s", "/tmp/c").build();
}

/// Error kinds used by error.rs.
#[allow(dead_code)]
fn error_kind_surface(k: arti_client::ErrorKind) {
    match k {
        arti_client::ErrorKind::OnionServiceNotFound => {}
        arti_client::ErrorKind::OnionServiceNotRunning => {}
        arti_client::ErrorKind::OnionServiceConnectionFailed => {}
        arti_client::ErrorKind::RemoteHostNotFound => {}
        _ => {}
    }
}

/// The onion-service surface used by listener.rs.
#[allow(dead_code)]
async fn service_surface(client: TorClient<PreferredRuntime>) {
    use tor_hsservice::config::OnionServiceConfigBuilder;
    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("fungi-probe".parse().unwrap())
        .build()
        .unwrap();
    // `launch_onion_service` returns `Ok(None)` iff the service is disabled
    // in its config, which is never true for this probe's config:
    let (service, rend_requests) = client.launch_onion_service(svc_cfg).unwrap().unwrap();
    // Rend requests → stream requests (listener.rs):
    let incoming = tor_hsservice::handle_rend_requests(rend_requests);
    fn assert_stream<S: Stream + Send>(_: &S) {}
    assert_stream(&incoming);
    // StreamRequest handling (listener.rs):
    use futures_util::StreamExt;
    futures_util::pin_mut!(incoming);
    if let Some(req) = incoming.next().await {
        use tor_cell::relaycell::msg::Connected;
        use tor_cell::relaycell::msg::{End, EndReason};
        use tor_proto::stream::IncomingStreamRequest;
        match req.request() {
            IncomingStreamRequest::Begin(begin) => {
                let _port: u16 = begin.port();
                let _ = req.accept(Connected::new_empty()).await;
            }
            _ => {
                let _ = req.reject(End::new_with_reason(EndReason::DONE)).await;
            }
        }
    }
    // Onion address exposure (listener.rs):
    let _name = service.onion_address();
}
