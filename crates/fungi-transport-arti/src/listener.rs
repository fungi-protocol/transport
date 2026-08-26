//! The [`Listener`] half: run an onion service, accept framed channels.

use std::pin::Pin;
use std::sync::Arc;

use arti_client::DataStream;
use fungi_transport::framed::FramedChannel;
use fungi_transport::{ConnectError, Listener, OnionAddr};
use futures_util::{Stream, StreamExt};
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{RunningOnionService, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;

use crate::error::connect_error;
use crate::transport::ArtiTransport;

/// Accepts inbound framed channels arriving at this peer's onion service.
///
/// The service lives as long as this listener (the `Arc<RunningOnionService>`
/// is held here); its identity persists in the transport's `state_dir` per
/// nickname — the same nickname yields the same `.onion` across runs.
pub struct ArtiListener {
    incoming: Pin<Box<dyn Stream<Item = StreamRequest> + Send>>,
    addr: OnionAddr,
    virt_port: u16,
    max_msg_len: usize,
    _service: Arc<RunningOnionService>,
}

impl std::fmt::Debug for ArtiListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtiListener")
            .field("addr", &self.addr)
            .field("virt_port", &self.virt_port)
            .finish_non_exhaustive()
    }
}

impl ArtiListener {
    /// This peer's onion address, to hand to peers out of band.
    pub fn onion_addr(&self) -> &OnionAddr {
        &self.addr
    }
}

impl ArtiTransport {
    /// Publish an onion service under `nickname` and listen on `virt_port`.
    /// The onion identity is loaded from (or created in) the transport's
    /// `state_dir`.
    pub async fn listen(
        &self,
        nickname: &str,
        virt_port: u16,
    ) -> Result<ArtiListener, ConnectError> {
        use tor_hsservice::config::OnionServiceConfigBuilder;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(
                nickname
                    .parse()
                    .map_err(|e: tor_hsservice::InvalidNickname| {
                        ConnectError::Transport(e.into())
                    })?,
            )
            .build()
            .map_err(|e| ConnectError::Transport(e.into()))?;
        // `launch_onion_service` returns `Ok(None)` iff the service is
        // disabled in its config — never true for the config built above,
        // but we still handle it as a real error rather than unwrapping (the
        // probe in tests/api_surface.rs double-unwraps; that's fine for a
        // compile-time probe, not for production).
        let (service, rend_requests) = self
            .client
            .launch_onion_service(svc_cfg)
            .map_err(connect_error)?
            .ok_or_else(|| {
                ConnectError::Transport("onion service disabled in its own config".into())
            })?;
        let hs_id = service.onion_address().ok_or_else(|| {
            ConnectError::Transport("onion address not yet derivable from service keys".into())
        })?;
        // HsId only implements `safelog::DisplayRedacted`, not plain
        // `Display` (redaction-by-default, to keep onion addresses out of
        // logs by accident); we want the real address here, to hand to
        // peers out of band, so ask for the unredacted form explicitly.
        let host = hs_id.display_unredacted().to_string();
        let addr =
            OnionAddr::new(host, virt_port).map_err(|e| ConnectError::Transport(e.into()))?;
        Ok(ArtiListener {
            incoming: Box::pin(tor_hsservice::handle_rend_requests(rend_requests)),
            addr,
            virt_port,
            max_msg_len: self.max_msg_len,
            _service: service,
        })
    }
}

impl Listener for ArtiListener {
    type Channel = FramedChannel<DataStream>;

    async fn accept(&mut self) -> Result<Self::Channel, ConnectError> {
        loop {
            let req = self
                .incoming
                .next()
                .await
                .ok_or(ConnectError::Unreachable)?;
            match req.request() {
                IncomingStreamRequest::Begin(begin) if begin.port() == self.virt_port => {
                    let stream = req
                        .accept(Connected::new_empty())
                        .await
                        .map_err(|e| ConnectError::Transport(e.into()))?;
                    return Ok(FramedChannel::new(stream, self.max_msg_len));
                }
                _ => {
                    // Wrong port or non-Begin request: refuse and keep
                    // listening.
                    let _ = req.shutdown_circuit();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time contract: ArtiListener implements Listener with the
    /// framed DataStream channel, and is Send.
    #[allow(dead_code)]
    fn listener_contract()
    where
        ArtiListener: fungi_transport::Listener<
                Channel = fungi_transport::framed::FramedChannel<arti_client::DataStream>,
            > + Send,
    {
    }

    #[test]
    fn contract_holds() {
        // The function above compiling IS the assertion.
    }
}
