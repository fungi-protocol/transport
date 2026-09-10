use std::{fmt, future::Future, time::Duration};

use fungi_transport::BoxError;
use payjoin::directory::ENCAPSULATED_RESPONSE_BYTES;

/// Executes encapsulated requests against an OHTTP relay.
///
/// Implementations must preserve the request URL, content type and body, bound
/// response allocation, and never retry ambiguous POSTs or follow redirects.
/// A cancelled request may have reached the server. This seam also supports
/// deterministic tests without replacing HPKE or OHTTP with mock cryptography.
pub trait HttpClient: Send + Sync {
    /// POST an encapsulated request and return its encapsulated response body.
    fn post(
        &self,
        request: payjoin::Request,
    ) -> impl Future<Output = Result<Vec<u8>, BoxError>> + Send;
}

/// Bounded HTTPS relay client with redirects and environment proxies disabled.
#[derive(Clone)]
pub struct RelayClient(reqwest::Client);

impl fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayClient").finish_non_exhaustive()
    }
}

impl RelayClient {
    /// Create a client with a per-request deadline (including response reads).
    /// An expired deadline is fatal to the channel, not a peer-close signal.
    pub fn new(timeout: Duration) -> Result<Self, BoxError> {
        if timeout.is_zero() {
            return Err("request timeout must be nonzero".into());
        }
        Ok(Self(
            reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .timeout(timeout)
                .build()?,
        ))
    }
}

impl HttpClient for RelayClient {
    async fn post(&self, request: payjoin::Request) -> Result<Vec<u8>, BoxError> {
        let mut response = self
            .0
            .post(request.url)
            .header(reqwest::header::CONTENT_TYPE, request.content_type)
            .body(request.body)
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!("OHTTP relay returned {}", response.status()).into());
        }
        if response
            .content_length()
            .is_some_and(|n| n > ENCAPSULATED_RESPONSE_BYTES as u64)
        {
            return Err("OHTTP response exceeds the fixed response size".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > ENCAPSULATED_RESPONSE_BYTES - body.len() {
                return Err("OHTTP response exceeds the fixed response size".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
