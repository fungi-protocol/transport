//! Shared real-directory fixture and deterministic HTTP failure controls.

use super::*;

#[derive(Default)]
pub(super) struct Controls {
    pub(super) calls: AtomicUsize,
    // 1 = fail the next request; 2 = park after the directory responds.
    pub(super) next: AtomicUsize,
    pub(super) parked: Notify,
}

#[derive(Clone)]
pub(super) struct DirectClient {
    pub(super) service: Service<FilesDb>,
    pub(super) controls: Arc<Controls>,
}

impl HttpClient for DirectClient {
    async fn post(&self, request: payjoin::Request) -> Result<Vec<u8>, BoxError> {
        self.controls.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.content_type, "message/ohttp-req");
        assert_eq!(
            request.body.len(),
            payjoin::directory::ENCAPSULATED_MESSAGE_BYTES
        );
        assert_eq!(
            request.url,
            "https://relay.example/http://directory.example/"
        );
        let action = self.controls.next.swap(0, Ordering::SeqCst);
        if action == 1 {
            return Err("injected HTTP failure".into());
        }
        let response = self
            .service
            .clone()
            .oneshot(Request::post("/").body(Body::from(request.body))?)
            .await
            .map_err(|e| -> BoxError { e.into() })?;
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await?.to_bytes().to_vec();
        if action == 2 {
            self.controls.parked.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(bytes)
    }
}

pub(super) struct Fixture {
    _storage: tempfile::TempDir,
    pub(super) service: Service<FilesDb>,
    pub(super) keys: OhttpKeys,
    pub(super) alice: HpkeKeyPair,
    pub(super) bob: HpkeKeyPair,
    pub(super) secret: LinkSecret,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let storage = tempfile::tempdir().unwrap();
        let db = FilesDb::init(
            Duration::from_millis(10),
            storage.path().into(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap()
        .with_append_mailbox();
        let config = ohttp::KeyConfig::new(
            1,
            ohttp::hpke::Kem::K256Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::ChaCha20Poly1305,
            )],
        )
        .unwrap();
        let keys = OhttpKeys::decode(&config.encode().unwrap()).unwrap();
        let service = Service::new(
            db,
            ohttp::Server::new(config).unwrap(),
            SentinelTag::new([1; 32]),
            None,
        );
        Self {
            _storage: storage,
            service,
            keys,
            alice: HpkeKeyPair::gen_keypair(),
            bob: HpkeKeyPair::gen_keypair(),
            secret: LinkSecret::generate(),
        }
    }

    pub(super) fn config(&self, alice: bool) -> MailboxConfig {
        let (local, peer) = if alice {
            (&self.alice, &self.bob)
        } else {
            (&self.bob, &self.alice)
        };
        MailboxConfig {
            directory: Url::parse("http://directory.example/").unwrap(),
            relay: Url::parse("https://relay.example/").unwrap(),
            ohttp_keys: self.keys.clone(),
            incoming: ShortId([7; 8]),
            outgoing: ShortId([7; 8]),
            local_keys: local.clone(),
            peer_key: peer.public_key().clone(),
            link_secret: self.secret.clone(),
            poll_interval: Duration::from_millis(25),
        }
    }

    pub(super) fn client(&self) -> DirectClient {
        DirectClient {
            service: self.service.clone(),
            controls: Arc::default(),
        }
    }

    pub(super) fn pair(&self) -> (OhttpChannel<DirectClient>, OhttpChannel<DirectClient>) {
        (
            OhttpChannel::new(self.config(true), self.client()).unwrap(),
            OhttpChannel::new(self.config(false), self.client()).unwrap(),
        )
    }
}
