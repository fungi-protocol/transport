//! Security behavior.

use super::*;

/// Accepts a valid envelope and rejects a wrong recipient, wrong secret, truncated envelope and modified payload.
#[test]
fn envelope_rejects_forgery_reflection_and_truncation() {
    let secret = LinkSecret::generate();
    let a = HpkeKeyPair::gen_keypair();
    let b = HpkeKeyPair::gen_keypair();
    let mut body = envelope::encode(b"test\0", &secret, b.public_key());
    assert_eq!(
        envelope::decode(&body, &secret, b.public_key()).unwrap(),
        b"test\0"
    );
    assert!(envelope::decode(&body, &secret, a.public_key()).is_none());
    assert!(envelope::decode(&body, &LinkSecret::generate(), b.public_key()).is_none());
    for n in 0..body.len() {
        assert!(envelope::decode(&body[..n], &secret, b.public_key()).is_none());
    }
    body[12] ^= 1;
    assert!(envelope::decode(&body, &secret, b.public_key()).is_none());
}

/// Rejects a zero polling interval, identical endpoint keys, a directory query and a relay URL with a non-root path.
#[tokio::test]
async fn rejects_invalid_configuration() {
    let fixture = Fixture::new().await;
    let mut config = fixture.config(true);
    config.poll_interval = Duration::ZERO;
    assert!(OhttpChannel::new(config, fixture.client()).is_err());
    let mut config = fixture.config(true);
    config.peer_key = config.local_keys.public_key().clone();
    assert!(OhttpChannel::new(config, fixture.client()).is_err());
    let mut config = fixture.config(true);
    config.directory = Url::parse("https://example.com/?exposed=1").unwrap();
    assert!(OhttpChannel::new(config, fixture.client()).is_err());
    let mut config = fixture.config(true);
    config.relay = Url::parse("https://relay.example/ignored-path").unwrap();
    assert!(OhttpChannel::new(config, fixture.client()).is_err());
}

/// The path-shape checks must track the parser that actually dispatches the
/// request (reqwest re-parses `Request::url` in `RelayClient::post`), not
/// payjoin's own minimal parser, which stores paths literally without
/// decoding percent-encoding or collapsing dot-segments. A relay URL whose
/// path is a percent-encoded traversal back to root resolves to `/` under
/// the parser that actually sends the request, so it must be accepted, even
/// though payjoin's own (unused-for-dispatch) parser sees a non-root path.
#[tokio::test]
async fn relay_root_path_check_matches_the_dispatching_parser() {
    let fixture = Fixture::new().await;
    let raw = "https://relay.example/a/%2e%2e";
    assert_eq!(payjoin::Url::parse(raw).unwrap().path(), "/a/%2e%2e");
    assert_eq!(reqwest::Url::parse(raw).unwrap().path(), "/");
    let mut config = fixture.config(true);
    config.relay = Url::parse(raw).unwrap();
    assert!(OhttpChannel::new(config, fixture.client()).is_ok());
}
