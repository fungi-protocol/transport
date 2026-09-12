//! Compile-time probe of the arti network-override API used by
//! src/private_net.rs. No test here touches the network.

use arti_client::config::TorClientConfigBuilder;
use arti_client::config::dir;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

/// The private-network surface: custom authorities + fallback caches.
///
/// Reconciled against the real 0.45.0 API (see task-1-report.md for the
/// full list of adaptations vs. the plan's draft):
///
/// - There is no per-authority `AuthorityBuilder`. `NetworkConfig`'s
///   `authorities` field is a single `AuthorityContacts` struct holding
///   *parallel* lists (`v3idents`, `uploads`, `downloads`, `votes`); you
///   build it via `dir::AuthorityContacts::builder()` and push identities
///   directly onto the `v3idents()` list accessor.
/// - `FallbackDirBuilder` is real, but lives in `tor_dircommon::fallback`
///   (re-exported as `dir::FallbackDir` / `dir::FallbackDirBuilder`), and
///   is obtained via `dir::FallbackDir::builder()`, not
///   `FallbackDirBuilder::default()`.
/// - `NetworkConfigBuilder::set_authorities` does not exist. Authorities
///   are set by assigning through the `authorities()` sub-builder accessor:
///   `*tor_network.authorities() = authorities_builder`.
/// - `NetworkConfigBuilder::set_fallback_caches` does exist, taking
///   `Vec<FallbackDirBuilder>`, exactly as drafted.
/// - `RsaIdentity` has no `FromStr`/`.parse()`; use `RsaIdentity::from_hex`.
/// - `Ed25519Identity` has no `FromStr`/`.parse()` either; use
///   `Ed25519Identity::new([u8; 32])` (or `from_base64`).
/// - `DirTolerance`'s fields are `pre_valid_tolerance` /
///   `post_valid_tolerance`, not `pre_valid` / `post_valid`; the builder
///   setters follow the field names.
/// - Setting non-default authorities without also overriding
///   `fallback_caches` fails `NetworkConfigBuilder::validate` at
///   `.build()` time — both must be set together for a private network.
#[allow(dead_code)]
fn network_override_surface() {
    let mut authorities = dir::AuthorityContacts::builder();
    authorities
        .v3idents()
        .push(RsaIdentity::from_hex("0000000000000000000000000000000000000000").unwrap());

    let mut fallback = dir::FallbackDir::builder();
    fallback
        .rsa_identity(RsaIdentity::from_hex("0000000000000000000000000000000000000000").unwrap())
        .ed_identity(Ed25519Identity::new([0u8; 32]));
    fallback
        .orports()
        .push("192.168.1.11:9001".parse().unwrap());

    let mut b = TorClientConfigBuilder::default();
    *b.tor_network().authorities() = authorities;
    b.tor_network().set_fallback_caches(vec![fallback]);

    // Testing-network tolerances used by src/private_net.rs:
    b.directory_tolerance()
        .pre_valid_tolerance(std::time::Duration::from_secs(300));
    b.directory_tolerance()
        .post_valid_tolerance(std::time::Duration::from_secs(300));

    // Confirm the whole thing actually builds (still no network use: this
    // only validates the in-memory config, it never dials out).
    b.build().expect("private-net config should build");
}
