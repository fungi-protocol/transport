//! `--private-net` descriptor: point arti at a private test network's own
//! directory authorities and fallback caches instead of the real Tor network.
//!
//! Line format: `authority <name> <v3ident-hex>` and
//! `fallback <rsa-id-hex> <ed-id-base64> <ip:orport>`. `#` starts a comment.
//!
//! This lives in the arti backend crate (not the e2e harness) so that both the
//! in-process harness path and the out-of-process arti plugin can share one
//! parser/applier: the plugin reads the descriptor from its environment at
//! startup and applies it before bootstrap (see the `fungi-arti-plugin`
//! binary), while the harness applies it inline.

use std::path::Path;

use std::net::SocketAddr;

use arti_client::TorClientConfig;
use arti_client::config::TorClientConfigBuilder;
use arti_client::config::dir;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

/// A single directory authority's decoded v3 identity. arti holds parallel
/// vectors of identities, not named authority objects, so the descriptor's
/// name field is positional only. Identities are decoded at parse time, so a
/// malformed descriptor is rejected there rather than at bootstrap.
#[derive(Debug)]
struct Authority {
    v3ident: RsaIdentity,
}

/// A single fallback directory cache: its decoded RSA + ed25519 identities and
/// ORPort.
#[derive(Debug)]
struct Fallback {
    rsa: RsaIdentity,
    ed: Ed25519Identity,
    orport: SocketAddr,
}

/// A parsed private-network descriptor: the authorities and fallback caches a
/// peer should trust instead of the public Tor directory.
#[derive(Debug)]
pub struct PrivateNet {
    authorities: Vec<Authority>,
    fallbacks: Vec<Fallback>,
}

impl PrivateNet {
    /// Parse a descriptor from its text form. Returns a human-readable error
    /// naming the offending line on malformed input.
    pub fn parse(text: &str) -> Result<PrivateNet, String> {
        let mut authorities = Vec::new();
        let mut fallbacks = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["authority", _name, v3ident] => {
                    let v3ident = RsaIdentity::from_hex(v3ident).ok_or_else(|| {
                        format!("line {}: v3ident is not a valid hex RSA identity", n + 1)
                    })?;
                    authorities.push(Authority { v3ident });
                }
                ["fallback", rsa, ed, orport] => {
                    let rsa = RsaIdentity::from_hex(rsa).ok_or_else(|| {
                        format!(
                            "line {}: fallback rsa is not a valid hex RSA identity",
                            n + 1
                        )
                    })?;
                    let ed = Ed25519Identity::from_base64(ed).ok_or_else(|| {
                        format!(
                            "line {}: fallback ed is not a valid base64 ed25519 identity",
                            n + 1
                        )
                    })?;
                    let orport = orport.parse::<SocketAddr>().map_err(|e| {
                        format!(
                            "line {}: fallback orport is not a valid address: {e}",
                            n + 1
                        )
                    })?;
                    fallbacks.push(Fallback { rsa, ed, orport });
                }
                _ => return Err(format!("line {}: unrecognized directive", n + 1)),
            }
        }
        if authorities.is_empty() {
            return Err("no authorities in private-net file".into());
        }
        if fallbacks.is_empty() {
            return Err("no fallback caches in private-net file".into());
        }
        Ok(PrivateNet {
            authorities,
            fallbacks,
        })
    }

    /// Apply onto arti's config builder: custom authorities + fallbacks and
    /// testing-network directory tolerances.
    pub fn apply(&self, b: &mut TorClientConfigBuilder) -> Result<(), String> {
        let mut authorities = dir::AuthorityContacts::builder();
        for a in &self.authorities {
            // The name is unused here: AuthorityContacts holds parallel vectors
            // of identities, not named authority objects. Identities were
            // decoded and validated at parse time.
            authorities.v3idents().push(a.v3ident);
        }

        let mut fbs = Vec::new();
        for f in &self.fallbacks {
            let mut fb = dir::FallbackDir::builder();
            fb.rsa_identity(f.rsa).ed_identity(f.ed);
            fb.orports().push(f.orport);
            fbs.push(fb);
        }

        let net = b.tor_network();
        *net.authorities() = authorities;
        net.set_fallback_caches(fbs);

        // A freshly-started testing network votes on short consensus
        // lifetimes; be tolerant of clock skew between VMs.
        b.directory_tolerance()
            .pre_valid_tolerance(std::time::Duration::from_secs(300));
        b.directory_tolerance()
            .post_valid_tolerance(std::time::Duration::from_secs(300));

        // arti has no `TestingTorNetwork`, so — like that C-tor directive does
        // for the daemons — relax the distinct-subnet path rule for this test
        // network, whose nodes all share one subnet. Scoped to the private-net
        // config only: the public-network path (`tor_config`) keeps the rule on.
        b.path_rules()
            .ipv4_subnet_family_prefix(32)
            .ipv6_subnet_family_prefix(128);

        // The VM test network is tiny and CPU-starved — many VMs share the CI
        // runner's few cores — so hidden-service rendezvous circuits build
        // slowly and the defaults (60s request timeout, ~6 attempts) give up
        // before one completes. Grant far more time and attempts so a slow
        // circuit still succeeds. Private-net scoped, like the relaxations above.
        b.circuit_timing()
            .request_timeout(std::time::Duration::from_secs(240))
            .hs_desc_fetch_attempts(32)
            .hs_intro_rend_attempts(32)
            // The service rotates intro points under the churny net, so a
            // cached descriptor goes stale and every INTRODUCE is rejected
            // NOT_RECOGNIZED. arti refetches on that NACK, but the default
            // 15-minute requery interval makes it reuse the stale cache; drop
            // it so arti pulls a fresh descriptor with the current intro points.
            .hs_dir_requery_interval(std::time::Duration::from_secs(5));

        Ok(())
    }

    /// Build a ready-to-bootstrap [`TorClientConfig`] rooted at `state_dir` /
    /// `cache_dir` with this private network applied. Pair with
    /// [`ArtiTransport::bootstrap_with`](crate::ArtiTransport::bootstrap_with).
    pub fn build_config(
        &self,
        state_dir: &Path,
        cache_dir: &Path,
    ) -> Result<TorClientConfig, String> {
        let mut b = TorClientConfigBuilder::from_directories(state_dir, cache_dir);
        self.apply(&mut b)?;
        b.build().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# test net
authority test-da1 27102BC123E7AF1D4741AE047E160C91ADC76B21
authority test-da2 5B5A54A6C2778775E11B7E00A0C7DF562AF9AFE9

fallback 27102BC123E7AF1D4741AE047E160C91ADC76B21 xGYRXQ2b1SDpLoNjKilDNzrqAX2XCEBEyYlVmIGSjTo 192.168.1.11:9001
";

    #[test]
    fn parses_authorities_and_fallbacks() {
        let net = PrivateNet::parse(SAMPLE).unwrap();
        assert_eq!(net.authorities.len(), 2);
        assert_eq!(net.fallbacks.len(), 1);
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(PrivateNet::parse("authority only-two-fields\n").is_err());
        assert!(PrivateNet::parse("unknown x y z\n").is_err());
        assert!(PrivateNet::parse("authority da NOT-HEX\n").is_err());
    }

    /// Identities are validated at parse time, not deferred to bootstrap: a
    /// well-formed line whose identity fields are the wrong length or encoding
    /// is rejected by `parse`, so the fixture call fails, not the later boot.
    #[test]
    fn rejects_bad_identities_at_parse() {
        // v3ident is valid hex but too short for a 20-byte RSA identity.
        assert!(PrivateNet::parse("authority da AABBCC\nfallback 27102BC123E7AF1D4741AE047E160C91ADC76B21 xGYRXQ2b1SDpLoNjKilDNzrqAX2XCEBEyYlVmIGSjTo 192.168.1.11:9001\n").is_err());
        // fallback ed identity is not valid base64.
        assert!(PrivateNet::parse("authority da 27102BC123E7AF1D4741AE047E160C91ADC76B21\nfallback 27102BC123E7AF1D4741AE047E160C91ADC76B21 not-base64!!! 192.168.1.11:9001\n").is_err());
        // fallback orport is not a socket address.
        assert!(PrivateNet::parse("authority da 27102BC123E7AF1D4741AE047E160C91ADC76B21\nfallback 27102BC123E7AF1D4741AE047E160C91ADC76B21 xGYRXQ2b1SDpLoNjKilDNzrqAX2XCEBEyYlVmIGSjTo not-an-addr\n").is_err());
    }

    /// The parsed net applies onto a TorClientConfigBuilder without error.
    #[test]
    fn applies_to_builder() {
        let net = PrivateNet::parse(SAMPLE).unwrap();
        let mut b = TorClientConfigBuilder::default();
        net.apply(&mut b).unwrap();
    }

    /// The parsed net produces a valid in-memory config that builds successfully.
    /// This constructs a full config with state/cache directories and calls
    /// `build_config` to validate runtime config construction (no network access).
    #[test]
    fn built_config_validates() {
        use std::env;
        use std::process;

        let net = PrivateNet::parse(SAMPLE).unwrap();

        // Create temporary state and cache directories unique to this test run.
        let pid = process::id();
        let temp_base = env::temp_dir();
        let temp_state = temp_base.join(format!("fungi-arti-test-state-{}", pid));
        let temp_cache = temp_base.join(format!("fungi-arti-test-cache-{}", pid));

        std::fs::create_dir_all(&temp_state).expect("failed to create temp state dir");
        std::fs::create_dir_all(&temp_cache).expect("failed to create temp cache dir");

        // `build_config` validates all config constraints in-memory: this
        // ensures authorities + fallbacks are consistent per arti's validation.
        net.build_config(&temp_state, &temp_cache)
            .expect("private-net config should build");

        // Clean up temporary directories.
        let _ = std::fs::remove_dir_all(&temp_state);
        let _ = std::fs::remove_dir_all(&temp_cache);
    }
}
