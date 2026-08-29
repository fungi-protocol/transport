//! A capnp plugin process backed by the in-process arti Tor client.
//!
//! It speaks the server side of the plugin protocol over its own stdin/stdout,
//! so a harness can drive it through
//! [`connect_plugin`](fungi_transport_capnp::connect_plugin). Its configuration
//! is taken from the environment at startup, defaulting under the system temp
//! dir:
//!
//! - `FUNGI_STATE_DIR` — arti's persistent state, including onion-service keys
//!   (identity persists per nickname; a throwaway dir gives an ephemeral
//!   identity).
//! - `FUNGI_CACHE_DIR` — arti's network-directory cache.
//!
//! The private test network is *not* an env var: arti's directory authorities
//! must be fixed before its single bootstrap, so the transport is bootstrapped
//! lazily and the harness installs the private net first through the plugin's
//! `TestFixtures.configurePrivateNet` capability (see [`ArtiFixtures`]). With no
//! such call — the production path — the first transport operation bootstraps
//! onto the public Tor network.
//!
//! Bootstrap needs a live Tor network, so this binary has no deterministic
//! test; it is exercised end to end by the NixOS VM suite. What is asserted
//! here is that it compiles and is a valid plugin server.

use std::path::PathBuf;

use fungi_transport::framed::DEFAULT_MAX_MSG_LEN;
use fungi_transport_arti::LazyArtiTransport;
use fungi_transport_capnp::{PluginFixtures, serve_plugin_with_stdio};

/// Read a directory path from `var`, falling back to `<temp>/default_leaf`.
fn env_dir(var: &str, default_leaf: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(value) => PathBuf::from(value),
        None => std::env::temp_dir().join(default_leaf),
    }
}

/// The plugin's test-fixtures tier: forwards `configurePrivateNet` to the lazy
/// transport, which applies the descriptor before its one bootstrap. Keeping
/// the `PluginFixtures` impl here (not in the library) leaves the arti library
/// free of the capnp plugin layer.
struct ArtiFixtures {
    transport: LazyArtiTransport,
}

impl PluginFixtures for ArtiFixtures {
    fn configure_private_net(&self, net_file: &[u8]) -> Result<(), String> {
        self.transport.configure_private_net(net_file)
    }
}

fn main() {
    let state_dir = env_dir("FUNGI_STATE_DIR", "fungi-arti-state");
    let cache_dir = env_dir("FUNGI_CACHE_DIR", "fungi-arti-cache");

    // Install a crypto provider explicitly: auto-install only fires when a
    // single provider is in the graph, so make the choice unambiguous.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let transport = LazyArtiTransport::new(state_dir, cache_dir, DEFAULT_MAX_MSG_LEN);
    let fixtures = ArtiFixtures {
        transport: transport.clone(),
    };
    serve_plugin_with_stdio(transport, fixtures);
}
