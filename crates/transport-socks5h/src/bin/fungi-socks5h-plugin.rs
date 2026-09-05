//! A capnp plugin process backed by the SOCKS5h tor-daemon backend.
//!
//! It speaks the server side of the plugin protocol over its own stdin/stdout,
//! so a harness can drive it through
//! [`connect_plugin`](fungi_transport_capnp::connect_plugin). The daemon's
//! SOCKS and control ports are taken from the environment, defaulting to a
//! stock daemon on localhost:
//!
//! - `FUNGI_SOCKS_ADDR` — the daemon's SOCKS port (default `127.0.0.1:9050`).
//! - `FUNGI_CONTROL_ADDR` — the daemon's control port (default `127.0.0.1:9051`).

use std::net::SocketAddr;

use fungi_transport_capnp::serve_plugin_stdio;
use fungi_transport_socks5h::{TorConfig, TorTransport};

/// Read a `SocketAddr` from `var`, falling back to `default` when unset. A set
/// but unparseable value is a hard error: a misconfigured daemon address must
/// not silently fall back to the stock port.
fn env_addr(var: &str, default: SocketAddr) -> SocketAddr {
    match std::env::var(var) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{var} is not a valid socket address: {value:?}")),
        Err(_) => default,
    }
}

fn main() {
    let cfg = TorConfig {
        socks_addr: env_addr("FUNGI_SOCKS_ADDR", SocketAddr::from(([127, 0, 0, 1], 9050))),
        control_addr: env_addr(
            "FUNGI_CONTROL_ADDR",
            SocketAddr::from(([127, 0, 0, 1], 9051)),
        ),
        ..TorConfig::default()
    };

    serve_plugin_stdio(TorTransport::new(cfg));
}
