//! A minimal plugin process backed by the in-memory [`MemTransport`].
//!
//! It speaks the server side of the plugin protocol over its own stdin/stdout,
//! so a harness can drive it through [`connect_plugin`](fungi_transport_capnp::connect_plugin).
//! Used by the crate's subprocess integration tests via `CARGO_BIN_EXE_mem-plugin`.
//!
//! With any command-line argument it exits immediately without serving — a stand
//! in for a plugin that dies before the capnp handshake, so the harness can be
//! shown to report the failure as unreachable.

use fungi_transport::mem::{MemConfig, MemTransport};
use fungi_transport_capnp::serve_plugin_stdio;

fn main() {
    if std::env::args().nth(1).is_some() {
        // Simulate a plugin that crashes before serving anything.
        std::process::exit(1);
    }

    serve_plugin_stdio(MemTransport::new(MemConfig::default()));
}
