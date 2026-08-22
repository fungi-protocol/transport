//! Arti (in-process Tor) backend for the fungi P2P datagram channel.
//!
//! The second real implementation of the [`fungi_transport`] traits: Tor
//! runs inside the process via `arti-client` — no external daemon. Each
//! peer runs an onion service and opens streams to peer `.onion` addresses;
//! message delimitation is the same [`fungi_transport::framed`] length-prefix
//! layer the SOCKS5h backend uses.
//!
//! Entry point: [`ArtiTransport::bootstrap`] (once per peer — it is
//! expensive), then [`ArtiTransport::connector`] and
//! [`ArtiTransport::listen`]. Unlike the SOCKS5h backend's ephemeral
//! onions, identity here PERSISTS: the address derives from keys stored in
//! the configured state directory per nickname. No internal deadlines —
//! callers own timeouts; cancelling by drop is safe, though an `accept`
//! cancelled mid-handshake rejects that one in-flight inbound request (the
//! peer's `connect` fails and it simply reconnects).
//!
//! Deterministic tests run in CI; the cross-backend path is exercised by the
//! NixOS VM suite.

mod connector;
mod error;
mod lazy;
mod listener;
mod private_net;
mod transport;

pub use connector::ArtiConnector;
pub use lazy::{LazyArtiConnector, LazyArtiTransport};
pub use listener::ArtiListener;
pub use private_net::PrivateNet;
pub use transport::{ArtiConfig, ArtiTransport};
