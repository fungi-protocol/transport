# Fungi transport workspace

A P2P datagram-channel abstraction, transport backends, and canonical wire
messages for the Fungi protocol.

> **Temporary home.** This repository is where the transport layer is being
> developed in isolation. Once it stabilizes, this work will move into the
> Fungi monorepo at
> [fungi-protocol/fungi](https://github.com/fungi-protocol/fungi).

The core transport abstraction is a **channel**: a connection to *one* peer
that moves opaque byte messages, one message per call. The workspace also
contains framing adapters, gossip, transport backends, and the independent
canonical wire-message layer.

## Crates

| Crate | What it does |
| --- | --- |
| [`fungi-transport`](crates/transport) | Channel traits, framing adapters, in-memory channels, and gossip. |
| [`fungi-transport-socks5h`](crates/transport-socks5h) | Tor backend over an **external** tor daemon. |
| [`fungi-transport-arti`](crates/transport-arti) | Tor backend with Tor running **in-process** (Arti). |
| [`fungi-transport-capnp`](crates/transport-capnp) | Cap'n Proto plugin layer to run a backend out-of-process. |
| [`fungi-wire`](crates/wire) | Candidate canonical typed-message encoding, logical message IDs, and grow-only message sets. |

Directory names stay short inside the workspace, while Cargo package names
retain the `fungi-` prefix so dependencies and Rust imports remain explicit to
consumers (`fungi_transport`, `fungi_wire`, and the backend crates).

## Building and testing

The workspace builds with the stable Rust toolchain (see `rust-toolchain.toml`).
Common tasks are wrapped in the [`Justfile`](Justfile):

```sh
just test    # cargo test --all-targets + doctests
just clippy  # clippy with warnings denied (what CI runs)
just check   # fmt + clippy + tests + echo example (dev loop)
just e2e     # the cross-backend end-to-end NixOS VM test
just flake-check  # full CI entry point: crane checks + VM test
```
