# fungi-transport

A P2P datagram-channel abstraction for the Fungi protocol

The core idea is a **channel**: a connection to *one* peer that moves opaque
byte messages, one message per call. It carries no ordering across channels, no
deduplication, no framing; those belong to other layers.

## Crates

| Crate | What it does |
| --- | --- |
| [`fungi-transport`](crates/fungi-transport) | The core abstraction. |
| [`fungi-transport-socks5h`](crates/fungi-transport-socks5h) | Tor backend over an **external** tor daemon. |
| [`fungi-transport-arti`](crates/fungi-transport-arti) | Tor backend with Tor running **in-process** (Arti). |
| [`fungi-transport-capnp`](crates/fungi-transport-capnp) | Cap'n Proto plugin layer to run a backend out-of-process. |

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

