//! listen/dial driver: spawns a backend plugin subprocess and drives it over
//! the `Transport` trait via capnp-rpc. The generic channel-driving primitives
//! live in `fungi_transport::harness`; this binary adds the CLI and the stdout
//! ONION/READY/OK protocol the NixOS VM test greps for. It is backend-agnostic:
//! every backend is reached the same way, through its plugin binary.

use std::time::Duration;

use fungi_transport::harness::{dial_sequence, echo_one_peer};
use fungi_transport::{
    BroadcastChannel, Connector, DialRetry, GossipBroadcast, ListenParams, ListenSide, Listener,
    OnionAddr, SessionId, SplitChannel, Transport, WireConfig, Wiring,
};
use fungi_wire::{Body, CanonicalMessage, Extension, Extensions, Message, MessageSet};

/// Bounded wait for every network step: the VM test must fail, not hang.
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(300);

/// Bounded wait for `accept()`: must cover the dialer's full retry budget
/// in the VM test (the dial side's `wait_until_succeeds` retries for up to
/// 900s while the listener sits in `accept()`), so this is wider than
/// [`STEP_TIMEOUT`].
pub(crate) const ACCEPT_TIMEOUT: Duration = Duration::from_secs(900);

/// Parsed CLI.
pub(crate) struct Cli {
    pub(crate) cmd: Cmd,
    pub(crate) private_net: Option<std::path::PathBuf>,
    pub(crate) state_dir: Option<std::path::PathBuf>,
    /// The plugin binary to drive: the harness spawns it and speaks capnp-rpc
    /// to it over its stdio. Every backend is reached this way, so this is
    /// required.
    pub(crate) plugin: std::path::PathBuf,
}

pub(crate) enum Cmd {
    Listen {
        virt_port: u16,
        /// How many peers to accept and echo, one after the other.
        peers: u16,
    },
    Dial {
        target: OnionAddr,
        /// Session to dial under; `None` dials on the backend's shared
        /// default connector.
        session: Option<SessionId>,
    },
    Gossip {
        /// Listen side, when this node accepts inbound links.
        virt_port: Option<u16>,
        /// How many inbound links to accept before gossiping.
        listen_peers: u16,
        /// Outbound links to open, each with its own in-command retry.
        dials: Vec<OnionAddr>,
        /// This node's own canonical application message.
        message: CanonicalMessage,
        /// Publish the same event twice to exercise idempotent insertion.
        duplicate: bool,
        /// Distinct messages (own included) that mean convergence. Every
        /// participant in one run must use the same total.
        expect: usize,
    },
}

pub(crate) fn parse_args(args: Vec<String>) -> Result<Cli, String> {
    let mut it = args.into_iter().skip(1);
    let cmd_word = it.next().ok_or("usage: fungi-harness listen|dial ...")?;
    let mut private_net = None;
    let mut virt_port = None;
    let mut target = None;
    let mut plugin = None;
    let mut state_dir = None;
    let mut session = None;
    let mut peers = None;
    let mut dials = Vec::new();
    let mut message = None;
    let mut message_type = None;
    let mut extensions = Vec::new();
    let mut duplicate = false;
    let mut expect = None;
    let mut listen_peers = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--private-net" => {
                private_net = Some(it.next().ok_or("--private-net needs a file")?.into())
            }
            "--session" => {
                session = Some(
                    it.next()
                        .ok_or("--session needs a pid-seq id")?
                        .parse::<SessionId>()
                        .map_err(|e| e.to_string())?,
                )
            }
            "--virt-port" => {
                virt_port = Some(
                    it.next()
                        .ok_or("--virt-port needs a number")?
                        .parse::<u16>()
                        .map_err(|e| e.to_string())?,
                )
            }
            "--peers" => {
                peers = Some(
                    it.next()
                        .ok_or("--peers needs a count")?
                        .parse::<u16>()
                        .map_err(|e| e.to_string())?,
                )
            }
            "--state-dir" => state_dir = Some(it.next().ok_or("--state-dir needs a path")?.into()),
            "--plugin" => plugin = Some(it.next().ok_or("--plugin needs a path")?.into()),
            "--dial" => {
                let raw = it.next().ok_or("--dial needs host:port")?;
                let (host, port) = raw.rsplit_once(':').ok_or("--dial needs host:port")?;
                dials.push(
                    OnionAddr::new(
                        host,
                        port.parse()
                            .map_err(|e: std::num::ParseIntError| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?,
                );
            }
            "--listen-peers" => {
                listen_peers = Some(
                    it.next()
                        .ok_or("--listen-peers needs a count")?
                        .parse::<u16>()
                        .map_err(|e| e.to_string())?,
                )
            }
            "--message" => message = Some(it.next().ok_or("--message needs text")?.into_bytes()),
            "--message-type" => {
                message_type = Some(it.next().ok_or("--message-type needs a kind")?)
            }
            "--extension" => {
                let raw = it.next().ok_or("--extension needs TYPE:VALUE")?;
                let (ty, value) = raw.split_once(':').ok_or("--extension needs TYPE:VALUE")?;
                extensions.push(Extension {
                    ty: ty
                        .parse::<u64>()
                        .map_err(|e: std::num::ParseIntError| e.to_string())?,
                    value: value.as_bytes().to_vec(),
                });
            }
            "--duplicate" => duplicate = true,
            "--expect" => {
                expect = Some(
                    it.next()
                        .ok_or("--expect needs a count")?
                        .parse::<usize>()
                        .map_err(|e| e.to_string())?,
                )
            }
            other if !other.starts_with("--") && target.is_none() => {
                let (host, port) = other.rsplit_once(':').ok_or("target must be host:port")?;
                target = Some(
                    OnionAddr::new(
                        host,
                        port.parse()
                            .map_err(|e: std::num::ParseIntError| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?,
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let plugin = plugin.ok_or("--plugin is required")?;
    let cmd = match cmd_word.as_str() {
        "listen" => Cmd::Listen {
            virt_port: virt_port.ok_or("listen needs --virt-port")?,
            peers: peers.unwrap_or(1),
        },
        "dial" => Cmd::Dial {
            target: target.ok_or("dial needs a host:port target")?,
            session,
        },
        "gossip" => {
            let payload = message.ok_or("gossip needs --message")?;
            let body = match message_type.as_deref() {
                Some("psbt") => Body::Psbt(payload),
                Some("payment") => Body::Payment(payload),
                Some("confirmation") => Body::Confirmation(payload),
                Some(other) => return Err(format!("unknown --message-type {other}")),
                None => return Err("gossip needs --message-type".to_string()),
            };
            Cmd::Gossip {
                virt_port,
                listen_peers: listen_peers.unwrap_or(0),
                dials,
                message: CanonicalMessage::encode(&Message {
                    body,
                    extensions: Extensions::new(extensions).map_err(|e| e.to_string())?,
                })
                .map_err(|e| e.to_string())?,
                duplicate,
                expect: expect.ok_or("gossip needs --expect")?,
            }
        }
        other => return Err(format!("unknown subcommand {other}")),
    };
    Ok(Cli {
        cmd,
        private_net,
        state_dir,
        plugin,
    })
}

/// Listen over any backend: publish, then accept and echo `peers` peers, one
/// after the other, each until it closes. Establishment awaits are bounded by
/// `STEP_TIMEOUT`; each `accept()` gets its own `ACCEPT_TIMEOUT`, so a later
/// peer's budget does not shrink with the earlier peers' wall time.
pub(crate) async fn run_listen<T>(
    transport: T,
    params: ListenParams,
    peers: u16,
) -> Result<(), String>
where
    T: Transport,
    T::Addr: std::fmt::Display,
{
    let (mut listener, addr) = tokio::time::timeout(STEP_TIMEOUT, transport.listen(params))
        .await
        .map_err(|_| "listen timed out".to_string())?
        .map_err(|e| e.to_string())?;
    println!("ONION={addr}");
    println!("READY");
    for _ in 0..peers {
        let ch = tokio::time::timeout(ACCEPT_TIMEOUT, listener.accept())
            .await
            .map_err(|_| "accept timed out".to_string())?
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(STEP_TIMEOUT, echo_one_peer(ch))
            .await
            .map_err(|_| "echo/dial phase timed out".to_string())??;
    }
    Ok(())
}

/// Dial one peer over any connector: connect, run the message sequence.
pub(crate) async fn run_dial<Co>(connector: Co, target: &Co::Addr) -> Result<(), String>
where
    Co: Connector,
{
    let ch = tokio::time::timeout(STEP_TIMEOUT, connector.connect(target))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    tokio::time::timeout(STEP_TIMEOUT, dial_sequence(ch))
        .await
        .map_err(|_| "echo/dial phase timed out".to_string())??;
    println!("OK");
    Ok(())
}

/// Gossip over any backend: wire the group with [`fungi_transport::gossip`]
/// (optionally accepting `listen_peers` inbound links, dialing every
/// `--dial` target with the harness's own retry cadence), then run naive
/// gossip to convergence and print the converged set.
pub(crate) async fn run_gossip<T>(
    transport: T,
    virt_port: Option<u16>,
    listen_peers: u16,
    dials: &[T::Addr],
    message: CanonicalMessage,
    duplicate: bool,
    expect: usize,
) -> Result<(), String>
where
    T: Transport,
    T::Addr: std::fmt::Display + Clone,
    <T::Connector as Connector>::Channel: SplitChannel + 'static,
    T::Listener: Listener<Channel = <T::Connector as Connector>::Channel>,
{
    let retry = DialRetry {
        deadline: Some(ACCEPT_TIMEOUT),
        attempt_timeout: STEP_TIMEOUT,
        pause: Duration::from_secs(10),
    };
    let cfg = WireConfig {
        listen: virt_port.map(|port| ListenSide {
            params: ListenParams::new(port).with_nickname("fungigossip"),
            accept: listen_peers,
        }),
        dials: dials.to_vec(),
        dial_retry: retry,
        session: None,
    };
    let (wiring, addr) = tokio::time::timeout(STEP_TIMEOUT, Wiring::start(&transport, cfg))
        .await
        .map_err(|_| "listen timed out".to_string())?
        .map_err(|e| e.to_string())?;
    if let Some(addr) = addr {
        println!("ONION={addr}");
        println!("READY");
    }
    // Aggregate of the per-step budgets: establish runs its accepts and
    // dials sequentially, so its bound is one ACCEPT_TIMEOUT per accept
    // plus one dial deadline per address (plus a step of slack) — the
    // same total the pre-wiring code gave each step its own clock for.
    let accepts = if virt_port.is_some() {
        u32::from(listen_peers)
    } else {
        0
    };
    let dial_budget = retry.deadline.unwrap_or(ACCEPT_TIMEOUT) * dials.len() as u32;
    let establish_budget = ACCEPT_TIMEOUT * accepts + dial_budget + STEP_TIMEOUT;
    let channels = tokio::time::timeout(
        establish_budget,
        // Every failed attempt lands in the VM test's stderr capture —
        // the only record of what a node saw when a run goes bad.
        wiring.establish_with(|addr, e| eprintln!("dial {addr} attempt failed: {e}")),
    )
    .await
    .map_err(|_| "wiring timed out".to_string())?
    .map_err(|e| e.to_string())?;

    let mut node = GossipBroadcast::new(channels);
    let converged = tokio::time::timeout(
        STEP_TIMEOUT,
        collect_gossip(&mut node, &message, duplicate, expect),
    )
    .await
    .unwrap_or_else(|_| Err("gossip convergence timed out".to_string()));
    // Drain whether or not the set converged. On success this flushes the
    // forwards peers still need — normal peer closure is already tolerated by
    // `shutdown`, so anything left means the convergence proof is incomplete
    // and must suppress `OK`. On failure it is the only path that reports WHY
    // the engine gave up (a timed-out forward, a saturated queue); a bare
    // "links closed" would leave the VM log with no cause.
    let drained = shutdown_gossip(node).await;
    let set = match (converged, drained) {
        (Ok(set), Ok(())) => set,
        (Err(convergence), Err(drain)) => return Err(format!("{convergence}; {drain}")),
        (Err(failure), Ok(())) | (Ok(_), Err(failure)) => return Err(failure),
    };
    for (id, message) in set.iter() {
        println!(
            "MSG={}:{}",
            hex::encode(id.as_bytes()),
            hex::encode(message.as_bytes())
        );
    }
    println!("COUNT={}", set.len());
    println!("COMMITMENT={}", hex::encode(set.commitment().as_bytes()));
    println!("OK");
    Ok(())
}

/// Publish one node's message and collect the distinct set expected by one
/// harness run. Every participant must use the same `expect` total.
async fn collect_gossip(
    node: &mut GossipBroadcast,
    message: &CanonicalMessage,
    duplicate: bool,
    expect: usize,
) -> Result<MessageSet, String> {
    let mut set = MessageSet::default();
    set.insert(message.clone()).map_err(|e| e.to_string())?;
    node.send(message.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if duplicate {
        node.send(message.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    while set.len() < expect {
        match node.recv().await {
            Ok(msg) => {
                let message = CanonicalMessage::parse(msg).map_err(|e| e.to_string())?;
                set.insert(message).map_err(|e| e.to_string())?;
            }
            Err(_) => {
                return Err(format!(
                    "links closed holding {}/{expect} messages",
                    set.len()
                ));
            }
        }
    }
    Ok(set)
}

async fn shutdown_gossip(node: GossipBroadcast) -> Result<(), String> {
    tokio::time::timeout(STEP_TIMEOUT, node.shutdown())
        .await
        .map_err(|_| "shutdown drain timed out".to_string())?
        .map_err(|e| format!("shutdown drain failed: {e}"))
}

/// Drive the parsed command over a plugin subprocess: spawn `cli.plugin` and
/// speak capnp-rpc to it (via
/// [`connect_plugin`](fungi_transport_capnp::connect_plugin)), then run the
/// generic [`run_listen`]/[`run_dial`]. Establishment awaits
/// (listen/connect/bootstrap) are bounded by [`STEP_TIMEOUT`]; `accept()` is
/// bounded by the wider [`ACCEPT_TIMEOUT`] so the listener outlives the dialer's
/// retry budget in the VM test; the data phase is bounded by [`STEP_TIMEOUT`].
///
/// Backend configuration is delivered two ways, and each backend uses only what
/// it needs. Directory config goes through the environment: `--state-dir` sets
/// `FUNGI_STATE_DIR`/`FUNGI_CACHE_DIR` for arti's persistent state and cache
/// (socks5h ignores them). The private test network goes through the plugin's
/// `TestFixtures.configurePrivateNet` capability instead — `--private-net` is
/// read here and installed before the transport is first driven, since arti must
/// fix its authorities before its one bootstrap; socks5h treats it as a no-op.
pub(crate) async fn run(cli: Cli) -> Result<(), String> {
    use fungi_transport::OnionAddr;
    use fungi_transport_capnp::{CapnpTransport, connect_plugin};

    let mut command = tokio::process::Command::new(&cli.plugin);
    // The harness only ever runs backends in test/VM contexts, whose state dirs
    // (e.g. under a world-writable /tmp) arti's fs-mistrust guard would reject.
    // Relax it for the spawned plugin; a plugin run outside the harness keeps
    // the guard on.
    command.env("FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS", "1");
    if let Some(dir) = &cli.state_dir {
        command.env("FUNGI_STATE_DIR", dir.join("state"));
        command.env("FUNGI_CACHE_DIR", dir.join("cache"));
    }

    let transport: CapnpTransport<OnionAddr> = connect_plugin(command);
    // Install the private test network through the fixtures tier before the
    // first factory call, since a backend may fix its network only once.
    if let Some(path) = &cli.private_net {
        let net_file = tokio::fs::read(path)
            .await
            .map_err(|e| format!("reading --private-net {}: {e}", path.display()))?;
        transport
            .configure_private_net(&net_file)
            .await
            .map_err(|e| e.to_string())?;
    }
    match &cli.cmd {
        Cmd::Listen { virt_port, peers } => {
            run_listen(
                transport,
                ListenParams::new(*virt_port).with_nickname("fungie2e"),
                *peers,
            )
            .await
        }
        Cmd::Dial { target, session } => {
            let connector = match session {
                Some(session) => transport.connector_for(session),
                None => transport.connector(),
            };
            run_dial(connector, target).await
        }
        Cmd::Gossip {
            virt_port,
            listen_peers,
            dials,
            message,
            duplicate,
            expect,
        } => {
            run_gossip(
                transport,
                *virt_port,
                *listen_peers,
                dials,
                message.clone(),
                *duplicate,
                *expect,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_listen_and_run_dial_roundtrip_over_mem() {
        use fungi_transport::mem::{MemAddr, MemConfig, MemTransport};
        use fungi_transport::{ListenParams, Transport};
        let transport = MemTransport::new(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        let connector = transport.connector();
        let listen = tokio::spawn(run_listen(transport, ListenParams::new(1), 1));
        // The dialer connects, runs the sequence, then drops — the echo side sees
        // the close and run_listen returns Ok.
        run_dial(connector, &MemAddr).await.unwrap();
        listen.await.unwrap().unwrap();
    }

    /// With `peers: 2` the listener survives its first peer's departure and
    /// serves the next dial; it returns only after both ran the sequence.
    #[tokio::test]
    async fn run_listen_serves_peers_one_after_the_other() {
        use fungi_transport::mem::{MemAddr, MemConfig, MemTransport};
        use fungi_transport::{ListenParams, Transport};
        let transport = MemTransport::new(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        let connector = transport.connector();
        let listen = tokio::spawn(run_listen(transport, ListenParams::new(1), 2));
        run_dial(connector.clone(), &MemAddr).await.unwrap();
        run_dial(connector, &MemAddr).await.unwrap();
        listen.await.unwrap().unwrap();
    }

    /// `--plugin <path>` is required: without it the parse fails.
    #[test]
    fn cli_parsing_rejects_missing_plugin() {
        assert!(
            parse_args(
                ["fungi-harness", "listen", "--virt-port", "1"]
                    .map(String::from)
                    .to_vec()
            )
            .is_err()
        );
    }

    /// `--plugin <path>` populates the plugin field with the binary to drive.
    #[test]
    fn cli_parsing_accepts_plugin_path() {
        let cli = parse_args(
            [
                "fungi-harness",
                "listen",
                "--plugin",
                "/nix/store/xxx/bin/fungi-arti-plugin",
                "--virt-port",
                "9735",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        assert_eq!(
            cli.plugin,
            std::path::Path::new("/nix/store/xxx/bin/fungi-arti-plugin")
        );
    }

    /// `--session <pid-seq>` binds the dial to that session; malformed ids
    /// fail the parse rather than silently dialing unbound.
    #[test]
    fn cli_parsing_accepts_and_validates_session() {
        let args = |sess: &str| {
            [
                "fungi-harness",
                "dial",
                "--plugin",
                "/nix/store/xxx/bin/fungi-socks5h-plugin",
                "--session",
                sess,
                &format!("{:a<56}.onion:9735", "host"),
            ]
            .map(String::from)
            .to_vec()
        };
        let cli = parse_args(args("4242-1")).unwrap();
        match cli.cmd {
            Cmd::Dial { session, .. } => {
                assert_eq!(session, Some("4242-1".parse().unwrap()));
            }
            _ => panic!("expected a dial command"),
        }
        assert!(parse_args(args("not-an-id")).is_err());
    }

    /// Without `--session`, the dial stays on the shared default connector.
    #[test]
    fn cli_parsing_defaults_to_no_session() {
        let cli = parse_args(
            [
                "fungi-harness",
                "dial",
                "--plugin",
                "/nix/store/xxx/bin/fungi-socks5h-plugin",
                &format!("{:a<56}.onion:9735", "host"),
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match cli.cmd {
            Cmd::Dial { session, .. } => assert_eq!(session, None),
            _ => panic!("expected a dial command"),
        }
    }

    /// `gossip` parses its mixed listen/dial role: optional listen side,
    /// repeatable dials, required message and expected count.
    #[test]
    fn cli_parsing_accepts_gossip() {
        let cli = parse_args(
            [
                "fungi-harness",
                "gossip",
                "--plugin",
                "/nix/store/xxx/bin/fungi-arti-plugin",
                "--virt-port",
                "9736",
                "--listen-peers",
                "2",
                "--message-type",
                "psbt",
                "--message",
                "from-b",
                "--extension",
                "1:optional",
                "--duplicate",
                "--expect",
                "3",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match cli.cmd {
            Cmd::Gossip {
                virt_port,
                listen_peers,
                dials,
                message,
                duplicate,
                expect,
            } => {
                assert_eq!(virt_port, Some(9736));
                assert_eq!(listen_peers, 2);
                assert!(dials.is_empty());
                let decoded = message.decode();
                assert_eq!(decoded.body, Body::Psbt(b"from-b".to_vec()));
                assert_eq!(
                    decoded.extensions.records(),
                    &[Extension {
                        ty: 1,
                        value: b"optional".to_vec(),
                    }]
                );
                assert!(duplicate);
                assert_eq!(expect, 3);
            }
            _ => panic!("expected a gossip command"),
        }
    }

    /// A dial-only gossip node needs no listen side; `--dial` repeats.
    #[test]
    fn cli_parsing_accepts_dial_only_gossip() {
        let onion = format!("{:a<56}.onion:9736", "host");
        let cli = parse_args(
            [
                "fungi-harness",
                "gossip",
                "--plugin",
                "/nix/store/xxx/bin/fungi-socks5h-plugin",
                "--dial",
                &onion,
                "--message-type",
                "payment",
                "--message",
                "from-a",
                "--expect",
                "3",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match cli.cmd {
            Cmd::Gossip {
                virt_port, dials, ..
            } => {
                assert_eq!(virt_port, None);
                assert_eq!(dials.len(), 1);
            }
            _ => panic!("expected a gossip command"),
        }
    }

    /// The generic flags parse without a backend selector: `--state-dir` and
    /// `--private-net` are backend-agnostic and reach the plugin via env.
    #[test]
    fn cli_parsing_accepts_generic_flags() {
        let cli = parse_args(
            [
                "fungi-harness",
                "dial",
                "--plugin",
                "/nix/store/xxx/bin/fungi-socks5h-plugin",
                "--private-net",
                "/tmp/private-net",
                "--state-dir",
                "/tmp/arti-dial",
                &format!("{:a<56}.onion:9735", "host"),
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        assert_eq!(
            cli.private_net.as_deref(),
            Some(std::path::Path::new("/tmp/private-net"))
        );
        assert_eq!(
            cli.state_dir.as_deref(),
            Some(std::path::Path::new("/tmp/arti-dial"))
        );
    }

    /// The harness's generic `run_listen`/`run_dial` drive the SAME
    /// [`CapnpTransport`](fungi_transport_capnp::CapnpTransport) handle that the
    /// real plugin path returns from `connect_plugin`. Here the plugin server is
    /// an in-process `serve_plugin(MemTransport)` reached over a duplex rather
    /// than a subprocess's stdio; the subprocess topology itself is covered by
    /// the capnp crate's `connect_plugin` subprocess tests. This proves the
    /// harness's drive path works over the capnp transport handle end to end,
    /// locally.
    #[tokio::test]
    async fn run_listen_and_run_dial_over_capnp_plugin() {
        use fungi_transport::ListenParams;
        use fungi_transport::mem::{MemAddr, MemConfig, MemTransport};
        use fungi_transport_capnp::{CapnpTransport, serve_plugin};

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        // `serve_plugin` is `!Send`; drive it on its own current-thread runtime.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building the server runtime");
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                let (reader, writer) = tokio::io::split(server_io);
                let cfg = MemConfig {
                    capacity: Some(16),
                    ..MemConfig::default()
                };
                serve_plugin(MemTransport::new(cfg), reader, writer).await;
            });
        });

        let transport: CapnpTransport<MemAddr> = CapnpTransport::connect(client_io);
        let connector = transport.connector();
        let listen = tokio::spawn(run_listen(transport, ListenParams::new(1), 1));
        // The dialer connects, runs the sequence, then drops — the echo side sees
        // the close and run_listen returns Ok.
        run_dial(connector, &MemAddr).await.unwrap();
        listen.await.unwrap().unwrap();
    }

    /// A 3-node line over the mem transport: B listens for 2 links, A and C
    /// dial in, all three converge on the same set through B.
    #[tokio::test]
    async fn run_gossip_converges_over_mem() {
        use fungi_transport::mem::{MemAddr, MemConfig, MemTransport};
        let transport = MemTransport::new(MemConfig {
            capacity: Some(16),
            ..MemConfig::default()
        });
        let conn_a = transport.connector();
        let conn_c = transport.connector();
        let encode = |body| CanonicalMessage::encode(&Message::new(body)).unwrap();
        let b_message = CanonicalMessage::encode(&Message {
            body: Body::Psbt(b"from-b".to_vec()),
            extensions: Extensions::new(vec![Extension {
                ty: 1,
                value: b"optional".to_vec(),
            }])
            .unwrap(),
        })
        .unwrap();
        let b = tokio::spawn(run_gossip(transport, Some(1), 2, &[], b_message, true, 3));
        let dial_gossip = |conn: fungi_transport::mem::MemConnector, message: CanonicalMessage| async move {
            let ch = conn.connect(&MemAddr).await.unwrap();
            let mut node = GossipBroadcast::new(vec![ch]);
            let set = collect_gossip(&mut node, &message, false, 3).await.unwrap();
            node.shutdown().await.unwrap();
            set
        };
        let (sa, sc) = tokio::join!(
            dial_gossip(conn_a, encode(Body::Payment(b"from-a".to_vec()))),
            dial_gossip(conn_c, encode(Body::Confirmation(b"from-c".to_vec())))
        );
        b.await.unwrap().unwrap();
        assert_eq!(sa, sc);
        assert_eq!(sa.len(), 3);
    }

    // A locally complete set is not enough to print OK: an owed forward may
    // still fail during drain, and that failure must reach the command caller.
    #[tokio::test]
    async fn gossip_shutdown_propagates_an_unflushed_forward() {
        use fungi_transport::BroadcastChannel;
        use fungi_transport::mem::{MemConfig, duplex};

        let (ab, _ba) = duplex(MemConfig::default());
        ab.fail_next(1);
        let mut node = GossipBroadcast::new(vec![ab]);
        node.send(b"owed").await.unwrap();

        let error = shutdown_gossip(node).await.unwrap_err();
        assert!(
            error.contains("shutdown drain failed: gossip forward on link 0 failed"),
            "unexpected shutdown diagnostic: {error}"
        );
    }
}
