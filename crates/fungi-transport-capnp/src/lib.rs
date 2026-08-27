//! A Cap'n Proto plugin layer for the fungi transport crates.
//!
//! capnp-rpc is single-threaded and `!Send` (it is built on `Rc`), yet the
//! [`fungi_transport`] traits require their futures to be `Send`. This crate
//! bridges the two with a "Send bridge": each capnp-rpc connection is driven by
//! a dedicated actor OS thread running a `current_thread` runtime plus a
//! [`LocalSet`](tokio::task::LocalSet), and the `Send` client handles proxy
//! each trait call to it over a [`tokio::sync::mpsc`] command channel plus a
//! [`oneshot`] reply. Because only a command and its
//! reply — both `Send` — cross the trait boundary, the returned futures are
//! `Send` while the capnp machinery stays confined to its thread.
//!
//! The whole [`fungi_transport::Transport`] factory graph is bridged this way.
//! A single actor thread hosts one capnp-rpc connection and therefore the whole
//! `!Send` capability graph reachable through it: the `Transport`, and every
//! `Connector`/`Listener`/`Channel` derived from it. The actor keeps those
//! capabilities in a `Registry` keyed by a small integer id; each client
//! handle ([`CapnpTransport`], [`CapnpConnector`], [`CapnpListener`],
//! [`CapnpChannel`]) carries that id plus a clone of the command sender, and a
//! command references its capability by id. Because every handle holds a sender
//! clone, the actor loop runs until the last handle for a connection is
//! dropped; each handle's `Drop` also releases its stored capability so the
//! remote server tears the matching object down.
//!
//! Commands that create or destroy nothing capnp-blocking (`connector`) are
//! served inline; the rest are dispatched as `spawn_local` tasks so that
//! independent calls — a `connect` racing an `accept`, two channels in flight —
//! make progress concurrently on the one thread rather than head-of-line
//! blocking each other.
//!
//! The server end is provided by [`serve_loopback`] and [`serve_backend`] (a
//! single [`Channel`] backend, from the Channel-only phase) and [`serve_plugin`]
//! (an arbitrary [`Transport`] backend exposed as the whole capnp graph).
//!
//! The opening contract passes through unchanged: this layer only proxies a
//! backend, so a channel's anonymity and authentication guarantees are
//! whatever the plugged backend provides. The capnp link itself (stdio to a
//! child process, or an in-memory duplex) is same-host plumbing inside the
//! trust base, not a network boundary.
//!
//! A plugin can run either in-process — over an in-memory duplex, driven by
//! [`serve_plugin`] on a background thread — or as a real child process:
//! [`connect_plugin`] spawns a program, speaks capnp-rpc over its stdin/stdout,
//! and returns the same [`CapnpTransport`], while the child runs
//! [`serve_plugin`] over its own stdio. Both paths share the one client actor
//! loop; only the transport source differs (an in-memory server vs a
//! bootstrapped remote `Plugin`).

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::str::FromStr;

use capnp::capability::Promise;
use capnp_rpc::{RpcSystem, pry, rpc_twoparty_capnp::Side, twoparty};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use fungi_transport::framed::DEFAULT_MAX_MSG_LEN;
use fungi_transport::mem::MemAddr;
use fungi_transport::{
    Channel, ConnectError, Connector, ListenParams, Listener, RecvError, SendError, Transport,
};

/// Generated code for `channel.capnp`.
mod channel_capnp {
    #![allow(clippy::all)]
    #![allow(missing_docs)]
    #![allow(dead_code)]
    #![allow(missing_debug_implementations)]
    include!(concat!(env!("OUT_DIR"), "/channel_capnp.rs"));
}
use channel_capnp::{channel, connector, listener, plugin, test_fixtures, transport};

/// Depth of the command queue feeding an actor thread. Commands are small and
/// consumed promptly; a little slack avoids needless wakeups.
const COMMAND_QUEUE_DEPTH: usize = 32;

/// The capability id reserved for the connection's bootstrap object (a
/// `Channel` for [`CapnpChannel::connect`], a `Transport` for
/// [`CapnpTransport::connect`]). Ids for derived capabilities start above it.
const BOOTSTRAP_ID: u64 = 0;

// ---------------------------------------------------------------------------
// Client actor: command protocol, capability registry, dispatch loop
// ---------------------------------------------------------------------------

/// A request sent from a client handle to its actor thread, carrying a one-shot
/// channel on which the actor returns the capnp call's result. Every command
/// names the capability it acts on by its [`Registry`] id.
enum Command {
    /// `transport.connector()` — store the new connector, return its id.
    Connector {
        transport_id: u64,
        reply: oneshot::Sender<u64>,
    },
    /// `transport.listen(..)` — store the new listener, return its id together
    /// with the published address text (from `listener.onionAddr()`).
    Listen {
        transport_id: u64,
        virt_port: u16,
        nickname: Option<String>,
        reply: oneshot::Sender<Result<(u64, String), ConnectError>>,
    },
    /// `connector.connect(addr)` — store the new channel, return its id.
    Connect {
        connector_id: u64,
        addr: String,
        reply: oneshot::Sender<Result<u64, ConnectError>>,
    },
    /// `listener.accept()` — store the new channel, return its id.
    Accept {
        listener_id: u64,
        reply: oneshot::Sender<Result<u64, ConnectError>>,
    },
    /// `channel.send(msg)`.
    Send {
        channel_id: u64,
        msg: Vec<u8>,
        reply: oneshot::Sender<Result<(), SendError>>,
    },
    /// `channel.recv()`.
    Recv {
        channel_id: u64,
        reply: oneshot::Sender<Result<Vec<u8>, RecvError>>,
    },
    /// Drop a stored capability (and any per-channel receive state) so the
    /// remote server tears its object down. Sent by a handle's `Drop`.
    Release { id: u64 },
    /// `plugin.fixtures().configurePrivateNet(netFile)` — a test-only fixture
    /// call, distinct from the primary transport API, carried to the plugin's
    /// `TestFixtures` capability. Only meaningful for a `Plugin` bootstrap.
    ConfigurePrivateNet {
        net_file: Vec<u8>,
        reply: oneshot::Sender<Result<(), ConnectError>>,
    },
}

/// What the actor bootstraps from the remote vat and stores at
/// [`BOOTSTRAP_ID`].
enum Bootstrap {
    /// The bootstrap capability is a `Channel` (Channel-only clients).
    Channel,
    /// The bootstrap capability is a `Plugin`; its `transport()` is pipelined
    /// into the `Transport` stored at [`BOOTSTRAP_ID`].
    Plugin,
}

/// Per-channel receive state that keeps `recv` cancel-safe and serialized.
///
/// At most one capnp `recv` is ever outstanding per channel: a `recv` command
/// arriving while one is in flight simply replaces the waiter (the `&mut self`
/// contract guarantees the previous caller's future was dropped). When the
/// in-flight call resolves, its message goes to the current waiter, or — if the
/// caller has since abandoned it — into `buffer` for the next `recv`, so a
/// dropped `recv` future never loses a message.
#[derive(Default)]
struct RecvState {
    in_flight: bool,
    waiter: Option<oneshot::Sender<Result<Vec<u8>, RecvError>>>,
    buffer: VecDeque<Vec<u8>>,
}

/// The `!Send` capability graph for one capnp connection, owned by its actor
/// thread. Capabilities are keyed by an id the client handles carry.
#[derive(Default)]
struct Registry {
    next_id: u64,
    transports: HashMap<u64, transport::Client>,
    connectors: HashMap<u64, connector::Client>,
    listeners: HashMap<u64, listener::Client>,
    channels: HashMap<u64, channel::Client>,
    recv_states: HashMap<u64, RecvState>,
}

impl Registry {
    fn new() -> Self {
        Self {
            next_id: BOOTSTRAP_ID + 1,
            ..Default::default()
        }
    }

    /// Allocate a fresh id for a newly created capability.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

/// Build the `current_thread` runtime + `LocalSet` and run the client actor to
/// completion on this thread.
fn run_client_actor<R, W>(reader: R, writer: W, boot: Bootstrap, rx: mpsc::Receiver<Command>)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building the capnp client runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, client_actor(reader, writer, boot, rx));
}

/// The client actor: bootstrap the remote capability, then translate each
/// [`Command`] into a capnp call against the [`Registry`].
///
/// The loop only ever awaits `rx.recv()`; each command is either served inline
/// or dispatched as a `spawn_local` task, so the loop never head-of-line blocks
/// on an in-flight call and independent calls proceed concurrently. When the
/// last client handle drops, `rx` closes, the loop ends, and returning drops
/// the `LocalSet` — tearing down the RPC system and any parked task, so a drop
/// even mid-`recv` cleanly closes the connection.
async fn client_actor<R, W>(reader: R, writer: W, boot: Bootstrap, mut rx: mpsc::Receiver<Command>)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    let network = twoparty::VatNetwork::new(
        reader.compat(),
        writer.compat_write(),
        Side::Client,
        Default::default(),
    );
    let mut rpc_system = RpcSystem::new(Box::new(network), None);
    let registry = Rc::new(RefCell::new(Registry::new()));

    // Kept in scope so the bootstrap plugin capability outlives the pipelined
    // transport that was derived from it; it is also the capability
    // `ConfigurePrivateNet` drives its `fixtures()` from.
    let plugin_cap: Option<plugin::Client> = match boot {
        Bootstrap::Channel => {
            let channel: channel::Client = rpc_system.bootstrap(Side::Server);
            registry.borrow_mut().channels.insert(BOOTSTRAP_ID, channel);
            None
        }
        Bootstrap::Plugin => {
            let plugin: plugin::Client = rpc_system.bootstrap(Side::Server);
            let transport = plugin.transport_request().send().pipeline.get_transport();
            registry
                .borrow_mut()
                .transports
                .insert(BOOTSTRAP_ID, transport);
            Some(plugin)
        }
    };

    // Drive the RPC system alongside the command loop; it resolves (ending its
    // task) when the connection drops.
    tokio::task::spawn_local(async move {
        let _ = rpc_system.await;
    });

    while let Some(cmd) = rx.recv().await {
        match cmd {
            Command::Connector {
                transport_id,
                reply,
            } => {
                // Pure capnp pipelining — no await — so serve it inline.
                let mut reg = registry.borrow_mut();
                if let Some(transport) = reg.transports.get(&transport_id).cloned() {
                    let connector = transport
                        .connector_request()
                        .send()
                        .pipeline
                        .get_connector();
                    let id = reg.alloc_id();
                    reg.connectors.insert(id, connector);
                    let _ = reply.send(id);
                }
            }

            Command::Listen {
                transport_id,
                virt_port,
                nickname,
                reply,
            } => {
                let transport = registry.borrow().transports.get(&transport_id).cloned();
                let registry = registry.clone();
                tokio::task::spawn_local(async move {
                    let Some(transport) = transport else {
                        let _ = reply.send(Err(ConnectError::Unreachable));
                        return;
                    };
                    let mut req = transport.listen_request();
                    {
                        let mut b = req.get();
                        b.set_virt_port(virt_port);
                        b.set_nickname(nickname.as_deref().unwrap_or(""));
                    }
                    let listener = match req.send().promise.await {
                        Ok(resp) => match resp.get().and_then(|r| r.get_listener()) {
                            Ok(l) => l,
                            Err(e) => {
                                let _ = reply.send(Err(map_connect_error(e)));
                                return;
                            }
                        },
                        Err(e) => {
                            let _ = reply.send(Err(map_connect_error(e)));
                            return;
                        }
                    };
                    let addr = match listener.onion_addr_request().send().promise.await {
                        Ok(resp) => match resp.get().and_then(|r| r.get_addr()).and_then(|t| {
                            t.to_str().map(|s| s.to_owned()).map_err(capnp::Error::from)
                        }) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = reply.send(Err(map_connect_error(e)));
                                return;
                            }
                        },
                        Err(e) => {
                            let _ = reply.send(Err(map_connect_error(e)));
                            return;
                        }
                    };
                    let id = {
                        let mut reg = registry.borrow_mut();
                        let id = reg.alloc_id();
                        reg.listeners.insert(id, listener);
                        id
                    };
                    let _ = reply.send(Ok((id, addr)));
                });
            }

            Command::Connect {
                connector_id,
                addr,
                reply,
            } => {
                let connector = registry.borrow().connectors.get(&connector_id).cloned();
                let registry = registry.clone();
                tokio::task::spawn_local(async move {
                    let Some(connector) = connector else {
                        let _ = reply.send(Err(ConnectError::Unreachable));
                        return;
                    };
                    let mut req = connector.connect_request();
                    req.get().set_addr(addr.as_str());
                    let channel = match req.send().promise.await {
                        Ok(resp) => match resp.get().and_then(|r| r.get_channel()) {
                            Ok(ch) => ch,
                            Err(e) => {
                                let _ = reply.send(Err(map_connect_error(e)));
                                return;
                            }
                        },
                        Err(e) => {
                            let _ = reply.send(Err(map_connect_error(e)));
                            return;
                        }
                    };
                    let id = {
                        let mut reg = registry.borrow_mut();
                        let id = reg.alloc_id();
                        reg.channels.insert(id, channel);
                        id
                    };
                    let _ = reply.send(Ok(id));
                });
            }

            Command::Accept { listener_id, reply } => {
                let listener = registry.borrow().listeners.get(&listener_id).cloned();
                let registry = registry.clone();
                tokio::task::spawn_local(async move {
                    let Some(listener) = listener else {
                        let _ = reply.send(Err(ConnectError::Unreachable));
                        return;
                    };
                    let channel = match listener.accept_request().send().promise.await {
                        Ok(resp) => match resp.get().and_then(|r| r.get_channel()) {
                            Ok(ch) => ch,
                            Err(e) => {
                                let _ = reply.send(Err(map_connect_error(e)));
                                return;
                            }
                        },
                        Err(e) => {
                            let _ = reply.send(Err(map_connect_error(e)));
                            return;
                        }
                    };
                    let id = {
                        let mut reg = registry.borrow_mut();
                        let id = reg.alloc_id();
                        reg.channels.insert(id, channel);
                        id
                    };
                    let _ = reply.send(Ok(id));
                });
            }

            Command::Send {
                channel_id,
                msg,
                reply,
            } => {
                let channel = registry.borrow().channels.get(&channel_id).cloned();
                tokio::task::spawn_local(async move {
                    let Some(channel) = channel else {
                        let _ = reply.send(Err(SendError::Closed));
                        return;
                    };
                    let mut req = channel.send_request();
                    req.get().set_msg(&msg);
                    let result = req.send().promise.await.map(|_| ()).map_err(map_send_error);
                    let _ = reply.send(result);
                });
            }

            Command::Recv { channel_id, reply } => {
                // Decide inline what to do, holding the registry borrow only
                // long enough to inspect/update the per-channel receive state.
                let channel = {
                    let mut reg = registry.borrow_mut();
                    {
                        let state = reg.recv_states.entry(channel_id).or_default();
                        if let Some(msg) = state.buffer.pop_front() {
                            // A message pulled for an abandoned caller reaches
                            // the next one; re-buffer if this caller is gone too.
                            drop(reg);
                            if let Err(Ok(msg)) = reply.send(Ok(msg)) {
                                registry
                                    .borrow_mut()
                                    .recv_states
                                    .entry(channel_id)
                                    .or_default()
                                    .buffer
                                    .push_front(msg);
                            }
                            continue;
                        }
                        state.waiter = Some(reply);
                        if state.in_flight {
                            // The outstanding call will deliver to this waiter.
                            continue;
                        }
                        state.in_flight = true;
                    }
                    reg.channels.get(&channel_id).cloned()
                };

                let registry = registry.clone();
                tokio::task::spawn_local(async move {
                    let result = match channel {
                        Some(channel) => match channel.recv_request().send().promise.await {
                            Ok(resp) => resp
                                .get()
                                .and_then(|r| r.get_msg().map(|m| m.to_vec()))
                                .map_err(map_recv_error),
                            Err(e) => Err(map_recv_error(e)),
                        },
                        None => Err(RecvError::Closed),
                    };
                    let mut reg = registry.borrow_mut();
                    // The channel may have been released while this recv was in
                    // flight; its state is then gone. Look it up rather than
                    // re-creating it — an `entry().or_default()` here would
                    // resurrect the entry Release removed and leak it for the
                    // connection's life. If it's gone, drop the message.
                    let Some(state) = reg.recv_states.get_mut(&channel_id) else {
                        return;
                    };
                    state.in_flight = false;
                    match state.waiter.take() {
                        // A dropped waiter loses no message: a successful one is
                        // buffered for the next `recv` (an error is discarded).
                        Some(w) => {
                            if let Err(Ok(msg)) = w.send(result) {
                                state.buffer.push_back(msg);
                            }
                        }
                        None => {
                            if let Ok(msg) = result {
                                state.buffer.push_back(msg);
                            }
                        }
                    }
                });
            }

            Command::Release { id } => {
                let mut reg = registry.borrow_mut();
                reg.transports.remove(&id);
                reg.connectors.remove(&id);
                reg.listeners.remove(&id);
                reg.channels.remove(&id);
                reg.recv_states.remove(&id);
            }

            Command::ConfigurePrivateNet { net_file, reply } => {
                // Fixtures live only behind a `Plugin` bootstrap; a Channel-only
                // client has no fixtures capability to drive.
                let Some(plugin) = plugin_cap.clone() else {
                    let _ = reply.send(Err(ConnectError::Unreachable));
                    continue;
                };
                tokio::task::spawn_local(async move {
                    let fixtures = plugin.fixtures_request().send().pipeline.get_fixtures();
                    let mut req = fixtures.configure_private_net_request();
                    req.get().set_net_file(&net_file);
                    let result = req
                        .send()
                        .promise
                        .await
                        .map(|_| ())
                        .map_err(map_connect_error);
                    let _ = reply.send(result);
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error mapping (client <-> capnp <-> backend)
// ---------------------------------------------------------------------------

/// A capnp `Disconnected` maps to a closed channel; anything else is an opaque
/// transport error.
fn map_send_error(e: capnp::Error) -> SendError {
    if matches!(e.kind, capnp::ErrorKind::Disconnected) {
        SendError::Closed
    } else {
        SendError::Transport(e.to_string().into())
    }
}

/// See [`map_send_error`]; the same rule for the receive side.
fn map_recv_error(e: capnp::Error) -> RecvError {
    if matches!(e.kind, capnp::ErrorKind::Disconnected) {
        RecvError::Closed
    } else {
        RecvError::Transport(e.to_string().into())
    }
}

/// A capnp `Disconnected` maps to an unreachable peer; anything else is an
/// opaque transport error.
fn map_connect_error(e: capnp::Error) -> ConnectError {
    if matches!(e.kind, capnp::ErrorKind::Disconnected) {
        ConnectError::Unreachable
    } else {
        ConnectError::Transport(e.to_string().into())
    }
}

/// Server-side: a backend `Closed` becomes a capnp `Disconnected` so the
/// client reconstructs it as [`SendError::Closed`]; other failures stay
/// `Failed` (which the client maps to `Transport`).
fn backend_send_error_to_capnp(e: SendError) -> capnp::Error {
    match e {
        SendError::Closed => capnp::Error::disconnected("channel closed".into()),
        other => capnp::Error::failed(other.to_string()),
    }
}

/// See [`backend_send_error_to_capnp`]; the same rule for the receive side.
fn backend_recv_error_to_capnp(e: RecvError) -> capnp::Error {
    match e {
        RecvError::Closed => capnp::Error::disconnected("channel closed".into()),
        other => capnp::Error::failed(other.to_string()),
    }
}

/// Server-side: an `Unreachable` becomes a capnp `Disconnected` so the client
/// reconstructs it as [`ConnectError::Unreachable`]; other failures stay
/// `Failed` (which the client maps to `Transport`).
fn backend_connect_error_to_capnp(e: ConnectError) -> capnp::Error {
    match e {
        ConnectError::Unreachable => capnp::Error::disconnected("peer unreachable".into()),
        other => capnp::Error::failed(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Client handles implementing the fungi-transport traits
// ---------------------------------------------------------------------------

/// A [`Transport`] whose factory calls are carried over capnp-rpc to a plugin
/// server (see [`serve_plugin`]). The remote `Transport` capability lives on
/// this connection's actor thread; this handle only holds a `Send` command
/// channel to it.
///
/// `A` is the address type the graph exchanges: it is sent as text (via
/// [`Display`]) on `connect` and parsed back (via [`FromStr`]) from the
/// published listener address. It defaults to [`MemAddr`] for the in-memory
/// backend; real onion-address backends substitute their own.
#[derive(Debug)]
pub struct CapnpTransport<A = MemAddr> {
    tx: mpsc::Sender<Command>,
    transport_id: u64,
    /// The adapter's known maximum message size. It bounds `send` locally on
    /// every channel derived from this transport, so an oversized message is
    /// rejected here rather than round-tripped to the plugin.
    max_msg_len: usize,
    _addr: PhantomData<fn() -> A>,
}

impl<A> CapnpTransport<A>
where
    A: FromStr + Display + Send + Sync + 'static,
{
    /// Connect a `CapnpTransport` over `io`, whose peer must run a plugin
    /// server (see [`serve_plugin`]).
    ///
    /// This spawns the connection's actor thread and pipelines the plugin's
    /// `transport()` immediately, so the handle is usable without a round trip;
    /// the first factory call resolves it.
    ///
    /// Channels derived from this transport use the default maximum message
    /// size; use [`connect_with`](Self::connect_with) to pick another.
    pub fn connect<Io>(io: Io) -> Self
    where
        Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::connect_with(io, DEFAULT_MAX_MSG_LEN)
    }

    /// Like [`connect`](Self::connect), but with an explicit maximum message
    /// size that bounds `send` on every channel derived from this transport.
    pub fn connect_with<Io>(io: Io, max_msg_len: usize) -> Self
    where
        Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (tx, rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let (reader, writer) = tokio::io::split(io);
        std::thread::spawn(move || run_client_actor(reader, writer, Bootstrap::Plugin, rx));
        Self {
            tx,
            transport_id: BOOTSTRAP_ID,
            max_msg_len,
            _addr: PhantomData,
        }
    }

    /// Drive the plugin's `TestFixtures.configurePrivateNet` with `net_file`:
    /// a test-only hook, separate from the primary transport API, that installs
    /// a private test network in the plugin before its transport is first used.
    /// The bytes are opaque here — the backend parses them. A backend that needs
    /// no such setup treats the call as a no-op. Errors (or a non-plugin peer)
    /// surface as [`ConnectError`].
    ///
    /// Call it before the first `connector`/`listen`, since a backend may fix
    /// its network only once (arti's authorities must be set before its one
    /// bootstrap).
    pub async fn configure_private_net(&self, net_file: &[u8]) -> Result<(), ConnectError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::ConfigurePrivateNet {
                net_file: net_file.to_vec(),
                reply,
            })
            .await
            .map_err(|_| ConnectError::Unreachable)?;
        rx.await.map_err(|_| ConnectError::Unreachable)?
    }
}

/// Spawn a plugin child process and connect a [`CapnpTransport`] to it over the
/// child's stdin/stdout.
///
/// `command` is the program to run; its stdin and stdout are overridden with
/// pipes to carry capnp-rpc, and its stderr is inherited so a plugin panic is
/// visible on the parent's stderr. The child speaks the server side of the
/// plugin protocol (see [`serve_plugin`]).
///
/// The child is spawned inside the connection's actor thread — the same
/// `current_thread` runtime that drives the RPC system — because a child's
/// piped stdin/stdout are bound to the runtime that creates them and cannot be
/// moved to another. The returned handle is therefore usable immediately; the
/// plugin's `transport()` is pipelined and resolved by the first factory call.
///
/// A child that cannot be spawned, or that exits before the capnp handshake
/// completes, surfaces as [`ConnectError::Unreachable`] on the first transport
/// operation (never a hang or a panic). A mid-session disconnect maps to a
/// closed channel, as with the in-process path.
///
/// Channels derived from the returned transport use the default maximum message
/// size; use [`connect_plugin_with`] to pick another.
pub fn connect_plugin<A>(command: tokio::process::Command) -> CapnpTransport<A>
where
    A: FromStr + Display + Send + Sync + 'static,
{
    connect_plugin_with(command, DEFAULT_MAX_MSG_LEN)
}

/// Like [`connect_plugin`], but with an explicit maximum message size that
/// bounds `send` on every channel derived from the returned transport (an
/// oversized message is rejected by the adapter before the RPC).
pub fn connect_plugin_with<A>(
    mut command: tokio::process::Command,
    max_msg_len: usize,
) -> CapnpTransport<A>
where
    A: FromStr + Display + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the capnp client runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                // The actor loop reaps the child deterministically on its normal
                // return (start_kill + wait below). kill_on_drop is the fallback
                // for the one path that skips it: an unexpected panic unwinding
                // this thread after spawn — the Child's drop then still kills the
                // plugin instead of orphaning it.
                .kill_on_drop(true);
            // A spawn failure drops `rx`; the first factory call then fails its
            // `tx.send` and reports `Unreachable`. The error is logged (not
            // swallowed silently) so a real backend launch failure is
            // debuggable on the parent's stderr.
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(err) => {
                    eprintln!("connect_plugin: failed to spawn plugin process: {err}");
                    return;
                }
            };
            let reader = child.stdout.take().expect("child stdout is piped");
            let writer = child.stdin.take().expect("child stdin is piped");

            // `writer` (the child's stdin) is moved into the actor loop and
            // dropped when it returns, delivering stdin-EOF to the plugin. The
            // `child` handle is kept alive past the loop so it can then be reaped
            // deterministically inside this still-live runtime: `start_kill` +
            // `wait` guarantee no orphan even if the plugin ignores EOF.
            client_actor(reader, writer, Bootstrap::Plugin, rx).await;
            let _ = child.start_kill();
            let _ = child.wait().await;
        });
    });
    CapnpTransport {
        tx,
        transport_id: BOOTSTRAP_ID,
        max_msg_len,
        _addr: PhantomData,
    }
}

impl<A> Transport for CapnpTransport<A>
where
    A: FromStr + Display + Send + Sync + 'static,
{
    type Addr = A;
    type Connector = CapnpConnector<A>;
    type Listener = CapnpListener;

    fn connector(&self) -> CapnpConnector<A> {
        CapnpConnector {
            tx: self.tx.clone(),
            transport_id: self.transport_id,
            connector_id: tokio::sync::OnceCell::new(),
            max_msg_len: self.max_msg_len,
            _addr: PhantomData,
        }
    }

    fn listen(
        &self,
        params: ListenParams,
    ) -> impl Future<Output = Result<(CapnpListener, A), ConnectError>> + Send {
        let tx = self.tx.clone();
        let transport_id = self.transport_id;
        let max_msg_len = self.max_msg_len;
        async move {
            let (reply, rx) = oneshot::channel();
            tx.send(Command::Listen {
                transport_id,
                virt_port: params.virt_port,
                nickname: params.nickname,
                reply,
            })
            .await
            .map_err(|_| ConnectError::Unreachable)?;
            let (listener_id, addr_text) = rx.await.map_err(|_| ConnectError::Unreachable)??;
            let addr = addr_text.parse().map_err(|_| {
                ConnectError::Transport(
                    format!("unparseable listener address: {addr_text:?}").into(),
                )
            })?;
            Ok((
                CapnpListener {
                    tx,
                    listener_id,
                    max_msg_len,
                },
                addr,
            ))
        }
    }
}

/// A [`Connector`] carried over capnp-rpc. The remote connector capability is
/// created lazily — on first `connect` — and reused thereafter, so a handle
/// obtained from [`Transport::connector`] costs nothing until used.
#[derive(Debug)]
pub struct CapnpConnector<A = MemAddr> {
    tx: mpsc::Sender<Command>,
    transport_id: u64,
    connector_id: tokio::sync::OnceCell<u64>,
    max_msg_len: usize,
    _addr: PhantomData<fn() -> A>,
}

impl<A> CapnpConnector<A> {
    /// Resolve (once) and return the remote connector's registry id.
    async fn ensure_connector(&self) -> Result<u64, ConnectError> {
        self.connector_id
            .get_or_try_init(|| async {
                let (reply, rx) = oneshot::channel();
                self.tx
                    .send(Command::Connector {
                        transport_id: self.transport_id,
                        reply,
                    })
                    .await
                    .map_err(|_| ConnectError::Unreachable)?;
                rx.await.map_err(|_| ConnectError::Unreachable)
            })
            .await
            .copied()
    }
}

impl<A> Connector for CapnpConnector<A>
where
    A: Display + Send + Sync + 'static,
{
    type Addr = A;
    type Channel = CapnpChannel;

    fn connect(&self, addr: &A) -> impl Future<Output = Result<CapnpChannel, ConnectError>> + Send {
        let addr_text = addr.to_string();
        async move {
            let connector_id = self.ensure_connector().await?;
            let (reply, rx) = oneshot::channel();
            self.tx
                .send(Command::Connect {
                    connector_id,
                    addr: addr_text,
                    reply,
                })
                .await
                .map_err(|_| ConnectError::Unreachable)?;
            let channel_id = rx.await.map_err(|_| ConnectError::Unreachable)??;
            Ok(CapnpChannel {
                tx: self.tx.clone(),
                channel_id,
                max_msg_len: self.max_msg_len,
            })
        }
    }
}

impl<A> Drop for CapnpConnector<A> {
    // Best-effort release: `Drop` cannot block or await, so it must use
    // `try_send`. A saturated command queue therefore drops this `Release`,
    // leaking the one remote capability until the connection is torn down.
    // That trade-off is inherent — blocking in `Drop` is not an option.
    fn drop(&mut self) {
        if let Some(&id) = self.connector_id.get() {
            let _ = self.tx.try_send(Command::Release { id });
        }
    }
}

/// A [`Listener`] carried over capnp-rpc. Its remote capability is created by
/// [`Transport::listen`]; each `accept` proxies to it.
#[derive(Debug)]
pub struct CapnpListener {
    tx: mpsc::Sender<Command>,
    listener_id: u64,
    max_msg_len: usize,
}

impl Listener for CapnpListener {
    type Channel = CapnpChannel;

    fn accept(&mut self) -> impl Future<Output = Result<CapnpChannel, ConnectError>> + Send {
        let tx = self.tx.clone();
        let listener_id = self.listener_id;
        let max_msg_len = self.max_msg_len;
        async move {
            let (reply, rx) = oneshot::channel();
            tx.send(Command::Accept { listener_id, reply })
                .await
                .map_err(|_| ConnectError::Unreachable)?;
            let channel_id = rx.await.map_err(|_| ConnectError::Unreachable)??;
            Ok(CapnpChannel {
                tx,
                channel_id,
                max_msg_len,
            })
        }
    }
}

impl Drop for CapnpListener {
    // Best-effort release: see the note on `CapnpConnector`'s `Drop`. A full
    // command queue can drop this `Release`, leaking the remote listener until
    // connection teardown; `Drop` cannot block/await to avoid it.
    fn drop(&mut self) {
        let _ = self.tx.try_send(Command::Release {
            id: self.listener_id,
        });
    }
}

/// A [`Channel`] whose messages are carried over capnp-rpc. The remote channel
/// capability lives on its connection's actor thread; this handle holds only a
/// `Send` command channel to it, which is what lets `send`/`recv` return `Send`
/// futures.
///
/// A `CapnpChannel` is produced either directly by [`CapnpChannel::connect`]
/// (the bootstrap object is a `Channel`) or by a [`CapnpConnector`]/
/// [`CapnpListener`] within a larger graph. Dropping it releases the remote
/// channel object.
#[derive(Debug)]
pub struct CapnpChannel {
    tx: mpsc::Sender<Command>,
    channel_id: u64,
    /// The adapter's known maximum message size; `send` rejects anything larger
    /// locally, before touching the actor.
    max_msg_len: usize,
}

impl CapnpChannel {
    /// Connect a `CapnpChannel` over `io`, whose peer must run a channel server
    /// (see [`serve_loopback`]/[`serve_backend`]).
    ///
    /// This spawns a dedicated actor thread whose bootstrap capability is the
    /// remote `Channel`; the thread drives the capnp-rpc client and services
    /// commands until this handle is dropped. It uses the default maximum
    /// message size; use [`connect_with`](Self::connect_with) to pick another.
    pub fn connect<Io>(io: Io) -> Self
    where
        Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::connect_with(io, DEFAULT_MAX_MSG_LEN)
    }

    /// Like [`connect`](Self::connect), but with an explicit maximum message
    /// size that bounds `send` on this channel.
    pub fn connect_with<Io>(io: Io, max_msg_len: usize) -> Self
    where
        Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (tx, rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let (reader, writer) = tokio::io::split(io);
        std::thread::spawn(move || run_client_actor(reader, writer, Bootstrap::Channel, rx));
        Self {
            tx,
            channel_id: BOOTSTRAP_ID,
            max_msg_len,
        }
    }
}

impl Channel for CapnpChannel {
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        // Reject an oversized message with the adapter's known limit before it
        // ever reaches the actor: the check is local, so no RPC is made. Test
        // the length FIRST, before copying — an oversized message is rejected
        // without ever being allocated.
        let too_large = (msg.len() > self.max_msg_len).then_some(self.max_msg_len);
        let tx = self.tx.clone();
        let channel_id = self.channel_id;
        // Copy only a within-bounds message into the returned `'static` future.
        let msg = too_large.is_none().then(|| msg.to_vec());
        async move {
            let msg = match too_large {
                Some(max) => return Err(SendError::TooLarge { max }),
                None => msg.expect("a within-bounds message is always copied"),
            };
            let (reply, rx) = oneshot::channel();
            tx.send(Command::Send {
                channel_id,
                msg,
                reply,
            })
            .await
            .map_err(|_| SendError::Closed)?;
            rx.await.map_err(|_| SendError::Closed)?
        }
    }

    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
        let tx = self.tx.clone();
        let channel_id = self.channel_id;
        async move {
            let (reply, rx) = oneshot::channel();
            tx.send(Command::Recv { channel_id, reply })
                .await
                .map_err(|_| RecvError::Closed)?;
            rx.await.map_err(|_| RecvError::Closed)?
        }
    }
}

impl Drop for CapnpChannel {
    // Best-effort release: see the note on `CapnpConnector`'s `Drop`. A full
    // command queue can drop this `Release`, leaking the remote channel until
    // connection teardown; `Drop` cannot block/await to avoid it.
    fn drop(&mut self) {
        let _ = self.tx.try_send(Command::Release {
            id: self.channel_id,
        });
    }
}

// ---------------------------------------------------------------------------
// Server side: capnp servers wrapping in-process backends
// ---------------------------------------------------------------------------

/// A trivial in-memory FIFO queue implementing the capnp [`channel::Server`].
/// `recv` on an empty queue fails; a driving client is expected to `recv` only
/// what it has already `send`-ed (as the minimum conformance test does).
struct Loopback {
    queue: std::collections::VecDeque<Vec<u8>>,
}

impl channel::Server for Loopback {
    fn send(
        &mut self,
        params: channel::SendParams,
        _results: channel::SendResults,
    ) -> Promise<(), capnp::Error> {
        let msg = pry!(pry!(params.get()).get_msg()).to_vec();
        self.queue.push_back(msg);
        Promise::ok(())
    }

    fn recv(
        &mut self,
        _params: channel::RecvParams,
        mut results: channel::RecvResults,
    ) -> Promise<(), capnp::Error> {
        match self.queue.pop_front() {
            Some(msg) => {
                results.get().set_msg(&msg);
                Promise::ok(())
            }
            None => Promise::err(capnp::Error::failed("channel empty".into())),
        }
    }
}

/// A capnp [`channel::Server`] that forwards each call to an async [`Channel`]
/// backend.
///
/// The capnp `Server` methods return a `Promise` and cannot borrow an async
/// `&mut self` across an await point, so the backend lives behind an
/// `Rc<Mutex<..>>` shared into a per-call future. This keeps the whole thing on
/// the actor's single thread (the server is `!Send`) while still allowing the
/// backend's `send`/`recv` futures to suspend. The lock cannot deadlock a
/// send against a recv: the `Channel` contract takes `&mut self`, so a single
/// channel never has a send and a recv outstanding at once.
struct BackendServer<C: Channel> {
    backend: Rc<tokio::sync::Mutex<C>>,
}

impl<C: Channel + 'static> channel::Server for BackendServer<C> {
    fn send(
        &mut self,
        params: channel::SendParams,
        _results: channel::SendResults,
    ) -> Promise<(), capnp::Error> {
        let msg = pry!(pry!(params.get()).get_msg()).to_vec();
        let backend = self.backend.clone();
        Promise::from_future(async move {
            backend
                .lock()
                .await
                .send(&msg)
                .await
                .map_err(backend_send_error_to_capnp)
        })
    }

    fn recv(
        &mut self,
        _params: channel::RecvParams,
        mut results: channel::RecvResults,
    ) -> Promise<(), capnp::Error> {
        let backend = self.backend.clone();
        Promise::from_future(async move {
            let msg = backend
                .lock()
                .await
                .recv()
                .await
                .map_err(backend_recv_error_to_capnp)?;
            results.get().set_msg(&msg);
            Ok(())
        })
    }
}

/// Wrap a freshly produced backend channel as a new capnp `Channel` capability.
fn new_channel_client<C: Channel + 'static>(channel: C) -> channel::Client {
    capnp_rpc::new_client(BackendServer {
        backend: Rc::new(tokio::sync::Mutex::new(channel)),
    })
}

/// A capnp [`connector::Server`] forwarding to a [`Connector`] backend. Its
/// address text is parsed back into the backend's native `Addr` via [`FromStr`].
struct ConnectorServer<Co: Connector> {
    connector: Rc<Co>,
}

impl<Co: Connector + 'static> connector::Server for ConnectorServer<Co>
where
    Co::Addr: FromStr,
{
    fn connect(
        &mut self,
        params: connector::ConnectParams,
        mut results: connector::ConnectResults,
    ) -> Promise<(), capnp::Error> {
        let addr_text = pry!(pry!(pry!(params.get()).get_addr()).to_str()).to_owned();
        let addr: Co::Addr = match addr_text.parse() {
            Ok(a) => a,
            Err(_) => return Promise::err(capnp::Error::failed("invalid address".into())),
        };
        let connector = self.connector.clone();
        Promise::from_future(async move {
            let channel = connector
                .connect(&addr)
                .await
                .map_err(backend_connect_error_to_capnp)?;
            results.get().set_channel(new_channel_client(channel));
            Ok(())
        })
    }
}

/// A capnp [`listener::Server`] forwarding to a [`Listener`] backend and
/// serving the published address it was created under.
struct ListenerServer<L: Listener> {
    listener: Rc<tokio::sync::Mutex<L>>,
    addr: String,
}

impl<L: Listener + 'static> listener::Server for ListenerServer<L> {
    fn accept(
        &mut self,
        _params: listener::AcceptParams,
        mut results: listener::AcceptResults,
    ) -> Promise<(), capnp::Error> {
        let listener = self.listener.clone();
        Promise::from_future(async move {
            let channel = listener
                .lock()
                .await
                .accept()
                .await
                .map_err(backend_connect_error_to_capnp)?;
            results.get().set_channel(new_channel_client(channel));
            Ok(())
        })
    }

    fn onion_addr(
        &mut self,
        _params: listener::OnionAddrParams,
        mut results: listener::OnionAddrResults,
    ) -> Promise<(), capnp::Error> {
        results.get().set_addr(self.addr.as_str());
        Promise::ok(())
    }
}

/// A capnp [`transport::Server`] forwarding to a [`Transport`] backend. Its
/// `Addr` must round-trip through capnp text.
struct TransportServer<T: Transport> {
    backend: Rc<T>,
}

impl<T: Transport + 'static> transport::Server for TransportServer<T>
where
    T::Addr: FromStr + Display,
{
    fn connector(
        &mut self,
        _params: transport::ConnectorParams,
        mut results: transport::ConnectorResults,
    ) -> Promise<(), capnp::Error> {
        let connector = self.backend.connector();
        let client: connector::Client = capnp_rpc::new_client(ConnectorServer {
            connector: Rc::new(connector),
        });
        results.get().set_connector(client);
        Promise::ok(())
    }

    fn listen(
        &mut self,
        params: transport::ListenParams,
        mut results: transport::ListenResults,
    ) -> Promise<(), capnp::Error> {
        let params_reader = pry!(params.get());
        let virt_port = params_reader.get_virt_port();
        let nickname = pry!(pry!(params_reader.get_nickname()).to_str()).to_owned();
        let backend = self.backend.clone();
        Promise::from_future(async move {
            let listen_params = ListenParams {
                virt_port,
                nickname: (!nickname.is_empty()).then_some(nickname),
            };
            let (listener, addr) = backend
                .listen(listen_params)
                .await
                .map_err(backend_connect_error_to_capnp)?;
            let client: listener::Client = capnp_rpc::new_client(ListenerServer {
                listener: Rc::new(tokio::sync::Mutex::new(listener)),
                addr: addr.to_string(),
            });
            results.get().set_listener(client);
            Ok(())
        })
    }
}

/// Backend-provided test fixtures: the setup/teardown hooks a harness drives
/// over the plugin's `TestFixtures` capability, kept distinct from the primary
/// transport API. The bytes handed to [`configure_private_net`] are opaque to
/// this layer — the backend parses them. A backend that needs no test-time setup
/// uses [`NoopFixtures`] (the default in [`serve_plugin`]); arti implements this
/// to install a private test network before its one bootstrap.
///
/// [`configure_private_net`]: PluginFixtures::configure_private_net
pub trait PluginFixtures {
    /// Install a private-network descriptor before the transport is first used.
    /// Returns a human-readable message on failure (surfaced as a capnp error).
    fn configure_private_net(&self, net_file: &[u8]) -> Result<(), String>;
    /// Tear down any test state. Defaults to a no-op.
    fn reset(&self) -> Result<(), String> {
        Ok(())
    }
}

/// A [`PluginFixtures`] that does nothing: the default for backends whose test
/// network is set up out of band (e.g. socks5h, whose private Tor net is the
/// system daemon's torrc, or the in-memory backend).
#[derive(Debug)]
pub struct NoopFixtures;

impl PluginFixtures for NoopFixtures {
    fn configure_private_net(&self, _net_file: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

/// Adapts any [`PluginFixtures`] onto the capnp `TestFixtures` server interface.
struct FixturesServer<F> {
    fixtures: Rc<F>,
}

impl<F: PluginFixtures + 'static> test_fixtures::Server for FixturesServer<F> {
    fn configure_private_net(
        &mut self,
        params: test_fixtures::ConfigurePrivateNetParams,
        _results: test_fixtures::ConfigurePrivateNetResults,
    ) -> Promise<(), capnp::Error> {
        let net_file = pry!(pry!(params.get()).get_net_file()).to_vec();
        match self.fixtures.configure_private_net(&net_file) {
            Ok(()) => Promise::ok(()),
            Err(e) => Promise::err(capnp::Error::failed(e)),
        }
    }

    fn reset(
        &mut self,
        _params: test_fixtures::ResetParams,
        _results: test_fixtures::ResetResults,
    ) -> Promise<(), capnp::Error> {
        match self.fixtures.reset() {
            Ok(()) => Promise::ok(()),
            Err(e) => Promise::err(capnp::Error::failed(e)),
        }
    }
}

/// The capnp [`plugin::Server`] bootstrap: exposes a [`Transport`] backend
/// (the primary API) and a [`PluginFixtures`] (the test-only tier).
struct PluginServer<T: Transport, F> {
    backend: Rc<T>,
    fixtures: Rc<F>,
}

impl<T: Transport + 'static, F: PluginFixtures + 'static> plugin::Server for PluginServer<T, F>
where
    T::Addr: FromStr + Display,
{
    fn transport(
        &mut self,
        _params: plugin::TransportParams,
        mut results: plugin::TransportResults,
    ) -> Promise<(), capnp::Error> {
        let client: transport::Client = capnp_rpc::new_client(TransportServer {
            backend: self.backend.clone(),
        });
        results.get().set_transport(client);
        Promise::ok(())
    }

    fn fixtures(
        &mut self,
        _params: plugin::FixturesParams,
        mut results: plugin::FixturesResults,
    ) -> Promise<(), capnp::Error> {
        let client: test_fixtures::Client = capnp_rpc::new_client(FixturesServer {
            fixtures: self.fixtures.clone(),
        });
        results.get().set_fixtures(client);
        Promise::ok(())
    }
}

/// Run an RPC server on a fresh actor thread, bootstrapping `client` as the
/// connection's exported capability. `client` is `!Send` (it is `Rc`-based), so
/// it is built by `make_client` on the server thread; `io` crosses the boundary
/// beforehand and is `Send`.
fn serve<Io, F>(io: Io, make_client: F) -> std::thread::JoinHandle<()>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: FnOnce() -> capnp::capability::Client + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the capnp server runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let (reader, writer) = tokio::io::split(io);
            let network = twoparty::VatNetwork::new(
                reader.compat(),
                writer.compat_write(),
                Side::Server,
                Default::default(),
            );
            let rpc_system = RpcSystem::new(Box::new(network), Some(make_client()));
            let _ = rpc_system.await;
        });
    })
}

/// Serve a simple FIFO loopback channel over `io`. Everything `send`-ed is
/// queued and returned by later `recv` calls, in order. Pair with a
/// [`CapnpChannel::connect`] on the other end of `io`.
pub fn serve_loopback<Io>(io: Io) -> std::thread::JoinHandle<()>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    serve(io, || {
        let client: channel::Client = capnp_rpc::new_client(Loopback {
            queue: Default::default(),
        });
        client.client
    })
}

/// Serve a channel over `io` backed by an arbitrary [`Channel`], so real
/// conformance can run through capnp-rpc. Each capnp `send`/`recv` is forwarded
/// to `backend`. Pair with a [`CapnpChannel::connect`] on the other end of `io`.
pub fn serve_backend<Io, C>(io: Io, backend: C) -> std::thread::JoinHandle<()>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: Channel + 'static,
{
    serve(io, move || new_channel_client(backend).client)
}

/// Serve the whole transport graph over `reader`/`writer` backed by an
/// arbitrary [`Transport`], exposing a `Plugin` bootstrap, and run until the
/// connection closes. Its addresses must round-trip through capnp text
/// ([`FromStr`] + [`Display`]).
///
/// This is the plugin process's entry point: a plugin binary builds a
/// `current_thread` runtime plus a [`LocalSet`](tokio::task::LocalSet) and runs
/// this over its own stdin (`reader`) and stdout (`writer`). Pair it with a
/// [`connect_plugin`] (across a real process boundary) or a
/// [`CapnpTransport::connect`] (in-process) on the other end.
///
/// This future is `!Send` — the capnp machinery is `Rc`-based — so it must be
/// driven on a `current_thread` runtime under a `LocalSet`.
pub async fn serve_plugin<R, W, T>(backend: T, reader: R, writer: W)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
    T: Transport + 'static,
    T::Addr: FromStr + Display,
{
    serve_plugin_with(backend, NoopFixtures, reader, writer).await
}

/// Like [`serve_plugin`], but with a backend-provided [`PluginFixtures`] exposed
/// on the plugin's `TestFixtures` capability. A backend that must set up test
/// resources before its transport is usable (arti installs a private network
/// before its one bootstrap) serves a fixtures value that shares state with a
/// lazily-initialized transport; `serve_plugin` is this with [`NoopFixtures`].
pub async fn serve_plugin_with<R, W, T, F>(backend: T, fixtures: F, reader: R, writer: W)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
    T: Transport + 'static,
    T::Addr: FromStr + Display,
    F: PluginFixtures + 'static,
{
    let network = twoparty::VatNetwork::new(
        reader.compat(),
        writer.compat_write(),
        Side::Server,
        Default::default(),
    );
    let client: plugin::Client = capnp_rpc::new_client(PluginServer {
        backend: Rc::new(backend),
        fixtures: Rc::new(fixtures),
    });
    let rpc_system = RpcSystem::new(Box::new(network), Some(client.client));
    let _ = rpc_system.await;
}
