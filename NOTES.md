# Broadcast channel type shapes: gossip-consumer evaluation

Two probes on this branch implement the same naive epidemic-gossip consumer
against two trait shapes for a P2P channel:

- **Shape A** (`crates/fungi-transport/src/gossip_spike_a.rs`) — the unified
  `Channel` trait already on `main`: one object, `send`/`recv` both behind
  `&mut self`.
- **Shape C** (`crates/fungi-transport/src/gossip_spike_c.rs`) — a split into
  `ChannelSender`/`ChannelReceiver`, each a smaller trait with one method,
  built branch-only against a `split_duplex` mem constructor.

Both probes pass the same two topology tests (line and triangle):

```
running 5 tests
test gossip_spike_c::tests::a_receive_only_relay_is_expressible ... ok
test gossip_spike_a::tests::line_topology_converges ... ok
test gossip_spike_c::tests::line_topology_converges ... ok
test gossip_spike_a::tests::triangle_topology_converges ... ok
test gossip_spike_c::tests::triangle_topology_converges ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.01s
```

## 1. Consumer ergonomics

Task and multiplexing machinery per link, counted directly from the two
`gossip_until` implementations:

| | tasks spawned per link | `tokio::select!` uses | `gossip_until` body |
|---|---|---|---|
| Shape A (`gossip_spike_a.rs:17`) | 1 (`tokio::spawn` at `gossip_spike_a.rs:29`) | 1, inside that one task (`gossip_spike_a.rs:39`) | 78 lines |
| Shape C (`gossip_spike_c.rs:79`) | 2 (`tokio::spawn` at `gossip_spike_c.rs:96` and `:103`) | 0 | 68 lines |

Shape A's single per-link task has to multiplex two independent concerns —
"a command arrived to forward" and "the peer sent something" — behind one
`select!` over an `Event` enum (`gossip_spike_a.rs:34-58`), because `send`
and `recv` share `&mut self` and cannot be awaited from two places at once.
Shape C's two per-link tasks (`gossip_spike_c.rs:96-101` receive,
`:103-108` send) each do one thing in a plain loop; no enum, no `select!`.

Shape C reads simpler *per task* — each task is a five-line loop — but costs
one more task per link and one more channel (the `cmd_tx`/`cmd_rx` pair
still exists in both shapes to carry the hub's forwarding decisions to the
link, so that part is identical). The net line count favors C slightly (68
vs 78 in the function that matters), but the difference is almost entirely
the `Event` enum and match shape A needs to reunify what the split already
kept apart.

The split also paid for itself directly during implementation: both probes'
verbatim `gossip_until` bodies shipped with a task-cleanup bug — the final
hub-to-link forward that completes the message set was queued into a `cmd`
channel and then the link task was `abort()`-ed before it necessarily got to
actually deliver that message, losing it under `#[tokio::test]`'s
single-threaded scheduler (reproduced 5/5 runs before the fix, 8-10/10 after
— see the fix on both files, `gossip_spike_a.rs:84-92` and
`gossip_spike_c.rs:133-144`). The fix is instructive by shape: shape A's one
multiplexed task mixes a cancel-safe operation (`recv`, contract in
`channel.rs:25-27`) and a cancel-UNSAFE one (`send`, contract in
`channel.rs:28-30`) in the same task, so the whole task has to be joined
(drained), not aborted. Shape C's split makes that asymmetry directly
actionable: the receive tasks are still safe to `abort()` outright
(`gossip_spike_c.rs:138-140`), and only the send tasks need joining
(`:141-144`) — the fix is more surgical because the trait split already
separated the two operations onto different tasks.

## 2. Type-state power

`gossip_spike_c.rs:196-210`, `a_receive_only_relay_is_expressible`, builds a
pure relay: it holds `b_r: MemRecvHalf` (received from A's link) and
`relay_out_s: MemSendHalf` (send toward C), and explicitly drops
`b_s_unused` — the half that would let it send back toward A — before ever
spawning the relay task. The type alone proves the relay cannot originate a
message back toward A on that link: it never has a value of the type that
would let it call `send` there. The test spells this out with `// the relay
provably cannot send back toward A`.

Shape A cannot express this. `Channel` (`channel.rs:61-66`) bundles `send`
and `recv` on one object; any value of a type implementing `Channel` always
carries both capabilities. A shape-A relay can be *written* to never call
`send` on a particular channel, but nothing in the type stops it — the
restriction lives in the relay's source code, not its signature. Shape C
turns "this node cannot originate here" from a code-review claim into a
compile-time fact.

## 3. Shared fate

In the mem split (`gossip_spike_c.rs:42-54`, `split_duplex`): A's send half
holds `tx_ab`, A's recv half holds `rx_ba`; B's send half holds `tx_ba`, B's
recv half holds `rx_ab`. A's send half and B's recv half are the two ends of
the *same* underlying `mpsc` channel, and likewise for B's send half and A's
recv half. So: **dropping your own recv half kills the peer's send half**
(their next `send` sees the receiver gone and returns
`SendError::Closed`, per `MemSendHalf::send` at `gossip_spike_c.rs:56-68`)
— **but your own send half is untouched**, because it is paired with the
peer's recv half, not your own. The two halves of one node have
independent fates: dropping one says nothing about the other's health.

This is not acceptable against the channel-death contract as stated for the
unified trait — `channel.rs:32-34` says "any `recv` error, and any other
`send` error, means the channel is DEAD" and `error.rs:37-38` says the same
from the `RecvError` side ("ANY receive error means the channel is dead"),
i.e. the trait's mental model is one dead/alive channel, not two
independently dying halves. Shape C's split channel has no such single "the channel is dead"
fact to observe; a consumer holding only the send half sees nothing wrong
even after the receive half is long gone, until it happens to also lose its
own peer.

A real backend joining these two shapes — say a Tor stream split into a
`DataReader`/`DataWriter` — would have to manufacture the coupling shape C's
mem impl does not have: some shared state (an `Arc<Mutex<..>>` around the
stream, a shared atomic/watch flag, or a call that shuts the whole stream
down) so that either half observing the underlying connection's death marks
*both* halves dead, not just the one that noticed. `tokio::io::split`
already does exactly this for a generic `AsyncRead + AsyncWrite` type — it
wraps the value in `Arc<Mutex<..>>` so both halves talk to the same stream
— but even that only helps up to what the underlying transport actually
guarantees: TCP itself supports half-close (one direction can be closed
while the other differs), so "coupled fates" is deliberate backend work, not
something splitting the type gets for free.

## 4. Implementation burden

Both real backends on this repo already implement `Channel` as one type
wrapping one object: `FramedChannel<S>` (`crates/fungi-transport/src/framed.rs:30`)
requires only `S: AsyncRead + AsyncWrite + Send + Unpin`, and both
`fungi-transport-socks5h` (over a `tokio::net::TcpStream`) and
`fungi-transport-arti` (over an `arti_client::DataStream`) instantiate it
directly — zero extra work for shape A, because the trait already matches
what a socket naturally is.

Shape C would ask each backend for two new types (a send-half wrapper and a
recv-half wrapper) instead of one, plus a split constructor/handshake to
produce them as a coupled pair, plus — per criterion 3 — the shared-state
work to keep their fates linked instead of independent.

The capnp plugin interface already committed to shape A:
`crates/fungi-transport-capnp/channel.capnp:9-12` —

```
interface Channel {
  send @0 (msg :Data) -> ();
  recv @1 () -> (msg :Data);
}
```

— one interface, two methods, mirroring the Rust trait 1:1 (comment at
`channel.capnp:8`). Projecting shape C onto capnp costs more than doubling
the interface count: either two interfaces (`ChannelSender { send @0 }`,
`ChannelReceiver { recv @0 }`) handed out as two independent capability
references from `Connector.connect`/`Listener.accept`, or one "split
handshake" call that returns both — and in either case, capnp capability
references have no notion of two references keeling over together, so the
shared-fate coupling from criterion 3 would have to be re-implemented over
RPC (e.g. the plugin process tracking both references' liveness against one
internal stream and erroring both once either is gone).

## 5. Parked contract questions

**Overflow policy**: the hub in both probes uses a bounded `mpsc::channel(64)`
(`gossip_spike_a.rs:22`, `gossip_spike_c.rs:88`) for both the hub-inbound
channel and each link's forwarding-command channel. Every `send` onto these
is `.await`-ed, so a full buffer applies backpressure to the sender rather
than dropping or erroring. Across both topology tests (3 nodes, up to 2
links each, 3 messages converging) this bounded-and-blocking design never
needed a `Lagged`-style "you fell behind, here's a gap" signal — the
consumer never had to answer "what do I do when I'm too slow," because the
naive gossip volume in these probes never demanded it. This is a parked
question, not a closed one: nothing here proves it stays absorbed at
production message rates or larger fanouts.

**No-echo**: neither probe's hub ever sends a message back out on the link
it arrived from — the forwarding loop is `if j != from` (`gossip_spike_a.rs:74-78`,
`gossip_spike_c.rs:126-130`) — and the initial broadcast of `own` goes out
to every link once, never looped back to the node itself (`own` is inserted
into `set` directly, not received). The gossip consumer never wanted its
own message back, and the no-echo rule already documented for
`BroadcastChannel` (`channel.rs:181`: "the sender does not receive its own
message back") held throughout without the consumer needing to do anything
extra to enforce it.

## Decision

Shape A stays the trait surface on `main`: it is what both real backends
already are (one object wrapping one stream, criterion 4), it is what the
capnp plugin interface already committed to (one interface, two methods,
criterion 4), and its cost is concentrated exactly where the type-state
power shape C offers is not needed by this consumer (criterion 2 — naive
gossip never needs to *prove* a link is receive-only). Shape C's split
remains available to consumers as a local pattern — spawn two tasks over
one `Channel` via a hub, exactly as shape A's own probe already does
internally — for the specific case (a proven-relay, or code that wants to
hand out a receive-only or send-only capability) where the type-state proof
in criterion 2 is worth the independent-fate cost documented in criterion 3.
That shared-fate cost is the one criterion that could have flipped this: had
the mem split's two halves shared fate for free, shape C's cost would drop
to "two traits, two tasks" with no downstream coupling burden, and the
capnp/backend cost in criterion 4 would be the whole remaining case against
it. It does not — the halves are independently alive by construction unless
a backend does extra work to couple them — so the evidence keeps A as the
main trait surface.
