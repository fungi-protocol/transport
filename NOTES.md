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

Shape A's cost is not purely cosmetic — the multiplexing has a real
behavioral consequence under backpressure. Inside the `Event::Forward(Some(msg))`
arm (`gossip_spike_a.rs:46-50`), the link task is sitting in `ch.send(&msg).await`
and is NOT polling `ch.recv()` at all while that send is pending — `send` and
`recv` share `&mut self`, so the task literally cannot do both at once. If
the peer's own forward is blocked the same way (its outbound buffer full,
waiting on this same link to drain), the two shape-A nodes forwarding to
each other can mutually head-of-line block: each is awaiting a `send` the
other side isn't ready to `recv`, and neither task ever reaches its `select!`
again to pick up the peer's message. Shape C's separate send/receive tasks
(`gossip_spike_c.rs:96-108`) cannot deadlock this way — the receive task on
each side keeps polling `recv_half.recv()` regardless of what the send task
on that side is doing, so a full send buffer on one direction never blocks
draining the other.

The join-based shutdown fix above also turned out to have its own shape-A-
specific hazard, caught in review: joining the link tasks without also
dropping the hub's own receiver (`from_links`) leaves a live path to hang —
a link task blocked in `to_hub.send((i, msg))` (hub-inbound traffic still
arriving while shutdown is in progress, e.g. more than the 64-slot hub
buffer's worth) would never reach the `Forward(None)` that ends its loop,
so the join in `gossip_spike_a.rs:97-99` would wait forever. It cannot fire
in these probes (3 messages total, well under the 64-slot buffer), but it is
a property of the code, not of the test data, and would ride straight into
a later port. Fixed by `drop(from_links)` before the join
(`gossip_spike_a.rs:95`): a dropped receiver wakes any blocked sender with an
error, so `to_hub.send(..).is_err()` returns the task promptly either way.
Shape C structurally lacks this hazard: it aborts the receive tasks before
joining the send tasks (`gossip_spike_c.rs:138-144`), so there is no
receive-side task left to block on hub-inbound traffic by the time anything
is joined — an uncredited data point in C's favor that criterion 1 missed on
first pass.

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
recv half. So, with `split_duplex` exactly as written: **dropping your own
recv half kills the peer's send half** (their next `send` sees the receiver
gone and returns `SendError::Closed`, per `MemSendHalf::send` at
`gossip_spike_c.rs:56-68`) — **but your own send half is untouched**,
because it is paired with the peer's recv half, not your own.

That is a property of `split_duplex` as built, not a property of the
`ChannelSender`/`ChannelReceiver` split itself: nothing in either trait
(`gossip_spike_c.rs:16-25`) says anything about the other half's liveness —
the split shape is silent on fate, and `split_duplex` filled that silence
with two independent plain `mpsc` pairs. A constructor built around one
shared `Arc<Mutex<..>>` (or a shared atomic/watch "dead" flag) instead would
produce the opposite answer — either half's fatal error observed by the
other — with the same two trait definitions unchanged. The honest finding
is narrower than "the halves have independent fates": **the split shape
does not GIVE you shared fate for free**; whoever builds the split has to
manufacture coupling if the whole-channel-death contract is wanted, and
`split_duplex` on this branch chose not to.

That non-choice matters because the unified trait already promises the
coupled behavior: `channel.rs:32-34` says "any `recv` error, and any other
`send` error, means the channel is DEAD" and `error.rs:37-38` says the same
from the `RecvError` side ("ANY receive error means the channel is dead").
A split implementation that wants to be a drop-in equivalent of `Channel`
has to reproduce that single dead/alive fact across two objects instead of
getting it for the same effort shape A's one object gets automatically. As
built here, it doesn't: a consumer holding only the send half sees nothing
wrong even after the receive half is long gone, until it happens to also
lose its own peer.

A real backend joining these two shapes — say a Tor stream split into a
`DataReader`/`DataWriter` — would have to do that manufacturing work: some
shared state (an `Arc<Mutex<..>>` around the stream, a shared atomic/watch
flag, or a call that shuts the whole stream down) so that either half
observing the underlying connection's death marks *both* halves dead, not
just the one that noticed. `tokio::io::split` already does exactly this for
a generic `AsyncRead + AsyncWrite` type — it wraps the value in
`Arc<Mutex<..>>` so both halves talk to the same stream — but even that only
helps up to what the underlying transport actually guarantees: TCP itself
supports half-close (one direction can be closed while the other
survives), so "coupled fates" is deliberate backend work either way, not
something splitting the type gets for free, and not something the split
type forbids either — it is simply unaddressed by the trait split, and left
to whoever implements it.

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

## Loss observation

Naive gossip promises no redelivery, so a silently lost forward should just
lose the message it carried — verified directly against shape A's
`line_topology_converges` with a temporary variant (not committed): call
`b_ab.drop_next(1)` on B's side of the A–B link before the `tokio::join!`,
wrap the join in `tokio::time::timeout(Duration::from_secs(2), ..)`.

The actual mechanism: `drop_next(1)` silently drops the *next* physical send
on `b_ab`, which turns out to be B's own initial broadcast of `"from-b"`
toward A (the first thing `gossip_until` sends on any link,
`gossip_spike_a.rs:66-68`), not a later relayed forward — nothing in
"before the join" targets a specific later send. A never receives
`"from-b"`, its only link to the rest of the network, so once B's link task
finishes and A's underlying `mpsc` receiver closes, A's `gossip_until`
returns promptly rather than hanging — no timeout needed to observe the
failure, reproduced 5/5:

```
thread '...' panicked at ...: expected the timeout to fire, got
Ok((Err("links closed holding 2/3 messages"), Ok({...3 msgs...}), Ok({...3 msgs...})))
```

The mechanism (a clean early error, not a hang) differs from what a first
guess at "the forward that completes the set gets dropped" would predict,
but the point it demonstrates is the one that matters: naive gossip has no
retry, so a silently dropped send is a message a node never gets — here it
cost A a fast, explicit error instead of a wedge, but the message is just as
permanently gone. This is exactly the redelivery gap that epidemic gossip's
continued retransmission (not implemented in this naive probe) exists to
close.

## Decision

Shape A stays the trait surface on `main` — not because its costs are
purely cosmetic (criterion 1 found a real one: the `send`/`recv` bundling
means a link's single task cannot poll `recv` while a `send` is pending, so
two shape-A nodes forwarding to each other under backpressure can mutually
head-of-line block, a hazard shape C's separate send/receive tasks
structurally cannot have) — but because the concrete, present-tense costs
land the other way. It is what both real backends already are (one object
wrapping one stream, criterion 4), it is what the capnp plugin interface
already committed to (one interface, two methods, criterion 4), and its
type-state gap is not one this consumer needs to close (criterion 2 — naive
gossip never needs to *prove* a link is receive-only; it already works
correctly enforcing "don't echo the sender" at the value level). Shape C's
split remains available to consumers as a local pattern — spawn two tasks over
one `Channel` via a hub, exactly as shape A's own probe already does
internally — for the specific case (a proven-relay, or code that wants to
hand out a receive-only or send-only capability) where the type-state proof
in criterion 2 is worth the extra coupling work criterion 3 says the split
does not get for free. Criterion 3 does not add an inherent independent-fate
cost to the split shape itself — the split leaves fate unspecified, and a
different constructor than the branch's `split_duplex` could make the two
halves share it — but *something* has to do that manufacturing (an
`Arc<Mutex<..>>`, a shared close flag, an explicit shutdown call), and shape
A's one-object design gets the equivalent single dead/alive fact for free by
construction, no manufacturing required. Combined with criterion 4's
concrete zero-cost-today reality (both real backends and the capnp interface
already *are* shape A), that tips the balance to A even after crediting
criterion 1's real head-of-line-blocking cost: today, nothing downstream of
the trait needs the type-state proof shape C offers, and everything
downstream of the trait already pays shape A's price. The head-of-line risk
is worth carrying forward as an open question for whichever consumer first
needs genuine concurrent full-duplex under backpressure — it is not
resolved by staying on shape A, only judged not to be this decision's
deciding factor yet.
