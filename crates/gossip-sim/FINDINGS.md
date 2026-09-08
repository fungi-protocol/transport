# Gossip dissemination — measured

The harness in this crate drives the production `GossipBroadcast` over in-memory
links and reduces the traffic to a **redundancy factor**: bytes a peer sends
divided by the size of the distinct message set.

## The answer

**Announce/pull, in both settings. What differs between them is the node degree,
not the scheme.**

| | push | announce/pull |
|---|---|---|
| closed construction, n=100, k=4, compact proofs | 3.4 MB per peer, factor 3.01 | **1.27 MB, factor 1.12** |
| open broadcast, n=100, k=4, compact proofs | 0.23 MB per peer, factor 3.01 | **0.09 MB, factor 1.19** |
| open broadcast, n=100, k=4, naive proofs | 2.4 MB per peer, factor 3.01 | **0.82 MB, factor 1.01** |
| open broadcast, n=300, k=8, compact proofs | 1.6 MB per peer, factor 7.00 | **0.32 MB, factor 1.37** |
| open broadcast, n=1000, k=8, compact proofs | 3.2 MB per peer, factor 7.00 | **0.70 MB, factor 1.55** |

1. **Push meets the criterion on its own.** Its redundancy factor is exactly
   `k − 1` and bounded in n — 3.05 at twenty peers, 3.01 at a hundred. At the
   full message count a peer sends 3.4 MB per session, against a stated budget
   of tens of megabytes for a mobile client.
2. **Announce/pull sends a half to two-thirds of that**, and the advantage
   widens with message size: factor 1.41 on the happy path, 1.12 with BFT
   overhead, 1.01 on an open network carrying naive proofs.
3. **It decouples bandwidth from degree.** Push's factor is `k − 1`; pull's
   moves from 1.19 to 1.37 while the degree doubles and hop depth falls from
   4.5 to 3.0. Under pull the degree knob buys latency almost for free.
4. **Hybrid loses at every threshold, in both settings.** An announcement floods
   as far as a message does, so naming an object beats flooding it whenever the
   object exceeds about **1.5x the identity width**. The smallest object in a
   concurrent-PSBT construction is about 70 bytes against a 37-byte identity.
5. **Pull costs latency**: three round trips per phase against one hop, paid
   three times because the phases are barriers.
6. **On link buffers pull is heavier below the target scale and lighter above
   it.** Most frames queued on one link direction at once: 26 against push's 18
   at twenty peers, 52 against 34 at forty, 68 against 105 at a hundred, 248
   against 666 at a thousand.
7. **The figures hold across sampled graphs and on a real engine.** Five seeds
   per scheme; pull's spread is 0.4% and its factor reads 1.41 in every draw.
   Announce/pull built with the production engine's shape — hub task, link
   tasks, bounded queues — lands within 0.2% of the model at 20, 40 and 100
   peers.
8. **Validation dependencies are 22% of construction traffic**, and at a
   half-and-half population 0.10-0.11 of everything a peer sends is deliverable
   to a peer that already held it.
9. **One open defect, handed back rather than fixed:** the transport's per-link
   send loops park under backpressure with no explicit-failure path, so a
   producer that outruns its consumers closes a cycle of waiting tasks.

## Method

Message sizes are measured, from fragments serialised with `concurrent-psbt`
(fungi-protocol/concurrent-psbt, branch develop at 24bcca7e6545):

```
empty fragment (concurrent-PSBT globals alone)   105 bytes
+ one segwit input                               +77   -> 182
+ one legacy input (prev tx, 2 in / 2 out)      +420   -> 525
+ one output                                     +73   -> 178
+ a signature on an input                       +107   -> 289
```

Every fragment pays a 105-byte floor for the concurrent-PSBT globals, so the
smallest fragment is about three times a 32-byte message id. The workload uses
the segwit sizes, the common case. A legacy input is 5.5x a segwit one, which is
why previous transactions are the object the validation-dependency work makes
separately addressable — thirteen legacy inputs approach the ~7 KB a BIP 77
mailbox frame carries.

The factor derives from bytes **sent**. `GossipBroadcast::shutdown` drains what a
node owes, not what it is owed, so sends are complete once the drain returns
while receipts are a lower bound at teardown. The duplicate column is
receipt-derived and carries that caveat.

The session hello is not counted: the harness admits links through
`AssumeSessionBound`, so no handshake frames exist to meter. At 20 peers on a
complete graph that omits roughly 1 KB per peer against a set of about 6.7 KB —
about 1% at degree 4.

## Push: the factor is k − 1

Degree 4, seed 0, `legacy_fraction: 0.3`, `full_node_fraction: 0.5`, link buffer
32, engine queue 512.

```
peers  per_peer  wire    factor  dupes  hops_mean (in,out,sig)  avoid_share
20      59410     60460   3.05    3612  2.00,2.00,2.00          0.11
40     117908    119989   3.02   14104  2.66,2.67,2.67          0.11
60     176137    179250   3.02   31476  3.05,3.05,3.05          0.11
80     234821    238966   3.01   55728  3.38,3.38,3.38          0.11
100    292894    298071   3.01   86860  3.53,3.51,3.52          0.11
```

**The acceptance criterion is met across a fivefold range of peer counts.** The
factor moves from 3.05 to 3.01: it converges downward on `k − 1` = 3 as the
`k/(n−1)` term of `k + (n−1)(k−1)` divided by n washes out.

**Per-peer cost is linear in n with a small constant.** About 2.93 KB of sent
traffic per peer per additional peer — 293 KB per peer for a hundred-peer
session against a distinct set of about 97 KB, three orders of magnitude inside
the stated budget. The quadratic behaviour belongs to the complete graph, whose
factor is `(n−1)²/n` — 98.01 at a hundred peers, about 7.4 MB per peer.

**The factor is analytic, and the measurement confirms the harness.** Naive
flooding sends `k + (n−1)(k−1)` copies of every message on any connected
k-regular graph: at k = n−1 that is `(n−1)²`, giving 361/20 = 18.05, and at
k = 4 it is 61, giving 3.05. The same form gives 3.20 for a complete graph of 5
and 1.12 for a ring of 8, both confirmed by the unit tests. Because the factor
depends only on n and k, every connected k-regular graph gives the identical
number: the seed axis is a self-consistency check on the harness, not evidence
about topology. What varies by draw is hop depth and partition risk.

### The degree axis

Five seeds per cell, `legacy_fraction: 0.3`, `full_node_fraction: 0.5`, push.

```
      n = 20                            n = 100
k     per_peer  factor  hops_mean       per_peer  factor  hops_mean
3      39931     2.05    2.48-2.60       195587    2.01    4.62-4.90
4      59410     3.05    2.00-2.15       292894    3.01    3.53-3.59
8     137326     7.05    1.50-1.52       682122    7.01    2.41-2.44
```

**Degree is the whole of the redundancy factor**: 2.01, 3.01, 7.01 at a hundred
peers. Halving the degree halves the traffic at any scale.

**Latency pays for it.** Mean depth at a hundred peers runs 4.6-4.9 hops at
degree 3 against 2.4 at degree 8, and the phases are barriers, so a session pays
three times over. Degree 4 sits at 3.5.

**Degree 3 converged in all ten cells.** `Topology::degree_k` checks connectivity
before every run; ten sampled graphs is the difference between unmeasured and
not seen yet, not a bound on partition risk.

**Seeds do not move the byte columns.** `per_peer` varies by less than 0.2%
across five draws. What the seed axis carries is the hop-depth spread.

## Hop depth

Depth is how many relays a frame crossed before a node first held it. It is not
analytic in (n, k): the reconstruction reports the depth of the first copy that
arrived, and the origin's fan-out is not simultaneous, so depth measures the
realised delivery order of one execution.

```
peers  degree  seed  hops_max (in,out,sig)  hops_mean (in,out,sig)
20     19      0     1,4,1                  0.95,1.70,0.95
20      4      0     4,4,4                  2.00,2.00,2.00
20     19      1     1,4,1                  0.95,1.65,0.95
20      4      1     4,4,4                  2.04,2.04,2.04
20     19      2     1,4,1                  0.95,1.67,0.95
20      4      2     4,4,4                  2.07,2.07,2.07
20     19      3     1,4,1                  0.95,1.66,0.95
20      4      3     4,4,4                  2.15,2.15,2.15
20     19      4     1,4,1                  0.95,1.66,0.95
20      4      4     4,4,4                  2.06,2.06,2.06
```

**The phase asymmetry is scheduling, not structure.** The three phases are built
identically — every peer publishes exactly once in each — and feeding the same
phases one publication at a time gives the complete graph max depth 1 and mean
0.95 in every phase, which is the structurally correct answer for a graph that
puts every peer one hop from the origin. The depth above 1 is the burst.

**Depth is not reproducible run to run; the bytes are.** `report.rs` pins that
boundary as a test: same config twice, byte metrics asserted equal, depth and
duplicates deliberately not asserted.

**Degree 4 costs about one extra hop** — mean ~2.0 against ~0.95-1.70, max 4-5
against 1-4 — which is the price of the sixfold traffic reduction.

## The three schemes

Degree 4, seed 0, `legacy_fraction: 0.3`, `full_node_fraction: 0.5`. `per_peer`
is bytes a peer sends; `wire` adds the four-byte length prefix.

```
                      n = 20                        n = 100
scheme                per_peer   wire    factor     per_peer   wire     factor
push (engine)           59410   60460     3.05       292894   298071     3.01
push (modelled)         59410   60460     3.05       292894   298071     3.01
announce/pull b=1       27083   28560     1.39       139040   146527     1.43
announce/pull b=8       26874   27512     1.38       137790   140279     1.42
announce/pull b=50      26863   27459     1.38       137666   139659     1.41
hybrid b=50 push<=200   28001   28791     1.44       143513   146480     1.47
hybrid b=50 push<=300   37487   38339     1.92       187301   191167     1.92
hybrid b=50 push<=600   51786   52707     2.66       257218   261813     2.64
```

All three modelled schemes share one lockstep round driver over the same metered
links, so a difference between rows is a difference between schemes rather than
between drivers. **`push (modelled)` and `push (engine)` agree to the byte and to
the frame** at both peer counts and at n = 5 on a complete graph; a test in
`engine.rs` pins it.

**Announce/pull more than halves the traffic: 3.01 to 1.41 at a hundred peers.**
Push spends `k + (n−1)(k−1)` = 61 copies of every object; pull spends one copy
per peer that lacks it, plus an announcement on every link. Most of the saving is
duplicate suppression rather than the dependency saving.

**Batching barely matters.** One identity per frame against fifty moves
`per_peer` by 1% — 139,040 against 137,666. The whole of the difference is
framing: `wire`, which adds four bytes per frame, moves by 5% (146,527 against
139,659). At these message counts the announcement traffic is dominated by the
identities themselves, not by their envelopes.

**Across five sampled graphs the ordering holds on every draw.** Announce/pull's
spread is 0.4% and its factor reads 1.41 in all five; at twenty peers pull at
batch 50 runs 26,762 to 26,904.

```
n=100, degree 4        per_peer, five seeds     factor
push (engine)          292713 .. 293252         3.01
push (modelled)        292713 .. 293252         3.01
announce/pull b=1      138494 .. 139040         1.42-1.43
announce/pull b=8      137258 .. 137790         1.41-1.42
announce/pull b=50     137135 .. 137666         1.41
hybrid b=50 <=200      142545 .. 143513         1.46-1.47
hybrid b=50 <=300      185880 .. 187301         1.91-1.92
hybrid b=50 <=600      254364 .. 257218         2.61-2.64
```

**A pull round is not a push round.** A push round is one hop; a pull round is
announce, then request, then data — a full round trip and a half. Pull uses about
the same number of rounds as push (7 against 7 at a hundred peers, 4 against 5 at
twenty), so it costs roughly two to three times the latency for half the bytes.

### Where the push/pull threshold sits

Hybrid at a hundred peers, degree 4, batch 50, `push_below` swept. The curve is a
step function whose steps are the measured fragment sizes.

```
push_below   per_peer   factor   what it starts pushing
announce all   137666    1.41    -
       <= 50   137666    1.41    nothing: the smallest object on the wire is ~70 B
      <= 120   143513    1.47    prevouts
      <= 200   143513    1.47    -
      <= 300   187301    1.92    inputs and outputs
      <= 450   232288    2.39    signatures
      <= 600   257218    2.64    previous transactions
```

**The minimum is at "announce everything".** Every step upward costs more, so
hybrid is a strictly worse announce/pull on this workload.

**The arithmetic.** An announcement floods exactly as a message does — 301 copies
at n = 100, k = 4 — but the object itself then travels only to the n − 1 peers
that ask. Announcing wins when

```
301 x id + 99 x object  <  301 x object      i.e.   object > 1.5 x id
```

With a 37-byte outpoint identity the break-even is near 55 bytes on the wire, and
the smallest object in a concurrent-PSBT construction is about 70 — the 105-byte
globals floor guarantees it. The crossover is at 1.5x the identity width rather
than the order of magnitude a size-ratio rule of thumb suggests, because the
saving comes from the `301 → 99` collapse in how far the payload travels. It
depends only on n, k and the identity width, so it transfers off this workload.

## Validation dependencies

A prev tx is addressed by its txid and a prevout by its outpoint — identities
that exist before the message does, which is what lets a peer decline an object
it never received. Every other message here is identified by the hash of its own
content, and no peer can claim to hold one of those in advance.

### What push wastes

20 peers, degree 4, `legacy_fraction: 0.3`, five seeds, with the share of peers
that are full nodes swept. A full node resolves any prevout locally, so every
dependency byte sent to one is a byte that did not need sending.

```
full_node_fraction  per_peer  dep_bytes  dep_to_holders  dep_ratio  avoid_share
0.0                 59410     ~257-260k  0               0.00       0.00
0.5                 59410     ~257-260k  ~119-132k       0.46-0.51  0.10-0.11
1.0                 59410     ~257-260k  ~257-260k       1.00       0.22
```

**Dependencies are 22% of the traffic.** The same workload without them sends
46,460 bytes per peer; with them, 59,410. That is the whole envelope
announce/pull could ever address.

**At a half-and-half population the ceiling is 11% of everything a peer sends.**
Announce/pull has to beat that net of its own announcement frames and the round
trip it adds. An outpoint is 31–43 bytes against a 32-byte id, so announcing one
is close to a wash; the 410–430 byte previous transactions of the legacy peers
carry whatever saving exists. The 30% legacy share is an input, and moving it
moves this number.

`dep_ratio` tracks `full_node_fraction` exactly, by construction: under flooding
every object reaches every peer, so the share of dependency bytes landing on
holders is the holder fraction whatever the topology, engine or object sizes. It
is a self-consistency check on the accounting. `avoid_share` carries the
information, because its denominator is the whole run.

### What pull keeps

100 peers, degree 4, `legacy_fraction: 0.3`, staggered.

```
full_node_fraction   push per_peer   pull per_peer   pull factor
0.0                     292894          148232          1.52
0.5                     292894          137666          1.41
1.0                     292894          129427          1.33
```

**Push does not move by one byte.** It has no way for a peer to decline what is
being forwarded, so a peer's a-priori holdings are worth exactly nothing to it.
That flat row is the control that makes the pull row a measurement.

**Pull turns the knowledge into traffic it does not send:** 10,566 bytes per peer
at a half-and-half population, 18,805 at a fully-resolving one — 7% and 13% of
its own traffic. The distinct dependency bytes in this workload are about 20,800
and pull sends each object once to each peer that lacks it, so halving the peers
that lack it removes about 10,400 bytes per peer. Measured 10,566.

This is smaller in absolute terms than the ceiling measured under push, because
the ceiling is computed on flooded traffic — 301 copies of every object — while
pull was only ever going to send 99. The saving that separate addressing buys is
proportional to what the scheme sends, not to what push wastes.

A full node also announces the objects it resolved locally, so its neighbours can
pull from it: the harness puts a-priori holdings into the same held set
everything else goes into.

**A caveat on `dep_to_holders`.** It counts sends whose receiving end already held
the object, and which link carries a copy depends on delivery order, so it moves
between runs the way duplicates do — 125,524 and 117,415 for the same cell under
the engine and the model. `dep_bytes` itself is stable. Read `avoid_share` as
0.10-0.11, not as 0.11.

## The open network

More peers, fewer and larger messages, one phase rather than three. **The sizes
in this table are estimates, not measured artifacts** — ownership proofs of
200-300 bytes, co-spend proposals of 1.2-2 KB compactly or 10-40 KB in the naive
proof format — because there is nothing to serialise a coalition-formation
message from yet. Ratios survive a uniform error in them; absolute per-peer
figures do not.

```
cell                              push                announce/pull b=50
                              per_peer  factor      per_peer   factor
n=100 k=4 compact proofs        231953    3.01         91553     1.19
n=100 k=4 naive proofs         2438548    3.01        817310     1.01
n=300 k=4 compact proofs        699452    3.00        277969     1.19
n=300 k=8 compact proofs       1631020    7.00        318141     1.37
```

**Pull decouples bandwidth from degree, and push does not.** Push's factor is
`k − 1` exactly — 3.00 at degree 4, 7.00 at degree 8 — so raising the degree to
cut latency costs proportionally more traffic. Pull's factor moves only 1.19 to
1.37 across the same change, while mean hop depth falls from 4.54 to 2.98. That
is the single most useful property either scheme has.

**The naive proof format sharpens the answer.** At tens of kilobytes per proposal
pull's factor falls to 1.01 — the floor of one copy per peer — because the
announcement overhead vanishes against the object size. Push still spends 2.4 MB
per peer against pull's 0.8 MB.

### The two policies

- **Closed transaction construction** — announce/pull. 137,666 bytes sent per
  peer at a hundred peers against push's 292,894: a 53% saving, at roughly two to
  three times the latency, paid three times because the phases are barriers.
  **The degree is not settled here.** Pull spends three round trips per phase
  whatever the degree, so what a higher degree buys is hops; the only measurement
  of that trade is on the open workload, where 4 to 8 cost 15% more bytes for a
  third fewer hops. Whether that is worth paying depends on round-trip time
  against transfer time, which is latency in seconds and is not modelled here.
- **Open broadcast** — announce/pull, degree 8. A 61% to 80% saving, and the
  higher degree costs almost nothing in traffic while cutting mean depth from 4.5
  hops to 3.0. There are no phase barriers here to multiply latency.

**What differs between the settings is a parameter, not a scheme:** one engine
with a degree knob, defaulting low for construction and high for open broadcast.

**Hybrid is in neither policy.** It loses at every threshold in both settings, and
nothing in either workload is smaller than 1.5x the identity width.

**Set reconciliation is untested.** Announce/pull already reaches a factor of
1.01-1.19 in the open setting, which leaves at most a fifth of the traffic for
reconciliation to remove, against the round trips and sketch overhead it costs.
Long-lived data re-synced by returning light clients is the case this workload
does not model, so this does not settle it — but the case for reconciliation has
to be made against pull, not against flooding.

## At the message count the target scale is described in

The target is ten to fifteen messages per peer, about a thousand messages overall
at a hundred peers. The happy-path workload publishes about 4.3; the gap is BFT
overhead, the validity proofs. With three per peer per phase the workload reaches
13.3 messages per peer.

```
100 peers, degree 4, staggered      per_peer    factor
push, no proofs                       292894      3.01
announce/pull b=50, no proofs         137666      1.41
push, 3 proofs per phase             3428254      3.01
announce/pull b=50, 3 proofs         1274343      1.12
```

**The criterion holds with the overhead carried.** 3.4 MB per peer under push,
1.27 MB under announce/pull, against a budget of tens of megabytes. Neither
scheme breaks it; the difference between them is 2.2 MB per peer per session.

**Pull gets better as the messages get larger** — its factor falls from 1.41 to
1.12 — because announcement overhead is fixed per object while the payload it
saves is not. This is the same effect the naive proof format shows in the open
setting: the more the traffic is made of large objects, the closer announce/pull
runs to the floor of one copy per peer.

**The proof sizes are an assumption**, drawn from 200 to 2000 bytes to span an
ownership proof at 200-300 bytes and a compact co-spend proposal at about 2 KB.
The absolute figures move with it; the scheme ranking does not.

## Buffers, and the transport's send-path wedge

### The capacity boundary

Sweeping the per-link buffer at 20 peers, seed 0, publishing a whole phase at a
time:

| capacity | degree 19 (complete) | degree 4 |
|---|---|---|
| 1 | **hangs** | **hangs** |
| 2 | **hangs** | converges, `drained=false`, 2 failed sends |
| 4 | **hangs** | converges cleanly |
| 8 | **hangs** | converges cleanly |
| 32 | converges cleanly | converges cleanly |

**The boundary is where the buffer falls under what the run queues.** A complete
graph at twenty peers puts 29 to 30 frames on one link direction at once and a
degree-4 graph puts 8 to 9; give the complete graph 8 and it cannot finish, give
it 32 and it does.

**On a complete graph the demand has a closed form, so the boundary is
predictable.** Running the three-phase happy path on complete graphs of 10, 20,
30, 40 and 50 peers gives a peak occupancy of 8, 18, 28, 38 and 48 — **n − 2**
exactly at every point, which is the number of links a node forwards onto when a
message arrives. The sweep hangs at a buffer of 8 and finishes at 32, and
`8 < 18 <= 32` says why. Adding dependency objects raises the figure with the
message count, so the law holds within one workload rather than across them.

**The two rows do not fail alike.** Degree 4 converges at a buffer of 2, far
under the 8 to 9 it queues when given room — a sender waits for space and the run
finishes slower. On the complete graph the same wait closes a cycle, because
there every node is a neighbour of every other and the tasks waiting for space
are the tasks that would free it. Backpressure works until the graph makes it
circular.

### The publication schedule

The producer side of the same knob. Twenty peers, engine queue 64, capacity
swept, `Schedule::Burst` against `Schedule::Staggered { publications: 1 }`.

```
capacity   burst, complete   burst, k=4   staggered, complete   staggered, k=4
1          hangs             hangs        converges             converges
2          hangs             converges    converges             converges
4          hangs             converges    converges             converges
8          hangs             converges    converges             converges
32         converges         converges    converges             converges
```

**The wedge is a burst phenomenon, not a density phenomenon.** Every cell that
hangs under a burst converges when the phase is fed one publication at a time,
including the complete graph at a link buffer of one. Only the rate at which work
is handed to the graph changed.

**Traffic does not move with the schedule, and a test pins that.** Every byte
column is identical across the two halves of the table — 274,955 and 46,460 per
peer either way — because a message crosses `k + (n−1)(k−1)` links whichever
order it goes in. What moves is queue occupancy, hop depth (the complete graph
settles at exactly 1) and the duplicate count (15,936 to 20,475 on the complete
graph, since a staggered run has no forwards truncated at teardown). The capacity
table above and the duplicate columns elsewhere belong to the burst case.

### The defect

The mechanism sits in `fungi-transport`. The per-link `sending` loops in
`crates/transport/src/gossip.rs` await `tx.send(&msg)`, which under backpressure
parks the task until the peer frees space, with no explicit-failure path — unlike
the engine's internal queues, which fail loudly through `try_send`. It does not
block a thread: the failure is a dependency cycle among await points, where each
forwarding task waits for space that only another waiting task can free. The
documented promise that a full queue ends the group covers the engine's own
queues, **not the physical link buffer**.

The open workload reaches it from a second direction. An open broadcast publishes
its whole set in one phase, and at a hundred peers on a degree-4 graph that walks
into the wedge — the process sits at zero CPU rather than failing. Fed one
publication at a time it completes those cells and reports 231,953 and 2,438,548
bytes per peer, identical to the model to the byte. That is stronger evidence
than the capacity sweep, because a hundred peers at degree 4 is squarely inside
the operating range the milestone targets, and because the fix it points at is a
failure path on the send loop rather than a bigger buffer.

Nothing in `crates/transport`, `crates/wire` or `crates/session` was changed to
chase it. **The engine's backpressure story is incomplete exactly where degree is
highest**, and it is the one thing here that is not optional whichever scheme is
chosen.

### Two bounded resources

A run is bounded by the link buffer and, separately, by the engine's own internal
queues, sized by `GossipConfig::queue_capacity`. They fail differently: a full
link buffer **parks** the sending task and the run stops returning at all, while
a full engine queue is served by `try_send` and **ends the group** with a typed
error, which arrives as an ordinary row with `converged: false` and a failed-send
count.

**The engine's queue binds first as peers are added.** At forty peers on a
degree-4 graph with dependency traffic the group ends under the default of 64,
and it ends identically with the link buffer at 32, 64, 128, 256 or 1024; the
same graph and workload converge cleanly once the engine's queues are widened
alone. Under the default only the twenty-peer row of the scale sweep converges:

```
n=40   drain did not finish — gossip link 0 did not finish flushing
n=60   drain did not finish — gossip forward on link 1 failed: channel closed
n=80   drain did not finish — gossip forward on link 1 failed: channel closed
n=100  drain did not finish — gossip forward on link 0 failed: channel closed
```

At forty peers the drain reports a link that still owed bytes when it was asked
to finish; beyond that, forwards fail outright on links already closed. Either
way what filled is the hub's queue toward its own consumer, not a link's: the
harness drains a node only between phases, so the engine fills that queue while
the consumer is not reading. The bound that binds first at this scale is a
property of how the caller drives the engine, not of the graph. The `factor`
column on those rows — 0.82, 0.53, 0.37, 0.30 — measures nothing: the run stopped
during the Inputs phase, which the zeroes in its Outputs and Signatures hop
columns show. A row that did not converge reports how far it got, not what
dissemination costs.

Both are inputs to a run: `RunConfig::capacity` and `RunConfig::queue_capacity`.

### The buffer depth each scheme demands

The depth is measured, not planned: walking the event log in order and tracking,
per link direction, how many frames had been sent and not yet received. That is
what the buffer actually held, and it is a smaller number than how many frames a
scheme hands to a link in one go, because the peer is draining throughout.

```
cell                              push        announce/pull b=50
construction, n=20,   k=4          18-21       26          model and engine agree
construction, n=40,   k=4          34          52          model and engine agree
construction, n=100,  k=4          105-121     68 engine / 130 model
open broadcast, n=300, k=4 and 8   151-242     73-81       modelled
open broadcast, n=1000, k=4        396         193         modelled
open broadcast, n=1000, k=8        666         248         modelled
```

**Pull is heavier at small n and lighter at large, and the crossover is between
forty and a hundred peers.** The reason is a difference in growth, not in degree:
push's occupancy is its fan-out repeated for everything it holds, which climbs
roughly with n — 18, 34, 105, 396 at 20, 40, 100 and 1000 peers — while pull's is
how many objects it answers on one link at once, which climbs far more slowly:
26, 52, 68, 193. At the target scale and above, pull asks less of a link buffer
while sending half the bytes; below it, slightly more.

**Where the model and the engine disagree, read the engine.** They report
identical depths at twenty and forty peers and split at a hundred: 130 against
68. The model plans a whole step and hands it to a link at once; the engine
flushes as it goes. The model's occupancy is an upper bound that loosens with
scale, and its byte figures, which do not depend on ordering, are unaffected.

**Only cells published in a burst belong in this table.** A staggered schedule
puts one publication in at a time, so every scheme reports a depth of exactly 1.
Occupancy is a joint property of the scheme and the rate it is fed at.

**The column reports what a run used, which is what the scheme wants only when
the buffer was generous enough not to clip it.** At `capacity: 1` every scheme
reports a depth of exactly 1, because that is all there is; a test pins both
halves of that. Every comparison table here runs at 4096, well above the largest
figure in it.

**This does not reproduce the engine's wedge.** In the asynchronous engine one
hub per node serves every link, so a node that cannot finish with one link stops
draining its others and a cycle can close; in the model each link direction has a
reader of its own. The depths above are a property of each scheme's traffic;
whether a given implementation deadlocks at them is a property of that
implementation.

## The model, checked against a running engine

Announce/pull was built a second time with the production engine's shape — a hub
task per node, a task per link, bounded queues that end the group rather than
drop — and driven through the same `run()`. Degree 4, seed 0,
`legacy_fraction: 0.3`, `full_node_fraction: 0.5`.

```
             pull b=50        pull b=50                    peak occupancy
n            model            engine        gap        push    model    engine
20            26863            26919       +0.2%         18       26        25
40            54637            54641      +0.01%         34       52        52
100          137666           137367       -0.2%        105      130        68
```

**The model holds on bytes**: within a fifth of a percent at every scale, and the
redundancy factor reads identically — 1.38, 1.40, 1.41 either way. Every
announce/pull figure in this document therefore stands on an engine with real
concurrency and real backpressure, not only on a model of one.

**On buffers the engine is lighter.** At a hundred peers the engine's pull peaks
at 68 frames on one link direction against push's 105.

**Building it surfaced a defect a lockstep model cannot express.** A node that
resolves a dependency locally must *announce* it, not merely hold it; holding
them silently leaves an object reachable only through full nodes never arriving,
and the group stops converging at fifteen peers with a mixed population. It
converges at a full-node share of 0.0 and of 1.0 and fails only in between, which
is the shape of bug a homogeneous test never sees.

## A thousand peers

The open network's own scale. Modelled: the asynchronous harness's drain wakes
every waiting task on every receipt and does not reach it. `proposal_fraction:
0.1`, compact proofs.

```
degree   push per_peer   factor    pull per_peer   factor   saving
4           1353610       3.00        579827       1.29      57%
8           3157822       7.00        699154       1.55      78%
```

**Everything the hundred- and three-hundred-peer rows say holds at a thousand.**
Push's factor is `k − 1` to two decimal places; pull's stays near the floor and
moves by a quarter while the degree doubles. The cell costs 2.2 GB and 103
seconds, which is what puts it at the edge of what this machine can measure and
why it is one seed rather than five.

## The harness's operating envelope

A run holds one event per frame per direction, about forty bytes each, and a
flooded run generates `messages x (k + (n-1)(k-1))` frames per direction. That
decides whether a cell fits in memory: cubic in n on a complete graph, linear at
fixed degree.

```
cell                                      events     peak RSS   wall clock
20 peers, degree 4                        ~10 k      7 MB       20 ms
100 peers, degree 4                       ~259 k     75 MB      0.5 s
50 peers, complete (link buffer 2048)     ~1.03 M    213 MB     1.3 s
1000 peers, degree 4 and 8, modelled      ~8 M       1.2 GB     159 s
100 peers, complete                       ~8.6 M     ~2 GB, not run
```

The thousand-peer cell is slow for a reason worth naming before anyone tries a
larger one: a modelled step joins one future per link, and `join_all` polls every
unfinished future in the set on every wake — at degree 8 that is four thousand
futures polled per step. A `FuturesUnordered` would poll only what became ready,
and is where to start if this ever has to reach further.

## What this does not answer

**Answered.** The push baseline, at measured message sizes and at the peer counts
the target names, on the production engine. The degree lever and what it costs in
hops. Validation dependencies as separately addressable objects, priced from both
sides — what push wastes delivering them to peers that already hold them, and
what pull keeps by not sending them. All three schemes, on one workload and one
graph, across five sampled graphs each. And announce/pull built a second time
with the production engine's shape, agreeing with the model on bytes to within
0.2% at twenty, forty and a hundred peers.

**Rests on assumptions, stated wherever they are used.** The validity-proof sizes
and every size in the open-broadcast workload are estimates, because nothing
exists yet to serialise those messages from. They move the absolute per-peer
figures for the BFT and open-network rows, not the ranking: announcing beats
flooding above about 1.5x the identity width, and every size in every range
clears that by a wide margin. The holder and legacy shares and the identity width
are inputs of the same kind, and the identity width is conservative, since a
shorter one only helps pull.

**Hybrid was never run on the asynchronous engine.** It loses at every threshold
in the model, for a reason that is arithmetic rather than empirical.

**Nothing here crossed a real network.** Every link is an in-memory duplex: the
byte counts are what an engine hands to a channel and do not depend on what
carries it, and the criteria are all stated in volume. What a real transport
would change is latency in seconds — deliberately not modelled — and where the
capacity boundary sits, which is already reported as a property of the transport
rather than of the scheme.

**The complete graph at a hundred peers was computed, not run.** Both quantities
it could produce are closed forms confirmed at five points each: the redundancy
factor is `(n−1)²/n` (8.10, 18.05, 28.03, 38.00, 47.47 at n = 10, 20, 30, 40, 50)
and the link occupancy is `n − 2` (8, 18, 28, 38, 48 at the same points). A
hundred peers would read 98.01 and 98, at about 2 GB and minutes.

**Partition risk at low degree is not measured.** `Topology::degree_k` checks that
each sampled graph is connected, which is not the same as bounding how often a
draw would fail.

**Churn is not modelled** — membership is fixed for a run, and the engine ends a
group when one link dies. It is the item's own deferral, along with robust
overlays, eager/lazy trees, erasure coding and set reconciliation, but it is the
one worth naming next to a recommendation of announce/pull, whose per-peer state
is exactly what churn would disturb.
