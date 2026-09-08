# Gossip dissemination, measured

The harness drives the production `GossipBroadcast` over in-memory links and
reduces the traffic to a **redundancy factor**: bytes a peer sends divided by the
size of the distinct message set. One copy per peer is 1.00, the floor.

## The answer

**Announce/pull, in both settings. What differs is a parameter, not the scheme.**

| | push | announce/pull |
|---|---|---|
| closed construction, n=100, k=4, compact proofs | 3.4 MB per peer, factor 3.01 | **1.27 MB, factor 1.12** |
| closed construction, n=100, k=4, naive proofs | 67.3 MB per peer, factor 3.01 | **22.3 MB, factor 1.00** |
| open broadcast, n=100, k=4, compact proofs | 0.23 MB per peer, factor 3.01 | **0.09 MB, factor 1.19** |
| open broadcast, n=100, k=4, naive proofs | 2.4 MB per peer, factor 3.01 | **0.82 MB, factor 1.01** |
| open broadcast, n=300, k=8, compact proofs | 1.6 MB per peer, factor 7.00 | **0.32 MB, factor 1.37** |
| open broadcast, n=1000, k=8, compact proofs | 3.2 MB per peer, factor 7.00 | **0.70 MB, factor 1.55** |

1. **Push's factor is exactly `k − 1` wherever the link buffer holds the
   fan-out, and bounded in n**: 3.05 at twenty peers, 3.01 at a hundred. Per-peer
   cost is linear in n, about 2.93 KB per added peer. Naive gossip on a k-regular
   mesh does not put a constrained peer at the mercy of the participant count;
   flooding a complete graph does, at `(n−1)²/n`.
2. **The proof format decides whether push is good enough, not the peer count.**
   Compact proofs: 3.4 MB per peer against a stated budget of about 10 MB.
   Naive proofs: 67.3 MB, six times over, while announce/pull reaches 1.00.
3. **Announce/pull sends a fifth to a half of push** across every cell measured,
   and improves as messages grow: 1.41 on the happy path, 1.12 with compact
   proofs, 1.00 with naive ones.
4. **On the open network it decouples bandwidth from degree; on the construction
   it does not.** Push pays `k − 1` everywhere. Pull moves 1.19 to 1.37 when the
   degree doubles on the open workload, against 1.41 to 1.87 on the construction,
   where small objects make announcements a large share of what it sends.
5. **Hybrid loses at every threshold.** An announcement floods as far as a message
   does, so naming beats flooding above **1.5x the identity width**, about 55
   bytes. No message reaches the wire that small: the smallest is ~70 B, its own
   envelope included.
6. **Pull costs latency**: three round trips per phase against one hop, paid three
   times because the phases are barriers.
7. **Separate addressing pays for previous transactions and not for prevouts.**
   Bundling a dependency into the fragment beats naming it at every legacy share
   below about a half; naming only previous transactions beats both everywhere,
   reaching 1.01 where every input is legacy. Bundling pays no envelope and no
   announcement, so the comparison there is the payload against the identity
   naming it: a 31 to 43 byte prevout against a 37-byte outpoint is a wash,
   while a 420-byte previous transaction is not.
8. **A link buffer under the fan-out costs redundancy, not convergence.** Every
   cell converges, including a complete graph given one slot per link
   direction; what a thin buffer drops are copies another path already
   carried, and the run reports them as failed sends.

## Where these numbers come from

Every byte column is produced by `Metered` wrapping the channel and counting what
crosses it. Push is `fungi_transport::GossipBroadcast` itself, publications are
`fungi_wire::CanonicalMessage` under a session context, convergence is equality of
`MessageSet::commitment()`, and links are `fungi_transport::mem::duplex`. Nothing
in the dissemination path is reimplemented for the harness.

Announce/pull exists twice over: a lockstep model and `AnnounceBroadcast`, built
to the production engine's shape (hub task per node, task per link, bounded queues
that end the group rather than drop). They agree within 0.2%, and modelled push
agrees with the engine to the byte.

**The one seam is the workload's size inputs.** Fragment sizes are constants
transcribed from `concurrent-psbt` (fungi-protocol/concurrent-psbt, develop at
24bcca7e6545); this crate does not depend on it and no test links the two, so an
encoding change there would not fail anything here.

```
empty fragment (concurrent-PSBT globals alone)   105 bytes
+ one segwit input                               +77   -> 182
+ one legacy input (prev tx, 2 in / 2 out)      +420   -> 525
+ one output                                     +73   -> 178
+ a signature on an input                       +107   -> 289
```

Every fragment pays a 105-byte floor for the globals, which puts the smallest
object about three times a 32-byte id. An output and an input are within four
bytes of each other, so no fragment class sits near the announcement threshold. A
legacy input is 5.5x a segwit one, which is why previous transactions are the
object worth addressing separately.

Reproduce with `cargo run --release -p gossip-sim --bin run -- <table>`, on a
single-threaded runtime.

**Tables run at different link buffers, engine queues and schedules, and their
byte columns are still comparable.** The same cell (n = 100, k = 4, seed 0, push)
reads 292,894 in four of them, across both schedules and across buffers of 32 and
4096: a message crosses `k + (n−1)(k−1)` links whichever order it goes in and
whatever it waits on, so long as nothing is dropped. The capacity sweep is the one
place where copies are dropped, and it is reported on its own terms. Three columns
are NOT comparable across tables, because they are joint properties of a scheme and
the rate it is fed at: `dupes`, `peak`, and hop depth.

**Three caveats that hold throughout.** The factor derives from bytes **sent**:
`shutdown` drains what a node owes, not what it is owed, so receipts (and the
duplicate column) are a lower bound at teardown. `per_peer` is a **mean**, which
equals the per-peer cost only because the graphs are regular. The session hello is
not counted; the harness admits links through `AssumeSessionBound`.

## Push

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

The factor converges downward on `k − 1` = 3 as the `k/(n−1)` term of
`k + (n−1)(k−1)` divided by n washes out. It is analytic: flooding sends
`k + (n−1)(k−1)` copies on any connected k-regular graph, which gives 3.05 at
k = 4 and 18.05 at k = n−1 = 19, both confirmed. Because the factor depends only
on n and k, the seed axis is a self-consistency check on the harness, not evidence
about topology; what varies by draw is hop depth and partition risk.

### Degree

Five seeds per cell, same shares, both schemes. Push's latency is mean hop depth;
pull's is rounds, since its frames are tagged and carry no depth of their own.

```
        n = 20                                  n = 100
k       push            pull b=50               push            pull b=50
3        39911  2.05     24485  1.26             195466  2.01    126038  1.29
         2.48-2.59 hops  5-6 rounds              4.61-4.90 hops  9-10 rounds
4        59380  3.05     26762  1.37             292713  3.01    137135  1.41
         2.00-2.15 hops  4-5 rounds              3.53-3.59 hops  6-7 rounds
8       137256  7.05     35881  1.84             681701  7.01    182169  1.87
         1.50-1.52 hops  3 rounds                2.42-2.44 hops  5 rounds
```

**Degree is the whole of push's redundancy factor.** Halving it halves the
traffic at any scale. Seeds move `per_peer` by less than 0.2%.

**Degree is not nearly free for pull on this workload, as it is on the open
network.** Doubling from 4 to 8 costs pull **33%** more bytes here — 137,135 to
182,169 — against 15% on the open network, and buys one round rather than a third
of the depth. The reason is the same arithmetic the
threshold turns on, read from the other side: an announcement floods with the
degree, and this workload's objects are small enough that the announcements are
a large share of what pull sends. On the open network, where a proposal is
kilobytes, they are not.

**The two settings therefore want different degrees, each measured on its own
workload.**

### Hop depth

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
identically, and feeding them one publication at a time gives the complete graph
max depth 1 in every phase, which is the structurally correct answer. Depth above
1 is the burst. Depth is not reproducible run to run and push's bytes are; a test
in `report.rs` pins that boundary.

## The three schemes

Degree 4, seed 0, same shares. `per_peer` is bytes sent; `wire` adds the four-byte
length prefix. All three modelled schemes share one lockstep round driver over the
same metered links, so a difference between rows is a difference between schemes.

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

**Announce/pull more than halves the traffic**, 3.01 to 1.41. Push spends
`k + (n−1)(k−1)` copies of every object, 301 at a hundred peers; pull spends one
copy per peer that lacks it, plus an announcement on every link. Most of the
saving is duplicate suppression, not the dependency saving.

**Batching barely matters.** One identity per frame against fifty moves `per_peer`
by 1%; only `wire` moves, by 5%. At these message counts the announcement traffic
is the identities, not their envelopes.

**A pull round is not a push round.** Pull uses about the same number of rounds
(7 against 7 at a hundred peers), but each is announce, request, then data, so it
costs two to three times the latency for half the bytes.

Across five sampled graphs the ordering holds on every draw.

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

### Where the push/pull threshold sits

Hybrid at a hundred peers, degree 4, batch 50, `push_below` swept. A step function
whose steps are the measured fragment sizes.

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

**The minimum is at "announce everything".** An announcement floods exactly as a
message does, 301 copies at n = 100, k = 4, but the object then travels only to
the 99 peers that ask. Announcing wins when

```
301 x id + 99 x object  <  301 x object      i.e.   object > 1.5 x id
```

With a 37-byte outpoint identity the break-even is near 55 bytes on the wire, and
the 105-byte globals floor puts every object above it. The crossover is 1.5x the
identity width rather than the order of magnitude a size-ratio rule suggests,
because the saving comes from the `301 → 99` collapse in how far the payload
travels. It depends only on n, k and the identity width, so it transfers.

## Validation dependencies

A prev tx is addressed by its txid and a prevout by its outpoint: identities that
exist before the message does, which is what lets a peer decline an object it
never received. Every other message here is identified by the hash of its own
content, which no peer can claim to hold in advance.

### What push wastes

20 peers, degree 4, `legacy_fraction: 0.3`, five seeds, full-node share swept.

```
full_node_fraction  per_peer  dep_bytes  dep_to_holders  dep_ratio  avoid_share
0.0                 59410     ~257-260k  0               0.00       0.00
0.5                 59410     ~257-260k  ~119-132k       0.46-0.51  0.10-0.11
1.0                 59410     ~257-260k  ~257-260k       1.00       0.22
```

**Dependencies are 22% of the traffic at the ceiling** (46,460 bytes per peer
without them, 59,410 with), and **at a half-and-half population the avoidable
share is 11% of everything a peer sends**. That ceiling is n-invariant:
`avoid_share` reads 0.11 at twenty peers and at a hundred.

`dep_ratio` tracks the holder fraction by construction and is a self-consistency
check on the accounting; `avoid_share` carries the information. `dep_to_holders`
depends on delivery order and moves between runs the way duplicates do, so read
`avoid_share` as 0.10-0.11.

### What pull keeps

100 peers, degree 4, `legacy_fraction: 0.3`, staggered.

```
full_node_fraction   push per_peer   pull per_peer   pull factor
0.0                     292894          148232          1.52
0.5                     292894          137666          1.41
1.0                     292894          129427          1.33
```

**Push does not move by one byte**, because it cannot decline what is being
forwarded. That flat row is the control that makes the pull row a measurement.
Pull turns the knowledge into traffic it does not send: 7% and 13% of its own
traffic. Smaller in absolute terms than push's ceiling, because the ceiling is
computed on 301 flooded copies while pull was only ever going to send 99. **The
saving separate addressing buys is proportional to what the scheme sends, not to
what push wastes.**

A full node announces what it resolves locally as well as holding it, so any
neighbour can pull the object from there. The peer that owns a late addition is
therefore not the only one that can serve its prevout data.

### What the proposal already settled

Resolving locally is one of two reasons a peer can decline, and the weaker one.
The other is a property of the object: an input named in the coalition formation
proposal every participant signed carries dependencies all of them already hold.
Separate addressing is worth something only for what is not named there.

100 peers, degree 4, `legacy_fraction: 0.3`, `full_node_fraction: 0.5`.

```
late_addition_fraction   push per_peer   pull per_peer   pull factor   pull peak
0.00                        292894          129427          1.33          21
0.25                        292894          129881          1.33          26
0.50                        292894          130328          1.34          50
1.00                        292894          137666          1.41         130
```

**Every other figure in this document is measured at 1.00, the ceiling**, where
every input is treated as unnamed. The setting the protocol describes sits at the
other end, where pull lands on 129,427, the same figure a fully-resolving
population reaches, as it must.

**That ceiling is a bound, not a case.** A late addition's block space has to be
covered by an input the proposal did name, so some share of the inputs is always
named and the axis cannot reach 1.00. Where it stops short depends on allocation
sizes, which this workload does not model — so the right-hand column is the most
that unnamed inputs can cost, measured rather than argued.

**The curve steps late, and the step is the legacy inputs.** Late additions are
drawn from the end of the peer range and legacy inputs from the start, so the
420-byte previous transactions only join the replicated set above about 0.70.
A prevout is 31 to 43 bytes against a 37-byte identity, so announcing one is close
to a wash. **Whether separate addressing pays is decided by how many legacy inputs
are unnamed, not how many inputs are.** On buffers the effect is sixfold: pull's
peak occupancy falls from 130 frames to 21.

**The axis is a-priori knowledge, not the whole cost of arriving late**, and the
rest of that cost is priced separately below rather than folded in here. An input
the proposal does not name has to be proven spendable by an online key it does not
name either, so it arrives with at least an ownership proof certifying that key —
an object no peer can decline. Every figure in this section, and every other
figure in this document, is measured with none of them published.

### What arriving late costs on top

100 peers, degree 4, `legacy_fraction: 0.3`, `full_node_fraction: 0.5`,
`late_addition_fraction: 1.0`, one object of 200 to 300 bytes per unit.

```
overhead   push per_peer   factor   pull per_peer   factor
0             292894        3.01       137666        1.41
1             379624        3.01       177906        1.41
2             465984        3.01       218029        1.41
```

**One such object costs about 30% of the whole run under either scheme, and moves
the redundancy factor by nothing at all.** Both are what an undeclinable object
has to do: each scheme carries it at its own rate, so the ratio between them
cannot move, and the absolute cost is large because the object is large next to
the fragments it accompanies. The second unit costs the same as the first, so
whether the new online key is a gossiped object of its own or a field inside the
proof certifying it — which the protocol has not settled — is worth one row of
this table either way.

**This is what the a-priori axis does not measure, and it does not change what
separate addressing is worth:** an object no peer can decline is outside that
envelope, which is why it is charged here and left out of every other table.

### Separate, bundled, or both

Naming an object is only worth what declining it saves, less what naming costs,
and neither term is knowable without running the arm where the dependency is not
named at all. Bundled carries it inside the input fragment that needs it: no
identity, so no peer can hold it in advance and no announcement is spent on it,
but every peer receives it.

100 peers, degree 4, `full_node_fraction: 0.5`, pull b=50 and push.

```
scheme                     per_peer   factor
push,  bundled               278415     3.01
push,  separate l=1.0        292894     3.01
pull,  bundled               126838     1.37
pull,  separate l=1.0        137666     1.41
pull,  separate l=0.0        129427     1.33
```

**At this workload's shares, bundling wins under both schemes.** Push saves an
envelope per dependency. Pull saves the announcement too, and the announcements
cost more than the payload declining avoids.

That is one cell, and it is not the cell separate addressing does best in. Its
best case is every dependency a whole previous transaction and every peer already
holding it, so the legacy share is swept there.

100 peers, degree 4, `full_node_fraction: 1.0`, `late_addition_fraction: 0.0`,
pull b=50.

```
legacy   bundled   separate   prev-tx only
0.0      114321     125467       114321
0.3      126838     129427       118281
0.7      143563     134711       123565
1.0      156113     138675       127529
```

**Addressing everything separately loses below about half legacy inputs and wins
above it. Addressing only previous transactions wins everywhere.** At a legacy
share of zero it is bundling exactly, as it must be, and at a legacy share of one
it reaches a factor of **1.01**, the floor.

**The two dependency objects sit on opposite sides of the same arithmetic the
hybrid result turns on, measured against a different baseline.** Hybrid compares
an object on the wire, envelope included, against 1.5x the identity; bundling
pays neither envelope nor announcement, so it compares the payload alone. A
prevout of 31 to 43 bytes against a 37-byte outpoint is a wash, so naming it is
overhead however many peers could decline it. A previous transaction at 420 bytes
is an order of magnitude clear. Both follow from the sizes, not from this
workload.

**This contradicts half of the clause it discharges.** Previous transactions
identified by txid pay; prevouts identified by outpoint do not, at any share
measured. An implementation wants one identity space for txids and no separate
addressing for prevouts, which is less protocol, not more.

## The open network

More peers, fewer and larger messages, one phase rather than three. **These sizes
are estimates**, not measured artifacts: ownership proofs of 200-300 bytes,
co-spend proposals of 1.2-2 KB compactly or 10-40 KB naively. Ratios survive a
uniform error in them; absolute per-peer figures do not.

```
cell                              push                announce/pull b=50
                              per_peer  factor      per_peer   factor
n=100 k=4 compact proofs        231953    3.01         91553     1.19
n=100 k=4 naive proofs         2438548    3.01        817310     1.01
n=300 k=4 compact proofs        699452    3.00        277969     1.19
n=300 k=8 compact proofs       1631020    7.00        318141     1.37
```

**Pull decouples bandwidth from degree and push does not.** Push's factor is
`k − 1` exactly, so raising the degree to cut latency costs proportionally more
traffic; pull's moves only 1.19 to 1.37 across the same change while mean depth
falls from 4.54 to 2.98 hops. That is the single most useful property either
scheme has. At tens of kilobytes per proposal pull reaches 1.01, the floor, because
announcement overhead vanishes against the object size.

**The two policies.** Announce/pull in both, at different degrees, and the degree
sweep run on each workload is what separates them. Open broadcast takes degree 8,
where 15% more bytes buy a third fewer hops and no phase barrier multiplies what a
hop costs. Closed construction takes degree 4, where the same doubling costs 33%
and buys one round out of six. Degree 3 is cheaper still, at 1.29, for three more
rounds; which of 3 and 4 to default to is a latency question, and latency in
seconds is the axis this harness does not model. **The difference between the two
settings is a parameter, not a scheme:** one engine with a degree knob.

## At the message count the target scale is described in

Ten to fifteen messages per peer, about a thousand overall at a hundred peers. The
happy path publishes 4.3; three validity proofs per peer per phase reach 13.3.

```
100 peers, degree 4, staggered           per_peer    factor
push, no proofs                            292894      3.01
announce/pull b=50, no proofs              137666      1.41
push, 3 compact proofs per phase          3428254      3.01
announce/pull b=50, 3 compact proofs      1274343      1.12
push, 3 naive proofs per phase           67300725      3.01
announce/pull b=50, 3 naive proofs       22282232      1.00
```

**In the compact format the criterion holds, with less room than it looks:** push
has 2.9x of headroom against a budget of about 10 MB. **In the naive format push
breaks it and announce/pull does not rescue it either.** 67.3 MB is six times the
budget; pull sends 22.3 MB, still over, but at a factor of **1.00**. Below that
floor there is nothing left for any scheme to remove, so a workload carrying naive
proofs is a proof-size problem, not a dissemination problem. **What the
measurement settles is that push cannot help and announce/pull leaves nothing on
the table.**

Pull improves as messages grow, 1.41 to 1.12 to 1.00, because announcement
overhead is fixed per object while the payload it saves is not. The proof sizes
are an assumption in both directions; the ranking does not move with it, the
verdict on the baseline does, which is why both ends are run.

## Buffers

### The capacity boundary

Per-link buffer swept at 20 peers, seed 0, publishing a whole phase at a time.

```
capacity   degree 19 (complete)                 degree 4
1          per_peer 179361  factor 11.77        45723   3.00
2          per_peer 195778  factor 12.85        46460   3.05
4          per_peer 225718  factor 14.82        46460   3.05
8          per_peer 254993  factor 16.74        46460   3.05
32         per_peer 274955  factor 18.05        46460   3.05
```

**Every row converges**, including a complete graph given one slot per link
direction. The buffer sets how much redundancy survives, not whether the group
agrees: a copy dropped on a saturated link is one another path already carried,
and `seen` discards it there anyway. Rows that drop report `drained: false` and
a failed-send count.

**The transitional row is one draw, not a constant.** Where a buffer drops
everything it can or nothing at all the bytes reproduce exactly; where it is wide
enough that some sends survive and some do not — the complete graph at a buffer of
8 — how many are abandoned depends on the interleaving, and the figure moves about
3% between runs. It is the only row here whose bytes move that far: the
asynchronous engine's own column moves by hundredths of a percent, and every
modelled row reproduces exactly.

**Degree 4 is clean from a buffer of 2 upward** and loses 1.6% of its traffic at
a buffer of 1. The complete graph is where the fan-out has nowhere to go, and
its factor falls from 18.05 to 11.77 as the buffer narrows.

**The demand has a closed form on a complete graph.** Peak occupancy is `n − 2`,
the number of links a node forwards onto, confirmed at n = 10, 20, 30, 40, 50. A
buffer under that is a buffer that drops.

### The publication schedule

The producer side of the same knob. Twenty peers, engine queue 64, capacity
swept, `Schedule::Burst` against `Schedule::Staggered { publications: 1 }`.

```
              burst, complete   burst, k=4   staggered, complete   staggered, k=4
capacity 1     179361 (11.77)   45723 (3.00)   274955 (18.05)      46460 (3.05)
capacity 2     195778 (12.85)   46460 (3.05)   274955 (18.05)      46460 (3.05)
capacity 4     225718 (14.82)   46460 (3.05)   274955 (18.05)      46460 (3.05)
capacity 8     254993 (16.74)   46460 (3.05)   274955 (18.05)      46460 (3.05)
capacity 32    274955 (18.05)   46460 (3.05)   274955 (18.05)      46460 (3.05)
```

**Fed one publication at a time, the buffer stops mattering entirely.** Every
staggered cell reports the same bytes, the same factor and a peak occupancy of
exactly 1, at every capacity. Nothing is ever parked, so nothing is ever
abandoned.

**Traffic is invariant to the schedule wherever nothing is abandoned.** Burst
and staggered agree to the byte at a buffer of 32, because a message crosses
`k + (n−1)(k−1)` links whichever order it goes in. They diverge below that, and
the difference is exactly the redundant copies the burst dropped.

**What moves with the schedule alone is hop depth and duplicates.** The complete
graph settles at a depth of exactly 1 when staggered, against 1 to 4 in a burst,
and the duplicate count rises from 15,941 to 20,475 because a staggered run has
no forwards truncated at teardown.

### Two bounded resources

A run is bounded by the per-link buffer and, separately, by the engine's own
queues. They behave differently. A full link buffer parks the sending task,
which costs the copies it was carrying: a link whose peer has stopped talking
drops the forward it is parked on, and the run reports a failed send. A full
engine queue is served by `try_send` and ends the group with a typed error,
which arrives as a row with `converged: false`. Both are inputs:
`RunConfig::capacity` and `RunConfig::queue_capacity`.

**The engine's queue binds first as peers are added.** At forty peers with
dependency traffic the group ends under the default of 64, identically at link
buffers of 32 through 1024, and converges once the engine's queues alone are
widened.

```
n=40   drain did not finish — gossip link 0 did not finish flushing
n=60   drain did not finish — gossip forward on link 1 failed: channel closed
n=80   drain did not finish — gossip forward on link 1 failed: channel closed
n=100  drain did not finish — gossip forward on link 0 failed: channel closed
```

At forty peers the drain reports a link that still owed bytes when it was asked
to finish; beyond that, forwards fail outright on links already closed. Either
way what filled is the hub's queue toward its own consumer, because the harness
drains a node only between phases. The bound that binds first at this scale is a
property of how the caller drives the engine, not of the graph — widening the
engine's queues alone converges every row, at the same bytes the push table
reports. **A row that did not converge reports how far it got, not what
dissemination costs.**

### The buffer depth each scheme demands

Measured by walking the event log and tracking, per link direction, how many
frames had been sent and not yet received.

```
cell                              push        announce/pull b=50
construction, n=20,   k=4          18-21       26          model and engine agree
construction, n=40,   k=4          34          52          model and engine agree
construction, n=100,  k=4          105-121     68 engine / 130 model
open broadcast, n=300, k=4 and 8   151-242     73-81       modelled
open broadcast, n=1000, k=4        396         193         modelled
open broadcast, n=1000, k=8        666         248         modelled
```

**Pull is heavier at small n and lighter at large, crossing between forty and a
hundred peers.** Push's occupancy is its fan-out repeated for everything it holds,
climbing roughly with n; pull's is how many objects it answers on one link at
once, which climbs far more slowly. Where the model and the engine disagree, read
the engine: the model plans a whole step and hands it over at once, the engine
flushes as it goes, so the model's occupancy is an upper bound that loosens with
scale. Its byte figures do not depend on ordering and are unaffected.

Only burst cells belong in this table; a staggered schedule gives every scheme a
depth of exactly 1. Every comparison table here runs at a capacity of 4096, well
above the largest figure in it.

## The model, checked against a running engine

Announce/pull built a second time with the production engine's shape and driven
through the same `run()`. Degree 4, seed 0, same shares.

```
             pull b=50        pull b=50                    peak occupancy
n            model            engine        gap        push    model    engine
20            26863            26919       +0.2%         18       26        25
40            54637            54641      +0.01%         34       52        52
100          137666           137367       -0.2%        105      130        68
```

The model holds on bytes within a fifth of a percent at every scale, and the
factor reads identically. The engine column is one draw of an asynchronous run and
moves by a few hundredths of a percent between them, which is why the agreement is
stated as a bound. **Every announce/pull figure in this document therefore
stands on an engine with real concurrency and real backpressure.**

## A thousand peers

Modelled: the asynchronous harness's drain wakes every waiting task on every
receipt and does not reach this scale. `proposal_fraction: 0.1`, compact proofs.

```
degree   push per_peer   factor    pull per_peer   factor   saving
4           1353610       3.00        579827       1.29      57%
8           3157822       7.00        699154       1.55      78%
```

Everything the smaller rows say holds. The two cells together cost 0.94 GB and
126 s of CPU, which is why each is one seed rather than five.

## The harness's operating envelope

A run holds one event per frame per direction, about forty bytes each, and a
flooded run generates `messages x (k + (n-1)(k-1))` frames per direction.

```
cell                                      events     peak RSS   CPU
20 peers, degree 4                        ~10 k      7 MB       20 ms
100 peers, degree 4                       ~259 k     75 MB      0.5 s
50 peers, complete (link buffer 2048)     ~1.03 M    213 MB     1.3 s
1000 peers, degree 4 and 8, modelled      ~8 M       0.94 GB    126 s
100 peers, complete                       ~8.6 M     ~2 GB, not run
```

The thousand-peer cell is slow because a modelled step joins one future per link
and `join_all` polls every unfinished future on every wake: at degree 8 that is
four thousand futures per step. `FuturesUnordered` would poll only what became
ready, and is where to start if this has to reach further.

## What this does not answer

**Answered.** The push baseline at measured message sizes and at the peer counts
the target names, on the production engine, in both proof formats. The degree
lever under both schemes on both workloads, and what it costs in hops and rounds.
What a late addition costs beyond the dependency nobody holds in advance.
Validation dependencies priced from three sides: what push wastes, what pull
keeps, and what is left once the proposal has already named most inputs. All
three schemes on one workload and one graph, five sampled graphs each.
Announce/pull built twice and agreeing to 0.2%.

**Rests on assumptions, stated where used.** The validity-proof sizes, the late
addition's overhead objects and every size in the open-broadcast workload are
estimates, because nothing exists yet to serialise those messages from. They do
not move the ranking: announcing beats flooding above 1.5x the identity width,
which every size in every range clears.
They do move the verdict on the baseline, which is why both ends are run. The
holder, legacy and unnamed shares and the identity width are inputs of the same
kind; the identity width is conservative, since a shorter one only helps pull.

**Hybrid was never run on the asynchronous engine.** It loses at every threshold in
the model, for a reason that is arithmetic rather than empirical.

**Nothing here crossed a real network.** Every link is an in-memory duplex. The
byte counts are what an engine hands to a channel and do not depend on what
carries it, and the criteria are stated in volume. What a real transport would
change is latency in seconds, deliberately not modelled, and where the capacity
boundary sits, already reported as a property of the transport.

**The complete graph at a hundred peers was computed, not run.** Both quantities
are closed forms confirmed at five points each: the factor is `(n−1)²/n` and the
occupancy `n − 2`. A hundred peers would read 98.01 and 98.

**Partition risk at low degree is not measured.** Sampling is checked for
connectivity over the feasible input space, which is not the same as bounding how
often a draw would fail.

**Churn is not modelled.** Membership is fixed for a run and the engine ends a
group when a link dies. It is the item's own deferral, and the one worth naming
next to a recommendation of announce/pull, whose per-peer state is exactly what
churn would disturb.

**Set reconciliation is untested, and this workload cannot settle it.** Every run
here is one-shot: peers start empty, publish once, converge. In that regime every
peer lacks nearly everything, announce/pull already runs at 1.01-1.19 in the open
setting, and there is at most a fifth of the traffic left to remove. **That result
does not transfer to the case reconciliation is actually proposed for**, a
long-lived set re-synced by a returning light client, where a peer lacks few of
many. Announce/pull's discovery cost does not depend on how much is missing: a
peer rejoining with `k` neighbours holding `m` objects receives `k x m x 33` bytes
of identities whatever it lacks. At `m = 1000`, `d = 50`, `k = 4` that is about
132 KB of identities to locate fifty objects, against a sketch of capacity 50 at a
few hundred bytes. **The entire headroom for reconciliation is the identities of
the objects you already hold, and it grows with the intersection.** This is
arithmetic from measured parameters, not a measurement; the missing number is what
a rejoining peer actually pays under each scheme, which needs no reconciliation
primitive to obtain and is the denominator any primitive has to beat.
