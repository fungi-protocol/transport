# Message encoding and logical identity findings

Evidence from `crates/fungi-wire` on the `message-encoding-experiments`
branch.

## Reproduction

```console
cargo test --manifest-path crates/fungi-wire/Cargo.toml
cargo run --manifest-path crates/fungi-wire/Cargo.toml --example measure
cargo fmt --manifest-path crates/fungi-wire/Cargo.toml --check
cargo clippy --manifest-path crates/fungi-wire/Cargo.toml --all-targets -- -D warnings
cargo doc --manifest-path crates/fungi-wire/Cargo.toml --no-deps
```

The suite contains 106 passing tests. BOLT #1 fixtures are pinned to
`lightning/bolts` commit `152897261850d93c4f4597f39cf22d7d22d6ede6`.
The deterministic CBOR candidate implements the restricted data model directly
and follows RFC 8949 section 4.2.1.

## Recommendation

Use a fixed message header and payload followed by a Lightning-style TLV
extension stream:

```text
type:u16 || payload_length:BigSize || payload || extensions:TLV*
```

Header+TLV has the smallest overhead among the candidates that can represent
each measured workload. It keeps the message type and payload explicit, uses
TLV only for extensibility, and does not reserve extension types for envelope
fields.

## Encoding comparison

Extension-free messages:

| message | payload | header+tlv | all-tlv | kv-pairs | deterministic-cbor |
|---|---:|---:|---:|---:|---:|
| payment | 32 | 35 | 38 | 44 | 40 |
| confirmation | 32 | 35 | 38 | 44 | 40 |
| psbt input (segwit) | 128 | 131 | 134 | 140 | 136 |
| psbt input (legacy) | 4096 | 4101 | 4104 | 4110 | 4105 |
| validity proof | 1024 | 1029 | 1032 | 1038 | 1033 |
| listen advertisement | 256 | 261 | 264 | 270 | 265 |
| co-spend proposal | 65536 | 65543 | 65546 | 65552 | 65547 |

Envelope overhead is exact:

| payload range | header+tlv | all-tlv | kv-pairs | deterministic-cbor |
|---|---:|---:|---:|---:|
| representative small messages | 3 | 6 | 12 | 8 |
| 256–65535-byte workloads | 5 | 8 | 14 | 9 |
| 65536-byte workload | 7 | 10 | 16 | 11 |

For the BigSize candidates, with `L` equal to the encoded payload-length width:

```text
HeaderTlv = 2 + L
AllTlv   = 5 + L
KvPairs  = 11 + L
```

For the restricted CBOR map, `DeterministicCbor = 6 + C`, where `C` is
the preferred CBOR byte-string head width.

Messages carrying one 16-byte validity extension:

| message | payload | header+tlv | all-tlv | kv-pairs | deterministic-cbor |
|---|---:|---:|---:|---:|---:|
| payment + validity | 32 | 53 | cannot represent | 64 | 59 |
| listen advertisement + validity | 256 | 279 | cannot represent | 290 | 284 |

Under the provisional registry, all-TLV reserves record type 2 for its payload
while `EXT_VALIDITY` also uses type 2. A different extension assignment would
remove this collision, but the envelope would still require coordinated
allocation between structural and extension records.

The key-value candidate includes a six-byte `b"fungi\x00"` self-identification
prefix. Of its nine-byte gap from header+TLV, six bytes come from that independent
choice and three from the key-value shape.

The legacy concurrent-PSBT envelope at commit
`94032ea1bf632343f170475ea8b815042750fafb` uses one `u8` type, one big-endian
`u32` payload length, and the payload. Its constant five-byte overhead is two
bytes larger below 253 bytes, equal from 253 through 65535 bytes, and two bytes
smaller above 65535 bytes. It has no extension namespace, unknown-message
policy, logical identity, set commitment, or message-set algebra.

## Canonicality and compatibility

All four candidates share tests for round trips, exact lengths, nesting,
canonical re-encoding, message identity, extension ordering, duplicate record
rejection, minimal integer encodings, truncation, and trailing data.

The decoders reject unknown even message and extension types. Unknown odd types
are retained as opaque values and re-encode byte-for-byte for transparent
relay. Known extensions validate their value schema; the validity window is two
big-endian `u64` values with `from <= until`.

The protocol caps a canonical message at one MiB, matching the framed
transport's default payload cap. Extensions count toward this limit. The
four-byte frame prefix is outside the canonical message, the protocol cap, and
the logical identity. Tests cover exact size calculation, max−1, max, max+1,
BigSize boundaries, truncated lengths, integer conversion, and length-sum
overflow.

## Logical identity

The full logical identity is the BIP340-style tagged hash of the canonical
message bytes:

```text
MessageId = SHA256(
    SHA256("fungi/message-id") ||
    SHA256("fungi/message-id") ||
    canonical_message_bytes
)
```

It is 32 bytes and contains no transport, origin, clock, or author input.
Byte-identical messages therefore denote one logical event. Applications that
need identical content to denote distinct events must include a stable event or
idempotence identifier in the payload. Collision resistance relies on the
standard SHA-256 collision-resistance assumption.

The experiment also evaluates an eight-byte salted short ID for later bulk ID
exchange. It never keys `MessageSet` and is not part of the main-branch identity
scheme. The 16-byte random IDs used by concurrent-PSBT identify G-set entries in
PSBT keydata and have different semantics.

## Message-set convergence

`MessageSet` is a grow-only set keyed by full `MessageId`. Identical insertion
is a no-op. A full-ID collision with different canonical bytes returns
`IdentityCollision`; merge validates every collision before changing the set.

Property tests verify the join-semilattice laws:

```text
A ⊔ B = B ⊔ A
(A ⊔ B) ⊔ C = A ⊔ (B ⊔ C)
A ⊔ A = A
```

The set commitment is a tagged hash over the big-endian `u64` cardinality and
the sorted full 32-byte IDs:

```text
tagged_hash("fungi/message-set", count:u64_be || sorted_full_ids)
```

It is invariant under arrival order, duplication, and merge order. It is a flat
equality commitment under the same SHA-256 collision-resistance assumption,
not a Merkle root or inclusion-proof structure.

A representative application fold is tested as a join-semilattice
homomorphism over generated sets and validity windows:

```text
fold_at(now, A ∪ B) = fold_at(now, A) ⊔ fold_at(now, B)
```

A deliberately incorrect join fails the same property, confirming that the
test detects an invalid fold. The fold is experimental evidence for consumer
algebra, not the concurrent-PSBT state machine or a formal proof. Validity-based
derived state also depends on the evaluation clock even when the underlying
message sets are equal.

An in-memory integration test sends three typed messages in different orders,
including a duplicate, through server-style broadcast and line-shaped P2P
gossip. Every replica reaches the same full-ID set and commitment. This tests
transport-independent set convergence; it does not implement a set-
reconciliation algorithm.

## Main-branch implementation

The recommended header+TLV design is implemented on `main` at
`31a29a83eb9fed3b384ecfcaf420e434b42f5470`. The main-branch registry contains
PSBT (1), payment (3), and confirmation (5); the additional experimental
workloads do not define production message types. The main branch has no
assigned extension type yet; `EXT_VALIDITY = 2` is an experiment-only proposal.

The implementation includes conformance vectors, a separate reference
implementation of decoding, IDs, and commitments, and tests across memory,
framed streams, and Cap'n Proto subprocesses. The NixOS Tor E2E exercises typed
messages, canonical bytes, an odd extension, full IDs, deduplication, and equal
set commitments across socks5h–arti–socks5h. Both CI jobs passed:

<https://github.com/fungi-protocol/transport/actions/runs/33833144828>

## Decisions for review

- Select header+TLV as the canonical v1 envelope.
- Approve the message and extension registries.
- Approve the `"fungi/message-id"` and `"fungi/message-set"` domain tags.
- Preserve unknown odd messages and extensions for transparent relay while
  rejecting unknown even types.
- Treat byte-identical canonical messages as one logical event.

## Scope

This experiment does not select a set-reconciliation algorithm, change gossip
fanout, define replacement semantics, choose the internal structure of PSBT
fragment payloads, implement the concurrent-PSBT state machine, or provide a
formal proof. These remain separate follow-up decisions.
