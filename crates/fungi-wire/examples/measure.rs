//! Encoded size per message kind and per encoding, at both scale regimes.
//!
//! The two regimes are not interchangeable: transaction construction is
//! roughly a hundred peers exchanging many small messages, while coalition
//! formation is far more peers exchanging fewer, larger ones. A fixed
//! per-message overhead is noise on a large proposal and significant on a
//! small update, so a single sample could elect the wrong shape.
//!
//! Run with:
//!   cargo run --manifest-path crates/fungi-wire/Cargo.toml --example measure

use fungi_wire::encoding::{AllTlv, Encoding, HeaderTlv, KvPairs, wrap};
use fungi_wire::{Body, Message};

fn sizes(msg: &Message) -> (usize, usize, usize) {
    // Every message this example builds is representable in all three
    // shapes, so an encode failure is a defect and must be loud rather
    // than silently reported as a zero-length row.
    (
        HeaderTlv::encode(msg)
            .expect("sample messages are encodable")
            .len(),
        AllTlv::encode(msg)
            .expect("sample messages are encodable")
            .len(),
        KvPairs::encode(msg)
            .expect("sample messages are encodable")
            .len(),
    )
}

/// How many extra bytes a shape spends carrying one message inside a
/// block, measured with that shape on BOTH layers.
///
/// Wrapping with one shape and measuring with another would report the
/// overhead of a mixture that no node would ever send.
fn wrap_overhead<E: Encoding>(inner: &Message) -> usize {
    let bare = E::encode(inner)
        .expect("sample messages are encodable")
        .len();
    let block = wrap::<E>(inner).expect("a block with no extensions is encodable");
    let wrapped = E::encode(&block)
        .expect("sample messages are encodable")
        .len();
    wrapped - bare
}

fn row(name: &str, msg: &Message) {
    let (h, a, k) = sizes(msg);
    let payload = msg.body.payload().len();
    println!(
        "{name:<34} {payload:>8} {h:>10} {a:>10} {k:>10}   {:>6} {:>6} {:>6}",
        h - payload,
        a - payload,
        k - payload
    );
}

fn main() {
    println!(
        "{:<34} {:>8} {:>10} {:>10} {:>10}   {:>6} {:>6} {:>6}",
        "message",
        "payload",
        HeaderTlv::NAME,
        AllTlv::NAME,
        KvPairs::NAME,
        "ovh",
        "ovh",
        "ovh"
    );

    println!("\n-- transaction construction: many small messages --");
    row("payment", &Message::new(Body::Payment(vec![0u8; 32])));
    row(
        "confirmation",
        &Message::new(Body::Confirmation(vec![0u8; 32])),
    );
    // Segwit spends carry prevouts; legacy ones carry whole previous
    // transactions, which is the widest spread in this regime.
    row(
        "psbt input (segwit)",
        &Message::new(Body::Psbt(vec![0u8; 128])),
    );
    row(
        "psbt input (legacy)",
        &Message::new(Body::Psbt(vec![0u8; 4096])),
    );
    row(
        "validity proof",
        &Message::new(Body::ValidityProof(vec![0u8; 1024])),
    );

    println!("\n-- coalition formation: fewer, larger messages --");
    row(
        "listen advertisement",
        &Message::new(Body::ListenAdvertisement(vec![0u8; 256])),
    );
    row(
        "co-spend proposal",
        &Message::new(Body::Psbt(vec![0u8; 65536])),
    );

    println!("\n-- nesting: what a Byzantine layer costs --");
    let inner = Message::new(Body::Psbt(vec![0u8; 128]));
    println!(
        "{:<34} {:>8} {:>10} {:>10} {:>10}",
        "block-wrapped psbt (overhead)",
        inner.body.payload().len(),
        wrap_overhead::<HeaderTlv>(&inner),
        wrap_overhead::<AllTlv>(&inner),
        wrap_overhead::<KvPairs>(&inner),
    );

    println!(
        "\nid exchange at 1000 messages: {} bytes full, {} bytes short",
        1000 * 32,
        1000 * 8
    );
}
