//! Incept a multi-key identifier with a signing threshold.
//!
//! KERI identifiers can be controlled by several keys at once, with a
//! *threshold* saying how many must sign. `Tholder` expresses two kinds:
//! `Simple(m)` is any `m` of the `n` keys (an M-of-N rule); `Weighted(..)`
//! assigns fractional weights per key, satisfied when a clause sums to at
//! least 1. This builds a 2-of-3 identifier and a fractionally-weighted one,
//! and shows how each threshold lands in the canonical event.
//!
//! Note: this constructs the multisig *event*. Coordinating the actual signing
//! across parties is an agent-layer concern outside this primitives crate.
//!
//! Run with:
//! ```text
//! cargo run --example multisig_threshold_icp --features serder
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the multisig events it builds"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::VerKeyCode;
use cesr::keri::InceptionEvent;
use cesr::serder::{KeriDeserialize, KeriSerialize};
use cesr::{InceptionBuilder, Tholder, Verfer};
use std::error::Error;

/// A deterministic Ed25519 `Verfer` from a fill byte (stands in for a real key
/// so the events are reproducible). The owned Vec gives it a 'static lifetime.
fn verfer(fill: u8) -> Result<Verfer<'static>, Box<dyn Error>> {
    Ok(MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(vec![fill; 32])?
        .build()?)
}

fn main() -> Result<(), Box<dyn Error>> {
    // ── 2-of-3 (simple threshold) ────────────────────────────────────────
    let simple = InceptionBuilder::new()
        .keys(vec![verfer(0xA1)?, verfer(0xB2)?, verfer(0xC3)?])
        .threshold(Tholder::Simple(2))
        .build()?;
    let simple_json = std::str::from_utf8(simple.as_bytes())?;
    println!("2-of-3 (simple threshold):\n{simple_json}\n");

    assert!(
        simple_json.contains(r#""kt":"2""#),
        "a simple 2-of-3 threshold serializes as the string kt=\"2\""
    );
    let simple_event = InceptionEvent::deserialize(simple.as_bytes())?;
    assert_eq!(
        simple_event.keys().len(),
        3,
        "the identifier is controlled by three keys"
    );
    assert_eq!(
        simple_event.serialize()?.as_bytes(),
        simple.as_bytes(),
        "round-trip: re-serialized multisig event is byte-identical"
    );

    // ── weighted threshold: [1/2, 1/2, 1/2] — any two of three sum to ≥ 1 ─
    let weighted = InceptionBuilder::new()
        .keys(vec![verfer(0xA1)?, verfer(0xB2)?, verfer(0xC3)?])
        .threshold(Tholder::Weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]))
        .build()?;
    let weighted_json = std::str::from_utf8(weighted.as_bytes())?;
    println!("weighted threshold:\n{weighted_json}\n");

    assert!(
        weighted_json.contains(r#""kt":["1/2","1/2","1/2"]"#),
        "a weighted threshold serializes kt as an array of fraction strings"
    );
    let weighted_event = InceptionEvent::deserialize(weighted.as_bytes())?;
    assert_eq!(
        weighted_event.serialize()?.as_bytes(),
        weighted.as_bytes(),
        "round-trip: weighted multisig event is byte-identical"
    );

    println!("Both multisig inceptions verified and round-tripped.");
    Ok(())
}
