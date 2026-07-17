//! Incept a KERI identifier (AID) and verify it round-trips.
//!
//! An *inception* event creates an identifier. For a transferable identifier
//! the prefix (`i`) is self-addressing: it equals the event's own SAID (`d`), a
//! digest computed over the event. `InceptionBuilder` computes and splices that
//! SAID in for you. Deserializing re-verifies the SAID, so a successful
//! `deserialize` is proof the event is internally consistent.
//!
//! Run with:
//! ```text
//! cargo run --example incept_aid --features serder
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the identifier prefix and SAID"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::VerKeyCode;
use keri_codec::InceptionBuilder;
use keri_codec::{KeriDeserialize, KeriSerialize};
use keri_events::InceptionEvent;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // A deterministic public key stands in for a freshly generated one, so the
    // resulting AID is reproducible across runs. An owned Vec gives the Verfer a
    // 'static lifetime, which the builder requires.
    let key_bytes = [0x11u8; 32];
    let verfer = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(key_bytes.to_vec())?
        .build()?;

    // Single-signature inception: one current key, default threshold.
    let event = InceptionBuilder::new().keys(vec![verfer]).build()?;

    let said_text = event.said().to_qb64();
    let prefix = event
        .prefix()
        .ok_or("an inception event must expose a self-addressing prefix")?;
    let prefix_text = prefix.to_qb64();

    println!("AID prefix (i): {prefix_text}");
    println!("Event SAID (d): {said_text}");
    println!(
        "Serialized event:\n{}",
        String::from_utf8_lossy(event.as_bytes())
    );

    // The self-addressing invariant: for a transferable inception the prefix is
    // the event's own SAID.
    assert_eq!(
        prefix_text, said_text,
        "self-addressing inception: prefix (i) must equal the event SAID (d)"
    );

    // Deserialize the canonical bytes. This re-computes and verifies the SAID;
    // if it did not match, `deserialize` would return SerderError::SaidMismatch.
    let parsed = InceptionEvent::deserialize(event.as_bytes())?;
    assert_eq!(parsed.keys().len(), 1, "inception carries exactly one key");

    // Re-serializing the parsed event must reproduce the original bytes exactly
    // — a full encode → decode → encode round-trip.
    let reserialized = parsed.serialize()?;
    assert_eq!(
        reserialized.as_bytes(),
        event.as_bytes(),
        "round-trip: re-serialized event must be byte-identical"
    );

    println!("SAID verified on deserialize; byte-exact round-trip confirmed.");
    Ok(())
}
