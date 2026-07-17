//! Build a self-addressing KEL chain: inception -> interaction -> rotation.
//!
//! Every event's identifier prefix (`i`) is the SAID of the *inception* event,
//! carried forward verbatim. `SerializedEvent::identifier()` hands the
//! inception's self-addressing prefix to each subsequent builder without
//! re-parsing JSON.
//!
//! Run with:
//! ```text
//! cargo run --example kel_chain --features serder
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints each event in the chain"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use keri_codec::{InceptionBuilder, InteractionBuilder, RotationBuilder};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let icp_key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw([0x11u8; 32].to_vec())?
        .build()?;

    let icp = InceptionBuilder::new().keys(vec![icp_key]).build()?;
    let id = icp
        .identifier()
        .ok_or("inception must expose a self-addressing identifier")?;
    println!("icp:\n{}\n", String::from_utf8_lossy(icp.as_bytes()));

    let ixn = InteractionBuilder::new()
        .prefix(id.clone())
        .prior_event_said(icp.said().clone())
        .sn(1)
        .build()?;
    println!("ixn:\n{}\n", String::from_utf8_lossy(ixn.as_bytes()));

    let rot_key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw([0x22u8; 32].to_vec())?
        .build()?;
    let next_key = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw([0x33u8; 32].to_vec())?
        .build()?;
    let rot = RotationBuilder::new()
        .prefix(id)
        .prior_event_said(ixn.said().clone())
        .keys(vec![rot_key])
        .prior_witnesses(vec![])
        .sn(2)
        .next_keys(vec![next_key])
        .build()?;
    println!("rot:\n{}\n", String::from_utf8_lossy(rot.as_bytes()));

    println!("KEL chain built: every event shares the inception's self-addressing prefix.");
    Ok(())
}
