//! Build a delegated inception (`dip`) with a self-addressing delegator.
//!
//! A delegated identifier names its delegator in the `di` field. keripy allows
//! any valid prefix code there (basic *or* self-addressing); this example uses a
//! transferable (self-addressing) delegator AID — now expressible after #68.
//!
//! Run with:
//! ```text
//! cargo run --example delegated_inception --features serder
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the delegated inception event"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::keri::Identifier;
use cesr::serder::DelegatedInceptionBuilder;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw([0x11u8; 32].to_vec())?
        .build()?;

    let delegator = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw([0x44u8; 32].to_vec())?
        .build()?;

    let dip = DelegatedInceptionBuilder::new()
        .keys(vec![key])
        .delegator(Identifier::SelfAddressing(delegator))
        .build()?;

    println!(
        "delegated inception:\n{}",
        String::from_utf8_lossy(dip.as_bytes())
    );
    Ok(())
}
