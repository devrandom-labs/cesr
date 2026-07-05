//! Build a small CESR stream and parse it back into typed groups.
//!
//! A CESR stream is a sequence of *count-code framed* groups. Here we emit one
//! `-A` group (controller indexed signatures) announcing two signatures, then
//! parse the bytes back with `groups()` and inspect each signature. Parsing is
//! zero-copy and never panics on malformed input — it returns a typed
//! `ParseError`.
//!
//! Run with:
//! ```text
//! cargo run --example parse_stream --features stream
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the stream it builds and parses"
)]

use cesr::core::counter::CounterCodeV1;
use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::stream::encode::encode_counter_v1;
use cesr::stream::{CesrGroup, groups};
use std::error::Error;

const SIGS_PER_GROUP: u32 = 2;

fn main() -> Result<(), Box<dyn Error>> {
    // Frame one group by hand: a `-A` counter announcing two indexed signatures,
    // followed by the two 64-byte Ed25519 signatures (zeroed here for a
    // reproducible fixture).
    let mut stream = Vec::new();
    stream.extend_from_slice(&encode_counter_v1(
        CounterCodeV1::ControllerIdxSigs,
        SIGS_PER_GROUP,
    )?);
    for index in 0..SIGS_PER_GROUP {
        let siger_text = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)?
            .with_raw(vec![0u8; 64])?
            .to_qb64();
        stream.extend_from_slice(siger_text.as_bytes());
    }
    println!(
        "Built {}-byte stream: {}",
        stream.len(),
        String::from_utf8_lossy(&stream)
    );

    // Parse every group. Collecting the `Result`s surfaces any ParseError.
    let parsed = groups(&stream).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(parsed.len(), 1, "stream contained exactly one group");

    let Some(CesrGroup::ControllerIdxSigs(sigs)) = parsed.into_iter().next() else {
        return Err("expected a single ControllerIdxSigs group".into());
    };
    assert_eq!(
        sigs.count(),
        SIGS_PER_GROUP,
        "the count code must match the number of signatures built"
    );

    let sigers = sigs.into_vec()?;
    assert_eq!(sigers.len(), usize::try_from(SIGS_PER_GROUP)?);
    for (position, siger) in sigers.iter().enumerate() {
        assert_eq!(
            siger.index(),
            u32::try_from(position)?,
            "each signature's index must match its position in the group"
        );
        assert_eq!(siger.raw().len(), 64, "an Ed25519 signature is 64 bytes");
    }

    println!("Parsed 1 group of {SIGS_PER_GROUP} signatures; indices and sizes verified.");
    Ok(())
}
