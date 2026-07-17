//! #145 event-wire matrix: keripy-generated events across all 5 ilks, both
//! derivations, simple/weighted/multi-clause thresholds, witness lists (incl.
//! toad-max and rot cuts/adds), `TraitDex` config-trait combinations, event-seal
//! (`{i,s,d}`) anchors, and icp/rot intive rows must (1) deserialize on the
//! strict read path and (2) re-serialize byte-identically. Other seal shapes
//! live in the #150 `seal_events` family.
//!
//! The intive integer-threshold rows (`icp_intive`/`rot_intive`) round-trip
//! byte-for-byte like every other row: `ThresholdForm` on the establishment
//! events retains the integer-vs-hex wire form, closing #168 (rung 3 of #171).
//! Mixed wire forms (some numeric fields integer, others hex, in one event)
//! are rejected as non-canonical — a deliberate divergence-of-strictness, not
//! a corpus row.

use std::eprintln;
use std::string::String;

use crate::keri::KeriEvent;
use crate::serder::serialize::SerializedEvent;
use crate::serder::traits::{KeriDeserialize, KeriSerialize};

use super::load_events;

/// Full read→write round trip; on success returns the re-serialized event.
fn round_trip(raw: &[u8]) -> Result<SerializedEvent, String> {
    let event = KeriEvent::deserialize(raw).map_err(|e| alloc::format!("read: {e}"))?;
    let reser = event
        .serialize()
        .map_err(|e| alloc::format!("write: {e}"))?;
    if reser.as_bytes() == raw {
        Ok(reser)
    } else {
        Err(alloc::format!(
            "re-serialized bytes differ: {} vs {}",
            String::from_utf8_lossy(reser.as_bytes()),
            String::from_utf8_lossy(raw),
        ))
    }
}

/// Read differential: every corpus event — including delegated (dip/drt),
/// witnessed, weighted, config, seal, and intive shapes — must deserialize
/// on the strict path. A typed error here is a red build.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: an unreadable vector panics with case context"
)]
fn event_corpus_reads_cleanly() {
    let vectors = load_events();
    assert!(!vectors.is_empty(), "events corpus is empty");
    for v in &vectors {
        KeriEvent::deserialize(v.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{} ({}): read: {e}", v.case, v.ilk));
    }
}

/// Write differential: every corpus event must re-serialize byte-for-byte —
/// basic derivation (#144), weighted/multi-clause thresholds, witness br/ba,
/// config traits, event-seal anchors, AND the intive integer-threshold rows
/// (#168, closed by `ThresholdForm`).
#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: failed round trips panic with context; the count is logged"
)]
fn event_corpus_reserializes_byte_identically() {
    let mut asserted = 0_usize;
    for v in load_events() {
        // Anti-rot guard: the generator marks every row `identical` now that
        // #168 is closed. A future generator re-introducing a non-round-trip
        // row without a Rust-side counterpart fails loudly here.
        assert_eq!(
            v.reserialize, "identical",
            "{}: every corpus row must round-trip byte-identically",
            v.case
        );
        round_trip(v.raw.as_bytes()).unwrap_or_else(|e| panic!("{} ({}): {e}", v.case, v.ilk));
        asserted += 1;
    }
    eprintln!("events: {asserted} asserted");
    assert_eq!(
        asserted, 26,
        "every representable corpus row must assert — count changes only with a reviewed generator change"
    );
}
