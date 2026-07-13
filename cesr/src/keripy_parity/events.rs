//! #145 event-wire matrix: keripy-generated events across all 5 ilks, both
//! derivations, simple/weighted/multi-clause thresholds, witness lists (incl.
//! toad-max and rot cuts/adds), `TraitDex` config-trait combinations, event-seal
//! (`{i,s,d}`) anchors, and icp/rot intive rows must (1) deserialize on the
//! strict read path and (2) re-serialize byte-identically. Other seal shapes
//! live in the #150 `seal_events` family.
//!
//! The one anticipated write gap is keripy's `intive=True` integer thresholds:
//! the domain `Tholder`/`witness_threshold` do not retain the integer-vs-hex
//! wire form, and the writer always emits hex strings, so intive events read
//! and fold correctly but cannot round-trip byte-for-byte. Those rows are
//! `TRACKED` below (skipped by the byte-identity sweep) next to an `#[ignore]`d
//! probe that FAILS while the gap exists — the #144/#160 doctrine.

use std::eprintln;
use std::string::String;

use crate::serder::deserialize::deserialize_event;
use crate::serder::serialize::{SerializedEvent, serialize};

use super::load_events;

/// Scenario cases whose byte-identity is blocked by the intive write gap
/// (issue #168). The byte-identity sweep skips these; the `#[ignore]`d probe
/// FAILS while any remains non-round-trippable. Remove entries as #168 lands
/// (the stale-entry guard flags leftovers).
const TRACKED: &[(&str, &str)] = &[("icp_intive", "#168"), ("rot_intive", "#168")];

fn tracked_issue(case: &str) -> Option<&'static str> {
    TRACKED
        .iter()
        .find(|(c, _)| *c == case)
        .map(|(_, issue)| *issue)
}

/// Full read→write round trip; on success returns the re-serialized event.
fn round_trip(raw: &[u8]) -> Result<SerializedEvent, String> {
    let event = deserialize_event(raw).map_err(|e| alloc::format!("read: {e}"))?;
    let reser = serialize(&event).map_err(|e| alloc::format!("write: {e}"))?;
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
        deserialize_event(v.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{} ({}): read: {e}", v.case, v.ilk));
    }
}

/// Write differential: every representable corpus event must re-serialize
/// byte-for-byte. Intive rows (TRACKED) are skipped; everything else — basic
/// derivation (#144), weighted/multi-clause thresholds, witness br/ba, config
/// traits, and event-seal anchors — must round-trip exactly.
#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: failed round trips panic with context; tracked skips logged"
)]
fn event_corpus_reserializes_byte_identically() {
    let mut asserted = 0_usize;
    let mut skipped = 0_usize;
    for v in load_events() {
        assert_eq!(
            tracked_issue(&v.case).unwrap_or(""),
            v.blocked_by,
            "{}: corpus blocked_by and TRACKED table disagree",
            v.case
        );
        if v.reserialize == "blocked" {
            let issue = tracked_issue(&v.case)
                .unwrap_or_else(|| panic!("{}: blocked in corpus but absent from TRACKED", v.case));
            eprintln!("TRACKED {}: {issue}", v.case);
            skipped += 1;
            continue;
        }
        round_trip(v.raw.as_bytes()).unwrap_or_else(|e| panic!("{} ({}): {e}", v.case, v.ilk));
        asserted += 1;
    }
    eprintln!("events: {asserted} asserted, {skipped} tracked (#168)");
    assert_eq!(
        asserted, 24,
        "every representable corpus row must assert — count changes only with a reviewed generator change"
    );
}

/// Bug-probe for the intive write gap (#168): FAILS while any TRACKED intive
/// vector cannot round-trip byte-identically. `#[ignore]`d so the gap is a
/// tracked red, not a green build. Delete the `#[ignore]` (and the TRACKED
/// entries) when #168 lands.
#[test]
#[ignore = "#168: intive integer thresholds are not preserved on the write path"]
#[allow(
    clippy::panic,
    reason = "test-only probe: documents the gap, fails while it exists"
)]
fn intive_events_round_trip_byte_identically() {
    for v in load_events()
        .into_iter()
        .filter(|v| tracked_issue(&v.case).is_some())
    {
        round_trip(v.raw.as_bytes()).unwrap_or_else(|e| panic!("{}: {e}", v.case));
    }
}

/// Stale-entry guard: every `TRACKED` case must exist in the corpus and must
/// still FAIL its byte-identity round trip. When #168 lands and a row starts
/// round-tripping, this test fails until the entry is removed (and the row
/// joins the main sweep).
#[test]
#[allow(
    clippy::panic,
    reason = "test-only guard: a stale or missing tracked entry panics with context"
)]
fn tracked_entries_are_not_stale() {
    let vectors = load_events();
    for (case, issue) in TRACKED {
        let v = vectors.iter().find(|v| v.case == *case).unwrap_or_else(|| {
            panic!("TRACKED case `{case}` ({issue}) is absent from the corpus — stale entry")
        });
        assert!(
            round_trip(v.raw.as_bytes()).is_err(),
            "{case}: tracked as non-round-trippable but now round-trips — {issue} has landed; remove it from TRACKED"
        );
    }
}
