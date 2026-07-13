//! #145 event-wire matrix: keripy-generated events across all 5 ilks, both
//! derivations, and every threshold/witness/seal/config/intive variant must
//! (1) deserialize on the strict read path and (2) re-serialize byte-identically.
//!
//! The one anticipated write gap is keripy's `intive=True` integer thresholds:
//! the domain `Tholder`/`witness_threshold` do not retain the integer-vs-hex
//! wire form, and the writer always emits hex strings, so intive events read
//! and fold correctly but cannot round-trip byte-for-byte. Those rows are
//! `TRACKED` below (skipped by the byte-identity sweep) next to an `#[ignore]`d
//! probe that FAILS while the gap exists — the #144/#160 doctrine.

use std::eprintln;
use std::string::String;
use std::vec::Vec;

use crate::serder::deserialize::deserialize_event;
use crate::serder::serialize::serialize;

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
/// traits, and seal anchors — must round-trip exactly.
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
        let blocked = v.reserialize == "blocked";
        assert_eq!(
            blocked,
            tracked_issue(&v.case).is_some(),
            "{}: corpus `reserialize` flag and TRACKED table disagree",
            v.case
        );
        if blocked {
            eprintln!("TRACKED {}: #168", v.case);
            skipped += 1;
            continue;
        }
        let event =
            deserialize_event(v.raw.as_bytes()).unwrap_or_else(|e| panic!("{}: read: {e}", v.case));
        let re = serialize(&event).unwrap_or_else(|e| panic!("{}: write: {e}", v.case));
        assert_eq!(
            String::from_utf8_lossy(re.as_bytes()),
            v.raw,
            "{} ({}) must re-serialize byte-identically",
            v.case,
            v.ilk
        );
        asserted += 1;
    }
    eprintln!("events: {asserted} asserted, {skipped} tracked (#168)");
    assert!(
        asserted >= 20,
        "expected >=20 representable rows, got {asserted}"
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
        let event =
            deserialize_event(v.raw.as_bytes()).unwrap_or_else(|e| panic!("{}: read: {e}", v.case));
        let re = serialize(&event).unwrap_or_else(|e| panic!("{}: write: {e}", v.case));
        assert_eq!(
            String::from_utf8_lossy(re.as_bytes()),
            v.raw,
            "{}: intive event must re-serialize byte-identically once #168 lands",
            v.case
        );
    }
}

/// Anti-rot guard: every TRACKED case must still exist in the corpus. A stale
/// entry (case renamed or removed) means the tracked list drifted from reality.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only guard: a stale tracked entry panics with context"
)]
fn tracked_cases_exist_in_corpus() {
    let cases: Vec<String> = load_events().into_iter().map(|v| v.case).collect();
    for (case, issue) in TRACKED {
        assert!(
            cases.iter().any(|c| c == case),
            "TRACKED case `{case}` ({issue}) is absent from the corpus — stale entry"
        );
    }
}
