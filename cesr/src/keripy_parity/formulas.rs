//! Formula parity sweeps — `formulas.jsonl` (issue #151).
//!
//! Reintroducing the #147 `ample(3)` bug turns `ample_matches_keripy_table`
//! red at n=3 (mutation-proven in the PR). Strong-majority ample rows and
//! `divergence`-marked satisfy rows are counted and skipped — both are
//! deliberate, ledger-backed (`docs/keripy-parity/ledger.md`).

use std::eprintln;
use std::vec::Vec;

use crate::serder::ample::ample;
use crate::serder::deserialize::reference::tholder_from_json;

use super::load_formulas;

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: malformed corpus rows panic with context; counts logged"
)]
fn ample_matches_keripy_table() {
    let vectors = load_formulas();
    let mut weak = 0usize;
    let mut strong = 0usize;
    for v in vectors.iter().filter(|v| v.formula == "ample") {
        let n = usize::try_from(v.n.unwrap_or_else(|| panic!("ample row missing n")))
            .unwrap_or_else(|_| panic!("ample n exceeds usize"));
        if v.weak == Some(false) {
            strong += 1;
            continue;
        }
        let m =
            v.m.unwrap_or_else(|| panic!("weak ample row missing m (n={n})"));
        assert_eq!(
            u64::from(ample(n).unwrap_or_else(|e| panic!("ample({n}): {e}"))),
            m,
            "ample({n})"
        );
        weak += 1;
    }
    assert!(
        weak >= 257,
        "expected the full 0..=256 weak sweep, got {weak}"
    );
    eprintln!("ample: {weak} weak rows asserted, {strong} strong rows skipped (ledger)");
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: malformed corpus rows panic with context; counts logged"
)]
fn tholder_satisfy_matches_keripy() {
    let vectors = load_formulas();
    let mut rows = 0usize;
    let mut diverged = 0usize;
    for v in vectors.iter().filter(|v| v.formula == "tholder_satisfy") {
        let sith = v
            .sith
            .as_ref()
            .unwrap_or_else(|| panic!("satisfy row missing sith"));
        if let Some(reason) = &v.divergence {
            eprintln!(
                "DIVERGENCE satisfy(sith={sith}, indices={:?}): {reason}",
                v.indices
            );
            diverged += 1;
            continue;
        }
        let tholder = tholder_from_json(sith).unwrap_or_else(|e| panic!("sith {sith}: {e}"));
        let want = v
            .satisfies
            .unwrap_or_else(|| panic!("satisfy row missing verdict"));
        assert_eq!(
            tholder.satisfy(v.indices.iter().copied()),
            want,
            "satisfy(sith={sith}, indices={:?})",
            v.indices
        );
        rows += 1;
    }
    assert!(rows > 0, "no tholder_satisfy rows in corpus");
    eprintln!("tholder_satisfy: {rows} rows asserted, {diverged} divergence-skipped (ledger)");
}

#[test]
#[allow(
    clippy::expect_used,
    reason = "test-only guard: malformed corpus rows fail with context"
)]
fn satisfy_divergences_are_marked_not_dropped() {
    // Guard both directions of the divergence contract: the known divergent
    // row must still exist (marked), and cesr must actually disagree with
    // keripy on it — if cesr ever starts agreeing, the marker is stale and
    // must be removed so the row rejoins the main sweep.
    let vectors = load_formulas();
    let marked: Vec<_> = vectors
        .iter()
        .filter(|v| v.formula == "tholder_satisfy" && v.divergence.is_some())
        .collect();
    assert!(
        !marked.is_empty(),
        "expected at least the numeric-dup divergence row to be marked"
    );
    for v in &marked {
        let sith = v.sith.as_ref().expect("marked satisfy row missing sith");
        let tholder = tholder_from_json(sith).expect("marked satisfy row: unparseable sith");
        let keripy_verdict = v.satisfies.expect("marked satisfy row missing verdict");
        assert_ne!(
            tholder.satisfy(v.indices.iter().copied()),
            keripy_verdict,
            "divergence marker is stale: cesr now agrees with keripy on satisfy(sith={sith}, indices={:?}) — unmark the row",
            v.indices
        );
    }
}
