//! Codex parity sweeps — `codex.jsonl` (issue #151).
//!
//! Deleting a `ConfigTrait`/`Ilk` arm or a `Seal` reader arm turns
//! `codex_tables_match_keripy` red (mutation-proven in the PR). A codex entry
//! keripy adds at a future pin lands as a red diff via the nightly regen.
//!
//! `pre` rows replay cesr's identifier acceptance the way production does
//! (`parse_qb64_identifier`): a KERI prefix is either a basic derivation
//! (`VerKeyCode`) or a self-addressing digest (`DigestCode`), so the sweep
//! tries the prefixer path first and falls back to the diger path.

use serde_json::json;
use std::eprintln;
use std::string::String;
use std::vec::Vec;

use crate::core::matter::code::CesrCode;
use crate::core::matter::matter::Matter;
use crate::keri::{ConfigTrait, Ilk, Seal};
use crate::serder::deserialize::reference::{
    parse_qb64_diger_array, parse_qb64_prefixer_array, parse_seal_array,
};
use crate::serder::error::SerderError;
use crate::serder::primitives::to_qb64_string;

use super::{CodexVector, load_codex};

/// Seal shapes in keripy's codex not yet representable in cesr's `Seal`.
/// Burn-down list for #150: the `#[ignore]`d probe below FAILS while any
/// entry remains unimplemented; remove entries as #150 lands.
const TRACKED_SEALS: &[(&str, &str)] = &[("SealBack", "#150"), ("SealKind", "#150")];

fn tracked_seal(name: &str) -> Option<&'static str> {
    TRACKED_SEALS
        .iter()
        .find(|(seal, _)| *seal == name)
        .map(|(_, issue)| *issue)
}

fn seal_variant_matches(name: &str, seal: &Seal) -> bool {
    matches!(
        (name, seal),
        ("SealDigest", Seal::Digest { .. })
            | ("SealRoot", Seal::Root { .. })
            | ("SealSource", Seal::Source { .. })
            | ("SealEvent", Seal::Event { .. })
            | ("SealLast", Seal::Last { .. })
    )
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus rows panic with context"
)]
fn parse_sample_seal(v: &CodexVector) -> Result<Vec<Seal>, SerderError> {
    let sample = v
        .sample
        .as_ref()
        .unwrap_or_else(|| panic!("seal row {} missing sample", v.name));
    parse_seal_array(&json!([sample]))
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: a multi-element parse is a harness bug"
)]
fn single_to_qb64<C: CesrCode>(parsed: &[Matter<'_, C>], v: &CodexVector) -> String {
    let [matter] = parsed else {
        panic!(
            "{} {}: expected exactly one parsed primitive",
            v.family, v.name
        );
    };
    to_qb64_string(matter)
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: malformed corpus rows panic with context; counts logged"
)]
fn codex_tables_match_keripy() {
    let vectors = load_codex();
    let mut asserted = 0usize;
    let mut diverged = 0usize;
    let mut tracked = 0usize;

    for v in &vectors {
        if let Some(reason) = &v.divergence {
            eprintln!("DIVERGENCE {}/{}: {reason}", v.family, v.name);
            diverged += 1;
            continue;
        }
        match v.family.as_str() {
            "trait" => {
                let parsed = ConfigTrait::from_code(&v.code)
                    .unwrap_or_else(|e| panic!("trait {} ({}): {e}", v.name, v.code));
                assert_eq!(parsed.code(), v.code, "trait roundtrip {}", v.name);
            }
            "ilk" => {
                let parsed = Ilk::from_code(&v.code)
                    .unwrap_or_else(|e| panic!("ilk {} ({}): {e}", v.name, v.code));
                assert_eq!(parsed.code(), v.code, "ilk roundtrip {}", v.name);
            }
            "dig" => {
                let parsed = parse_qb64_diger_array(&json!([v.qb64]))
                    .unwrap_or_else(|e| panic!("dig {} ({}): {e}", v.name, v.code));
                assert_eq!(
                    single_to_qb64(&parsed, v),
                    v.qb64,
                    "dig roundtrip {}",
                    v.name
                );
            }
            "pre" => {
                let arr = json!([v.qb64]);
                let reencoded = match parse_qb64_prefixer_array(&arr) {
                    Ok(parsed) => single_to_qb64(&parsed, v),
                    Err(basic) => match parse_qb64_diger_array(&arr) {
                        Ok(parsed) => single_to_qb64(&parsed, v),
                        Err(dig) => panic!(
                            "pre {} ({}): not a basic prefix ({basic}) nor self-addressing ({dig})",
                            v.name, v.code
                        ),
                    },
                };
                assert_eq!(reencoded, v.qb64, "pre roundtrip {}", v.name);
            }
            "seal" => {
                if tracked_seal(&v.name).is_some() {
                    tracked += 1;
                    continue;
                }
                let seals = parse_sample_seal(v).unwrap_or_else(|e| panic!("seal {}: {e}", v.name));
                let [seal] = seals.as_slice() else {
                    panic!("seal {}: expected exactly one parsed seal", v.name);
                };
                assert!(
                    seal_variant_matches(&v.name, seal),
                    "seal {} parsed to the wrong variant",
                    v.name
                );
            }
            other => panic!("unknown codex family {other:?}"),
        }
        asserted += 1;
    }
    assert!(asserted > 0, "codex corpus asserted nothing");
    eprintln!(
        "codex: {asserted} asserted, {diverged} divergence-skipped (ledger), {tracked} tracked (#150)"
    );
}

/// Bug-probe for #150: keripy seal shapes cesr cannot read yet. FAILS while
/// the gap is open (run with `--ignored`); flips to a stale-marker failure in
/// `tracked_seals_still_exist_in_corpus` pruning once #150 lands.
#[test]
#[ignore = "#150: SealBack/SealKind not in cesr's Seal — this probe fails while the gap is open"]
fn tracked_seal_shapes_parse_150() {
    let vectors = load_codex();
    for v in vectors.iter().filter(|v| v.family == "seal") {
        let Some(issue) = tracked_seal(&v.name) else {
            continue;
        };
        let parsed = parse_sample_seal(v);
        assert!(
            parsed.is_ok(),
            "{issue} still open: seal {} rejected: {:?}",
            v.name,
            parsed.err()
        );
    }
}

#[test]
fn tracked_seals_still_exist_in_corpus() {
    // Guard: if a regen drops a tracked seal row the probe above passes
    // vacuously — fail here instead so TRACKED_SEALS gets pruned deliberately.
    let vectors = load_codex();
    for (name, issue) in TRACKED_SEALS {
        assert!(
            vectors
                .iter()
                .any(|v| v.family == "seal" && v.name == *name),
            "tracked seal {name} ({issue}) no longer in corpus — prune TRACKED_SEALS"
        );
    }
}
