//! SAID-derivation-code parity sweep vs keripy (#144/#148).
//!
//! Replays `said_codes.jsonl` — keripy `incept()`/`delcept()` wire bytes per
//! SAID derivation code — through the full cesr read→write path and asserts
//! byte-identity. The vectors settle empirically what the #148 audit left
//! unconfirmed: keripy keeps `d` at the Blake3-256 field default and computes
//! `i` as an *independent* SAID under the override code, so `incept(code=…)`
//! emits a mixed-code event (`i != d`) for every non-Blake3-256 code.
//!
//! cesr's verify rule dummies `i` only when `i == d` (string equality), while
//! keripy dummies every said field whose code is digestive — the rules agree
//! except on mixed-code events, which cesr's read path therefore rejects.
//! That gap is `TRACKED` below per the porting doctrine, next to an
//! `#[ignore]`d bug-probe that FAILS while it exists.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::eprintln;
use std::string::String;
use std::vec::Vec;

use crate::primitives::to_qb64_string;
use crate::serialize::SerializedEvent;
use crate::traits::{KeriDeserialize, KeriSerialize};
use cesr::core::matter::code::DigestCode;
use cesr::keri::KeriEvent;

use super::{SaidCodeVector, load_said_codes};

/// Mixed-code rows (`i`'s digest code differs from `d`'s Blake3-256) that
/// cesr's read path rejects today — the #160 burn-down. The main sweep skips
/// these; the `#[ignore]` probe FAILS while any remains unreadable. Remove
/// entries as #160 lands (the stale-entry guard below flags leftovers).
const TRACKED: &[(&str, &str, &str)] = &[
    ("incept", "digest_Blake2b_256", "#160"),
    ("incept", "digest_Blake2b_512", "#160"),
    ("incept", "digest_Blake2s_256", "#160"),
    ("incept", "digest_Blake3_512", "#160"),
    ("incept", "digest_SHA2_256", "#160"),
    ("incept", "digest_SHA2_512", "#160"),
    ("incept", "digest_SHA3_256", "#160"),
    ("incept", "digest_SHA3_512", "#160"),
    ("delcept", "digest_SHA3_256", "#160"),
];

fn tracked_issue(v: &SaidCodeVector) -> Option<&'static str> {
    TRACKED
        .iter()
        .find(|(factory, case, _)| *factory == v.factory && *case == v.case)
        .map(|(_, _, issue)| *issue)
}

#[allow(
    clippy::panic,
    reason = "test-only corpus loader: panics with context on malformed fixtures"
)]
fn decode_raw(v: &SaidCodeVector) -> Vec<u8> {
    BASE64
        .decode(&v.raw_b64)
        .unwrap_or_else(|e| panic!("decode raw_b64 for {}/{}: {e}", v.factory, v.case))
}

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

/// Every representable vector — the basic derivation and the single-code
/// (`i == d`) double-SAIDs — must survive a cesr read→write round trip
/// byte-for-byte, reproducing keripy's own `said`/`pre`.
#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: failed round trips panic with context; tracked skips logged"
)]
fn representable_vectors_round_trip_byte_identically() {
    let mut asserted = 0usize;
    let mut skipped = 0usize;
    for v in load_said_codes() {
        if let Some(issue) = tracked_issue(&v) {
            eprintln!("TRACKED {}/{}: {issue}", v.factory, v.case);
            skipped += 1;
            continue;
        }
        let raw = decode_raw(&v);
        let reser =
            round_trip(&raw).unwrap_or_else(|e| panic!("round trip {}/{}: {e}", v.factory, v.case));
        assert_eq!(
            to_qb64_string(reser.said()),
            v.said,
            "{}/{}: cesr must reproduce keripy's said",
            v.factory,
            v.case
        );
        asserted += 1;
    }
    eprintln!("said_codes: {asserted} asserted, {skipped} tracked (#160)");
    assert_eq!(
        asserted, 3,
        "expected the basic + two Blake3-256 control rows to assert"
    );
}

/// The settled keripy semantics, pinned against the corpus itself: `d` stays
/// at the Blake3-256 field default for every override, `i` carries the
/// override code, and `i == d` exactly when the override IS Blake3-256.
#[test]
fn keripy_keeps_d_at_blake3_when_overriding_i() {
    let blake3_qb64_code = "E";
    for v in load_said_codes() {
        if v.code.is_empty() {
            continue; // basic derivation row: i is a public key, not a SAID
        }
        assert!(
            v.said.starts_with(blake3_qb64_code),
            "{}/{}: keripy computes d under the Blake3-256 default, got {}",
            v.factory,
            v.case,
            v.said
        );
        assert!(
            v.pre.starts_with(&v.code),
            "{}/{}: keripy derives i under the override code {}, got {}",
            v.factory,
            v.case,
            v.code,
            v.pre
        );
        assert_eq!(
            v.said == v.pre,
            v.code == "E",
            "{}/{}: i == d exactly when the override is Blake3-256",
            v.factory,
            v.case
        );
    }
}

/// cesr's builder covers keripy's `incept(code=…)` single-code projection:
/// `said_code` produces an `i == d` double-SAID under the chosen code, which
/// the pinned keripy semantics accept (each said field verifies under the
/// code inferred from its own value). Asserted per-code against `verify_said`.
#[test]
fn builder_said_code_output_verifies_per_field() {
    use crate::builder::InceptionBuilder;
    use crate::said::verify_said;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::VerKeyCode;

    let verfer = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(alloc::vec![7u8; 32])
        .unwrap()
        .build()
        .unwrap();
    let icp = InceptionBuilder::new()
        .keys(alloc::vec![verfer])
        .said_code(DigestCode::SHA3_256)
        .build()
        .unwrap();
    verify_said(icp.as_bytes(), DigestCode::SHA3_256)
        .expect("builder SHA3-256 double-SAID must verify");
}

/// Stale-entry guard: every `TRACKED` row must still FAIL its round trip.
/// When #160 lands and a row starts passing, this test fails until the entry
/// is removed (and the row joins the main sweep).
#[test]
fn tracked_entries_are_not_stale() {
    for v in load_said_codes() {
        if tracked_issue(&v).is_none() {
            continue;
        }
        let raw = decode_raw(&v);
        assert!(
            round_trip(&raw).is_err(),
            "{}/{}: tracked as unreadable but now round-trips — remove it from TRACKED",
            v.factory,
            v.case
        );
    }
}

/// Bug-probe for #160: keripy mixed-code inceptions cesr cannot yet read.
/// FAILS while the gap exists; unignore when #160 lands.
#[test]
#[ignore = "bug-probe for #160: read path rejects keripy mixed-code (i-code != d-code) inceptions"]
#[allow(
    clippy::panic,
    reason = "test-only bug-probe: failed round trips panic with context"
)]
fn mixed_code_vectors_round_trip_byte_identically() {
    for v in load_said_codes() {
        if tracked_issue(&v).is_none() {
            continue;
        }
        let raw = decode_raw(&v);
        round_trip(&raw).unwrap_or_else(|e| panic!("round trip {}/{}: {e}", v.factory, v.case));
    }
}
