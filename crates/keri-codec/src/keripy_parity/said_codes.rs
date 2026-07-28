//! SAID-derivation-code parity sweep vs keripy (#144/#148/#160).
//!
//! Replays `said_codes.jsonl` — keripy `incept()`/`delcept()` wire bytes per
//! SAID derivation code — through the full cesr read→write path and asserts
//! byte-identity. The vectors settle keripy's mixed-code semantics: `d`
//! stays at the Blake3-256 field default while `i` is computed as an
//! *independent* SAID under the override code, so `incept(code=…)` emits a
//! mixed-code event (`i != d`) for every non-Blake3-256 code.
//!
//! #160 closed the gap: cesr dummies and verifies EVERY said field whose
//! code is digestive (keripy's rule), each under its own code, and the
//! writer emits `i` under the prefix's own code — so all 12 corpus rows,
//! mixed-code included, round-trip byte-identically. The sweep pins that
//! digestive-rule semantics.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::string::String;
use std::vec::Vec;

use crate::serialize::SerializedEvent;
use crate::traits::{Deserialize, Serialize};
use cesr::core::matter::code::DigestCode;
use keri_events::KeriEvent;

use super::{SaidCodeVector, load_said_codes};

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

/// Every corpus vector — the basic derivation, the single-code (`i == d`)
/// double-SAIDs, and the mixed-code (`i != d`) rows — must survive a cesr
/// read→write round trip byte-for-byte, reproducing keripy's own `said`.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: failed round trips panic with context"
)]
fn representable_vectors_round_trip_byte_identically() {
    let mut asserted = 0usize;
    for v in load_said_codes() {
        let raw = decode_raw(&v);
        let reser =
            round_trip(&raw).unwrap_or_else(|e| panic!("round trip {}/{}: {e}", v.factory, v.case));
        assert_eq!(
            reser.said().to_qb64(),
            v.said,
            "{}/{}: cesr must reproduce keripy's said",
            v.factory,
            v.case
        );
        asserted += 1;
    }
    assert_eq!(
        asserted, 12,
        "every corpus row must be asserted (12 = corpus line count)"
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
    use crate::said::verify_said_raw;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::VerKeyCode;

    let verfer = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(alloc::vec![7u8; 32])
        .unwrap()
        .build()
        .unwrap();
    let icp = InceptionBuilder::new()
        .keys(alloc::vec![verfer.into()])
        .said_code(DigestCode::SHA3_256)
        .build()
        .unwrap();
    verify_said_raw(icp.as_bytes()).expect("builder SHA3-256 double-SAID must verify");
}
