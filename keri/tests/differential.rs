//! keripy differential vector for the key-state transition.
//!
//! Replays a checked-in, **keripy-generated** KEL — inception -> rotation ->
//! interaction — through the real public [`KeyState::incept`] + [`KeyState::ingest`],
//! verifying keripy's own signatures inside the fold, and asserts the folded
//! [`KeyState`] matches keripy's authoritative `Kever` output.
//!
//! The expected `final_state` is produced by keripy's `Kever`, NOT by this crate —
//! so the assertion is a genuine cross-implementation agreement check, not a
//! tautology. The events carry keripy's real Ed25519 signatures (`sigs_qb64`),
//! which the transition verifies cryptographically; a fixture that merely
//! replayed indices would no longer pass. See `scripts/keripy_keystate_gen.py`
//! and the corpus header for provenance (keripy v2.0.0.dev5, V1 JSON).
//!
//! The corpus is embedded via `include_str!` because the nix gate builds and runs
//! tests in separate hermetic phases, so a runtime `CARGO_MANIFEST_DIR` path is
//! unreliable.
mod common;

use std::error::Error;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde_json::Value;

use cesr::Matter;
use cesr::keri::{Identifier, KeriEvent, SigningThreshold, WeightedThreshold};
use cesr::serder::deserialize_event;

use common::siger_from_qb64;
use keri::{KeyState, Signed};

type Fallible<T> = Result<T, Box<dyn Error>>;

const CORPUS: &str = include_str!("corpus/keystate.jsonl");
const KELS: &str = include_str!("corpus/kels.jsonl");

#[derive(Debug, Deserialize)]
struct Vector {
    events: Vec<EventRecord>,
    final_state: FinalState,
}

#[derive(Debug, Deserialize)]
struct EventRecord {
    raw_b64: String,
    sigs_qb64: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FinalState {
    prefix_qb64: String,
    sn: u128,
    keys_qb64: Vec<String>,
    threshold_sith: Value,
    next_keys_qb64: Vec<String>,
    next_threshold_sith: Value,
    witness_threshold: u32,
    witnesses_qb64: Vec<String>,
}

fn prefix_qb64(id: &Identifier<'_>) -> String {
    match id {
        Identifier::Basic(p) => p.to_qb64(),
        Identifier::SelfAddressing(s) => s.to_qb64(),
    }
}

/// A weighted-sith weight ("1", "0", or "n/d") as a (numerator, denominator)
/// fraction; whole numbers get an implicit denominator of 1.
fn fraction_from_weight(weight: &str) -> Fallible<(u64, u64)> {
    match weight.split_once('/') {
        Some((n, d)) => Ok((n.parse()?, d.parse()?)),
        None => Ok((weight.parse()?, 1)),
    }
}

/// One weighted-sith clause (a JSON array of weight strings) as fractions.
fn clause_from_sith(clause: &Value) -> Fallible<Vec<(u64, u64)>> {
    clause
        .as_array()
        .ok_or("weighted sith clause must be an array")?
        .iter()
        .map(|w| fraction_from_weight(w.as_str().ok_or("sith weight must be a string")?))
        .collect()
}

/// The EXPECTED `Tholder` built from keripy's oracle `sith` value — keripy
/// emits a hex string for simple thresholds, a flat array of weight strings
/// for a single weighted clause, and nested arrays for multi-clause.
fn tholder_from_sith(sith: &Value) -> Fallible<SigningThreshold> {
    match sith {
        Value::String(s) => Ok(SigningThreshold::Simple(u64::from_str_radix(s, 16)?)),
        Value::Array(items) => {
            let clauses = if items.iter().all(Value::is_array) {
                items
                    .iter()
                    .map(clause_from_sith)
                    .collect::<Fallible<_>>()?
            } else {
                vec![clause_from_sith(sith)?]
            };
            Ok(SigningThreshold::Weighted(WeightedThreshold::from_nested(
                clauses,
            )?))
        }
        other => Err(format!("sith must be a string or array, got {other}").into()),
    }
}

fn load_vector() -> Fallible<Vector> {
    let line = CORPUS
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or("corpus has a vector line")?;
    Ok(serde_json::from_str(line)?)
}

/// Read → re-serialize → byte-identity over the keripy-generated KEL (#144).
///
/// keripy is the oracle: every corpus event must survive a cesr
/// deserialize/serialize round trip byte-for-byte. The genesis event is a
/// basic-derivation inception (`i` is an Ed25519 public key, `i != d`), the
/// exact class the write path corrupted by unconditionally backpatching
/// `i` with the recomputed double-SAID.
#[test]
fn corpus_events_reserialize_byte_identically_vs_keripy() -> Fallible<()> {
    let vector = load_vector()?;
    for (idx, rec) in vector.events.iter().enumerate() {
        let raw = BASE64.decode(&rec.raw_b64)?;
        let event = deserialize_event(&raw)?;
        let reserialized = cesr::serder::serialize(&event)?;
        assert_eq!(
            core::str::from_utf8(reserialized.as_bytes())?,
            core::str::from_utf8(&raw)?,
            "corpus event {idx} must re-serialize byte-identically"
        );
    }
    Ok(())
}

#[test]
fn fold_agrees_with_keripy_kever_on_happy_path_kel() -> Fallible<()> {
    let vector = load_vector()?;

    // Decode event bytes and parse them up front so both outlive the borrowed
    // `Signed`s and the `KeyState` that borrows through them.
    let raws: Vec<Vec<u8>> = vector
        .events
        .iter()
        .map(|rec| BASE64.decode(&rec.raw_b64).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let parsed: Vec<KeriEvent> = raws
        .iter()
        .map(|raw| deserialize_event(raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;

    let signed: Vec<Signed> = parsed
        .iter()
        .zip(&raws)
        .zip(&vector.events)
        .map(|((event, raw), rec)| {
            let sigs = rec
                .sigs_qb64
                .iter()
                .map(|q| siger_from_qb64(q))
                .collect::<Fallible<_>>()?;
            Ok(Signed {
                event,
                signed_bytes: raw,
                sigs,
                wigs: vec![],
            })
        })
        .collect::<Fallible<_>>()?;

    let (first, rest) = signed
        .split_first()
        .ok_or("corpus KEL has a genesis event")?;
    let state = rest
        .iter()
        .try_fold(KeyState::incept(first)?, KeyState::ingest)?;

    let expected = &vector.final_state;
    assert_eq!(
        prefix_qb64(state.prefix()),
        expected.prefix_qb64,
        "identifier prefix must match keripy Kever.prefixer.qb64"
    );
    assert_eq!(
        state.sn().value(),
        expected.sn,
        "sequence number must match keripy Kever.sner.num"
    );
    let keys: Vec<String> = state.keys().iter().map(Matter::to_qb64).collect();
    assert_eq!(
        keys, expected.keys_qb64,
        "current signing keys must match keripy Kever.verfers"
    );
    assert_eq!(
        state.threshold(),
        &tholder_from_sith(&expected.threshold_sith)?,
        "signing threshold must match keripy Kever.tholder.sith"
    );
    let next_keys: Vec<String> = state.next_keys().iter().map(Matter::to_qb64).collect();
    assert_eq!(
        next_keys, expected.next_keys_qb64,
        "next-key digests must match keripy Kever.ndigers"
    );
    assert_eq!(
        state.next_threshold(),
        &tholder_from_sith(&expected.next_threshold_sith)?,
        "next signing threshold must match keripy Kever.ntholder.sith"
    );
    assert_eq!(
        state.witness_threshold().value(),
        expected.witness_threshold,
        "witness threshold (TOAD) must match keripy Kever.toader.num"
    );
    let witnesses: Vec<String> = state.witnesses().iter().map(Matter::to_qb64).collect();
    assert_eq!(
        witnesses, expected.witnesses_qb64,
        "witness set must match keripy Kever.wits"
    );
    Ok(())
}

fn load_kels_vector() -> Fallible<Vector> {
    let line = KELS
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or("kels corpus has a vector line")?;
    Ok(serde_json::from_str(line)?)
}

/// Read → re-serialize → byte-identity over the keripy-generated weighted-multisig
/// KEL (#145). Same invariant as [`corpus_events_reserialize_byte_identically_vs_keripy`],
/// covering the separate `kels.jsonl` corpus so the weighted-threshold wire shapes
/// get their own byte-identity guard independent of the single-sig keystate corpus.
#[test]
fn weighted_multisig_kel_reserializes_byte_identically_vs_keripy() -> Fallible<()> {
    let vector = load_kels_vector()?;
    for (idx, rec) in vector.events.iter().enumerate() {
        let raw = BASE64.decode(&rec.raw_b64)?;
        let event = deserialize_event(&raw)?;
        let reserialized = cesr::serder::serialize(&event)?;
        assert_eq!(
            core::str::from_utf8(reserialized.as_bytes())?,
            core::str::from_utf8(&raw)?,
            "kels corpus event {idx} must re-serialize byte-identically"
        );
    }
    Ok(())
}

/// The keri-rs fold must agree with keripy's `Kever` on a weighted-multisig
/// KEL (3 keys, kt = `["1/2","1/2","1"]`): genuine cross-implementation
/// agreement on threshold-weighted key state, not a tautology (#145).
#[test]
fn weighted_multisig_kel_folds_to_keripy_state() -> Fallible<()> {
    let vector = load_kels_vector()?;

    let raws: Vec<Vec<u8>> = vector
        .events
        .iter()
        .map(|rec| BASE64.decode(&rec.raw_b64).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let parsed: Vec<KeriEvent> = raws
        .iter()
        .map(|raw| deserialize_event(raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let signed: Vec<Signed> = parsed
        .iter()
        .zip(&raws)
        .zip(&vector.events)
        .map(|((event, raw), rec)| {
            let sigs = rec
                .sigs_qb64
                .iter()
                .map(|q| siger_from_qb64(q))
                .collect::<Fallible<_>>()?;
            Ok(Signed {
                event,
                signed_bytes: raw,
                sigs,
                wigs: vec![],
            })
        })
        .collect::<Fallible<_>>()?;

    let (first, rest) = signed.split_first().ok_or("KEL has a genesis event")?;
    let state = rest
        .iter()
        .try_fold(KeyState::incept(first)?, KeyState::ingest)?;

    let expected = &vector.final_state;
    assert_eq!(
        prefix_qb64(state.prefix()),
        expected.prefix_qb64,
        "identifier prefix must match keripy Kever.prefixer.qb64"
    );
    assert_eq!(
        state.sn().value(),
        expected.sn,
        "sequence number must match keripy Kever.sner.num"
    );
    let keys: Vec<String> = state.keys().iter().map(Matter::to_qb64).collect();
    assert_eq!(
        keys, expected.keys_qb64,
        "weighted-multisig current keys must match keripy Kever.verfers"
    );
    assert_eq!(
        state.threshold(),
        &tholder_from_sith(&expected.threshold_sith)?,
        "signing threshold must match keripy Kever.tholder.sith"
    );
    let next_keys: Vec<String> = state.next_keys().iter().map(Matter::to_qb64).collect();
    assert_eq!(
        next_keys, expected.next_keys_qb64,
        "weighted-multisig next-key digests must match keripy Kever.ndigers"
    );
    assert_eq!(
        state.next_threshold(),
        &tholder_from_sith(&expected.next_threshold_sith)?,
        "next signing threshold must match keripy Kever.ntholder.sith"
    );
    assert_eq!(
        state.witness_threshold().value(),
        expected.witness_threshold,
        "witness threshold must match keripy Kever.toader.num"
    );
    Ok(())
}
