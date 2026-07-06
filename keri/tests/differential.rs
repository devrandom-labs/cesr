//! keripy differential vector for the key-state fold (K1, Phase 8).
//!
//! Replays a checked-in, **keripy-generated** KEL — inception -> rotation ->
//! interaction — through the real public [`keri::fold`] and asserts the folded
//! [`KeyState`] matches keripy's authoritative `Kever` fold output.
//!
//! The expected `final_state` values are produced by keripy's own `Kever`, NOT
//! by this crate's fold — so the assertion is a genuine cross-implementation
//! agreement check, not a tautology. See `scripts/keripy_keystate_gen.py` and
//! the corpus header for provenance (keripy v2.0.0.dev5-1030-gde59bc7d, V1 JSON).
//!
//! The corpus is embedded via `include_str!` for the same reason cesr's
//! `keripy_diff` harness does: the nix gate builds and runs tests in separate
//! hermetic phases, so a runtime `CARGO_MANIFEST_DIR` path is unreliable.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "differential test: a decode/parse failure here is a test-setup or a real serder bug that should abort loudly"
)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;

use cesr::keri::{Identifier, KeriEvent};
use cesr::serder::deserialize_event;

use common::{sig_for, verfer};
use keri::{SignedEvent, fold};

const CORPUS: &str = include_str!("corpus/keystate.jsonl");

#[derive(Debug, Deserialize)]
struct Vector {
    events: Vec<EventRecord>,
    final_state: FinalState,
}

#[derive(Debug, Deserialize)]
struct EventRecord {
    raw_b64: String,
    signer_indices: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct FinalState {
    prefix_qb64: String,
    sn: u128,
    keys_qb64: Vec<String>,
    next_keys_qb64: Vec<String>,
    witness_threshold: u32,
    witnesses_qb64: Vec<String>,
}

fn prefix_qb64(id: &Identifier<'_>) -> String {
    match id {
        Identifier::Basic(p) => p.to_qb64(),
        Identifier::SelfAddressing(s) => s.to_qb64(),
    }
}

fn load_vector() -> Vector {
    let line = CORPUS
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("corpus has a vector line");
    serde_json::from_str(line).expect("corpus line parses as a Vector")
}

#[test]
fn fold_agrees_with_keripy_kever_on_happy_path_kel() {
    let vector = load_vector();

    // Decode all events up front so they outlive the borrowed `SignedEvent`s.
    let events: Vec<KeriEvent> = vector
        .events
        .iter()
        .map(|rec| {
            let raw = BASE64
                .decode(&rec.raw_b64)
                .expect("valid base64 event bytes");
            deserialize_event(&raw).expect("cesr::serder deserializes keripy event bytes")
        })
        .collect();

    // The fold reads only signature indices; a dummy verfer is inert.
    let dummy = verfer(0);
    let signed: Vec<SignedEvent> = events
        .iter()
        .zip(&vector.events)
        .map(|(event, rec)| SignedEvent {
            event,
            sigs: rec
                .signer_indices
                .iter()
                .map(|&i| sig_for(i, &dummy))
                .collect(),
            wigs: vec![],
        })
        .collect();

    let state = fold(None, signed).expect("keripy-generated happy-path KEL folds cleanly");

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

    let keys: Vec<String> = state.keys().iter().map(cesr::Matter::to_qb64).collect();
    assert_eq!(
        keys, expected.keys_qb64,
        "current signing keys must match keripy Kever.verfers"
    );

    let next_keys: Vec<String> = state
        .next_keys()
        .iter()
        .map(cesr::Matter::to_qb64)
        .collect();
    assert_eq!(
        next_keys, expected.next_keys_qb64,
        "next-key digests must match keripy Kever.ndigers"
    );

    assert_eq!(
        state.witness_threshold(),
        expected.witness_threshold,
        "witness threshold (TOAD) must match keripy Kever.toader.num"
    );

    let witnesses: Vec<String> = state
        .witnesses()
        .iter()
        .map(cesr::Matter::to_qb64)
        .collect();
    assert_eq!(
        witnesses, expected.witnesses_qb64,
        "witness set must match keripy Kever.wits"
    );
}
