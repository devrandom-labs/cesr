//! keripy differential vectors for K9 (#95) semantic parity: the same events
//! in the same *delivery order* must produce the same per-event verdict and
//! the same final key state in cesr as in keripy.
//!
//! Replays the checked-in, **keripy-generated** semantic corpus
//! (`scripts/keripy_semantics_gen.py`): each scenario drives a bare
//! validator-role `keri.core.eventing.Kevery` with an event sequence in a
//! fixed delivery order and records keripy's own verdict per step —
//! `accepted` / `escrowed` (the raised escrow exception class) / `rejected`
//! (bare `ValidationError`) / `contested` (`LikelyDuplicitousError`) — plus
//! keripy's `Kever` final state after all deliveries and escrow
//! re-processing. The consumer folds the same deliveries through
//! [`KeyState::incept`]/[`KeyState::ingest`], verifying keripy's real
//! signatures inside the fold, and asserts [`Rejection::disposition`]
//! agreement per step — a genuine cross-implementation agreement check, not
//! a tautology. This is the executable form of the `Rejection` variant
//! doc-comment mapping (`crates/keri/src/error.rs`).
//!
//! Regenerate (keripy pin worktree path is the controller's scratchpad):
//!
//! ```text
//! DYLD_LIBRARY_PATH=/nix/store/4cip8y1ab6xcpr0vynm242h202m6a874-libsodium-1.0.22-unstable-2026-04-16/lib \
//! PYTHONPATH=/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages \
//! /Users/joel/.local/bin/python3.14 scripts/keripy_semantics_gen.py \
//!   --keripy /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/7bc70638-c9f8-4ceb-a375-0f85c47c2748/scratchpad/keripy-pin \
//!   --out-dir crates/keri-codec/tests/corpus/semantics
//! ```
//!
//! Pin: keripy v2.0.0.dev5-1030-gde59bc7d (`scripts/KERIPY_PIN` de59bc7d),
//! KERI/CESR V1 JSON. The corpus is embedded via `include_str!` because the
//! nix gate builds and runs tests in separate hermetic phases, so a runtime
//! `CARGO_MANIFEST_DIR` path is unreliable.
mod common;

use std::collections::BTreeMap;
use std::error::Error;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;

use keri_codec::Deserialize;
use keri_events::{Identifier, KeriEvent, SigningThreshold, WeightedThreshold};

use common::siger_from_qb64;
use keri::{Disposition, EvidenceKind, KeyState, Rejection, Signed};

type Fallible<T> = Result<T, Box<dyn Error>>;

const HAPPY: &str = include_str!("corpus/semantics/happy.jsonl");
const ESCROW: &str = include_str!("corpus/semantics/escrow.jsonl");

/// The keripy pin every checked-in vector was generated against.
const KERIPY_PIN: &str = "v2.0.0.dev5-1030-gde59bc7d";

#[derive(Debug, serde::Deserialize)]
struct Scenario {
    #[serde(rename = "scenario")]
    name: String,
    family: String,
    events: Vec<EventRecord>,
    delivery: Vec<usize>,
    expected: Vec<Expected>,
    final_state: Option<FinalState>,
    keripy_version: String,
    #[serde(rename = "note")]
    _note: String,
    /// Present iff this vector records a documented cesr↔keripy divergence
    /// (`docs/keripy-parity/semantics.md` ledger id); then `cesr_expected`
    /// carries the documented cesr verdicts and `expected` stays keripy's.
    #[serde(default)]
    divergent: Option<String>,
    #[serde(default)]
    cesr_expected: Option<Vec<Expected>>,
}

#[derive(Debug, serde::Deserialize)]
struct EventRecord {
    raw: String,
    sigs_qb64: Vec<String>,
    #[serde(default)]
    wigs_qb64: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Expected {
    event: usize,
    verdict: String,
    #[serde(default)]
    keripy_error: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    redrive: bool,
}

#[derive(Debug, serde::Deserialize)]
struct FinalState {
    prefix_qb64: String,
    sn: u128,
    keys_qb64: Vec<String>,
    threshold_sith: Value,
    next_keys_qb64: Vec<String>,
    next_threshold_sith: Value,
    witness_threshold: u32,
    witnesses_qb64: Vec<String>,
    said_qb64: String,
}

/// One delivery-step verdict: the fold's outcome classified exactly like the
/// vector's `verdict`/`evidence` pair.
#[derive(Debug, PartialEq, Eq)]
enum Verdict<'a> {
    Accepted,
    Escrowed(&'a str),
    Rejected,
    Contested,
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

/// The cesr `EvidenceKind` as the vector schema's `evidence` string.
const fn evidence_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::PriorEvents { .. } => "prior_events",
        EvidenceKind::Signatures => "signatures",
        EvidenceKind::WitnessReceipts { .. } => "witness_receipts",
        EvidenceKind::DelegationEvidence => "delegation",
        EvidenceKind::ReceiptorEstablishment => "receiptor_establishment",
    }
}

/// Classify a fold rejection into the vector schema's verdict vocabulary.
const fn classify(r: &Rejection) -> Verdict<'static> {
    match r.disposition() {
        Disposition::Terminal => Verdict::Rejected,
        Disposition::Contested => Verdict::Contested,
        Disposition::Awaiting(kind) => Verdict::Escrowed(evidence_name(kind)),
    }
}

/// The vector's expected verdict for one delivery step as a [`Verdict`].
fn want_verdict<'a>(scenario: &'a str, want: &'a Expected) -> Fallible<Verdict<'a>> {
    Ok(match want.verdict.as_str() {
        "accepted" => Verdict::Accepted,
        "escrowed" => Verdict::Escrowed(
            want.evidence
                .as_deref()
                .ok_or("escrowed verdict carries evidence")?,
        ),
        "rejected" => Verdict::Rejected,
        "contested" => Verdict::Contested,
        other => return Err(format!("{scenario}: unknown verdict {other:?}").into()),
    })
}

/// Schema invariants of one expected step: only escrowed steps carry an
/// evidence kind, every non-accepted step records keripy's exception class,
/// and a re-drive in this corpus always cures.
fn check_step_shape(scenario: &str, want: &Expected) {
    match want.verdict.as_str() {
        "accepted" => assert!(
            want.keripy_error.is_none() && want.evidence.is_none(),
            "{scenario}: accepted step carries keripy_error/evidence"
        ),
        "escrowed" => assert!(
            want.keripy_error.is_some() && want.evidence.is_some(),
            "{scenario}: escrowed step shape"
        ),
        "rejected" | "contested" => assert!(
            want.keripy_error.is_some() && want.evidence.is_none(),
            "{scenario}: rejected/contested step shape"
        ),
        _ => {}
    }
    if want.redrive {
        assert_eq!(
            want.verdict, "accepted",
            "{scenario}: a re-drive in this corpus always cures"
        );
    }
}

/// Fold one delivery against the per-identifier states, returning the
/// classified verdict. `ingest` consumes the state even on `Err`, so trial a
/// clone: the map's original survives any step that does not advance the fold.
fn fold_step<'e>(states: &mut BTreeMap<String, KeyState<'e>>, ev: &Signed<'e>) -> Verdict<'static> {
    let pre = prefix_qb64(ev.event.prefix());
    let result = states
        .get(&pre)
        .map_or_else(|| KeyState::incept(ev), |state| state.clone().ingest(ev));
    match result {
        Ok(next) => {
            states.insert(pre, next);
            Verdict::Accepted
        }
        Err(r) => classify(&r),
    }
}

/// Fold one scenario's deliveries and assert every step's verdict plus the
/// final key state against keripy's recorded oracle output.
fn drive(sc: &Scenario) -> Fallible<()> {
    // Decode event bytes and parse them up front so both outlive the borrowed
    // `Signed`s and the folded states that borrow through them.
    let raws: Vec<Vec<u8>> = sc
        .events
        .iter()
        .map(|e| BASE64.decode(&e.raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let parsed: Vec<KeriEvent> = raws
        .iter()
        .map(|raw| KeriEvent::deserialize(raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let signed: Vec<Signed> = parsed
        .iter()
        .zip(&raws)
        .zip(&sc.events)
        .map(|((event, raw), rec)| {
            Ok(Signed {
                event,
                signed_bytes: raw,
                sigs: rec
                    .sigs_qb64
                    .iter()
                    .map(|q| siger_from_qb64(q))
                    .collect::<Fallible<_>>()?,
                wigs: rec
                    .wigs_qb64
                    .iter()
                    .map(|q| siger_from_qb64(q))
                    .collect::<Fallible<_>>()?,
            })
        })
        .collect::<Fallible<_>>()?;

    // A divergent vector asserts the documented cesr behavior instead of
    // keripy's (`expected` stays the keripy record for the ledger).
    let expected = match (&sc.divergent, &sc.cesr_expected) {
        (Some(_), Some(cesr)) => cesr,
        (Some(id), None) => {
            return Err(format!(
                "{}: divergent vector {id} must carry cesr_expected",
                sc.name
            )
            .into());
        }
        (None, _) => &sc.expected,
    };
    assert_eq!(
        expected.len(),
        sc.delivery.len(),
        "{}: expected must be parallel to delivery",
        sc.name
    );

    // One fold per identifier (the delegation scenario interleaves two KELs).
    let mut states: BTreeMap<String, KeyState> = BTreeMap::new();
    for (step, (idx, want)) in sc.delivery.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            *idx, want.event,
            "{}: expected[{step}] must parallel delivery",
            sc.name
        );
        let want_v = want_verdict(&sc.name, want)?;
        check_step_shape(&sc.name, want);
        let ev = signed.get(*idx).ok_or("delivery index out of range")?;
        let got = fold_step(&mut states, ev);
        assert_eq!(
            got, want_v,
            "{}: step {step} (event {}) verdict",
            sc.name, want.event
        );
    }

    // Final state: the subject KEL is the last delivery's prefix. A null
    // final_state means the subject KEL never accepted an inception.
    let subject = *sc.delivery.last().ok_or("scenario carries a delivery")?;
    let subject_pre = prefix_qb64(parsed[subject].prefix());
    match &sc.final_state {
        Some(fs) => {
            let state = states
                .get(&subject_pre)
                .ok_or("final_state present but subject KEL never accepted")?;
            assert_final_state(state, fs, &sc.name)?;
        }
        None => assert!(
            !states.contains_key(&subject_pre),
            "{}: subject KEL accepted an inception but final_state is null",
            sc.name
        ),
    }
    Ok(())
}

/// Field-by-field agreement with keripy's `Kever` state (same style as
/// `differential.rs`), including the thresholds — the weighted-threshold
/// scenarios are the point.
fn assert_final_state(state: &KeyState, fs: &FinalState, scenario: &str) -> Fallible<()> {
    assert_eq!(
        prefix_qb64(state.prefix()),
        fs.prefix_qb64,
        "{scenario}: identifier prefix must match keripy Kever.prefixer.qb64"
    );
    assert_eq!(
        state.sn().value(),
        fs.sn,
        "{scenario}: sequence number must match keripy Kever.sner.num"
    );
    let keys: Vec<String> = state.keys().iter().map(|k| k.to_qb64()).collect();
    assert_eq!(
        keys, fs.keys_qb64,
        "{scenario}: current signing keys must match keripy Kever.verfers"
    );
    assert_eq!(
        state.threshold(),
        &tholder_from_sith(&fs.threshold_sith)?,
        "{scenario}: signing threshold must match keripy Kever.tholder.sith"
    );
    let next_keys: Vec<String> = state.next_keys().iter().map(|d| d.to_qb64()).collect();
    assert_eq!(
        next_keys, fs.next_keys_qb64,
        "{scenario}: next-key digests must match keripy Kever.ndigers"
    );
    assert_eq!(
        state.next_threshold(),
        &tholder_from_sith(&fs.next_threshold_sith)?,
        "{scenario}: next threshold must match keripy Kever.ntholder.sith"
    );
    assert_eq!(
        state.witness_threshold().value(),
        fs.witness_threshold,
        "{scenario}: witness threshold (TOAD) must match keripy Kever.toader.num"
    );
    let witnesses: Vec<String> = state.witnesses().iter().map(|w| w.to_qb64()).collect();
    assert_eq!(
        witnesses, fs.witnesses_qb64,
        "{scenario}: witness set must match keripy Kever.wits"
    );
    assert_eq!(
        state.latest_said().to_qb64(),
        fs.said_qb64,
        "{scenario}: latest SAID must match keripy Kever.serder.said"
    );
    Ok(())
}

/// Drive every line of one corpus file, asserting the family/pin guards.
fn drive_corpus(corpus: &str, file: &str, families: &[&str]) -> Fallible<usize> {
    let mut count = 0usize;
    for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
        let sc: Scenario = serde_json::from_str(line)?;
        assert!(
            families.contains(&sc.family.as_str()),
            "{}: {} has family {:?}, expected one of {families:?}",
            file,
            sc.name,
            sc.family
        );
        assert_eq!(
            sc.keripy_version, KERIPY_PIN,
            "{}: {} was generated against a different keripy pin",
            file, sc.name
        );
        drive(&sc)?;
        count += 1;
    }
    Ok(count)
}

/// Happy-path KELs: every delivery accepted, final state matches keripy's
/// Kever — including weighted-threshold and partial-rotation (ondex != index)
/// folds.
#[test]
fn keripy_semantics_happy_verdicts_and_state() -> Fallible<()> {
    let count = drive_corpus(HAPPY, "happy.jsonl", &["happy"])?;
    assert_eq!(count, 3, "happy.jsonl must carry 3 scenarios");
    Ok(())
}

/// Escrow/reject/contested KELs: per-step disposition agreement (awaiting
/// evidence kind, terminal, contested), re-drive cures, and final state.
#[test]
fn keripy_semantics_escrow_verdicts() -> Fallible<()> {
    let count = drive_corpus(ESCROW, "escrow.jsonl", &["escrow", "reject"])?;
    assert_eq!(count, 7, "escrow.jsonl must carry 7 scenarios");
    Ok(())
}

/// Count guard: every corpus line parses and the scenario totals match, so a
/// truncated or silently extended corpus fails loudly.
#[test]
fn keripy_semantics_corpus_fully_consumed() -> Fallible<()> {
    let count_lines = |corpus: &str| -> Fallible<usize> {
        let mut n = 0usize;
        for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
            let _: Scenario = serde_json::from_str(line)?;
            n += 1;
        }
        Ok(n)
    };
    assert_eq!(
        count_lines(HAPPY)?,
        3,
        "happy.jsonl truncated or extended without updating the guard"
    );
    assert_eq!(
        count_lines(ESCROW)?,
        7,
        "escrow.jsonl truncated or extended without updating the guard"
    );
    Ok(())
}
