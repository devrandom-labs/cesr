//! keripy differential vectors for the K4 (#90) delegation-validation fold.
//!
//! Replays checked-in, **keripy-generated** delegation scenarios: each
//! vector folds a delegator KEL through the validating fold, then drives
//! the delegate's dip/drt through [`KeyState::incept_delegated`]/
//! [`KeyState::ingest_delegated`] with evidence built from the anchoring
//! delegator event (or through the plain entries when the vector carries
//! none) and asserts the outcome — `accepted` / `awaiting` / `denied` —
//! matches keripy's own validator-role `Kevery.processEvent` verdict (a
//! bare `Kevery(db=db)`, so `validateDelegation` runs the full seal path,
//! eventing.py:3009-3416). A genuine cross-implementation agreement check,
//! not a tautology. See `scripts/keripy_delegation_gen.py` and the corpus
//! header for provenance (keripy v2.0.0.dev5, oracle main 9161a705, V1
//! JSON).
//!
//! The corpus is embedded via `include_str!` because the nix gate builds and
//! runs tests in separate hermetic phases, so a runtime `CARGO_MANIFEST_DIR`
//! path is unreliable.
mod common;

use std::error::Error;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use keri_codec::Deserialize;
use keri_events::KeriEvent;

use common::siger_from_qb64;
use keri::{
    AnchoredDelegation, DelegationError, DelegationEvidence, Disposition, EvidenceKind, KeyState,
    Rejection, Signed,
};

type Fallible<T> = Result<T, Box<dyn Error>>;

const CORPUS: &str = include_str!("corpus/delegation.jsonl");

#[derive(Debug, serde::Deserialize)]
struct Vector {
    name: String,
    delegator_events: Vec<String>,
    delegator_sigs: Vec<Vec<String>>,
    delegate_events: Vec<String>,
    delegate_sigs: Vec<Vec<String>>,
    /// One per delegate event: the index into `delegator_events` of the
    /// anchoring event, or null when the host has no evidence (the plain
    /// entries are driven instead).
    anchor_indices: Vec<Option<usize>>,
    expected: String,
}

/// Decode the base64 events and parse them. The parsed events are owned
/// (`KeriEvent<'static>`); the raws stay alive because [`Signed::signed_bytes`]
/// borrows them — [`signed_events`] pairs each event with its keripy
/// signatures.
fn decode_events(events: &[String]) -> Fallible<(Vec<Vec<u8>>, Vec<KeriEvent<'static>>)> {
    let raws: Vec<Vec<u8>> = events
        .iter()
        .map(|e| BASE64.decode(e).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let parsed: Vec<KeriEvent> = raws
        .iter()
        .map(|raw| KeriEvent::deserialize(raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    Ok((raws, parsed))
}

fn signed_events<'e>(
    parsed: &'e [KeriEvent<'e>],
    raws: &'e [Vec<u8>],
    sigs: &[Vec<String>],
) -> Fallible<Vec<Signed<'e>>> {
    parsed
        .iter()
        .zip(raws)
        .zip(sigs)
        .map(|((event, raw), qs)| {
            Ok(Signed {
                event,
                signed_bytes: raw,
                sigs: qs
                    .iter()
                    .map(|q| siger_from_qb64(q))
                    .collect::<Fallible<_>>()?,
                wigs: vec![],
            })
        })
        .collect()
}

/// Classify a rejection the way the corpus's `expected` strings do.
const fn classify(r: &Rejection) -> &'static str {
    match r.disposition() {
        Disposition::Awaiting(EvidenceKind::DelegationEvidence) => "awaiting",
        Disposition::Terminal if matches!(r, Rejection::Delegation(DelegationError::Denied)) => {
            "denied"
        }
        _ => "other",
    }
}

/// Fold one vector and return the outcome as keripy's verdict string.
fn fold_vector(vector: &Vector) -> Fallible<&'static str> {
    let (delegator_raws, delegator_parsed) = decode_events(&vector.delegator_events)?;
    let delegator_signed =
        signed_events(&delegator_parsed, &delegator_raws, &vector.delegator_sigs)?;
    let (first, rest) = delegator_signed
        .split_first()
        .ok_or("vector has a delegator genesis")?;
    let delegator_head = rest
        .iter()
        .try_fold(KeyState::incept(first)?, KeyState::ingest)?;

    let (delegate_raws, delegate_parsed) = decode_events(&vector.delegate_events)?;
    let delegate_signed = signed_events(&delegate_parsed, &delegate_raws, &vector.delegate_sigs)?;

    if vector.anchor_indices.len() != delegate_signed.len() {
        return Err(format!(
            "vector {}: anchor_indices must parallel delegate_events",
            vector.name
        )
        .into());
    }

    let mut state: Option<KeyState> = None;
    for (i, signed) in delegate_signed.iter().enumerate() {
        let result = match vector.anchor_indices[i] {
            Some(idx) => {
                let delegating_event = delegator_parsed
                    .get(idx)
                    .ok_or("anchor index out of range")?;
                let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
                    delegator: &delegator_head,
                    delegating_event,
                });
                state.take().map_or_else(
                    || KeyState::incept_delegated(signed, &evidence),
                    |s| s.ingest_delegated(signed, &evidence),
                )
            }
            // No evidence exists: the host drives the plain entry, which
            // must park the event as Awaiting(DelegationEvidence).
            None => state
                .take()
                .map_or_else(|| KeyState::incept(signed), |s| s.ingest(signed)),
        };
        match result {
            Ok(next) => state = Some(next),
            Err(r) => {
                if i + 1 != delegate_signed.len() {
                    return Err(format!(
                        "vector {}: delegate event {i} rejected early: {r}",
                        vector.name
                    )
                    .into());
                }
                return Ok(classify(&r));
            }
        }
    }
    Ok("accepted")
}

/// keripy's verdict for each delegation scenario must match the fold's.
#[test]
fn keripy_delegation_verdicts_match() -> Fallible<()> {
    let mut count = 0usize;
    for line in CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let vector: Vector = serde_json::from_str(line)?;
        count += 1;
        assert_eq!(
            fold_vector(&vector)?,
            vector.expected,
            "vector {}",
            vector.name
        );
    }
    assert!(
        count >= 5,
        "delegation corpus must carry at least 5 keripy vectors, found {count} — \
         regenerate via scripts/keripy_delegation_gen.py"
    );
    Ok(())
}
