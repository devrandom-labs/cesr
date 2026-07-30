//! keripy differential vectors for the K3 (#89) same-sn judge.
//!
//! Replays checked-in, **keripy-generated** duplicity/superseding scenarios:
//! each vector folds a base KEL, then judges a contest event at an
//! already-occupied sn through [`KeyState::judge_same_sn`] and asserts the
//! verdict matches keripy's own `Kevery.processEvent` outcome
//! (`supersedes`/`duplicate`/`duplicitous`/`yields`) — a genuine
//! cross-implementation agreement check, not a tautology. See
//! `scripts/keripy_duplicity_gen.py` and the corpus header for provenance
//! (keripy v2.0.0.dev5, oracle main 9161a705, V1 JSON).
//!
//! Gate vectors (empty `chain`) fold through the validating fold
//! ([`KeyState::incept`]/[`KeyState::ingest`]); delegated vectors fold the
//! delegate KEL through the trusted snapshot fold (the validating fold
//! rejects dip/drt until K4) and carry the delegating-event pair for the
//! cascade.
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
use keri::{DelegationContest, KeyState, KeyStateSnapshot, SameSnVerdict, Signed};

type Fallible<T> = Result<T, Box<dyn Error>>;

const CORPUS: &str = include_str!("corpus/duplicity.jsonl");

#[derive(Debug, serde::Deserialize)]
struct Vector {
    name: String,
    events: Vec<String>,
    sigs: Vec<Vec<String>>,
    contest: Contest,
    expected: String,
    #[serde(default)]
    chain: Vec<ChainPair>,
}

#[derive(Debug, serde::Deserialize)]
struct Contest {
    raw: String,
    /// keripy's controller signatures over the contest event. Provenance
    /// only — the judge is routing-only and never verifies signatures (on a
    /// `Supersedes` the host re-drives the validating fold, which does).
    #[serde(rename = "sigs")]
    _sigs: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ChainPair {
    incumbent: String,
    challenger: String,
}

/// Judge one vector's contest event against its folded base KEL and return
/// the verdict as keripy's outcome string.
fn judge_vector(vector: &Vector) -> Fallible<&'static str> {
    // Decode event bytes and parse them up front so both outlive the
    // borrowed `Signed`s / `DelegationContest`s and the folded states
    // that borrow through them.
    let raws: Vec<Vec<u8>> = vector
        .events
        .iter()
        .map(|e| BASE64.decode(e).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let parsed: Vec<KeriEvent> = raws
        .iter()
        .map(|raw| KeriEvent::deserialize(raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;

    let contest_raw = BASE64.decode(&vector.contest.raw)?;
    let contest = KeriEvent::deserialize(&contest_raw)?;
    let contest_sn = contest.sn().value();
    let recorded = parsed
        .iter()
        .find(|e| e.sn().value() == contest_sn)
        .ok_or("vector has no recorded event at the contest sn")?;

    let chain_raws: Vec<(Vec<u8>, Vec<u8>)> = vector
        .chain
        .iter()
        .map(|p| Ok((BASE64.decode(&p.incumbent)?, BASE64.decode(&p.challenger)?)))
        .collect::<Fallible<_>>()?;
    let chain_parsed: Vec<(KeriEvent, KeriEvent)> = chain_raws
        .iter()
        .map(|(i, c)| Ok((KeriEvent::deserialize(i)?, KeriEvent::deserialize(c)?)))
        .collect::<Fallible<_>>()?;
    let chain: Vec<DelegationContest<'_>> = chain_parsed
        .iter()
        .map(|(incumbent, challenger)| DelegationContest {
            incumbent,
            challenger,
        })
        .collect();

    let verdict = if vector.chain.is_empty() {
        // Gate vector: fold the base KEL through the validating fold,
        // verifying keripy's real signatures inside it.
        let signed: Vec<Signed> = parsed
            .iter()
            .zip(&raws)
            .zip(&vector.sigs)
            .map(|((event, raw), sigs)| {
                Ok(Signed {
                    event,
                    signed_bytes: raw,
                    sigs: sigs
                        .iter()
                        .map(|q| siger_from_qb64(q))
                        .collect::<Fallible<_>>()?,
                    wigs: vec![],
                })
            })
            .collect::<Fallible<_>>()?;
        let (first, rest) = signed.split_first().ok_or("vector has a genesis event")?;
        let state = rest
            .iter()
            .try_fold(KeyState::incept(first)?, KeyState::ingest)?;
        state.judge_same_sn(&contest, recorded, &chain)?
    } else {
        // Delegated vector: the trusted snapshot fold accepts dip/drt.
        let KeriEvent::DelegatedInception(dip) = &parsed[0] else {
            return Err(format!(
                "vector {}: delegated KEL must start with a dip",
                vector.name
            )
            .into());
        };
        let mut snapshot = KeyStateSnapshot::genesis(dip.inception());
        for event in &parsed[1..] {
            snapshot = snapshot.advance(event);
        }
        snapshot.view().judge_same_sn(&contest, recorded, &chain)?
    };

    Ok(match verdict {
        SameSnVerdict::Supersedes => "supersedes",
        SameSnVerdict::Duplicate => "duplicate",
        SameSnVerdict::Duplicitous { .. } => "duplicitous",
        SameSnVerdict::Yields => "yields",
        SameSnVerdict::Undecided => "undecided",
    })
}

/// keripy's outcome for each contest event must match the judge's verdict.
#[test]
fn keripy_same_sn_verdicts_match() -> Fallible<()> {
    let mut count = 0usize;
    for line in CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let vector: Vector = serde_json::from_str(line)?;
        count += 1;
        assert_eq!(
            judge_vector(&vector)?,
            vector.expected,
            "vector {}",
            vector.name
        );
    }
    assert!(
        count >= 5,
        "duplicity corpus must carry at least 5 keripy vectors, found {count} — \
         regenerate via scripts/keripy_duplicity_gen.py"
    );
    Ok(())
}
