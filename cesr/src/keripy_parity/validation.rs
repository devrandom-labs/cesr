//! Factory-validation parity sweeps — `validation.jsonl` (issue #151).
//!
//! Each corpus row was EXECUTED against the keripy factory at generation
//! time, so it is a verified keripy fact: `raises` rows are parameter
//! combinations keripy refuses to create; `control_valid` rows are accepted.
//! The sweep replays each representable row against the matching cesr
//! builder. `TRACKED` holds rows keripy rejects but cesr still accepts (a
//! burn-down list, emptied by #149); `INEXPRESSIBLE` holds rows whose
//! parameters cannot be stated through the builder API (also emptied by #149
//! — rotation builders now require the prior witness set). Per the porting
//! doctrine, a future type-level fix that makes a row unconstructable counts
//! as satisfied — move it to the type-enforced class, never force a runtime
//! Err.

use serde_json::{Value, json};
use std::eprintln;
use std::vec::Vec;

use crate::core::matter::code::DigestCode;
use crate::core::primitives::{Diger, Prefixer, Verfer};
use crate::keri::SigningThreshold;
use crate::serder::builder::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder, dummy_prefixer, dummy_saider,
};
use crate::serder::deserialize::reference::{
    parse_qb64_diger_array, parse_qb64_prefixer_array, parse_qb64_verfer_array, tholder_from_json,
};
use crate::serder::error::SerderError;

use super::{ValidationVector, load_validation};

/// Rejection rows cesr's builders accept today — the parity burn-down.
/// Emptied by #149; new corpus rows that cesr does not yet enforce go here
/// (the main sweep skips them; the stale-entry guard forces pruning).
const TRACKED: &[(&str, &str, &str)] = &[];

/// Rejection rows whose keripy parameters cannot be expressed through cesr's
/// builder API. Emptied by #149 (rotation builders now take the prior witness
/// set). Per the porting doctrine, a type-level fix moves a row to a
/// type-enforced skip — see the module doc — never to a forced runtime `Err`.
const INEXPRESSIBLE: &[(&str, &str, &str)] = &[];

fn lookup<'a>(table: &'a [(&str, &str, &str)], factory: &str, case: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(f, c, _)| *f == factory && *c == case)
        .map(|(_, _, why)| *why)
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus params panic with context"
)]
fn verfers(p: &Value) -> Vec<Verfer<'static>> {
    parse_qb64_verfer_array(&p["keys"]).unwrap_or_else(|e| panic!("keys: {e}"))
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus params panic with context"
)]
fn prefixers(p: &Value, field: &str) -> Vec<Prefixer<'static>> {
    parse_qb64_prefixer_array(&p[field]).unwrap_or_else(|e| panic!("{field}: {e}"))
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus params panic with context"
)]
fn digers(p: &Value) -> Vec<Diger<'static>> {
    parse_qb64_diger_array(&p["ndigs"]).unwrap_or_else(|e| panic!("ndigs: {e}"))
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus params panic with context"
)]
fn threshold(p: &Value, field: &str) -> Option<SigningThreshold> {
    let v = &p[field];
    (!v.is_null())
        .then(|| tholder_from_json(v, "signing").unwrap_or_else(|e| panic!("{field} {v}: {e}")))
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus params panic with context"
)]
fn toad(p: &Value) -> Option<u32> {
    let v = &p["toad"];
    (!v.is_null()).then(|| {
        u32::try_from(v.as_u64().unwrap_or_else(|| panic!("toad {v} not u64")))
            .unwrap_or_else(|_| panic!("toad {v} exceeds u32"))
    })
}

fn sn(p: &Value) -> Option<u128> {
    p["sn"].as_u64().map(u128::from)
}

#[allow(
    clippy::panic,
    reason = "test-only sweep helper: malformed corpus params panic with context"
)]
fn delegator(p: &Value) -> Prefixer<'static> {
    let mut parsed =
        parse_qb64_prefixer_array(&json!([p["delpre"]])).unwrap_or_else(|e| panic!("delpre: {e}"));
    let (Some(single), None) = (parsed.pop(), parsed.pop()) else {
        panic!("delpre must parse to exactly one prefixer");
    };
    single
}

fn replay_incept(p: &Value) -> Result<(), SerderError> {
    let mut b = InceptionBuilder::new().keys(verfers(p));
    if let Some(t) = threshold(p, "sith") {
        b = b.threshold(t);
    }
    b = b.next_keys(digers(p));
    if let Some(t) = threshold(p, "nsith") {
        b = b.next_threshold(t);
    }
    b = b.witnesses(prefixers(p, "wits"));
    if let Some(t) = toad(p) {
        b = b.witness_threshold(t);
    }
    b.build().map(|_| ())
}

fn replay_rotate(p: &Value) -> Result<(), SerderError> {
    let mut b = RotationBuilder::new()
        .prefix(dummy_prefixer()?)
        .prior_event_said(dummy_saider(DigestCode::Blake3_256)?)
        .keys(verfers(p))
        .prior_witnesses(prefixers(p, "wits"));
    if let Some(n) = sn(p) {
        b = b.sn(n);
    }
    if let Some(t) = threshold(p, "sith") {
        b = b.threshold(t);
    }
    b = b.next_keys(digers(p));
    if let Some(t) = threshold(p, "nsith") {
        b = b.next_threshold(t);
    }
    b = b.witness_removals(prefixers(p, "cuts"));
    b = b.witness_additions(prefixers(p, "adds"));
    if let Some(t) = toad(p) {
        b = b.witness_threshold(t);
    }
    b.build().map(|_| ())
}

fn replay_interact(p: &Value) -> Result<(), SerderError> {
    let mut b = InteractionBuilder::new()
        .prefix(dummy_prefixer()?)
        .prior_event_said(dummy_saider(DigestCode::Blake3_256)?);
    if let Some(n) = sn(p) {
        b = b.sn(n);
    }
    b.build().map(|_| ())
}

fn replay_delcept(p: &Value) -> Result<(), SerderError> {
    let mut b = DelegatedInceptionBuilder::new()
        .keys(verfers(p))
        .delegator(delegator(p));
    if let Some(t) = threshold(p, "sith") {
        b = b.threshold(t);
    }
    b = b.next_keys(digers(p));
    if let Some(t) = threshold(p, "nsith") {
        b = b.next_threshold(t);
    }
    b = b.witnesses(prefixers(p, "wits"));
    if let Some(t) = toad(p) {
        b = b.witness_threshold(t);
    }
    b.build().map(|_| ())
}

fn replay_deltate(p: &Value) -> Result<(), SerderError> {
    let mut b = DelegatedRotationBuilder::new()
        .prefix(dummy_prefixer()?)
        .prior_event_said(dummy_saider(DigestCode::Blake3_256)?)
        .keys(verfers(p))
        .prior_witnesses(prefixers(p, "wits"));
    if let Some(n) = sn(p) {
        b = b.sn(n);
    }
    if let Some(t) = threshold(p, "sith") {
        b = b.threshold(t);
    }
    b = b.next_keys(digers(p));
    if let Some(t) = threshold(p, "nsith") {
        b = b.next_threshold(t);
    }
    b = b.witness_removals(prefixers(p, "cuts"));
    b = b.witness_additions(prefixers(p, "adds"));
    if let Some(t) = toad(p) {
        b = b.witness_threshold(t);
    }
    b.build().map(|_| ())
}

/// Replays one corpus row against the matching cesr builder. `Ok(())` = the
/// builder accepted; `Err` = it rejected.
#[allow(
    clippy::panic,
    reason = "test-only sweep dispatcher: an unknown factory is a corpus bug"
)]
fn replay(v: &ValidationVector) -> Result<(), SerderError> {
    let p = &v.params;
    match v.factory.as_str() {
        "incept" => replay_incept(p),
        "rotate" => replay_rotate(p),
        "interact" => replay_interact(p),
        "delcept" => replay_delcept(p),
        "deltate" => replay_deltate(p),
        other => panic!("unknown factory {other:?}"),
    }
}

#[test]
#[allow(
    clippy::print_stderr,
    reason = "test-only sweep: skip classes and counts logged for the parity ledger"
)]
fn builder_validation_matches_keripy() {
    let vectors = load_validation();
    let mut asserted = 0usize;
    let mut static_skipped = 0usize;
    let mut tracked = 0usize;
    let mut controls_asserted = 0usize;

    for v in &vectors {
        if let Some(reason) = &v.rust_static {
            eprintln!("STATIC {}/{}: {reason}", v.factory, v.case);
            static_skipped += 1;
            continue;
        }
        if let Some(why) = lookup(TRACKED, &v.factory, &v.case)
            .or_else(|| lookup(INEXPRESSIBLE, &v.factory, &v.case))
        {
            eprintln!("TRACKED {}/{}: {why}", v.factory, v.case);
            tracked += 1;
            continue;
        }
        let outcome = replay(v);
        if let Some(exc) = &v.raises {
            assert!(
                outcome.is_err(),
                "{}/{}: keripy raises {exc} ({}) but cesr accepted",
                v.factory,
                v.case,
                v.message
            );
        } else {
            assert!(
                outcome.is_ok(),
                "{}/{}: keripy accepts but cesr rejected: {:?}",
                v.factory,
                v.case,
                outcome.err()
            );
            controls_asserted += 1;
        }
        asserted += 1;
    }

    assert!(asserted > 0, "validation corpus asserted nothing");
    assert_eq!(
        asserted + static_skipped + tracked,
        vectors.len(),
        "every corpus row must be asserted, static-skipped, or tracked"
    );
    let controls_total = vectors.iter().filter(|v| v.raises.is_none()).count();
    assert_eq!(
        controls_asserted, controls_total,
        "every control_valid row must be replayed and accepted — controls may never be tracked/static"
    );
    eprintln!(
        "validation: {asserted} asserted ({controls_asserted} controls), {static_skipped} static-skipped, {tracked} tracked (#149)"
    );
}

#[test]
#[allow(
    clippy::panic,
    reason = "test-only guard: a stale tracked entry panics with pruning instructions"
)]
fn tracked_tables_match_corpus() {
    // Guard: if a regen drops a tracked row the probe above passes vacuously —
    // fail here instead so the tables get pruned deliberately. Also enforces
    // that tables only ever hold representable keripy-rejection rows, and that
    // no (factory, case) appears in both tables — a duplicate is a
    // classification contradiction (a row cannot be both runtime-replayable
    // and inexpressible) that the lookup order would otherwise mask silently.
    let vectors = load_validation();
    let mut seen: Vec<(&str, &str)> = TRACKED
        .iter()
        .chain(INEXPRESSIBLE)
        .map(|(f, c, _)| (*f, *c))
        .collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(
        before,
        seen.len(),
        "a (factory, case) row appears in both TRACKED and INEXPRESSIBLE — keep each row in exactly one table"
    );
    for (factory, case, why) in TRACKED.iter().chain(INEXPRESSIBLE) {
        let row = vectors
            .iter()
            .find(|v| v.factory == *factory && v.case == *case)
            .unwrap_or_else(|| {
                panic!("tracked row {factory}/{case} ({why}) no longer in corpus — prune the table")
            });
        assert!(
            row.rust_static.is_none(),
            "tracked row {factory}/{case} is rust_static-marked — it never replays; remove it from the table"
        );
        assert!(
            row.raises.is_some(),
            "tracked row {factory}/{case} is a control row — tables may only hold keripy-rejection rows"
        );
    }
}
