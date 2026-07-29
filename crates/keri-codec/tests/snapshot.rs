//! K6 snapshot-duality tests: the owned [`KeyStateSnapshot`] carrier and the
//! total trusted fold, pinned against the K1 validating fold.
//!
//! The heart of this suite is the differential invariant: for any ACCEPTED
//! event sequence, folding with `genesis`/`advance` (trusted, crypto-free)
//! must produce exactly `KeyStateSnapshot::from(&validating_fold_result)`.
mod common;

use common::{
    Fallible, Key, WitnessChange, abandoning_rotation, genesis, inception_full, interaction,
    plain_rotation, prefix_of, rotation_witnessed, seed,
};
use keri::{KeyState, KeyStateSnapshot, Transferability};
use keri_events::{KeriEvent, SigningThreshold};
use proptest::prelude::*;

/// Extract the inception out of a fixture event (`Fallible`, not `panic!` —
/// the workspace denies `clippy::panic` in test targets too).
fn as_inception(ev: &common::Event) -> Fallible<&keri_events::InceptionEvent<'static>> {
    let KeriEvent::Inception(icp) = &ev.parsed else {
        return Err("fixture is not an inception".into());
    };
    Ok(icp)
}

#[test]
fn trusted_genesis_matches_validating_incept() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;

    let validated = seed(&icp, &k0)?; // full crypto path
    let trusted = KeyStateSnapshot::genesis(as_inception(&icp)?); // no crypto

    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}

/// The K6 heart: trusted fold ≡ snapshot of the validating fold, over a KEL
/// exercising all three accepted event kinds.
#[test]
fn trusted_fold_matches_validating_fold() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let rot = plain_rotation(&ixn1, 2, &k1, &k2)?;
    let ixn2 = interaction(&rot, 3)?;

    let validated = [
        ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]),
        rot.signed(vec![k1.sign(&rot.bytes, 0)?]),
        ixn2.signed(vec![k1.sign(&ixn2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    let trusted = [&ixn1, &rot, &ixn2]
        .into_iter()
        .fold(KeyStateSnapshot::genesis(as_inception(&icp)?), |s, ev| {
            s.advance(&ev.parsed)
        });

    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}

/// Same invariant across a witnessed rotation (mirrors the arrangement of
/// `rotation_swaps_a_witness` in `transitions.rs:100`): the trusted cut/add
/// algebra must land on exactly the validating fold's resolved witness set.
#[test]
fn trusted_fold_matches_validating_fold_with_witness_deltas() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, w1) = (Key::witness()?, Key::witness()?);

    let icp = inception_full(
        &[&k0],
        &[&k1],
        SigningThreshold::Simple(1),
        SigningThreshold::Simple(1),
        &[&w0],
        1,
        vec![],
    )?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![prefix_of(&w0)],
            removals: vec![prefix_of(&w0)],
            additions: vec![prefix_of(&w1)],
            toad: 1,
        },
    )?;

    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let validated =
        s0.ingest(&rot.receipted(vec![k1.sign(&rot.bytes, 0)?], rot.receipts(&[&w1])?))?;

    let trusted = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&rot.parsed);

    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}

/// Empty-`n` inception: validating and trusted folds must both deem the
/// identifier non-transferable at birth and agree field-for-field.
#[test]
fn trusted_genesis_matches_validating_incept_for_abandoned_at_birth() -> Fallible<()> {
    let k0 = Key::new()?;
    let icp = inception_full(
        &[&k0],
        &[],
        SigningThreshold::Simple(1),
        SigningThreshold::Simple(0),
        &[],
        0,
        vec![],
    )?;

    let validated = seed(&icp, &k0)?;
    let trusted = KeyStateSnapshot::genesis(as_inception(&icp)?);

    assert_eq!(
        trusted.view().transferability(),
        Transferability::NonTransferable
    );
    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}

/// Abandonment rotation: validating and trusted folds must both close the KEL
/// and stay equal.
#[test]
fn trusted_fold_matches_validating_fold_across_abandonment() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let rot = abandoning_rotation(&icp, 1, &k1)?;

    let validated = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?]))?;
    let trusted = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&rot.parsed);

    assert!(!validated.is_transferable());
    assert!(!trusted.view().is_transferable());
    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}

// ── Defensive boundary: advance is total and deterministic on input the
// validating fold would reject. No panics, exact deterministic outcomes. ──

#[test]
fn advance_on_second_inception_reseeds() -> Fallible<()> {
    let (k0, k1, k2, k3) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp_a = genesis(&k0, &k1)?;
    let icp_b = genesis(&k2, &k3)?;

    let reseeded = KeyStateSnapshot::genesis(as_inception(&icp_a)?).advance(&icp_b.parsed);
    assert_eq!(reseeded, KeyStateSnapshot::genesis(as_inception(&icp_b)?));
    Ok(())
}

#[test]
fn trusted_witness_cut_of_absent_prefix_is_noop_and_duplicate_add_is_skip() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, wx) = (Key::witness()?, Key::witness()?);

    // Actual current set: [w0]. The delta CLAIMS prior [wx], cuts wx (absent
    // from the true set), and adds w0 (already present). The builder accepts
    // it (cut/add relations hold against the CLAIMED prior — see the
    // WitnessChange doc, common/mod.rs:173); the validating fold rejects it
    // (WitnessSetError::RemovalNotCurrent). The trusted fold must compute
    // deterministically: cut-absent no-op, add-present skip → still [w0].
    let icp = inception_full(
        &[&k0],
        &[&k1],
        SigningThreshold::Simple(1),
        SigningThreshold::Simple(1),
        &[&w0],
        1,
        vec![],
    )?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![prefix_of(&wx)],
            removals: vec![prefix_of(&wx)],
            additions: vec![prefix_of(&w0)],
            toad: 1,
        },
    )?;

    let stepped = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&rot.parsed);
    let view = stepped.view();
    assert_eq!(view.witnesses().len(), 1);
    assert_eq!(view.witnesses()[0].raw(), w0.verfer.raw());
    Ok(())
}

#[test]
fn advance_on_out_of_order_sn_takes_event_values_verbatim() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn_gap = interaction(&icp, 7)?; // validating fold would reject: expected 1

    let stepped = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&ixn_gap.parsed);
    assert_eq!(stepped.view().sn().value(), 7);
    assert_eq!(stepped.view().latest_said(), &ixn_gap.said);
    Ok(())
}

/// Fold the same generated KEL both ways and return the pair of snapshots.
/// Shape: genesis, then for each element of `plan` an interaction (false) or
/// a plain rotation (true), sns strictly sequential — every event accepted.
fn both_folds(plan: &[bool]) -> Fallible<(KeyStateSnapshot, KeyStateSnapshot)> {
    let mut keys = vec![Key::new()?, Key::new()?];
    let icp = genesis(&keys[0], &keys[1])?;

    let mut events = Vec::new();
    let mut current = 0usize; // index of the current signing key
    for (i, &rotate) in plan.iter().enumerate() {
        let sn = u128::try_from(i)?.checked_add(1).ok_or("sn overflow")?;
        let prior = events.last().unwrap_or(&icp);
        if rotate {
            keys.push(Key::new()?);
            let reveal_idx = current + 1;
            let next_idx = keys.len() - 1;
            let ev = plain_rotation(prior, sn, &keys[reveal_idx], &keys[next_idx])?;
            events.push(ev);
            current = reveal_idx;
        } else {
            events.push(interaction(prior, sn)?);
        }
    }

    // Validating fold: sign each event with the key controlling at that point.
    let mut signer = 0usize;
    let mut state = seed(&icp, &keys[0])?;
    for (i, ev) in events.iter().enumerate() {
        if plan[i] {
            signer += 1;
        }
        let sig = keys[signer].sign(&ev.bytes, 0)?;
        state = state.ingest(&ev.signed(vec![sig]))?;
    }

    // Trusted fold: parsed events only.
    let trusted = events
        .iter()
        .fold(KeyStateSnapshot::genesis(as_inception(&icp)?), |s, ev| {
            s.advance(&ev.parsed)
        });

    Ok((trusted, KeyStateSnapshot::from(&state)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))] // real Ed25519 per case
    /// Spec §6.2: trusted fold ≡ snapshot of validating fold on any accepted
    /// sequence. Boundaries: empty plan (genesis only), all-rotations,
    /// all-interactions, and mixed, up to length 6.
    #[test]
    fn trusted_fold_is_differential_dual(plan in proptest::collection::vec(any::<bool>(), 0..=6)) {
        let (trusted, validated) = both_folds(&plan).expect("accepted KEL must fold");
        prop_assert_eq!(trusted, validated);
    }
}

/// Assert a lent view equals the state it was snapshotted from, field by field.
/// (`KeyState` has no `PartialEq`; accessors are the public comparison surface.)
fn assert_view_matches(view: &KeyState<'_>, original: &KeyState<'_>) {
    assert_eq!(view.prefix(), original.prefix());
    assert_eq!(view.sn().value(), original.sn().value());
    assert_eq!(view.latest_said(), original.latest_said());
    assert_eq!(view.latest_message_type(), original.latest_message_type());
    assert_eq!(view.keys(), original.keys());
    assert_eq!(view.threshold(), original.threshold());
    assert_eq!(view.next_keys(), original.next_keys());
    assert_eq!(view.next_threshold(), original.next_threshold());
    assert_eq!(view.witnesses(), original.witnesses());
    assert_eq!(view.witness_threshold(), original.witness_threshold());
    assert_eq!(view.config(), original.config());
    assert_eq!(view.delegator(), original.delegator());
    assert_eq!(view.transferability(), original.transferability());
    assert_eq!(
        view.last_establishment().sn.value(),
        original.last_establishment().sn.value()
    );
    assert_eq!(
        view.last_establishment().said,
        original.last_establishment().said
    );
}

#[test]
fn snapshot_round_trips_through_view() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn = interaction(&icp, 1)?;
    let rot = plain_rotation(&ixn, 2, &k1, &k2)?;

    let state = [
        ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]),
        rot.signed(vec![k1.sign(&rot.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    let snapshot = KeyStateSnapshot::from(&state);
    assert_view_matches(&snapshot.view(), &state);

    // Round-trip: snapshotting the view again is identity on the snapshot.
    let again = KeyStateSnapshot::from(&snapshot.view());
    assert_eq!(again, snapshot);
    Ok(())
}
