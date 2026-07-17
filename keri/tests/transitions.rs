//! End-to-end key-state transition tests: real Ed25519 keypairs, real signatures
//! verified inside the transition, driven through `incept` + `ingest`.
//!
//! One test per invariant the transition enforces, in the order the rules apply.
//! Every rejection test asserts the EXACT [`Rejection`] variant and is built so it
//! would fail if the corresponding rule were removed. Fixtures live in
//! [`common`]; the crate consumes only cesr's public API, so events are built with
//! the serder builders and the fold rejects the invalid ones.
mod common;

use cesr::keri::{ConfigTrait, Ilk, SigningThreshold, WeightedThreshold};

use cesr::crypto::IndexedVerifyError;
use common::{
    Fallible, Key, RotationKeys, WitnessChange, commit, delegated_inception, delegated_rotation,
    excess_threshold_inception_bytes, excess_toad_inception_bytes, genesis, genesis_config,
    inception_full, inception_multi, interaction, overlap_rotation, plain_rotation, rotation,
    rotation_witnessed, seed,
};
use keri::{KeyState, Rejection, StructuralError, TransferabilityError, WitnessSetError};

// ── Happy-path chains and establishment acceptance ──────────────────────────

#[test]
fn folds_a_four_event_kel() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);

    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let rot = plain_rotation(&ixn1, 2, &k1, &k2)?;
    let ixn2 = interaction(&rot, 3)?;

    let latest = [
        ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]),
        rot.signed(vec![k1.sign(&rot.bytes, 0)?]),
        ixn2.signed(vec![k1.sign(&ixn2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |state, ev| state.ingest(&ev))?;

    assert_eq!(latest.sn().value(), 3);
    assert_eq!(latest.latest_ilk(), Ilk::Ixn);
    assert_eq!(latest.keys()[0].raw(), k1.verfer.raw());
    assert_eq!(latest.last_establishment().sn.value(), 2);
    assert_eq!(latest.next_keys()[0].raw(), commit(&k2.verfer)?.raw());
    Ok(())
}

#[test]
fn rotation_chains_across_two_rotations() -> Fallible<()> {
    let (k0, k1, k2, k3) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);

    let icp = genesis(&k0, &k1)?;
    let rot1 = plain_rotation(&icp, 1, &k1, &k2)?;
    let rot2 = plain_rotation(&rot1, 2, &k2, &k3)?;

    let latest = [
        rot1.signed(vec![k1.sign(&rot1.bytes, 0)?]),
        rot2.signed(vec![k2.sign(&rot2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |state, ev| state.ingest(&ev))?;

    assert_eq!(latest.sn().value(), 2);
    assert_eq!(latest.latest_ilk(), Ilk::Rot);
    assert_eq!(latest.keys()[0].raw(), k2.verfer.raw());
    assert_eq!(latest.last_establishment().sn.value(), 2);
    assert_eq!(latest.next_keys()[0].raw(), commit(&k3.verfer)?.raw());
    Ok(())
}

#[test]
fn multisig_inception_accepts_a_threshold_signed_set() -> Fallible<()> {
    let (k0, k1, k2, next) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_multi(&[&k0, &k1, &k2], &next, SigningThreshold::Simple(2))?;

    let state = KeyState::incept(&icp.signed(icp.sign_all(&[&k0, &k1])?))?;

    assert_eq!(state.keys().len(), 3);
    assert_eq!(state.sn().value(), 0);
    Ok(())
}

#[test]
fn weighted_threshold_inception_validates_when_signed() -> Fallible<()> {
    let (k0, k1, next) = (Key::new()?, Key::new()?, Key::new()?);
    let weighted = SigningThreshold::Weighted(
        WeightedThreshold::from_nested(vec![vec![(1, 2), (1, 2)]]).unwrap(),
    );
    let icp = inception_multi(&[&k0, &k1], &next, weighted)?;

    // Both half-weights signing sum to 1 and satisfy the clause.
    let state = KeyState::incept(&icp.signed(icp.sign_all(&[&k0, &k1])?))?;

    assert_eq!(state.keys().len(), 2);
    Ok(())
}

#[test]
fn rotation_swaps_a_witness() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, w1) = (Key::witness()?, Key::witness()?);

    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![w0.verfer.clone()],
            removals: vec![w0.verfer.clone()],
            additions: vec![w1.verfer.clone()],
            toad: 1,
        },
    )?;

    // The genesis is receipted by its declared witness (w0); the rotation by
    // the post-cut/add set (w1) — receipts index into the resolved set.
    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let latest = s0.ingest(&rot.receipted(vec![k1.sign(&rot.bytes, 0)?], rot.receipts(&[&w1])?))?;

    assert_eq!(latest.witnesses().len(), 1);
    assert_eq!(latest.witnesses()[0].raw(), w1.verfer.raw());
    assert_eq!(latest.witness_threshold().value(), 1);
    Ok(())
}

#[test]
fn rotation_adds_a_witness() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let w0 = Key::witness()?;

    let icp = genesis(&k0, &k1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![],
            removals: vec![],
            additions: vec![w0.verfer.clone()],
            toad: 1,
        },
    )?;

    let latest = seed(&icp, &k0)?
        .ingest(&rot.receipted(vec![k1.sign(&rot.bytes, 0)?], rot.receipts(&[&w0])?))?;

    assert_eq!(latest.witnesses().len(), 1);
    assert_eq!(latest.witnesses()[0].raw(), w0.verfer.raw());
    assert_eq!(latest.witness_threshold().value(), 1);
    Ok(())
}

// ── Inception rejections ────────────────────────────────────────────────────

#[test]
fn genesis_without_signatures_is_missing_signatures() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let Err(r) = KeyState::incept(&icp.signed(vec![])) else {
        return Err("unsigned genesis was accepted".into());
    };
    assert!(matches!(r, Rejection::MissingSignatures));
    Ok(())
}

#[test]
fn genesis_with_a_bad_signature_is_invalid_signature() -> Fallible<()> {
    let (k0, k1, wrong) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    // Presented at index 0 (claiming to be k0) but produced by a different key.
    let Err(r) = KeyState::incept(&icp.signed(vec![wrong.sign(&icp.bytes, 0)?])) else {
        return Err("a genesis with a forged signature was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::UnverifiedSignature(IndexedVerifyError::Verification(_))
    ));
    Ok(())
}

#[test]
fn multisig_inception_below_threshold_is_missing_signatures() -> Fallible<()> {
    let (k0, k1, k2, next) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_multi(&[&k0, &k1, &k2], &next, SigningThreshold::Simple(2))?;
    // One valid signature under a 2-of-3 threshold.
    let Err(r) = KeyState::incept(&icp.signed(vec![k0.sign(&icp.bytes, 0)?])) else {
        return Err("a 2-of-3 genesis with one signature was accepted".into());
    };
    assert!(matches!(r, Rejection::MissingSignatures));
    Ok(())
}

#[test]
fn inception_with_an_empty_weighted_threshold_is_rejected_at_construction() -> Fallible<()> {
    // A `kt:[]` (empty weighted) threshold requires no signatures — malformed.
    // The serder builder rejects it before an event can exist, and since spine
    // phase 3 `deserialize_event` rejects the same shape arriving over the wire
    // (see `wire_inception_with_kt_above_key_count_is_rejected` below) — all
    // three enforcement points (builder, reader, fold) share
    // `SigningThreshold::check_well_formed`. This guards the construction-time
    // rule.
    let (k0, next) = (Key::new()?, Key::new()?);
    assert!(
        inception_multi(
            &[&k0],
            &next,
            SigningThreshold::Weighted(WeightedThreshold::from_nested(vec![]).unwrap())
        )
        .is_err(),
        "a kt:[] inception must be rejected at construction"
    );
    Ok(())
}

#[test]
fn inception_committing_to_no_next_keys_is_invalid() -> Fallible<()> {
    // A self-addressing prefix must commit to at least one next key.
    let k0 = Key::new()?;
    let icp = inception_full(&[&k0], &[], SigningThreshold::Simple(1), &[], 0)?;
    let Err(r) = KeyState::incept(&icp.signed(vec![k0.sign(&icp.bytes, 0)?])) else {
        return Err("a self-addressing genesis with no next-key commitment was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Transferability(TransferabilityError::SelfAddressingWithoutNextKeys)
    ));
    Ok(())
}

#[test]
fn inception_with_toad_above_witness_count_is_rejected_at_construction() -> Fallible<()> {
    // TOAD of 1 with zero witnesses. Unlike rotation, inception has no
    // separate "claimed prior" the builder trusts and the fold re-checks —
    // the declared witness set and TOAD are the same value on both sides, so
    // the builder's `Toad::exact` (#171) rejects this before an event can
    // exist. Unlike rotation, this rule is now also enforced at wire-parse
    // time (`InceptionEvent`/`DelegatedInceptionEvent` read via
    // `deserialize_event`, see `wire_inception_with_toad_above_witness_count_is_rejected`
    // below) — a forged wire event can no longer reach the fold's
    // `check_witness_threshold` for inception, only for rotation, where the
    // governing witness set is resolved rather than declared. This test
    // guards the construction-time rule, mirroring
    // `inception_with_an_empty_weighted_threshold_is_rejected_at_construction`.
    let (k0, k1) = (Key::new()?, Key::new()?);
    assert!(
        inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[], 1).is_err(),
        "a genesis with TOAD above its witness count must be rejected at construction"
    );
    Ok(())
}

#[test]
fn wire_inception_with_toad_above_witness_count_is_rejected() -> Fallible<()> {
    // #171: cesr's read path now validates TOAD against the wire witness
    // count at parse time (`Toad::exact` inside `build_inception`), so a
    // forged wire event with this shape is rejected by `deserialize_event`
    // itself and never reaches `KeyState::incept` — the fold's own
    // `check_witness_threshold` is unreachable for inception now (it stays
    // reachable for rotation, see `rotation_with_toad_above_resolved_witness_count_is_rejected`,
    // because rotation TOAD is validated against a *resolved* witness set the
    // fold computes, not the wire body alone).
    let (k0, k1) = (Key::new()?, Key::new()?);
    let bytes = excess_toad_inception_bytes(&k0, &k1)?;
    let Err(err) = cesr::serder::deserialize_event(&bytes) else {
        return Err("a wire genesis with TOAD above its witness count was accepted".into());
    };
    assert!(matches!(
        err,
        cesr::serder::SerderError::Toad(cesr::keri::ToadError::OutOfRange {
            toad: 1,
            witnesses: 0
        })
    ));
    Ok(())
}

#[test]
fn wire_inception_with_kt_above_key_count_is_rejected() -> Fallible<()> {
    // Spine phase 3: cesr's read path enforces the same threshold
    // well-formedness the builder and the fold enforce
    // (`SigningThreshold::check_well_formed`), so a forged wire event whose
    // `kt` exceeds its key count is rejected by `deserialize_event` itself
    // and never reaches the fold — whose own `Authority::well_formed` check
    // stays as defense in depth. Before phase 3 this shape deserialized
    // successfully and only the fold caught it.
    let (k0, k1) = (Key::new()?, Key::new()?);
    let bytes = excess_threshold_inception_bytes(&k0, &k1)?;
    let Err(err) = cesr::serder::deserialize_event(&bytes) else {
        return Err("a wire genesis with kt above its key count was accepted".into());
    };
    assert!(matches!(
        err,
        cesr::serder::SerderError::SigningThresholdOutOfRange {
            field: "signing",
            source: cesr::keri::SigningThresholdError::ExceedsKeyCount {
                required: 2,
                key_count: 1
            }
        }
    ));
    Ok(())
}

// ── Dispatch rejections ─────────────────────────────────────────────────────

#[test]
fn a_second_inception_is_invalid() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let icp2 = genesis(&k0, &k1)?;
    let Err(r) = seed(&icp, &k0)?.ingest(&icp2.signed(vec![k0.sign(&icp2.bytes, 0)?])) else {
        return Err("a duplicate inception was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Structural(StructuralError::DuplicateInception)
    ));
    Ok(())
}

#[test]
fn delegated_inception_is_unsupported() -> Fallible<()> {
    let (k0, k1, kd, kn) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let dip = delegated_inception(&kn, &kn, &kd.verfer)?;
    let Err(r) = seed(&icp, &k0)?.ingest(&dip.signed(vec![kn.sign(&dip.bytes, 0)?])) else {
        return Err("a delegated inception was accepted".into());
    };
    assert!(matches!(r, Rejection::DelegationUnsupported));
    Ok(())
}

#[test]
fn delegated_rotation_is_unsupported() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let drt = delegated_rotation(&icp, 1, &k1)?;
    let Err(r) = seed(&icp, &k0)?.ingest(&drt.signed(vec![k1.sign(&drt.bytes, 0)?])) else {
        return Err("a delegated rotation was accepted".into());
    };
    assert!(matches!(r, Rejection::DelegationUnsupported));
    Ok(())
}

// ── Rotation rejections ─────────────────────────────────────────────────────

#[test]
fn rotation_revealing_the_wrong_key_breaks_the_commitment() -> Fallible<()> {
    let (k0, k1, k2, k3) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?; // commits to k1
    let rot = plain_rotation(&icp, 1, &k2, &k3)?; // reveals k2, not the committed k1
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k2.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation revealing an uncommitted key was accepted".into());
    };
    assert!(matches!(r, Rejection::NextKeyCommitmentMismatch));
    Ok(())
}

#[test]
fn rotation_revealing_the_wrong_key_arity_breaks_the_commitment() -> Fallible<()> {
    let (k0, k1, kx, k2) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?; // commits to exactly one next key
    // Reveals two keys against a single-key commitment: a positional mismatch.
    let rot = rotation(
        &icp,
        1,
        RotationKeys {
            reveal: &[&k1, &kx],
            next: &[&k2],
            threshold: SigningThreshold::Simple(1),
        },
        WitnessChange::none(),
    )?;
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation with mismatched key arity was accepted".into());
    };
    assert!(matches!(r, Rejection::NextKeyCommitmentMismatch));
    Ok(())
}

#[test]
fn out_of_order_rotation_is_rejected() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let rot = plain_rotation(&icp, 5, &k1, &k2)?; // expected sn 1, not 5
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("an out-of-order rotation was accepted".into());
    };
    // expected the next sn (1), event carried 5 — the context is plumbed through.
    assert!(matches!(
        r,
        Rejection::OutOfOrder {
            expected: 1,
            actual: 5
        }
    ));
    Ok(())
}

#[test]
fn rotation_with_a_stale_prior_digest_is_rejected() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let s1 = seed(&icp, &k0)?.ingest(&ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]))?;
    // sn 2 is expected, but this rotation chains onto the genesis SAID, not ixn1's.
    let stale = plain_rotation(&icp, 2, &k1, &k2)?;
    let Err(r) = s1.ingest(&stale.signed(vec![k1.sign(&stale.bytes, 0)?])) else {
        return Err("a rotation with a stale prior digest was accepted".into());
    };
    assert!(matches!(r, Rejection::PriorDigestMismatch));
    Ok(())
}

#[test]
fn rotation_below_threshold_is_missing_signatures() -> Fallible<()> {
    let (k0, k1a, k1b, k2) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    // Genesis commits to a two-key next set.
    let icp = inception_full(&[&k0], &[&k1a, &k1b], SigningThreshold::Simple(1), &[], 0)?;
    // Rotation reveals both committed keys under a 2-of-2 signing threshold.
    let rot = rotation(
        &icp,
        1,
        RotationKeys {
            reveal: &[&k1a, &k1b],
            next: &[&k2],
            threshold: SigningThreshold::Simple(2),
        },
        WitnessChange::none(),
    )?;
    // Only one of the two required signatures.
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1a.sign(&rot.bytes, 0)?])) else {
        return Err("a below-threshold rotation was accepted".into());
    };
    assert!(matches!(r, Rejection::MissingSignatures));
    Ok(())
}

#[test]
fn rotation_removing_a_non_witness_is_rejected() -> Fallible<()> {
    let (k0, k1, k2, ghost) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?; // no witnesses
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            // falsely claimed prior — the builder accepts, the fold knows better
            prior: vec![ghost.verfer.clone()],
            removals: vec![ghost.verfer.clone()],
            additions: vec![],
            toad: 0,
        },
    )?;
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation cutting a non-witness was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::WitnessSet(WitnessSetError::RemovalNotCurrent)
    ));
    Ok(())
}

#[test]
fn rotation_with_overlapping_cut_and_add_is_rejected() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, decoy) = (Key::witness()?, Key::witness()?);
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let rot = overlap_rotation(
        &icp,
        1,
        RotationKeys {
            reveal: &[&k1],
            next: &[&k2],
            threshold: SigningThreshold::Simple(1),
        },
        &w0,
        &decoy,
    )?;
    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let Err(r) = s0.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation cutting and adding the same witness was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::WitnessSet(WitnessSetError::CutAddOverlap)
    ));
    Ok(())
}

#[test]
fn rotation_adding_an_existing_witness_is_rejected() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let w0 = Key::witness()?;
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            // falsely claimed empty prior — the builder sees add ∩ {} = ∅ and
            // accepts; the fold knows w0 is already a witness and rejects.
            prior: vec![],
            removals: vec![],
            additions: vec![w0.verfer.clone()],
            toad: 1,
        },
    )?;
    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let Err(r) = s0.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation re-adding a current witness was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::WitnessSet(WitnessSetError::AdditionAlreadyPresent)
    ));
    Ok(())
}

#[test]
fn rotation_with_toad_above_resolved_witness_count_is_rejected() -> Fallible<()> {
    let (k0, k1, k2, w0, decoy) = (
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
    );
    let icp = genesis(&k0, &k1)?; // no witnesses
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            // falsely claimed prior — builder sees {decoy, w0} (toad 2 in
            // bounds), the fold resolves {w0} and rejects.
            prior: vec![decoy.verfer.clone()],
            removals: vec![],
            additions: vec![w0.verfer.clone()],
            toad: 2, // one resolved witness cannot back a TOAD of 2
        },
    )?;
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation with TOAD above its resolved witness count was accepted".into());
    };
    assert!(matches!(r, Rejection::WitnessThresholdExceeded { .. }));
    Ok(())
}

// ── Interaction rejections ──────────────────────────────────────────────────

#[test]
fn interaction_with_a_gap_is_out_of_order() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn = interaction(&icp, 5)?; // expected sn 1, not 5
    let Err(r) = seed(&icp, &k0)?.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?])) else {
        return Err("an out-of-order interaction was accepted".into());
    };
    assert!(matches!(r, Rejection::OutOfOrder { .. }));
    Ok(())
}

#[test]
fn interaction_with_a_stale_prior_digest_is_rejected() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let s1 = seed(&icp, &k0)?.ingest(&ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]))?;
    // sn 2 is expected, but this event chains onto the genesis SAID, not ixn1's.
    let stale = interaction(&icp, 2)?;
    let Err(r) = s1.ingest(&stale.signed(vec![k0.sign(&stale.bytes, 0)?])) else {
        return Err("a stale-prior interaction was accepted".into());
    };
    assert!(matches!(r, Rejection::PriorDigestMismatch));
    Ok(())
}

#[test]
fn establishment_only_forbids_interaction() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis_config(&k0, &k1, vec![ConfigTrait::EstOnly])?;
    let ixn = interaction(&icp, 1)?;
    let Err(r) = seed(&icp, &k0)?.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?])) else {
        return Err("an interaction on an est-only identifier was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Structural(StructuralError::InteractionOnEstablishmentOnly)
    ));
    Ok(())
}

#[test]
fn interaction_below_threshold_is_missing_signatures() -> Fallible<()> {
    let (k0, k1, k2, next) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_multi(&[&k0, &k1, &k2], &next, SigningThreshold::Simple(2))?;
    let s0 = KeyState::incept(&icp.signed(icp.sign_all(&[&k0, &k1])?))?;
    let ixn = interaction(&icp, 1)?;
    // Interaction verifies against the current 2-of-3 threshold; one sig is short.
    let Err(r) = s0.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?])) else {
        return Err("a below-threshold interaction was accepted".into());
    };
    assert!(matches!(r, Rejection::MissingSignatures));
    Ok(())
}

// ── Signature / index rejections ────────────────────────────────────────────

#[test]
fn a_signature_from_the_wrong_key_is_rejected() -> Fallible<()> {
    let (k0, k1, wrong) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn = interaction(&icp, 1)?;
    // Signed by `wrong` but presented at index 0, claiming to be k0.
    let Err(r) = seed(&icp, &k0)?.ingest(&ixn.signed(vec![wrong.sign(&ixn.bytes, 0)?])) else {
        return Err("a signature from the wrong key was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::UnverifiedSignature(IndexedVerifyError::Verification(_))
    ));
    Ok(())
}

// ── Witness receipt verification ────────────────────────────────────────────
// Semantics pinned from keripy `Kever.valSigsWigsDel` (eventing.py:2735-2799
// at scripts/KERIPY_PIN): receipts verify over the event's raw bytes against
// the witness each index selects in the event's GOVERNING witness set;
// invalid/out-of-range receipts are skipped, duplicates count once, and the
// count of valid distinct receipts must reach the TOAD.

#[test]
fn witnessed_inception_with_sufficient_receipts_is_accepted() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let (w0, w1, w2) = (Key::witness()?, Key::witness()?, Key::witness()?);
    let icp = inception_full(
        &[&k0],
        &[&k1],
        SigningThreshold::Simple(1),
        &[&w0, &w1, &w2],
        2,
    )?;
    // Receipts from w0 (index 0) and w2 (index 2) — exactly TOAD of them.
    let wigs = vec![w0.sign(&icp.bytes, 0)?, w2.sign(&icp.bytes, 2)?];
    let state = KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], wigs))?;
    assert_eq!(state.witnesses().len(), 3);
    assert_eq!(state.witness_threshold().value(), 2);
    Ok(())
}

#[test]
fn witnessed_inception_below_toad_is_insufficient_receipts() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let (w0, w1) = (Key::witness()?, Key::witness()?);
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0, &w1], 2)?;
    // One valid receipt under a TOAD of 2.
    let wigs = vec![w0.sign(&icp.bytes, 0)?];
    let Err(r) = KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], wigs)) else {
        return Err("an under-receipted witnessed genesis was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::InsufficientWitnessReceipts {
            valid: 1,
            required: 2
        }
    ));
    Ok(())
}

#[test]
fn duplicate_witness_receipts_count_once() -> Fallible<()> {
    // keripy dedups receipts before counting them against the TOAD
    // (verifySigs `oset` dedup, eventing.py:325): two receipts from the same
    // witness are one witness's agreement.
    let (k0, k1) = (Key::new()?, Key::new()?);
    let (w0, w1) = (Key::witness()?, Key::witness()?);
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0, &w1], 2)?;
    let wigs = vec![w0.sign(&icp.bytes, 0)?, w0.sign(&icp.bytes, 0)?];
    let Err(r) = KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], wigs)) else {
        return Err("duplicate receipts were double-counted against the TOAD".into());
    };
    assert!(matches!(
        r,
        Rejection::InsufficientWitnessReceipts {
            valid: 1,
            required: 2
        }
    ));
    Ok(())
}

#[test]
fn out_of_range_witness_receipt_index_is_ignored() -> Fallible<()> {
    // keripy SKIPS a receipt whose index addresses no witness rather than
    // rejecting the event (eventing.py:332-334) — it simply never counts.
    let (k0, k1) = (Key::new()?, Key::new()?);
    let w0 = Key::witness()?;
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let wigs = vec![w0.sign(&icp.bytes, 5)?]; // index 5 in a 1-witness set
    let Err(r) = KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], wigs)) else {
        return Err("an out-of-range receipt index satisfied the TOAD".into());
    };
    assert!(matches!(
        r,
        Rejection::InsufficientWitnessReceipts {
            valid: 0,
            required: 1
        }
    ));

    // …and alongside a valid receipt it is inert, not an error.
    let mixed_wigs = vec![w0.sign(&icp.bytes, 5)?, w0.sign(&icp.bytes, 0)?];
    assert!(KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], mixed_wigs)).is_ok());
    Ok(())
}

#[test]
fn forged_witness_receipt_does_not_count() -> Fallible<()> {
    // A receipt at a valid index but produced by a different key: skipped
    // per keripy (verifySigs keeps only signatures that verify), so the
    // TOAD stays unmet — the exact counts prove it never counted.
    let (k0, k1) = (Key::new()?, Key::new()?);
    let (w0, impostor) = (Key::witness()?, Key::witness()?);
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let wigs = vec![impostor.sign(&icp.bytes, 0)?];
    let Err(r) = KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], wigs)) else {
        return Err("a forged witness receipt satisfied the TOAD".into());
    };
    assert!(matches!(
        r,
        Rejection::InsufficientWitnessReceipts {
            valid: 0,
            required: 1
        }
    ));
    Ok(())
}

#[test]
fn unwitnessed_event_ignores_stray_receipts() -> Fallible<()> {
    // TOAD 0 (no witnesses) is vacuously satisfied — stray receipts change
    // nothing, and the unwitnessed KEL behavior is exactly as before.
    let (k0, k1, stray) = (Key::new()?, Key::new()?, Key::witness()?);
    let icp = genesis(&k0, &k1)?;
    let wigs = vec![stray.sign(&icp.bytes, 0)?];
    let state = KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], wigs))?;
    assert_eq!(state.witness_threshold().value(), 0);
    Ok(())
}

#[test]
fn rotation_receipt_by_a_cut_witness_does_not_count() -> Fallible<()> {
    // Receipt indices select into the POST-cut/add resolved set (keripy
    // passes `wits = list((witset - cutset) | addset)` into
    // valSigsWigsDel, eventing.py:2624/2390). After cutting w0 for w1, a
    // receipt by w0 at index 0 verifies against w1 — and fails.
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, w1) = (Key::witness()?, Key::witness()?);
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![w0.verfer.clone()],
            removals: vec![w0.verfer.clone()],
            additions: vec![w1.verfer.clone()],
            toad: 1,
        },
    )?;
    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let Err(r) = s0.ingest(&rot.receipted(
        vec![k1.sign(&rot.bytes, 0)?],
        rot.receipts(&[&w0])?, // the CUT witness, not the resolved one
    )) else {
        return Err("a cut witness's receipt satisfied the post-rotation TOAD".into());
    };
    assert!(matches!(
        r,
        Rejection::InsufficientWitnessReceipts {
            valid: 0,
            required: 1
        }
    ));
    Ok(())
}

#[test]
fn witnessed_interaction_requires_receipts() -> Fallible<()> {
    // keripy validates an interaction's receipts against the state's carried
    // witness set and TOAD (ixn branch of Kever.update, eventing.py:2452-2461).
    let (k0, k1) = (Key::new()?, Key::new()?);
    let w0 = Key::witness()?;
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let ixn = interaction(&icp, 1)?;

    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let Err(r) = s0
        .clone()
        .ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))
    else {
        return Err("an unreceipted interaction on a witnessed identifier was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::InsufficientWitnessReceipts {
            valid: 0,
            required: 1
        }
    ));

    let latest = s0.ingest(&ixn.receipted(vec![k0.sign(&ixn.bytes, 0)?], ixn.receipts(&[&w0])?))?;
    assert_eq!(latest.sn().value(), 1);
    Ok(())
}

#[test]
fn a_signer_index_out_of_range_is_invalid() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn = interaction(&icp, 1)?;
    // A single-key state has no signer at index 5.
    let Err(r) = seed(&icp, &k0)?.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 5)?])) else {
        return Err("a signature at an out-of-range index was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::UnverifiedSignature(IndexedVerifyError::IndexOutOfRange { .. })
    ));
    Ok(())
}
