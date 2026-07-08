//! End-to-end key-state transition tests: real Ed25519 keypairs, real signatures
//! verified inside the transition, driven through `incept` + `ingest`.
//!
//! One test per invariant the transition enforces, in the order the rules apply.
//! Every rejection test asserts the EXACT [`Rejection`] variant and is built so it
//! would fail if the corresponding rule were removed. Fixtures live in
//! [`common`]; the crate consumes only cesr's public API, so events are built with
//! the serder builders and the fold rejects the invalid ones.
mod common;

use cesr::core::primitives::Tholder;
use cesr::keri::{ConfigTrait, Ilk};

use cesr::crypto::IndexedVerifyError;
use common::{
    Fallible, Key, RotationKeys, WitnessChange, commit, delegated_inception, delegated_rotation,
    genesis, genesis_config, inception_full, inception_multi, interaction, plain_rotation,
    rotation, rotation_witnessed, seed,
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
    let icp = inception_multi(&[&k0, &k1, &k2], &next, Tholder::Simple(2))?;

    let state = KeyState::incept(&icp.signed(icp.sign_all(&[&k0, &k1])?))?;

    assert_eq!(state.keys().len(), 3);
    assert_eq!(state.sn().value(), 0);
    Ok(())
}

#[test]
fn weighted_threshold_inception_validates_when_signed() -> Fallible<()> {
    let (k0, k1, next) = (Key::new()?, Key::new()?, Key::new()?);
    let weighted = Tholder::Weighted(vec![vec![(1, 2), (1, 2)]]);
    let icp = inception_multi(&[&k0, &k1], &next, weighted)?;

    // Both half-weights signing sum to 1 and satisfy the clause.
    let state = KeyState::incept(&icp.signed(icp.sign_all(&[&k0, &k1])?))?;

    assert_eq!(state.keys().len(), 2);
    Ok(())
}

#[test]
fn rotation_swaps_a_witness() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, w1) = (Key::new()?, Key::new()?);

    let icp = inception_full(&[&k0], &[&k1], Tholder::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            removals: vec![w0.verfer.clone()],
            additions: vec![w1.verfer.clone()],
            toad: 1,
        },
    )?;

    let latest = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?]))?;

    assert_eq!(latest.witnesses().len(), 1);
    assert_eq!(latest.witnesses()[0].raw(), w1.verfer.raw());
    assert_eq!(latest.witness_threshold(), 1);
    Ok(())
}

#[test]
fn rotation_adds_a_witness() -> Fallible<()> {
    let (k0, k1, k2, w0) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);

    let icp = genesis(&k0, &k1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            removals: vec![],
            additions: vec![w0.verfer.clone()],
            toad: 1,
        },
    )?;

    let latest = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?]))?;

    assert_eq!(latest.witnesses().len(), 1);
    assert_eq!(latest.witnesses()[0].raw(), w0.verfer.raw());
    assert_eq!(latest.witness_threshold(), 1);
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
    let icp = inception_multi(&[&k0, &k1, &k2], &next, Tholder::Simple(2))?;
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
    // The serder builder rejects it before an event can exist, so it can never
    // reach the fold. The fold enforces the same rule (check_established_threshold
    // -> Tholder::check_well_formed) for wire-parsed events, but a consumer using
    // the builder cannot construct one. This guards the construction-time rule.
    let (k0, next) = (Key::new()?, Key::new()?);
    assert!(
        inception_multi(&[&k0], &next, Tholder::Weighted(vec![])).is_err(),
        "a kt:[] inception must be rejected at construction"
    );
    Ok(())
}

#[test]
fn inception_committing_to_no_next_keys_is_invalid() -> Fallible<()> {
    // A self-addressing prefix must commit to at least one next key.
    let k0 = Key::new()?;
    let icp = inception_full(&[&k0], &[], Tholder::Simple(1), &[], 0)?;
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
fn inception_with_toad_above_witness_count_is_invalid() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    // TOAD of 1 with zero witnesses.
    let icp = inception_full(&[&k0], &[&k1], Tholder::Simple(1), &[], 1)?;
    let Err(r) = KeyState::incept(&icp.signed(vec![k0.sign(&icp.bytes, 0)?])) else {
        return Err("a genesis with TOAD above its witness count was accepted".into());
    };
    assert!(matches!(r, Rejection::WitnessThresholdExceeded { .. }));
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
            threshold: Tholder::Simple(1),
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
    let icp = inception_full(&[&k0], &[&k1a, &k1b], Tholder::Simple(1), &[], 0)?;
    // Rotation reveals both committed keys under a 2-of-2 signing threshold.
    let rot = rotation(
        &icp,
        1,
        RotationKeys {
            reveal: &[&k1a, &k1b],
            next: &[&k2],
            threshold: Tholder::Simple(2),
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
    let (k0, k1, k2, w0) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_full(&[&k0], &[&k1], Tholder::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            removals: vec![w0.verfer.clone()],
            additions: vec![w0.verfer.clone()],
            toad: 0,
        },
    )?;
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
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
    let (k0, k1, k2, w0) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_full(&[&k0], &[&k1], Tholder::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            removals: vec![],
            additions: vec![w0.verfer.clone()],
            toad: 1,
        },
    )?;
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
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
    let (k0, k1, k2, w0) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?; // no witnesses
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
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
    let icp = inception_multi(&[&k0, &k1, &k2], &next, Tholder::Simple(2))?;
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
