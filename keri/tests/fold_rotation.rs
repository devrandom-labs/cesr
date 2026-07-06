//! Rotation fold: validate + apply, including the next-key commitment.
mod common;
use common::*;

use keri::{RejectionReason, apply, validate};

#[test]
fn valid_rotation_replaces_keys() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));
    let icp = inception(&k0, &k1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let rot = rotation_after(&g, 1, &k1, &k2);
    let accepted = validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap();
    let s1 = apply(accepted);
    assert_eq!(s1.sn().value(), 1);
    assert_eq!(s1.latest_ilk(), cesr::keri::Ilk::Rot);
    assert_eq!(s1.keys().len(), 1);
    assert_eq!(s1.keys()[0].raw(), k1.raw());
    assert_eq!(s1.last_establishment().sn.value(), 1);
    assert_eq!(s1.last_establishment().said.raw(), s1.latest_said().raw());
    assert_eq!(s1.next_keys()[0].raw(), commit(&k2).raw());
}

#[test]
fn rotation_with_wrong_revealed_key_fails_commitment() {
    let (k0, k1, k2, kx) = (verfer(1), verfer(2), verfer(3), verfer(9));
    let icp = inception(&k0, &k1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let rot = rotation_after(&g, 1, &kx, &k2);
    let err = validate(Some(&g), &rot, &[sig_for(0, &kx)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::NextKeyCommitmentMismatch);
}

#[test]
fn out_of_order_rotation_is_rejected() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));
    let icp = inception(&k0, &k1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let rot = rotation_after(&g, 3, &k1, &k2);
    let err = validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::OutOfOrder);
    assert_eq!(err.expected_sn, Some(1));
    assert_eq!(err.actual_sn, Some(3));
}

#[test]
fn rotation_with_stale_prior_digest_is_rejected() {
    let (k0, k1, k2, k3) = (verfer(1), verfer(2), verfer(3), verfer(4));
    let icp = inception(&k0, &k1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    // First rotation onto genesis: reveal k1, commit k2.
    let rot1 = rotation_after(&g, 1, &k1, &k2);
    let s1 = apply(validate(Some(&g), &rot1, &[sig_for(0, &k1)], &[]).unwrap());
    // Build a second rotation whose prior_event_said points at the STALE genesis
    // SAID (via `g`) rather than `s1`'s latest SAID, but at the correct next sn.
    let rot2_stale = rotation_after(&g, 2, &k2, &k3);
    let err = validate(Some(&s1), &rot2_stale, &[sig_for(0, &k2)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::PriorDigestMismatch);
}

#[test]
fn rotation_below_threshold_is_rejected() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));
    let icp = inception(&k0, &k1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let rot = rotation_after(&g, 1, &k1, &k2);
    // No signatures at all: threshold of 1 over the revealed keys is unmet.
    let err = validate(Some(&g), &rot, &[], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::MissingSignatures);
}

#[test]
fn rotation_chains_across_two_rotations() {
    let (k0, k1, k2, k3) = (verfer(1), verfer(2), verfer(3), verfer(4));
    let icp = inception(&k0, &k1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let rot1 = rotation_after(&g, 1, &k1, &k2);
    let s1 = apply(validate(Some(&g), &rot1, &[sig_for(0, &k1)], &[]).unwrap());
    let rot2 = rotation_after(&s1, 2, &k2, &k3);
    let s2 = apply(validate(Some(&s1), &rot2, &[sig_for(0, &k2)], &[]).unwrap());
    assert_eq!(s2.sn().value(), 2);
    assert_eq!(s2.keys()[0].raw(), k2.raw());
    assert_eq!(s2.next_keys()[0].raw(), commit(&k3).raw());
}

/// Rotate out witness `w1` and in witness `w2`: the resolved set is exactly
/// `[w2]`, and it carries into the applied state.
#[test]
fn rotation_swaps_a_witness() {
    let (k0, k1, k2, w1, w2) = (verfer(1), verfer(2), verfer(3), verfer(10), verfer(11));
    let icp = inception_with_witnesses(&k0, &k1, vec![w1.clone()], 1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    assert_eq!(g.witnesses().len(), 1);
    assert_eq!(g.witnesses()[0].raw(), w1.raw());

    let rot = rotation_with_witnesses(&g, 1, &k1, &k2, vec![w1.clone()], vec![w2.clone()], 1);
    let s1 = apply(validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap());
    assert_eq!(s1.witnesses().len(), 1);
    assert_eq!(s1.witnesses()[0].raw(), w2.raw());
    assert_eq!(s1.witness_threshold(), 1);
}

/// Removing a prefix that is not a current witness is rejected.
#[test]
fn rotation_removing_non_witness_is_rejected() {
    let (k0, k1, k2, w1, w2) = (verfer(1), verfer(2), verfer(3), verfer(10), verfer(11));
    let icp = inception_with_witnesses(&k0, &k1, vec![w1.clone()], 1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    // w2 was never a witness, so it cannot be cut.
    let rot = rotation_with_witnesses(&g, 1, &k1, &k2, vec![w2.clone()], vec![], 0);
    let err = validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}

/// A prefix appearing in both cuts and adds (a no-op "keep") is rejected:
/// keripy requires cuts and adds to be disjoint.
#[test]
fn rotation_with_overlapping_cut_and_add_is_rejected() {
    let (k0, k1, k2, w1) = (verfer(1), verfer(2), verfer(3), verfer(10));
    let icp = inception_with_witnesses(&k0, &k1, vec![w1.clone()], 1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let rot = rotation_with_witnesses(&g, 1, &k1, &k2, vec![w1.clone()], vec![w1.clone()], 1);
    let err = validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}

/// Adding a witness that is already present (after removals) is rejected.
#[test]
fn rotation_adding_existing_witness_is_rejected() {
    let (k0, k1, k2, w1) = (verfer(1), verfer(2), verfer(3), verfer(10));
    let icp = inception_with_witnesses(&k0, &k1, vec![w1.clone()], 1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    // No removals, so w1 stays; adding it again is a duplicate.
    let rot = rotation_with_witnesses(&g, 1, &k1, &k2, vec![], vec![w1.clone()], 1);
    let err = validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}

/// A TOAD exceeding the resolved witness count is rejected.
#[test]
fn rotation_with_toad_above_witness_count_is_rejected() {
    let (k0, k1, k2, w1) = (verfer(1), verfer(2), verfer(3), verfer(10));
    let icp = inception_with_witnesses(&k0, &k1, vec![w1.clone()], 1);
    let g = apply(validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    // Resolved set is [w1] (count 1), but the new TOAD demands 5.
    let rot = rotation_with_witnesses(&g, 1, &k1, &k2, vec![], vec![], 5);
    let err = validate(Some(&g), &rot, &[sig_for(0, &k1)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}
