//! Defensive boundary sweep: one test per `Rejection` path not covered by the
//! per-ilk fold tests, each asserting the EXACT `RejectionReason` and each able
//! to fail if the corresponding rule were removed.
//!
//! The empty-weighted-threshold path (`"kt":[]` → `InvalidEvent`) is already
//! covered by `fold_inception::inception_with_empty_weighted_threshold_is_rejected`
//! and is intentionally NOT duplicated here.
mod common;

use common::{inception, inception_with_witnesses, interaction_after, sig_for, verfer};
use keri::{RejectionReason, apply, validate};

/// A second inception applied on top of an existing state is a duplicate
/// inception. `validate(Some(state), Inception)` is the duplicate-inception
/// dispatch arm → `InvalidEvent`.
#[test]
fn duplicate_inception_is_rejected() {
    let (k0, k1, k2, k3) = (verfer(1), verfer(2), verfer(3), verfer(4));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());

    // A distinct, independently valid inception offered against an existing state.
    let icp2 = inception(&k2, &k3);
    let err = validate(Some(&g), &icp2, &[sig_for(0, &k2)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}

/// An interaction at the correct next sn but whose `prior_event_said` points at a
/// stale (earlier) SAID than the state's latest must be rejected as a prior-digest
/// mismatch. Built by chaining `icp → ixn@1 → s1`, then constructing a second
/// interaction at sn 2 whose prior is the GENESIS SAID (via `g`) rather than
/// `ixn1`'s SAID, and validating it against `s1`.
#[test]
fn interaction_with_stale_prior_digest_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let ixn1 = interaction_after(&g, 1);
    let s1 = apply(&validate(Some(&g), &ixn1, &[sig_for(0, &k0)], &[]).unwrap());

    // sn 2 is the correct next sn, but prior points at the stale genesis SAID.
    let ixn2_stale = interaction_after(&g, 2);
    let err = validate(Some(&s1), &ixn2_stale, &[sig_for(0, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::PriorDigestMismatch);
}

/// A well-formed interaction at the correct sn with the correct prior digest but
/// no signatures cannot satisfy its signing threshold → `MissingSignatures`.
#[test]
fn interaction_below_threshold_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let ixn = interaction_after(&g, 1);

    let err = validate(Some(&g), &ixn, &[], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::MissingSignatures);
}

/// An inception with a single key but a signature whose index (5) exceeds the key
/// list must be rejected as structurally invalid → `InvalidEvent`.
#[test]
fn signer_index_out_of_range_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);

    let err = validate(None, &icp, &[sig_for(5, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}

/// A witness threshold (TOAD) that exceeds the number of witnesses is structurally
/// invalid. The builder does not enforce `toad <= witness-count`; the fold's
/// `check_witnesses` does → `InvalidEvent`.
#[test]
fn witness_threshold_exceeding_witness_count_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    // One witness, TOAD of 5.
    let icp = inception_with_witnesses(&k0, &k1, vec![verfer(7)], 5);

    let err = validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}
