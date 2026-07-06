//! Delegated events (`dip`/`drt`) are rejected by the K1 fold.
//!
//! Folding a delegated inception or rotation requires verifying the delegator's
//! authorizing seal against the delegator's KEL — that is K4 (delegation) scope.
//! K1 has neither the delegator's KEL nor an escrow, so it fails closed and
//! rejects delegated events with [`RejectionReason::DelegationUnsupported`],
//! regardless of prior state. These tests would fail if the fold ever routed a
//! delegated event into the base-event path (accepting it unverified).
mod common;

use common::{commit, delegated_inception, delegated_rotation, inception, sig_for, verfer};
use keri::{RejectionReason, apply, validate};

/// A delegated inception offered with no prior state is rejected as
/// `DelegationUnsupported` (not accepted as a genesis event).
#[test]
fn delegated_inception_is_rejected_without_state() {
    let (k0, delegator) = (verfer(1), verfer(9));
    let dip = delegated_inception(&k0, &delegator);

    let err = validate(None, &dip, &[sig_for(0, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::DelegationUnsupported);
}

/// A delegated inception offered against an existing state is rejected as
/// `DelegationUnsupported` too — the delegated dispatch fires before the
/// duplicate-inception (`InvalidEvent`) arm.
#[test]
fn delegated_inception_is_rejected_with_state() {
    let (k0, k1, delegator) = (verfer(1), verfer(2), verfer(9));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());

    let dip = delegated_inception(&verfer(3), &delegator);
    let err = validate(Some(&g), &dip, &[sig_for(0, &verfer(3))], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::DelegationUnsupported);
}

/// A delegated rotation offered against an existing state is rejected as
/// `DelegationUnsupported`, before any rotation structural check runs.
#[test]
fn delegated_rotation_is_rejected_with_state() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());

    let drt = delegated_rotation(&k2, g.latest_said(), 1, &k1);
    let err = validate(Some(&g), &drt, &[sig_for(0, &k1)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::DelegationUnsupported);
}

/// A delegated rotation offered with no prior state is rejected as
/// `DelegationUnsupported`, not as out-of-order.
#[test]
fn delegated_rotation_is_rejected_without_state() {
    let (prefix, reveal) = (verfer(1), verfer(2));
    let prior_said = commit(&verfer(5));
    let drt = delegated_rotation(&prefix, &prior_said, 1, &reveal);

    let err = validate(None, &drt, &[sig_for(0, &reveal)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::DelegationUnsupported);
}
