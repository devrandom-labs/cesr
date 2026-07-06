//! Inception fold tests: validation rules and genesis-state construction.
mod common;

use cesr::core::primitives::Tholder;
use cesr::keri::Ilk;
use common::{inception, inception_with_threshold, sig_for, verfer};
use keri::{RejectionReason, apply, validate};

#[test]
fn valid_inception_is_accepted() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let sigs = vec![sig_for(0, &k0)];
    assert!(
        validate(None, &icp, &sigs, &[]).is_ok(),
        "a threshold-satisfying, well-formed inception must be accepted"
    );
}

#[test]
fn inception_without_signatures_is_rejected_missing_signatures() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let err = validate(None, &icp, &[], &[])
        .expect_err("an inception with no signatures cannot satisfy its threshold");
    assert_eq!(err.reason, RejectionReason::MissingSignatures);
}

#[test]
fn inception_with_empty_weighted_threshold_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception_with_threshold(&k0, &k1, Tholder::Weighted(vec![]));
    let err = validate(None, &icp, &[], &[])
        .expect_err("an empty weighted threshold (\"kt\":[]) is malformed and cannot be satisfied");
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}

#[test]
fn inception_with_wellformed_weighted_threshold_validates_when_signed() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception_with_threshold(&k0, &k1, Tholder::Weighted(vec![vec![(1, 1)]]));
    let sigs = vec![sig_for(0, &k0)];
    assert!(
        validate(None, &icp, &sigs, &[]).is_ok(),
        "a well-formed weighted threshold satisfied by its signature must be accepted"
    );
}

#[test]
fn inception_apply_builds_genesis_state() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let sigs = vec![sig_for(0, &k0)];
    let accepted = validate(None, &icp, &sigs, &[]).expect("valid inception");

    let state = apply(&accepted);

    assert_eq!(state.sn().value(), 0, "genesis sequence number is 0");
    assert_eq!(state.latest_ilk(), Ilk::Icp, "latest ilk is inception");
    assert_eq!(state.keys().len(), 1, "one current signing key");
    assert_eq!(
        state.keys()[0].raw(),
        k0.raw(),
        "current key is the inception's key k0"
    );
    assert_eq!(state.next_keys().len(), 1, "one committed next-key digest");
    assert!(
        state.transferable(),
        "an inception with next keys is transferable"
    );
    assert_eq!(
        state.last_establishment().sn.value(),
        0,
        "last establishment points at the inception"
    );
}
