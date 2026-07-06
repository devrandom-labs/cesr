//! Inception fold tests: validation rules and genesis-state construction.
mod common;

use common::{inception, sig_for, verfer};
use keri::{RejectionReason, validate};

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
