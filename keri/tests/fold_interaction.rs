//! Interaction fold tests: sequential advance, ordering, and estOnly rules.
mod common;

use common::{inception, inception_with_config, interaction_after, sig_for, verfer};
use keri::{RejectionReason, apply, validate};

#[test]
fn valid_interaction_advances_sn_only() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let ixn = interaction_after(&g, 1);
    let accepted = validate(Some(&g), &ixn, &[sig_for(0, &k0)], &[]).unwrap();
    let s1 = apply(&accepted);
    assert_eq!(s1.sn().value(), 1);
    assert_eq!(s1.latest_ilk(), cesr::keri::Ilk::Ixn);
    assert_eq!(s1.keys()[0].raw(), g.keys()[0].raw()); // keys unchanged
    assert_eq!(s1.last_establishment().sn.value(), 0); // lastEst still the inception
}

#[test]
fn out_of_order_interaction_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let ixn = interaction_after(&g, 3); // gap
    let err = validate(Some(&g), &ixn, &[sig_for(0, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::OutOfOrder);
}

#[test]
fn interaction_under_est_only_is_rejected() {
    use cesr::keri::ConfigTrait;
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception_with_config(&k0, &k1, vec![ConfigTrait::EstOnly]);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let ixn = interaction_after(&g, 1);
    let err = validate(Some(&g), &ixn, &[sig_for(0, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::InvalidEvent);
}
