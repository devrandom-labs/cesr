//! Multi-event KEL chain driven end-to-end through the public `fold()`.
//!
//! Each event's `prior_event_said` depends on the previous event's SAID, so the
//! chain is built in order against the running state (validate + apply, exactly
//! as the per-ilk tests do) to learn each SAID. The same owned events are then
//! fed to the public `fold()` and the final state is asserted.
mod common;

use cesr::keri::Ilk;
use common::{inception, interaction_after, rotation_after, sig_for, verfer};
use keri::{SignedEvent, apply, fold, validate};

#[test]
fn folds_a_four_event_kel() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));

    // Build in order, learning each prior state.
    let icp = inception(&k0, &k1);
    let g = apply(&validate(None, &icp, &[sig_for(0, &k0)], &[]).unwrap());
    let ixn1 = interaction_after(&g, 1);
    let s1 = apply(&validate(Some(&g), &ixn1, &[sig_for(0, &k0)], &[]).unwrap());
    let rot = rotation_after(&s1, 2, &k1, &k2);
    let s2 = apply(&validate(Some(&s1), &rot, &[sig_for(0, &k1)], &[]).unwrap());
    let ixn2 = interaction_after(&s2, 3);
    let _s3 = apply(&validate(Some(&s2), &ixn2, &[sig_for(0, &k1)], &[]).unwrap());

    // Drive the SAME events through the public fold() and assert the final state.
    let events = vec![
        SignedEvent {
            event: &icp,
            sigs: vec![sig_for(0, &k0)],
            wigs: vec![],
        },
        SignedEvent {
            event: &ixn1,
            sigs: vec![sig_for(0, &k0)],
            wigs: vec![],
        },
        SignedEvent {
            event: &rot,
            sigs: vec![sig_for(0, &k1)],
            wigs: vec![],
        },
        SignedEvent {
            event: &ixn2,
            sigs: vec![sig_for(0, &k1)],
            wigs: vec![],
        },
    ];
    let final_state = fold(None, events).unwrap();

    assert_eq!(final_state.sn().value(), 3);
    assert_eq!(final_state.latest_ilk(), Ilk::Ixn);
    // Rotated to k1 at sn 2, unchanged by the trailing interaction.
    assert_eq!(final_state.keys()[0].raw(), k1.raw());
    // Last establishment is the rotation at sn 2, not the trailing ixn.
    assert_eq!(final_state.last_establishment().sn.value(), 2);
    // The rotation committed k2 as the next pre-rotation.
    assert_eq!(final_state.next_keys()[0].raw(), common::commit(&k2).raw());
}
