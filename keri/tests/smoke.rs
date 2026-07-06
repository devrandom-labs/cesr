//! Smoke test proving the serder-based fixture path builds a real inception.
mod common;

use common::{inception, verfer};

#[test]
fn fixtures_build_a_real_inception() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    assert!(matches!(icp, cesr::keri::KeriEvent::Inception(_)));
}
