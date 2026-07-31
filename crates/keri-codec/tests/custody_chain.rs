//! End-to-end: a `SaltyCustodian` drives a real icp -> rot chain through the
//! validating fold — custody-derived keys, custody-produced signatures, all
//! signature checks inside `KeyState`.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "integration test binary — unwrap documents the failing invariant"
)]
mod common;

use cesr::crypto::salt::{Salt, Tier};
use common::Event;
use keri_codec::{InceptionBuilder, RotationBuilder};
use keri::{Custodian, KeySpec, KeyState, PathConvention, SaltyCustodian};

#[test]
fn salty_custodian_drives_icp_rot_chain() {
    let salt = Salt::from_raw(b"0123456789abcdef").unwrap();
    let mut custodian = SaltyCustodian::new(salt, Tier::Low, PathConvention::Keripy);

    let spec = KeySpec {
        count: 1,
        ncount: 1,
        transferable: true,
    };
    let icp_keys = custodian.incept(spec).unwrap();

    let icp_ser = InceptionBuilder::new()
        .keys(icp_keys.verkeys.clone())
        .next_keys(icp_keys.next_digests.clone())
        .build()
        .unwrap();
    let prefix = icp_ser.identifier().unwrap();
    let icp = Event::build(
        icp_ser.as_bytes().to_vec(),
        icp_ser.said().clone().into_static(),
        prefix.clone(),
    )
    .unwrap();

    let state = KeyState::incept(&icp.signed(custodian.sign(&icp.bytes, None).unwrap())).unwrap();
    assert_eq!(state.keys()[0].raw(), icp_keys.verkeys[0].raw());

    let rot_keys = custodian.rotate(spec).unwrap();
    let rot_ser = RotationBuilder::new()
        .prefix(prefix)
        .prior_event_said(icp.said.clone())
        .keys(rot_keys.verkeys.clone())
        .prior_witnesses(vec![])
        .sn(1)
        .next_keys(rot_keys.next_digests.clone())
        .build()
        .unwrap();
    let rot = Event::build(
        rot_ser.as_bytes().to_vec(),
        rot_ser.said().clone().into_static(),
        icp.prefix.clone(),
    )
    .unwrap();

    let rotated = state
        .ingest(&rot.signed(custodian.sign(&rot.bytes, None).unwrap()))
        .unwrap();
    assert_eq!(rotated.sn().value(), 1);
    assert_eq!(rotated.keys()[0].raw(), rot_keys.verkeys[0].raw());
    assert_eq!(
        rotated.next_keys()[0].raw(),
        rot_keys.next_digests[0].raw()
    );
}
