//! Round-trip parity test for self-addressing KEL chains (#68).
//!
//! Builds a real `icp -> ixn -> rot` chain where every event's identifier
//! prefix (`i`) equals the inception SAID, serializes + deserializes each
//! event, and asserts the chain is internally consistent.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "integration test binary — entirely test code, same convention as \
              #[cfg(test)] mod tests in src/, which use unwrap() to document the \
              invariant that fails"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::keri::Identifier;
use cesr::keri::{DelegatedInceptionEvent, InceptionEvent, InteractionEvent, RotationEvent};
use keri_codec::DelegatedInceptionBuilder;
use keri_codec::KeriDeserialize;
use keri_codec::{InceptionBuilder, InteractionBuilder, RotationBuilder};

fn verfer(byte: u8) -> cesr::core::primitives::Verfer<'static> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(vec![byte; 32])
        .unwrap()
        .build()
        .unwrap()
}

fn diger(byte: u8) -> cesr::core::primitives::Diger<'static> {
    MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(vec![byte; 32])
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn icp_ixn_rot_chain_shares_self_addressing_prefix() {
    let icp = InceptionBuilder::new()
        .keys(vec![verfer(1)])
        .build()
        .unwrap();
    let id = icp
        .identifier()
        .expect("inception exposes a self-addressing identifier");
    assert!(matches!(id, Identifier::SelfAddressing(_)));

    let icp_parsed = InceptionEvent::deserialize(icp.as_bytes()).unwrap();
    assert!(
        *icp_parsed.prefix() == id,
        "icp i decodes to the inception SAID"
    );

    let ixn = InteractionBuilder::new()
        .prefix(id.clone())
        .prior_event_said(icp.said().clone())
        .sn(1)
        .build()
        .unwrap();
    let ixn_parsed = InteractionEvent::deserialize(ixn.as_bytes()).unwrap();
    assert!(
        *ixn_parsed.prefix() == id,
        "ixn i equals the inception identifier"
    );
    assert_eq!(
        ixn_parsed.prior_event_said().raw(),
        icp.said().raw(),
        "ixn prior = inception SAID"
    );

    let rot = RotationBuilder::new()
        .prefix(id.clone())
        .prior_event_said(ixn.said().clone())
        .keys(vec![verfer(2)])
        .prior_witnesses(vec![])
        .sn(2)
        .next_keys(vec![diger(3)])
        .build()
        .unwrap();
    let rot_parsed = RotationEvent::deserialize(rot.as_bytes()).unwrap();
    assert!(
        *rot_parsed.prefix() == id,
        "rot i equals the inception identifier"
    );
    assert_eq!(
        rot_parsed.prior_event_said().raw(),
        ixn.said().raw(),
        "rot prior = interaction SAID"
    );
}

#[test]
fn delegated_inception_self_addressing_delegator_round_trips() {
    let delegator = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(vec![9u8; 32])
        .unwrap()
        .build()
        .unwrap();
    let delegator_id = Identifier::SelfAddressing(delegator);

    let dip = DelegatedInceptionBuilder::new()
        .keys(vec![verfer(1)])
        .delegator(delegator_id.clone())
        .build()
        .unwrap();

    let parsed = DelegatedInceptionEvent::deserialize(dip.as_bytes()).unwrap();
    assert!(
        *parsed.delegator() == delegator_id,
        "di decodes to the self-addressing delegator"
    );
}
