//! A01: inception and delegation prefixes bind to the controlling authority.

mod common;

use cesr::core::primitives::Number;
use common::{Fallible, Key};
use keri::{DelegationEvidence, KeyState, Rejection, Signed, StructuralError};
use keri_codec::{
    BuilderError, CodecError, DelegatedRotationBuilder, Deserialize, DeserializeError,
    EventMessage, EventMessageError, Serialize,
};
use keri_events::{
    DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, InceptionEvent,
    InceptionIdentityError, KeriEvent, RotationEvent, Seal, SigningThreshold, ThresholdForm, Toad,
    VerifyingKey, WeightedThreshold,
};

#[test]
fn unrelated_basic_prefix_is_rejected_by_typed_decode_and_signed_fold() -> Fallible<()> {
    let victim = Key::new()?;
    let attacker = Key::new()?;
    let next = Key::new()?;
    let template = common::genesis(&attacker, &next)?;
    let victim_prefix = common::nontransferable_prefix_of(&victim)?;
    let event = InceptionEvent::new_unchecked(
        Identifier::Basic(victim_prefix),
        Number::new(0),
        template.said,
        vec![attacker.verfer.clone()],
        SigningThreshold::Simple(1),
        vec![],
        SigningThreshold::Simple(0),
        vec![],
        Toad::exact(0, 0)?,
        vec![],
        vec![],
        ThresholdForm::HexString,
    );
    let serialized = event.serialize()?;
    let signature = attacker.sign(serialized.as_bytes(), 0)?;
    let mut wire = serialized.as_bytes().to_vec();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(signature.to_qb64().as_bytes());

    assert!(matches!(
        InceptionEvent::deserialize(serialized.as_bytes(), keri_codec::JsonLimits::new(4096, 64)),
        Err(CodecError::Deserialize(
            DeserializeError::InceptionIdentity(InceptionIdentityError::BasicKeyMismatch)
        ))
    ));
    assert!(matches!(
        KeriEvent::deserialize(serialized.as_bytes(), keri_codec::JsonLimits::new(4096, 64)),
        Err(CodecError::Deserialize(
            DeserializeError::InceptionIdentity(InceptionIdentityError::BasicKeyMismatch)
        ))
    ));
    assert!(matches!(
        EventMessage::parse(&wire, common::message_limits()),
        Err(EventMessageError::Body(CodecError::Deserialize(
            DeserializeError::InceptionIdentity(InceptionIdentityError::BasicKeyMismatch)
        )))
    ));

    let parsed = KeriEvent::Inception(event);
    let signed =
        Signed::from_host_asserted_parts(&parsed, serialized.as_bytes(), vec![signature], vec![]);
    assert!(matches!(
        KeyState::incept(&signed),
        Err(Rejection::InceptionIdentity(
            InceptionIdentityError::BasicKeyMismatch
        ))
    ));
    Ok(())
}

#[test]
fn basic_inception_shape_rejects_cardinality_threshold_and_nontransferable_extras() -> Fallible<()>
{
    let key = Key::new()?;
    let next = Key::new()?;
    let witness = Key::witness()?;
    let said = common::genesis(&key, &next)?.said;
    let nontransferable = common::nontransferable_prefix_of(&key)?;
    let nontransferable_key = VerifyingKey::from_matter(nontransferable.as_matter().clone());
    let weighted_one =
        SigningThreshold::Weighted(WeightedThreshold::from_nested(vec![vec![(1, 1)]])?);
    let cases = vec![
        (
            Identifier::Basic(common::prefix_of(&key)),
            vec![key.verfer.clone(), Key::new()?.verfer],
            SigningThreshold::Simple(1),
            vec![],
            SigningThreshold::Simple(0),
            vec![],
            vec![],
            InceptionIdentityError::BasicKeyCount { actual: 2 },
        ),
        (
            Identifier::Basic(common::prefix_of(&key)),
            vec![key.verfer.clone()],
            weighted_one,
            vec![],
            SigningThreshold::Simple(0),
            vec![],
            vec![],
            InceptionIdentityError::BasicThreshold,
        ),
        (
            Identifier::Basic(nontransferable.clone()),
            vec![nontransferable_key.clone()],
            SigningThreshold::Simple(1),
            vec![common::commit(&next.verfer)?],
            SigningThreshold::Simple(1),
            vec![],
            vec![],
            InceptionIdentityError::NonTransferableNextKeys,
        ),
        (
            Identifier::Basic(nontransferable.clone()),
            vec![nontransferable_key.clone()],
            SigningThreshold::Simple(1),
            vec![],
            SigningThreshold::Simple(0),
            vec![common::prefix_of(&witness)],
            vec![],
            InceptionIdentityError::NonTransferableWitnesses,
        ),
        (
            Identifier::Basic(nontransferable),
            vec![nontransferable_key],
            SigningThreshold::Simple(1),
            vec![],
            SigningThreshold::Simple(0),
            vec![],
            vec![Seal::Digest { d: said.clone() }],
            InceptionIdentityError::NonTransferableAnchors,
        ),
    ];
    for (prefix, keys, threshold, next_keys, next_threshold, witnesses, anchors, expected) in cases
    {
        let toad = Toad::exact(u32::from(!witnesses.is_empty()), witnesses.len())?;
        let event = InceptionEvent::new_unchecked(
            prefix,
            Number::new(0),
            said.clone(),
            keys,
            threshold,
            next_keys,
            next_threshold,
            witnesses,
            toad,
            vec![],
            anchors,
            ThresholdForm::HexString,
        );
        assert_basic_decode_rejects(&event, &expected)?;
    }
    Ok(())
}

fn assert_basic_decode_rejects(
    event: &InceptionEvent<'_>,
    expected: &InceptionIdentityError,
) -> Fallible<()> {
    let bytes = event.serialize()?;
    let Err(CodecError::Deserialize(DeserializeError::InceptionIdentity(actual))) =
        InceptionEvent::deserialize(bytes.as_bytes(), keri_codec::JsonLimits::new(4096, 64))
    else {
        return Err("invalid basic inception decoded".into());
    };
    assert_eq!(&actual, expected);
    Ok(())
}

#[test]
fn valid_basic_and_self_addressing_inceptions_fold() -> Fallible<()> {
    let key = Key::new()?;
    let next = Key::new()?;
    let basic = common::basic_inception(&key)?;
    let basic_state = KeyState::incept(&basic.signed(vec![key.sign(&basic.bytes, 0)?]))?;
    assert_eq!(basic_state.prefix(), &basic.prefix);

    let self_addressing = common::genesis(&key, &next)?;
    let state =
        KeyState::incept(&self_addressing.signed(vec![key.sign(&self_addressing.bytes, 0)?]))?;
    assert_eq!(state.prefix(), &self_addressing.prefix);
    Ok(())
}

#[test]
fn delegated_basic_prefixes_fail_on_wire_and_direct_fold() -> Fallible<()> {
    let json = keri_codec::JsonLimits::new(4096, 64);
    let key = Key::new()?;
    let next = Key::new()?;
    let delegator = Key::new()?;
    let said = common::genesis(&key, &next)?.said;
    let basic = common::prefix_of(&key);
    let inception = InceptionEvent::new_unchecked(
        Identifier::Basic(basic.clone()),
        Number::new(0),
        said.clone(),
        vec![key.verfer.clone()],
        SigningThreshold::Simple(1),
        vec![common::commit(&next.verfer)?],
        SigningThreshold::Simple(1),
        vec![],
        Toad::exact(0, 0)?,
        vec![],
        vec![],
        ThresholdForm::HexString,
    );
    let dip =
        DelegatedInceptionEvent::new_unchecked(inception, common::prefix_of(&delegator).into());
    let dip_bytes = dip.serialize()?;
    assert!(matches!(
        DelegatedInceptionEvent::deserialize(dip_bytes.as_bytes(), json),
        Err(CodecError::Deserialize(
            DeserializeError::DelegatedPrefixNotDigestive
        ))
    ));
    let dip_event = KeriEvent::DelegatedInception(dip);
    let dip_signed = Signed::from_host_asserted_parts(
        &dip_event,
        dip_bytes.as_bytes(),
        vec![key.sign(dip_bytes.as_bytes(), 0)?],
        vec![],
    );
    assert!(matches!(
        KeyState::incept_delegated(&dip_signed, &DelegationEvidence::HostAccepted),
        Err(Rejection::Structural(
            StructuralError::DelegatedPrefixNotDigestive
        ))
    ));

    let rotation = RotationEvent::new_unchecked(
        Identifier::Basic(basic.clone()),
        Number::new(1),
        said.clone(),
        said.clone(),
        vec![next.verfer.clone()],
        SigningThreshold::Simple(1),
        vec![],
        SigningThreshold::Simple(0),
        vec![],
        vec![],
        Toad::from_wire(0),
        vec![],
        ThresholdForm::HexString,
    );
    let drt = DelegatedRotationEvent::new_unchecked(rotation);
    let drt_bytes = drt.serialize()?;
    assert!(matches!(
        DelegatedRotationEvent::deserialize(drt_bytes.as_bytes(), json),
        Err(CodecError::Deserialize(
            DeserializeError::DelegatedPrefixNotDigestive
        ))
    ));
    assert!(matches!(
        DelegatedRotationBuilder::new()
            .prefix(basic)
            .prior_event_said(said)
            .keys(vec![next.verfer.clone()])
            .prior_witnesses(vec![])
            .build(),
        Err(CodecError::Builder(
            BuilderError::DelegatedPrefixNotDigestive
        ))
    ));
    Ok(())
}
