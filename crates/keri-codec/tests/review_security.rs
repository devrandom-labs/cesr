//! Public regressions from the independent PR 300 security review.

mod common;

use std::error::Error;

use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::Number;
use cesr_stream::error::{LimitKind, ParseError};
use keri::{
    CredentialEvidence, CredentialState, CredentialVerificationError, CredentialVerificationLimits,
    CredentialVerifier, RegistryState, SignedTel, TelAnchorCoordinate, TelEvidence,
};
use keri_codec::{
    Deserialize, EventMessageError, JsonLimits, SadCodes, SchemaError, VerifiedSchema,
};
use keri_events::{Identifier, KeriEvent, Seal, TelEvent};

use common::{Event, Key, interaction_anchoring, seed};

type Fallible<T> = Result<T, Box<dyn Error>>;
const CORPUS: &str = include_str!("review_numeric.jsonl");
const LIMITS: JsonLimits = JsonLimits::new(4096, 64);

fn event(raw: &str) -> Fallible<Event> {
    let parsed = KeriEvent::deserialize(raw.as_bytes(), LIMITS)?.into_static();
    Ok(Event {
        said: parsed.said().clone().into_static(),
        prefix: parsed.prefix().clone().into_static(),
        parsed,
        bytes: raw.as_bytes().to_vec(),
    })
}

fn anchor(prior: &Event, sn: u128, tel: &TelEvent<'_>) -> Fallible<Event> {
    let target = match tel {
        TelEvent::RegistryInception(vcp) => vcp.said(),
        TelEvent::Issue(issue) => issue.credential_said(),
        _ => return Err("unexpected oracle TEL type".into()),
    };
    interaction_anchoring(
        prior,
        sn,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(target.clone().into_static()),
            s: tel.sn(),
            d: tel.said().clone().into_static(),
        }],
    )
}

fn tel_input<'a>(event: &'a TelEvent<'a>, bytes: &'a [u8], anchor: &'a Event) -> SignedTel<'a> {
    SignedTel::from_host_asserted_parts(event, bytes, vec![])
        .with_source(TelAnchorCoordinate::new(
            Number::new(anchor.parsed.sn().value()),
            anchor.said.clone(),
        ))
        .with_host_accepted_anchor(&anchor.parsed)
}

#[test]
fn review_large_integer_schema_constraints() -> Fallible<()> {
    for line in CORPUS.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let schema =
            VerifiedSchema::from_bytes(row["schema"].as_str().unwrap().as_bytes(), LIMITS)?;
        let raw = row["credential"].as_str().unwrap();
        let key = Key::from_seed_bytes(&[0x34; 32])?;
        let icp = event(row["issuer_icp"].as_str().unwrap())?;
        let mut issuer = seed(&icp, &key)?;
        let vcp_raw = row["registry_vcp"].as_str().unwrap();
        let vcp = TelEvent::deserialize(vcp_raw.as_bytes(), LIMITS)?;
        let vcp_anchor = anchor(&icp, 1, &vcp)?;
        issuer.ingest_mut(&vcp_anchor.signed(vec![key.sign(&vcp_anchor.bytes, 0)?]))?;
        let registry =
            RegistryState::incept(&tel_input(&vcp, vcp_raw.as_bytes(), &vcp_anchor), &issuer)?;
        let iss_raw = row["issue_iss"].as_str().unwrap();
        let iss = TelEvent::deserialize(iss_raw.as_bytes(), LIMITS)?;
        let iss_anchor = anchor(&vcp_anchor, 2, &iss)?;
        issuer.ingest_mut(&iss_anchor.signed(vec![key.sign(&iss_anchor.bytes, 0)?]))?;
        let tel = CredentialState::incept(
            &registry,
            &tel_input(&iss, iss_raw.as_bytes(), &iss_anchor),
            &TelEvidence::Issuer {
                state: &issuer,
                anchor: None,
            },
        )?;
        let evidence = CredentialEvidence::from_host_accepted(
            raw.as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&tel),
            Some(&issuer),
        );
        let result = CredentialVerifier::verify(
            &evidence,
            &[],
            CredentialVerificationLimits {
                json: LIMITS,
                max_document_bytes: 4096,
                max_nodes: 8,
                max_chain_depth: 4,
            },
        );
        assert!(
            matches!(
                result,
                Err(CredentialVerificationError::Schema(
                    SchemaError::InvalidCredential(_)
                ))
            ),
            "{} must violate its exact numeric schema constraint: {result:?}",
            row["case"]
        );
        let mut matching = raw
            .replace("18446744073709551617", "18446744073709551616")
            .into_bytes();
        let attributes_start = matching
            .windows(5)
            .position(|bytes| bytes == b"\"a\":{")
            .ok_or("missing attribute block")?
            + 4;
        let attributes_end = matching.len() - 1;
        let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
        let mut attributes = matching[attributes_start..attributes_end].to_vec();
        codes.saidify(&mut attributes)?;
        matching[attributes_start..attributes_end].copy_from_slice(&attributes);
        codes.saidify(&mut matching)?;
        schema.validate_credential(&matching, LIMITS)?;
    }
    Ok(())
}

#[test]
fn review_negative_and_decimal_schema_constraints() -> Fallible<()> {
    for line in CORPUS.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let original_schema = row["schema"].as_str().ok_or("missing schema")?;
        let original_credential = row["credential"].as_str().ok_or("missing credential")?;
        let original_schema_value: serde_json::Value = serde_json::from_str(original_schema)?;
        let original_schema_said = original_schema_value["$id"]
            .as_str()
            .ok_or("missing schema SAID")?;
        let negative = if row["case"] == "integer_maximum" {
            ("-1844674407370955162", "-1844674407370955161")
        } else {
            ("-1844674407370955161", "-1844674407370955162")
        };
        for (schema_number, credential_number) in
            [negative, ("1.844674407370955e19", "1.844674407370956e19")]
        {
            let mut schema = original_schema
                .replace("18446744073709551616", schema_number)
                .into_bytes();
            let schema_codes = SadCodes::from_pairs(&[("$id", DigestCode::Blake3_256)])?;
            schema_codes.saidify(&mut schema)?;
            let schema_value: serde_json::Value = serde_json::from_slice(&schema)?;
            let schema_said = schema_value["$id"]
                .as_str()
                .ok_or("missing new schema SAID")?;
            let verified = VerifiedSchema::from_bytes(&schema, LIMITS)?;

            let mut credential = original_credential
                .replace("18446744073709551617", credential_number)
                .replace(original_schema_said, schema_said)
                .into_bytes();
            let attributes_start = credential
                .windows(5)
                .position(|bytes| bytes == b"\"a\":{")
                .ok_or("missing attribute block")?
                + 4;
            let attributes_end = credential.len() - 1;
            let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
            let mut attributes = credential[attributes_start..attributes_end].to_vec();
            codes.saidify(&mut attributes)?;
            credential[attributes_start..attributes_end].copy_from_slice(&attributes);
            codes.saidify(&mut credential)?;
            assert!(matches!(
                verified.validate_credential(&credential, LIMITS),
                Err(SchemaError::InvalidCredential(_))
            ));
            let mut matching = String::from_utf8(credential)?
                .replace(credential_number, schema_number)
                .into_bytes();
            let mut matching_attributes = matching[attributes_start..attributes_end].to_vec();
            codes.saidify(&mut matching_attributes)?;
            matching[attributes_start..attributes_end].copy_from_slice(&matching_attributes);
            codes.saidify(&mut matching)?;
            verified.validate_credential(&matching, LIMITS)?;
        }
    }
    Ok(())
}

#[test]
fn review_pathed_signature_budget() -> Fallible<()> {
    let row: serde_json::Value = include_str!("corpus/ipex/flow.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["case"] == "offer")
        .unwrap();
    let wire = row["wire"].as_str().unwrap();
    let mut limits = common::message_limits();
    limits.frame.max_signatures = 1;
    let result = keri_codec::ExnMessage::parse(wire.as_bytes(), limits);
    assert!(matches!(
        result,
        Err(EventMessageError::Frame(ParseError::LimitExceeded {
            kind: LimitKind::Signatures,
            limit: 1,
            actual: 2,
        }))
    ));
    limits.frame.max_signatures = 2;
    let (parsed, rest) = keri_codec::ExnMessage::parse(wire.as_bytes(), limits)?;
    assert!(rest.is_empty());
    assert_eq!(parsed.sigs().len(), 1);
    assert_eq!(parsed.pathed()[0].controller_signatures()?.len(), 1);
    Ok(())
}

#[test]
fn review_core_rejects_zero_next_threshold() -> Fallible<()> {
    use keri::{KeyState, Rejection, Signed};
    use keri_codec::Serialize;
    use keri_events::{
        InceptionEvent, SigningThreshold, SigningThresholdError, ThresholdForm, Toad,
    };
    let controller = Key::from_seed_bytes(&[0x71; 32])?;
    let committed = Key::from_seed_bytes(&[0x72; 32])?;
    let template = common::genesis(&controller, &committed)?;
    let build = |said: keri_events::Said<'static>| {
        InceptionEvent::new_unchecked(
            Identifier::SelfAddressing(said.clone()),
            Number::new(0),
            said,
            vec![controller.verfer.clone()],
            SigningThreshold::Simple(1),
            vec![common::commit(&committed.verfer).unwrap()],
            SigningThreshold::Simple(0),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        )
    };
    let wire = build(template.said).serialize()?;
    let body = KeriEvent::Inception(build(wire.said().clone().into_static()));
    // The host assertion is true: every supplied typed field matches these exact bytes.
    assert_eq!(body.serialize()?.as_bytes(), wire.as_bytes());
    SadCodes::from_pairs(&[("d", DigestCode::Blake3_256), ("i", DigestCode::Blake3_256)])?
        .verify(wire.as_bytes())?;
    assert!(KeriEvent::deserialize(wire.as_bytes(), LIMITS).is_err());
    let signed = Signed::from_host_asserted_parts(
        &body,
        wire.as_bytes(),
        vec![controller.sign(wire.as_bytes(), 0)?],
        vec![],
    );
    assert!(matches!(
        KeyState::incept(&signed),
        Err(Rejection::MalformedThreshold(
            SigningThresholdError::BelowMinimum
        ))
    ));
    Ok(())
}

#[test]
fn review_core_rejects_invalid_next_threshold_on_rotation_without_advancing() -> Fallible<()> {
    use keri::{Rejection, Signed};
    use keri_codec::Serialize;
    use keri_events::{RotationEvent, SigningThreshold, SigningThresholdError};

    let controller = Key::from_seed_bytes(&[0x75; 32])?;
    let reveal = Key::from_seed_bytes(&[0x76; 32])?;
    let future = Key::from_seed_bytes(&[0x77; 32])?;
    let icp = common::genesis(&controller, &reveal)?;
    let mut state = seed(&icp, &controller)?;
    let valid = common::plain_rotation(&icp, 1, &reveal, &future)?;
    let KeriEvent::Rotation(rot) = &valid.parsed else {
        return Err("expected rotation".into());
    };
    let raw = String::from_utf8(valid.bytes)?.replace("\"nt\":\"1\"", "\"nt\":\"0\"");
    let (bytes, said) = common::reseal_spans(raw.into_bytes(), &[b"\"d\":\""])?;
    SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?.verify(&bytes)?;
    let body = KeriEvent::Rotation(RotationEvent::new_unchecked(
        rot.prefix().clone().into_static(),
        rot.sn(),
        said,
        rot.prior_event_said().clone().into_static(),
        rot.keys().to_vec(),
        rot.threshold().clone(),
        rot.next_keys().to_vec(),
        SigningThreshold::Simple(0),
        rot.witness_additions().to_vec(),
        rot.witness_removals().to_vec(),
        rot.witness_threshold(),
        rot.anchors().to_vec(),
        rot.threshold_form(),
    ));
    assert_eq!(body.serialize()?.as_bytes(), bytes);
    let signed =
        Signed::from_host_asserted_parts(&body, &bytes, vec![reveal.sign(&bytes, 0)?], vec![]);
    assert!(matches!(
        state.ingest_mut(&signed),
        Err(Rejection::MalformedThreshold(
            SigningThresholdError::BelowMinimum
        ))
    ));
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.keys(), &[controller.verfer]);
    Ok(())
}

#[test]
fn review_multiple_pathed_groups_share_signature_budget() -> Fallible<()> {
    let row: serde_json::Value = include_str!("corpus/ipex/flow.jsonl")
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .filter_map(Result::ok)
        .find(|row| row["case"] == "offer")
        .ok_or("missing offer")?;
    let original = row["wire"].as_str().ok_or("missing wire")?;
    let body = row["raw"].as_str().ok_or("missing body")?;
    let outer = &original[body.len()..body.len() + 92];
    let path = &original[body.len() + 92..];
    let doubled = format!("{body}{outer}{path}{path}");
    let mut limits = common::message_limits();
    limits.frame.max_signatures = 2;
    assert!(matches!(
        keri_codec::ExnMessage::parse(doubled.as_bytes(), limits),
        Err(EventMessageError::Frame(ParseError::LimitExceeded {
            kind: LimitKind::Signatures,
            limit: 2,
            actual: 3,
        }))
    ));
    limits.frame.max_signatures = 3;
    let (parsed, rest) = keri_codec::ExnMessage::parse(doubled.as_bytes(), limits)?;
    assert!(rest.is_empty());
    assert_eq!(parsed.sigs().len(), 1);
    assert_eq!(parsed.pathed().len(), 2);
    Ok(())
}

#[test]
fn review_wrapped_pathed_signatures_share_signature_budget() -> Fallible<()> {
    use cesr::core::counter::CounterCodeV1;
    use cesr_stream::encode::EncodeCount;

    let row: serde_json::Value = include_str!("corpus/ipex/flow.jsonl")
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .filter_map(Result::ok)
        .find(|row| row["case"] == "offer")
        .ok_or("missing offer")?;
    let original = row["wire"].as_str().ok_or("missing wire")?;
    let body = row["raw"].as_str().ok_or("missing body")?;
    let outer = &original[body.len()..body.len() + 92];
    let (parsed, _) = keri_codec::ExnMessage::parse(original.as_bytes(), common::message_limits())?;
    let path = parsed.pathed()[0].path_qb64();
    let signature_group = &original[original.len() - 92..];
    let wrapped = String::from_utf8(
        CounterCodeV1::AttachmentGroup.encode_count(u32::try_from(signature_group.len() / 4)?)?,
    )?;
    let material = format!("{path}{wrapped}{signature_group}");
    let path_counter = String::from_utf8(
        CounterCodeV1::PathedMaterialCouples.encode_count(u32::try_from(material.len() / 4)?)?,
    )?;
    let wire = format!("{body}{outer}{path_counter}{material}");
    let mut limits = common::message_limits();
    limits.frame.max_signatures = 1;
    assert!(matches!(
        keri_codec::ExnMessage::parse(wire.as_bytes(), limits),
        Err(EventMessageError::Frame(ParseError::LimitExceeded {
            kind: LimitKind::Signatures,
            limit: 1,
            actual: 2,
        }))
    ));
    limits.frame.max_signatures = 2;
    let (accepted, rest) = keri_codec::ExnMessage::parse(wire.as_bytes(), limits)?;
    assert!(rest.is_empty());
    assert_eq!(accepted.pathed().len(), 1);
    Ok(())
}

#[test]
fn review_pathed_group_element_budget() -> Fallible<()> {
    let row: serde_json::Value = include_str!("corpus/ipex/flow.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["case"] == "offer")
        .unwrap();
    let original = row["wire"].as_str().unwrap();
    let (parsed, _) = keri_codec::ExnMessage::parse(original.as_bytes(), common::message_limits())?;
    let sig = parsed.pathed()[0].controller_signatures()?[0].to_qb64();
    // 64 material signatures: -ABA; path is 12 bytes, counter 4, sigs 64*88.
    // Material length 5648 bytes = 1412 quadlets = base64 WE; path counter -LWE.
    let body = row["raw"].as_str().unwrap();
    let outer = &original[body.len()..body.len() + 92];
    let wire = format!("{body}{outer}-LWE4AACA-e-acdc-ABA{}", sig.repeat(64));
    let mut limits = common::message_limits();
    limits.frame.max_signatures = 1;
    limits.frame.max_group_elements = 1;
    let result = keri_codec::ExnMessage::parse(wire.as_bytes(), limits);
    assert!(matches!(
        result,
        Err(EventMessageError::Frame(ParseError::LimitExceeded {
            kind: LimitKind::GroupElements,
            limit: 1,
            actual: 64,
        }))
    ));
    Ok(())
}
