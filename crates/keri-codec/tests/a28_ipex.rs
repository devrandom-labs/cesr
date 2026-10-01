//! Pinned genuine two-party IPEX flow with EXN signatures and pathed proof.

mod common;

use std::error::Error;

use cesr::core::primitives::Number;
use cesr_stream::FrameLimits;
use keri::{
    CredentialState, CredentialVerificationLimits, Disposition, EvidenceKind, IpexConversation,
    IpexDecisionError, IpexEvidence, IpexLimits, RegistryState, SignedTel, TelAnchorCoordinate,
    TelEvidence,
};
use keri_codec::{Deserialize, ExnMessage, IpexMessage, JsonLimits, MessageLimits, VerifiedSchema};
use keri_events::{KeriEvent, TelEvent};

use common::{Event, Key, seed};

type Fallible<T> = Result<T, Box<dyn Error>>;
const CORPUS: &str = include_str!("corpus/ipex/flow.jsonl");

fn event(raw: &str) -> Fallible<Event> {
    let parsed = KeriEvent::deserialize(raw.as_bytes(), limits().json)?.into_static();
    Ok(Event {
        said: parsed.said().clone().into_static(),
        prefix: parsed.prefix().clone().into_static(),
        parsed,
        bytes: raw.as_bytes().to_vec(),
    })
}

fn tel_input<'a>(event: &'a TelEvent<'a>, bytes: &'a [u8], anchor: &'a Event) -> SignedTel<'a> {
    SignedTel::from_host_asserted_parts(event, bytes, vec![])
        .with_source(TelAnchorCoordinate::new(
            Number::new(anchor.parsed.sn().value()),
            anchor.said.clone(),
        ))
        .with_host_accepted_anchor(&anchor.parsed)
}

const fn decision_limits() -> IpexLimits {
    IpexLimits {
        json: JsonLimits::new(4096, 64),
        credential: CredentialVerificationLimits {
            json: JsonLimits::new(4096, 64),
            max_document_bytes: 4096,
            max_nodes: 8,
            max_chain_depth: 4,
        },
    }
}

const fn limits() -> MessageLimits {
    MessageLimits::new(
        FrameLimits {
            max_body_bytes: 4096,
            max_attachment_bytes: 4096,
            max_attachment_groups: 8,
            max_group_elements: 8,
            max_signatures: 8,
            max_nested_groups: 8,
            max_nesting_depth: 2,
        },
        JsonLimits::new(4096, 64),
    )
}

#[test]
fn pinned_two_party_ipex_frames_keep_embedded_proof_paths() -> Fallible<()> {
    let mut cases = 0;
    for line in CORPUS.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let raw = row["raw"].as_str().ok_or("raw")?;
        let wire = row["wire"].as_str().ok_or("wire")?;
        let (message, rest) = ExnMessage::parse(wire.as_bytes(), limits())?;
        assert!(rest.is_empty());
        assert_eq!(message.body(), raw.as_bytes());
        assert_eq!(
            message.exn().said().ok_or("exn SAID")?.to_qb64(),
            row["said"]
        );
        assert_eq!(message.exn().route(), row["route"]);
        assert_eq!(message.sigs().len(), 1);
        if matches!(
            row["case"].as_str(),
            Some(
                "offer"
                    | "grant"
                    | "wrong_sender_offer"
                    | "cross_credential_grant"
                    | "wrong_recipient_grant"
                    | "wrong_anchor_grant"
                    | "cross_conversation_offer"
                    | "bad_proof_offer"
            )
        ) {
            assert_eq!(message.pathed().len(), 1);
            assert_eq!(message.pathed()[0].path_qb64(), "4AACA-e-acdc");
            assert!(message.pathed()[0].material().starts_with(b"-AAB"));
        } else {
            assert!(message.pathed().is_empty());
        }
        assert_eq!(
            IpexMessage::parse(message.exn(), limits().json)?
                .route()
                .route(),
            row["route"]
        );
        cases += 1;
    }
    assert_eq!(cases, 13);
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one public transcript folds the two KELs, TEL and every IPEX route"
)]
fn issuer_holder_conversation_binds_credential_and_grant() -> Fallible<()> {
    let rows: Vec<serde_json::Value> = CORPUS
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let first = &rows[0];
    let issuer_key = Key::from_seed_bytes(&[0x34; 32])?;
    let holder_key = Key::from_seed_bytes(&[0x35; 32])?;
    let issuer_icp = event(first["issuer_icp"].as_str().ok_or("issuer ICP")?)?;
    let holder_icp = event(first["holder_icp"].as_str().ok_or("holder ICP")?)?;
    let mut issuer_state = seed(&issuer_icp, &issuer_key)?;
    let holder_state = seed(&holder_icp, &holder_key)?;
    let registry_anchor = event(
        first["registry_anchor_ixn"]
            .as_str()
            .ok_or("registry anchor")?,
    )?;
    issuer_state
        .ingest_mut(&registry_anchor.signed(vec![issuer_key.sign(&registry_anchor.bytes, 0)?]))?;
    let vcp_raw = first["registry_vcp"].as_str().ok_or("VCP")?;
    let vcp = TelEvent::deserialize(vcp_raw.as_bytes(), limits().json)?.into_static();
    let registry = RegistryState::incept(
        &tel_input(&vcp, vcp_raw.as_bytes(), &registry_anchor),
        &issuer_state,
    )?;
    let issue_anchor = event(first["issue_anchor_ixn"].as_str().ok_or("issue anchor")?)?;
    issuer_state
        .ingest_mut(&issue_anchor.signed(vec![issuer_key.sign(&issue_anchor.bytes, 0)?]))?;
    let issue_raw = first["issue_iss"].as_str().ok_or("ISS")?;
    let issue = TelEvent::deserialize(issue_raw.as_bytes(), limits().json)?.into_static();
    let credential_state = CredentialState::incept(
        &registry,
        &tel_input(&issue, issue_raw.as_bytes(), &issue_anchor),
        &TelEvidence::Issuer {
            state: &issuer_state,
            anchor: None,
        },
    )?;
    let schema = VerifiedSchema::from_bytes(
        first["schema"].as_str().ok_or("schema")?.as_bytes(),
        limits().json,
    )?;
    let messages: Vec<ExnMessage<'_>> = rows
        .iter()
        .map(|row| {
            let wire = row["wire"].as_str().ok_or("wire")?;
            let (message, rest) = ExnMessage::parse(wire.as_bytes(), limits())?;
            if !rest.is_empty() {
                return Err("EXN remainder".into());
            }
            Ok(message)
        })
        .collect::<Fallible<_>>()?;

    let mut conversation =
        IpexConversation::begin(&messages[0], Some(&holder_state), limits().json)?;
    assert_eq!(conversation.route().route(), "/ipex/apply");
    assert_eq!(conversation.root().to_qb64(), rows[0]["said"]);
    let offer_evidence = IpexEvidence {
        sender_state: Some(&issuer_state),
        schema: Some(&schema),
        registry: None,
        credential_state: None,
        issuer_state: Some(&issuer_state),
        anchor_state: None,
        chain: &[],
    };
    let apply_head = conversation.clone();
    for (index, expected) in [
        (6, IpexDecisionError::WrongParticipant),
        (10, IpexDecisionError::WrongPrior),
        (11, IpexDecisionError::MissingPathedProof),
        (12, IpexDecisionError::InvalidPathedProof),
    ] {
        let wrong_sender = IpexEvidence {
            sender_state: Some(&holder_state),
            ..offer_evidence
        };
        let evidence = if index == 6 {
            &wrong_sender
        } else {
            &offer_evidence
        };
        let error = conversation
            .ingest_mut(&messages[index], evidence, decision_limits())
            .unwrap_err();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected),
            "{}",
            rows[index]["case"]
        );
        assert_eq!(conversation, apply_head);
    }
    let no_schema = IpexEvidence {
        schema: None,
        ..offer_evidence
    };
    let schema_error = conversation
        .ingest_mut(&messages[1], &no_schema, decision_limits())
        .unwrap_err();
    assert!(matches!(schema_error, IpexDecisionError::MissingSchema));
    assert_eq!(
        schema_error.disposition(),
        Disposition::Awaiting(EvidenceKind::CredentialSchema)
    );
    assert_eq!(conversation, apply_head);
    let substituted_path_wire =
        rows[1]["wire"]
            .as_str()
            .ok_or("offer wire")?
            .replacen("4AACA-e-acdc", "5AACAA-e-iss", 1);
    let (substituted_path, rest) = ExnMessage::parse(substituted_path_wire.as_bytes(), limits())?;
    assert!(rest.is_empty());
    assert!(matches!(
        conversation.ingest_mut(&substituted_path, &offer_evidence, decision_limits()),
        Err(IpexDecisionError::InvalidPathedProof)
    ));
    assert_eq!(conversation, apply_head);
    conversation.ingest_mut(&messages[1], &offer_evidence, decision_limits())?;
    assert_eq!(conversation.route().route(), "/ipex/offer");

    let mut spurned = conversation.clone();
    spurned.ingest_mut(
        &messages[5],
        &IpexEvidence::sender(&holder_state),
        decision_limits(),
    )?;
    assert!(spurned.is_terminal());
    assert!(matches!(
        spurned.ingest_mut(
            &messages[2],
            &IpexEvidence::sender(&holder_state),
            decision_limits()
        ),
        Err(IpexDecisionError::Closed)
    ));

    let snapshot = conversation.clone();
    assert!(matches!(
        conversation.ingest_mut(&messages[1], &offer_evidence, decision_limits()),
        Err(IpexDecisionError::Duplicate)
    ));
    assert_eq!(conversation, snapshot);
    assert!(matches!(
        conversation.ingest_mut(&messages[3], &offer_evidence, decision_limits()),
        Err(IpexDecisionError::WrongPrior)
    ));
    assert_eq!(conversation, snapshot);

    conversation.ingest_mut(
        &messages[2],
        &IpexEvidence::sender(&holder_state),
        decision_limits(),
    )?;
    let grant_evidence = IpexEvidence {
        sender_state: Some(&issuer_state),
        schema: Some(&schema),
        registry: Some(&registry),
        credential_state: Some(&credential_state),
        issuer_state: Some(&issuer_state),
        anchor_state: Some(&issuer_state),
        chain: &[],
    };
    let before_grant = conversation.clone();
    let missing_registry = IpexEvidence {
        registry: None,
        ..grant_evidence
    };
    let registry_error = conversation
        .ingest_mut(&messages[3], &missing_registry, decision_limits())
        .unwrap_err();
    assert_eq!(
        registry_error.disposition(),
        Disposition::Awaiting(EvidenceKind::RegistryState)
    );
    assert_eq!(conversation, before_grant);
    let missing_anchor = IpexEvidence {
        anchor_state: None,
        ..grant_evidence
    };
    let anchor_error = conversation
        .ingest_mut(&messages[3], &missing_anchor, decision_limits())
        .unwrap_err();
    assert!(matches!(
        anchor_error,
        IpexDecisionError::MissingAnchorState
    ));
    assert_eq!(
        anchor_error.disposition(),
        Disposition::Awaiting(EvidenceKind::IpexAnchorState)
    );
    assert_eq!(conversation, before_grant);
    for (index, expected) in [
        (7, IpexDecisionError::WrongCredential),
        (8, IpexDecisionError::WrongRecipient),
        (9, IpexDecisionError::AnchorMismatch),
    ] {
        let error = conversation
            .ingest_mut(&messages[index], &grant_evidence, decision_limits())
            .unwrap_err();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected),
            "{}",
            rows[index]["case"]
        );
        assert_eq!(conversation, before_grant);
    }
    conversation.ingest_mut(&messages[3], &grant_evidence, decision_limits())?;
    conversation.ingest_mut(
        &messages[4],
        &IpexEvidence::sender(&holder_state),
        decision_limits(),
    )?;
    assert!(conversation.is_terminal());
    assert!(matches!(
        conversation.ingest_mut(
            &messages[5],
            &IpexEvidence::sender(&holder_state),
            decision_limits()
        ),
        Err(IpexDecisionError::Closed)
    ));
    Ok(())
}
