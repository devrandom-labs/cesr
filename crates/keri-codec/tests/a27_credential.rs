//! Independent pinned keripy credential/schema oracle at the public boundary.

mod common;

use std::error::Error;

use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::Number;
use keri::{
    ChainCredential, CredentialError, CredentialEvidence, CredentialState,
    CredentialVerificationError, CredentialVerificationLimits, CredentialVerifier, Disposition,
    EvidenceKind, RegistryState, SignedTel, TelAnchorCoordinate, TelEvidence,
};
use keri_codec::{Deserialize, JsonLimits, SadCodes, SchemaError, VerifiedSchema};
use keri_events::acdc::{Acdc, AcdcField};
use keri_events::{Identifier, KeriEvent, Seal, TelEvent};

use common::{Event, Key, interaction_anchoring, seed};

type Fallible<T> = Result<T, Box<dyn Error>>;
const CORPUS: &str = include_str!("corpus/credential/v1.jsonl");
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
fn valid_said_does_not_imply_schema_validity() -> Fallible<()> {
    let schema_codes = SadCodes::from_pairs(&[("$id", DigestCode::Blake3_256)])?;
    let mut cases = 0;
    for line in CORPUS.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let schema_raw = row["schema"].as_str().ok_or("missing schema")?;
        let credential_raw = row["credential"].as_str().ok_or("missing credential")?;
        schema_codes.verify(schema_raw.as_bytes())?;
        let credential = Acdc::deserialize(credential_raw.as_bytes(), LIMITS)?;
        assert_eq!(
            credential.said().as_matter().to_qb64(),
            row["credential_said"]
        );

        let schema = VerifiedSchema::from_bytes(schema_raw.as_bytes(), LIMITS)?;
        let result = schema.validate_credential(credential_raw.as_bytes(), LIMITS);
        assert_eq!(result.is_ok(), row["case"] != "schema_type_mismatch");
        cases += 1;
        if row["case"] == "issued" {
            for field in [
                "chained_credential",
                "wrong_issuee_credential",
                "ni2i_credential",
                "di2i_credential",
                "rule_credential",
            ] {
                let extra = row[field].as_str().ok_or("missing extra credential")?;
                Acdc::deserialize(extra.as_bytes(), LIMITS)?;
                schema.validate_credential(extra.as_bytes(), LIMITS)?;
            }
            for field in ["aggregate_credential", "referenced_attributes_credential"] {
                let extra = row[field].as_str().ok_or("missing disclosure credential")?;
                Acdc::deserialize(extra.as_bytes(), LIMITS)?;
                assert!(matches!(
                    schema.validate_credential(extra.as_bytes(), LIMITS),
                    Err(SchemaError::UnsupportedDisclosure)
                ));
            }
        }
    }
    assert_eq!(cases, 4);
    Ok(())
}

#[test]
fn schema_reference_requires_explicit_local_profile_support() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("$id", DigestCode::Blake3_256)])?;
    let placeholder = format!("E{}", "A".repeat(43));
    let mut raw = format!(
        "{{\"$id\":\"{placeholder}\",\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"$ref\":\"https://example.invalid/schema\"}}"
    ).into_bytes();
    codes.saidify(&mut raw)?;
    assert!(matches!(
        VerifiedSchema::from_bytes(&raw, LIMITS),
        Err(SchemaError::UnsupportedReference)
    ));
    assert!(matches!(
        VerifiedSchema::from_bytes(&raw, JsonLimits::new(4096, 129)),
        Err(SchemaError::ResourceLimit)
    ));
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one transcript folds issuer and holder KELs, two TELs and revocation"
)]
fn issuer_holder_registry_and_revocation_are_bound_to_accepted_folds() -> Fallible<()> {
    let rows: Vec<serde_json::Value> = CORPUS
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let valid = &rows[0];
    let issuer_key = Key::from_seed_bytes(&[0x34; 32])?;
    let holder_key = Key::from_seed_bytes(&[0x35; 32])?;
    let icp = event(valid["issuer_icp"].as_str().ok_or("issuer icp")?)?;
    let holder_icp = event(valid["other_issuer_icp"].as_str().ok_or("holder icp")?)?;
    let mut issuer_state = seed(&icp, &issuer_key)?;
    let mut holder_state = seed(&holder_icp, &holder_key)?;
    assert_ne!(issuer_state.prefix(), holder_state.prefix());

    let vcp_raw = valid["registry_vcp"].as_str().ok_or("vcp")?;
    let vcp = TelEvent::deserialize(vcp_raw.as_bytes(), LIMITS)?.into_static();
    let vcp_anchor = anchor(&icp, 1, &vcp)?;
    issuer_state.ingest_mut(&vcp_anchor.signed(vec![issuer_key.sign(&vcp_anchor.bytes, 0)?]))?;
    let registry = RegistryState::incept(
        &tel_input(&vcp, vcp_raw.as_bytes(), &vcp_anchor),
        &issuer_state,
    )?;

    let issue_raw = valid["issue_iss"].as_str().ok_or("iss")?;
    let issue = TelEvent::deserialize(issue_raw.as_bytes(), LIMITS)?.into_static();
    let issue_anchor = anchor(&vcp_anchor, 2, &issue)?;
    issuer_state
        .ingest_mut(&issue_anchor.signed(vec![issuer_key.sign(&issue_anchor.bytes, 0)?]))?;
    let issue_input = tel_input(&issue, issue_raw.as_bytes(), &issue_anchor);
    let credential_state = CredentialState::incept(
        &registry,
        &issue_input,
        &TelEvidence::Issuer {
            state: &issuer_state,
            anchor: None,
        },
    )?;
    let schema =
        VerifiedSchema::from_bytes(valid["schema"].as_str().ok_or("schema")?.as_bytes(), LIMITS)?;
    let limits = CredentialVerificationLimits {
        json: LIMITS,
        max_document_bytes: 4096,
        max_nodes: 8,
        max_chain_depth: 4,
    };
    let body = valid["credential"].as_str().ok_or("credential")?;
    {
        let evidence = CredentialEvidence::from_host_accepted(
            body.as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&credential_state),
            Some(&issuer_state),
        );
        let accepted = CredentialVerifier::verify(&evidence, &[], limits)?;
        assert_eq!(accepted.said().to_qb64(), valid["credential_said"]);
        let AcdcField::Block(attribute_block) = accepted.attributes().ok_or("attributes")? else {
            return Err("attributes must be inline".into());
        };
        let attributes: serde_json::Value = serde_json::from_str(attribute_block.payload())?;
        let holder_prefix = match holder_state.prefix() {
            Identifier::Basic(prefix) => prefix.to_qb64(),
            Identifier::SelfAddressing(said) => said.to_qb64(),
        };
        assert_eq!(attributes["i"], holder_prefix);

        let no_schema = CredentialEvidence::from_host_accepted(
            body.as_bytes(),
            None,
            Some(&registry),
            Some(&credential_state),
            Some(&issuer_state),
        );
        assert!(matches!(
            CredentialVerifier::verify(&no_schema, &[], limits),
            Err(CredentialVerificationError::MissingSchema)
        ));
        for (reg, tel, issuer, expected) in [
            (
                None,
                Some(&credential_state),
                Some(&issuer_state),
                EvidenceKind::RegistryState,
            ),
            (
                Some(&registry),
                None,
                Some(&issuer_state),
                EvidenceKind::CredentialTelState,
            ),
            (
                Some(&registry),
                Some(&credential_state),
                None,
                EvidenceKind::IssuerState,
            ),
        ] {
            let missing = CredentialEvidence::from_host_accepted(
                body.as_bytes(),
                Some(&schema),
                reg,
                tel,
                issuer,
            );
            let outcome = CredentialVerifier::verify(&missing, &[], limits).unwrap_err();
            assert_eq!(outcome.disposition(), Disposition::Awaiting(expected));
        }
        for row in &rows[1..] {
            let candidate_body = row["credential"].as_str().ok_or("credential")?;
            let candidate_evidence = CredentialEvidence::from_host_accepted(
                candidate_body.as_bytes(),
                Some(&schema),
                Some(&registry),
                Some(&credential_state),
                Some(&issuer_state),
            );
            let rejected = CredentialVerifier::verify(&candidate_evidence, &[], limits);
            match row["case"].as_str().ok_or("case")? {
                "schema_type_mismatch" => assert!(matches!(
                    rejected,
                    Err(CredentialVerificationError::Schema(_))
                )),
                "unrelated_issuer" => assert!(matches!(
                    rejected,
                    Err(CredentialVerificationError::Status(
                        CredentialError::IssuerMismatch
                    ))
                )),
                "unrelated_registry" => assert!(matches!(
                    rejected,
                    Err(CredentialVerificationError::Status(
                        CredentialError::RegistryMismatch
                    ))
                )),
                other => return Err(format!("unexpected case: {other}").into()),
            }
        }
        let rule = CredentialEvidence::from_host_accepted(
            valid["rule_credential"]
                .as_str()
                .ok_or("rule credential")?
                .as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&credential_state),
            Some(&issuer_state),
        );
        assert!(matches!(
            CredentialVerifier::verify(&rule, &[], limits),
            Err(CredentialVerificationError::UnsupportedForm)
        ));
    }

    let other_vcp_raw = valid["other_registry_vcp"].as_str().ok_or("other vcp")?;
    let other_vcp = TelEvent::deserialize(other_vcp_raw.as_bytes(), LIMITS)?.into_static();
    let holder_vcp_anchor = anchor(&holder_icp, 1, &other_vcp)?;
    holder_state.ingest_mut(
        &holder_vcp_anchor.signed(vec![holder_key.sign(&holder_vcp_anchor.bytes, 0)?]),
    )?;
    let holder_registry = RegistryState::incept(
        &tel_input(&other_vcp, other_vcp_raw.as_bytes(), &holder_vcp_anchor),
        &holder_state,
    )?;
    let chained_issue_raw = valid["chained_issue_iss"].as_str().ok_or("chained iss")?;
    let chained_issue = TelEvent::deserialize(chained_issue_raw.as_bytes(), LIMITS)?.into_static();
    let holder_issue_anchor = anchor(&holder_vcp_anchor, 2, &chained_issue)?;
    holder_state.ingest_mut(
        &holder_issue_anchor.signed(vec![holder_key.sign(&holder_issue_anchor.bytes, 0)?]),
    )?;
    let chained_state = CredentialState::incept(
        &holder_registry,
        &tel_input(
            &chained_issue,
            chained_issue_raw.as_bytes(),
            &holder_issue_anchor,
        ),
        &TelEvidence::Issuer {
            state: &holder_state,
            anchor: None,
        },
    )?;
    let chained_raw = valid["chained_credential"]
        .as_str()
        .ok_or("chained credential")?;
    let chained = CredentialEvidence::from_host_accepted(
        chained_raw.as_bytes(),
        Some(&schema),
        Some(&holder_registry),
        Some(&chained_state),
        Some(&holder_state),
    );
    assert!(matches!(
        CredentialVerifier::verify(&chained, &[], limits),
        Err(CredentialVerificationError::MissingChain(_))
    ));
    let parent = ChainCredential {
        said: valid["credential_said"].as_str().ok_or("parent said")?,
        evidence: CredentialEvidence::from_host_accepted(
            body.as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&credential_state),
            Some(&issuer_state),
        ),
    };
    let chain = [parent];
    let accepted_chain = CredentialVerifier::verify(&chained, &chain, limits)?;
    assert_eq!(accepted_chain.said().to_qb64(), valid["chained_said"]);
    let wrong_claim = [ChainCredential {
        said: valid["credential_said"].as_str().ok_or("parent said")?,
        evidence: CredentialEvidence::from_host_accepted(
            rows[2]["credential"]
                .as_str()
                .ok_or("wrong parent")?
                .as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&credential_state),
            Some(&issuer_state),
        ),
    }];
    assert!(matches!(
        CredentialVerifier::verify(&chained, &wrong_claim, limits),
        Err(CredentialVerificationError::ChainClaimMismatch)
    ));
    assert!(matches!(
        CredentialVerifier::verify(
            &chained,
            &chain,
            CredentialVerificationLimits {
                max_chain_depth: 0,
                ..limits
            }
        ),
        Err(CredentialVerificationError::ResourceLimit)
    ));
    assert!(matches!(
        CredentialVerifier::verify(
            &chained,
            &chain,
            CredentialVerificationLimits {
                max_nodes: 1,
                ..limits
            }
        ),
        Err(CredentialVerificationError::ResourceLimit)
    ));

    let wrong_issuee_raw = valid["wrong_issuee_credential"]
        .as_str()
        .ok_or("wrong issuee")?;
    let wrong_tel_raw = valid["wrong_issuee_issue_iss"]
        .as_str()
        .ok_or("wrong issuee iss")?;
    let wrong_issue = TelEvent::deserialize(wrong_tel_raw.as_bytes(), LIMITS)?.into_static();
    let wrong_anchor = anchor(&issue_anchor, 3, &wrong_issue)?;
    let mut issuer_for_wrong = issuer_state.clone();
    issuer_for_wrong
        .ingest_mut(&wrong_anchor.signed(vec![issuer_key.sign(&wrong_anchor.bytes, 0)?]))?;
    let wrong_state = CredentialState::incept(
        &registry,
        &tel_input(&wrong_issue, wrong_tel_raw.as_bytes(), &wrong_anchor),
        &TelEvidence::Issuer {
            state: &issuer_for_wrong,
            anchor: None,
        },
    )?;
    let wrong = CredentialEvidence::from_host_accepted(
        wrong_issuee_raw.as_bytes(),
        Some(&schema),
        Some(&registry),
        Some(&wrong_state),
        Some(&issuer_for_wrong),
    );
    assert!(matches!(
        CredentialVerifier::verify(&wrong, &chain, limits),
        Err(CredentialVerificationError::WrongIssuee)
    ));
    let mut branches = Vec::new();
    for (credential_field, issue_field, expected) in [
        ("ni2i_credential", "ni2i_issue_iss", true),
        ("di2i_credential", "di2i_issue_iss", false),
    ] {
        let candidate_raw = valid[credential_field].as_str().ok_or("edge credential")?;
        let candidate_issue_raw = valid[issue_field].as_str().ok_or("edge issue")?;
        let candidate_issue =
            TelEvent::deserialize(candidate_issue_raw.as_bytes(), LIMITS)?.into_static();
        let candidate_anchor = anchor(&issue_anchor, 3, &candidate_issue)?;
        branches.push((
            candidate_raw,
            candidate_issue_raw,
            candidate_issue,
            candidate_anchor,
            expected,
        ));
    }
    let mut branch_states: Vec<_> = branches.iter().map(|_| issuer_state.clone()).collect();
    for ((_, _, _, candidate_anchor, _), branch_state) in
        branches.iter().zip(branch_states.iter_mut())
    {
        branch_state.ingest_mut(
            &candidate_anchor.signed(vec![issuer_key.sign(&candidate_anchor.bytes, 0)?]),
        )?;
    }
    for (
        (candidate_raw, candidate_issue_raw, candidate_issue, candidate_anchor, expected),
        branch_state,
    ) in branches.iter().zip(branch_states.iter())
    {
        let candidate_state = CredentialState::incept(
            &registry,
            &tel_input(
                candidate_issue,
                candidate_issue_raw.as_bytes(),
                candidate_anchor,
            ),
            &TelEvidence::Issuer {
                state: branch_state,
                anchor: None,
            },
        )?;
        let candidate = CredentialEvidence::from_host_accepted(
            candidate_raw.as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&candidate_state),
            Some(branch_state),
        );
        let result = CredentialVerifier::verify(&candidate, &chain, limits);
        if *expected {
            assert!(
                result.is_ok(),
                "NI2I must accept an independently issued node: {result:?}"
            );
        } else {
            assert!(matches!(
                result,
                Err(CredentialVerificationError::UnsupportedOperator)
            ));
        }
    }

    let revoke_raw = valid["revoke_rev"].as_str().ok_or("rev")?;
    let revoke = TelEvent::deserialize(revoke_raw.as_bytes(), LIMITS)?.into_static();
    let revoke_anchor = interaction_anchoring(
        &issue_anchor,
        3,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(credential_state.credential().clone()),
            s: revoke.sn(),
            d: revoke.said().clone().into_static(),
        }],
    )?;
    let mut issuer_after_revoke = issuer_state.clone();
    issuer_after_revoke
        .ingest_mut(&revoke_anchor.signed(vec![issuer_key.sign(&revoke_anchor.bytes, 0)?]))?;
    let mut revoked_state = credential_state.clone();
    revoked_state.ingest_mut(
        &registry,
        &tel_input(&revoke, revoke_raw.as_bytes(), &revoke_anchor),
        &TelEvidence::Issuer {
            state: &issuer_after_revoke,
            anchor: None,
        },
    )?;
    let revoked = CredentialEvidence::from_host_accepted(
        body.as_bytes(),
        Some(&schema),
        Some(&registry),
        Some(&revoked_state),
        Some(&issuer_after_revoke),
    );
    assert!(matches!(
        CredentialVerifier::verify(&revoked, &[], limits),
        Err(CredentialVerificationError::Status(
            CredentialError::Revoked
        ))
    ));
    let revoked_parent = [ChainCredential {
        said: valid["credential_said"].as_str().ok_or("parent said")?,
        evidence: CredentialEvidence::from_host_accepted(
            body.as_bytes(),
            Some(&schema),
            Some(&registry),
            Some(&revoked_state),
            Some(&issuer_after_revoke),
        ),
    }];
    assert!(matches!(
        CredentialVerifier::verify(&chained, &revoked_parent, limits),
        Err(CredentialVerificationError::Status(
            CredentialError::Revoked
        ))
    ));
    assert_eq!(
        CredentialError::Revoked.disposition(),
        Disposition::Terminal
    );
    assert_eq!(
        CredentialVerificationError::MissingSchema.disposition(),
        Disposition::Awaiting(EvidenceKind::CredentialSchema)
    );
    Ok(())
}
