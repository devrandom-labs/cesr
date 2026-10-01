//! Pinned V1 query/reply bodies and framed attachment forms.

use std::error::Error;

use cesr::core::matter::code::DigestCode;
use cesr_stream::FrameLimits;
use keri::{DiscoveryError, DiscoveryJudge, DiscoveryVerdict, EvidenceKind, KeyStateSnapshot};
use keri_codec::{
    Deserialize, JsonLimits, Message, MessageLimits, RoutedBody, RoutedMessage, SadCodes,
};
use keri_events::{Identifier, KeriEvent, MessageType};

type Fallible<T> = Result<T, Box<dyn Error>>;

const CORPUS: &str = include_str!("corpus/discovery/v1.jsonl");

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
#[allow(
    clippy::too_many_lines,
    reason = "one loop checks all pinned wire and attachment cases"
)]
fn pinned_v1_query_reply_messages_have_typed_routes() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    let mut cases = 0;
    for line in CORPUS.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let raw = row["raw"].as_str().ok_or("missing raw body")?;
        let signed = row["signed"].as_str().ok_or("missing framed message")?;
        let ilk = row["ilk"].as_str().ok_or("missing ilk")?;
        let route = row["route"].as_str().ok_or("missing route")?;
        let body: serde_json::Value = serde_json::from_str(raw)?;
        assert_eq!(body["t"], ilk);
        assert_eq!(body["r"], route);
        assert!(body.get("i").is_none(), "V1 {ilk} has no V2 sender field");
        codes.verify(raw.as_bytes())?;

        let tag = MessageType::from_code(ilk)?;
        assert_eq!(tag.code(), ilk);
        let (message, remainder) = Message::parse(signed.as_bytes(), limits())?;
        assert!(remainder.is_empty());
        let Message::Routed(routed) = message else {
            return Err(format!("{ilk} must dispatch to RoutedMessage").into());
        };
        assert_eq!(routed.body(), raw.as_bytes());
        assert_eq!(routed.routed().kind(), tag);
        assert_eq!(routed.routed().route(), route);
        assert_eq!(routed.routed().datetime(), body["dt"].as_str().unwrap());
        let payload = if ilk == "qry" { &body["q"] } else { &body["a"] };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(routed.routed().payload().payload())?,
            *payload
        );
        if ilk == "qry" {
            assert_eq!(routed.routed().reply_route(), body["rr"].as_str());
            let rebuilt = RoutedBody::write_query(
                body["dt"].as_str().unwrap(),
                route,
                body["rr"].as_str().unwrap(),
                routed.routed().payload().payload(),
                limits().json,
            )?;
            assert_eq!(rebuilt, raw.as_bytes());
        } else {
            assert_eq!(routed.routed().reply_route(), None);
            let rebuilt = RoutedBody::write_reply(
                body["dt"].as_str().unwrap(),
                route,
                routed.routed().payload().payload(),
                limits().json,
            )?;
            assert_eq!(rebuilt, raw.as_bytes());
        }
        let signer_groups = routed.transferable_signers();
        if row["authorizer"].is_null() {
            assert!(signer_groups.is_empty());
            assert!(routed.nontransferable_signers().is_empty());
        } else if row["signer_est_raw"].is_null() {
            assert!(signer_groups.is_empty());
            assert_eq!(routed.nontransferable_signers().len(), 1);
            assert_eq!(
                routed.nontransferable_signers()[0]
                    .receiptor()
                    .as_matter()
                    .to_qb64(),
                row["authorizer"].as_str().unwrap()
            );
        } else {
            assert_eq!(signer_groups.len(), 1);
            let signer_prefix = match signer_groups[0].receiptor() {
                Identifier::Basic(prefix) => prefix.as_matter().to_qb64(),
                Identifier::SelfAddressing(said) => said.as_matter().to_qb64(),
            };
            assert_eq!(signer_prefix, row["authorizer"].as_str().unwrap());
            assert_eq!(
                signer_groups[0].sn().value().to_string(),
                row["signer_est_sn"].as_str().unwrap()
            );
            assert_eq!(
                signer_groups[0].said().as_matter().to_qb64(),
                row["signer_est_said"].as_str().unwrap()
            );
            assert_eq!(signer_groups[0].signatures().len(), 1);
        }
        let combined = format!("{signed}{signed}");
        let (_, suffix) = Message::parse(combined.as_bytes(), limits())?;
        assert_eq!(suffix, signed.as_bytes());
        cases += 1;
    }
    assert_eq!(cases, 7);
    Ok(())
}

#[test]
fn v1_routed_reader_rejects_v2_sender_and_corrupt_body() -> Fallible<()> {
    let row: serde_json::Value =
        serde_json::from_str(CORPUS.lines().nth(1).ok_or("missing reply")?)?;
    let raw = row["raw"].as_str().ok_or("missing reply body")?;
    let injected = raw.replacen(",\"dt\":", ",\"i\":\"Dbad\",\"dt\":", 1);
    assert!(RoutedBody::parse(injected.as_bytes(), limits().json).is_err());

    let tampered = raw.replacen("/end/role/add", "/end/role/cut", 1);
    assert!(RoutedBody::parse(tampered.as_bytes(), limits().json).is_err());

    assert!(RoutedBody::write_reply("bad\"date", "/route", "{}", limits().json).is_err());
    assert!(
        RoutedBody::write_reply("2026-10-01T00:00:00Z", "/route", "[]", limits().json).is_err()
    );
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one loop checks all pinned signer forms and replay outcomes"
)]
fn pinned_replies_require_historical_authority_and_reject_replay() -> Fallible<()> {
    for line in CORPUS.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let signed = row["signed"].as_str().ok_or("missing framed message")?;
        let (msg, rest) = RoutedMessage::parse(signed.as_bytes(), limits())?;
        assert!(rest.is_empty());
        if row["authorizer"].is_null() {
            assert_eq!(
                DiscoveryJudge::reply(&msg, None, None, None)?,
                DiscoveryVerdict::UntrustedHint
            );
            continue;
        }
        if row["ilk"] == "qry" {
            assert_eq!(
                DiscoveryJudge::query(&msg, None).err(),
                Some(DiscoveryError::MissingSignerState)
            );
            let establishment_raw = row["signer_est_raw"]
                .as_str()
                .ok_or("missing query signer state")?;
            let event = KeriEvent::deserialize(establishment_raw.as_bytes(), limits().json)?;
            let KeriEvent::Inception(icp) = &event else {
                return Err("expected pinned query signer inception".into());
            };
            let snapshot = KeyStateSnapshot::genesis(icp);
            let historical = snapshot.view();
            let query = DiscoveryJudge::query(&msg, Some(&historical))?;
            assert_eq!(query.target, *historical.prefix());
            assert_eq!(query.requester, *historical.prefix());
            assert_eq!(query.from_sn, 0);
            continue;
        }
        if row["signer_est_raw"].is_null() {
            let verdict = DiscoveryJudge::reply(&msg, None, None, None)?;
            let DiscoveryVerdict::Authenticated(version) = verdict else {
                return Err("nontransferable reply must authenticate".into());
            };
            assert_eq!(version.establishment_sn, 0);
            assert_eq!(
                DiscoveryJudge::reply(&msg, None, None, Some(version)),
                Err(DiscoveryError::Stale)
            );
            continue;
        }
        assert_eq!(
            DiscoveryJudge::reply(&msg, None, None, None),
            Err(DiscoveryError::MissingSignerState)
        );
        let establishment_raw = row["signer_est_raw"]
            .as_str()
            .ok_or("missing KEL evidence")?;
        let event = KeriEvent::deserialize(establishment_raw.as_bytes(), limits().json)?;
        let KeriEvent::Inception(icp) = &event else {
            return Err("expected pinned signer inception".into());
        };
        let snapshot = KeyStateSnapshot::genesis(icp);
        let historical = snapshot.view();
        if row["case"] == "rpy_ksn" {
            assert_eq!(
                DiscoveryJudge::reply(&msg, Some(&historical), None, None),
                Err(DiscoveryError::MissingSubjectState)
            );
        }
        let verdict = DiscoveryJudge::reply(&msg, Some(&historical), Some(&historical), None)?;
        let DiscoveryVerdict::Authenticated(version) = verdict else {
            return Err("signed reply must authenticate".into());
        };
        assert_eq!(
            DiscoveryJudge::reply(&msg, Some(&historical), Some(&historical), Some(version)),
            Err(DiscoveryError::Stale)
        );
        let prior = keri::ReplyVersion {
            utc_nanos: version.utc_nanos - 1,
            ..version
        };
        assert_eq!(
            DiscoveryJudge::reply(&msg, Some(&historical), Some(&historical), Some(prior))?,
            verdict
        );
    }
    assert_eq!(
        DiscoveryError::MissingSignerState.disposition(),
        keri::Disposition::Awaiting(EvidenceKind::DiscoverySignerState)
    );
    assert_eq!(
        DiscoveryError::Stale.disposition(),
        keri::Disposition::Terminal
    );
    Ok(())
}

#[test]
fn route_owner_and_signature_must_match_pinned_reply() -> Fallible<()> {
    let row: serde_json::Value =
        serde_json::from_str(CORPUS.lines().nth(1).ok_or("missing add reply")?)?;
    let raw = row["raw"].as_str().ok_or("missing body")?;
    let framed = row["signed"].as_str().ok_or("missing message")?;
    let suffix = framed
        .strip_prefix(raw)
        .ok_or("missing attachment suffix")?;
    let establishment_raw = row["signer_est_raw"]
        .as_str()
        .ok_or("missing KEL evidence")?;
    let event = KeriEvent::deserialize(establishment_raw.as_bytes(), limits().json)?;
    let KeriEvent::Inception(icp) = &event else {
        return Err("expected signer inception".into());
    };
    let snapshot = KeyStateSnapshot::genesis(icp);
    let historical = snapshot.view();
    let alternate = icp.keys()[0].as_matter().to_qb64();
    let original_payload: serde_json::Value = serde_json::from_str(raw)?;
    let timestamp = original_payload["dt"].as_str().ok_or("missing timestamp")?;
    let wrong_owner_payload = format!(
        "{{\"cid\":\"{alternate}\",\"role\":\"witness\",\"eid\":\"{}\"}}",
        row["authorizer"].as_str().ok_or("missing owner")?
    );
    let wrong_owner = RoutedBody::write_reply(
        timestamp,
        "/end/role/add",
        &wrong_owner_payload,
        limits().json,
    )?;
    let wrong_owner_framed = format!("{}{suffix}", std::str::from_utf8(&wrong_owner)?);
    let (wrong_owner_msg, _) = RoutedMessage::parse(wrong_owner_framed.as_bytes(), limits())?;
    assert_eq!(
        DiscoveryJudge::reply(&wrong_owner_msg, Some(&historical), None, None),
        Err(DiscoveryError::WrongSigner)
    );

    let same_owner_payload = original_payload["a"].to_string();
    let changed_body = RoutedBody::write_reply(
        "2026-10-01T00:00:06.000000+00:00",
        "/end/role/add",
        &same_owner_payload,
        limits().json,
    )?;
    let changed_framed = format!("{}{suffix}", std::str::from_utf8(&changed_body)?);
    let (changed_msg, _) = RoutedMessage::parse(changed_framed.as_bytes(), limits())?;
    assert_eq!(
        DiscoveryJudge::reply(&changed_msg, Some(&historical), None, None),
        Err(DiscoveryError::BadSignature)
    );
    Ok(())
}
