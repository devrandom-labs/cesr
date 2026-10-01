//! Public-path checks for the selected typed V1 JSON profile.

use std::error::Error;

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::version::{CesrVersion, Protocol, SerializationKind, VersionStringV2};
use cesr_stream::cold::ColdCode;
use cesr_stream::error::ParseError;
use cesr_stream::{FrameLimits, MessageFramer};
use keri_codec::{
    CodecError, Deserialize, EventMessage, EventMessageError, Exn, InceptionBuilder, JsonLimits,
    MessageLimits, SadCodes, VersionGrammarError,
};
use keri_events::{Acdc, InceptionEvent, KeriEvent, Receipt, TelEvent};

type Fallible<T> = Result<T, Box<dyn Error>>;

#[test]
fn said_valid_unimplemented_minor_version_is_rejected_by_typed_event_read() -> Fallible<()> {
    let key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(vec![0x24; 32])?
        .build()?;
    let event = InceptionBuilder::new().keys(vec![key.into()]).build()?;
    let mut bytes = event.as_bytes().to_vec();
    assert_eq!(&bytes[6..12], b"KERI10");
    bytes[11] = b'1';

    let codes =
        SadCodes::from_pairs(&[("d", DigestCode::Blake3_256), ("i", DigestCode::Blake3_256)])?;
    codes.saidify(&mut bytes)?;
    codes.verify(&bytes)?;

    assert!(matches!(
        InceptionEvent::deserialize(&bytes, JsonLimits::new(4096, 64)),
        Err(CodecError::Version(
            VersionGrammarError::UnsupportedProtocolVersion {
                protocol: Protocol::Keri,
                major: 1,
                minor: 1
            }
        ))
    ));
    let limits = MessageLimits::new(
        FrameLimits {
            max_body_bytes: 1024,
            max_attachment_bytes: 1024,
            max_attachment_groups: 8,
            max_group_elements: 8,
            max_signatures: 8,
            max_nested_groups: 8,
            max_nesting_depth: 2,
        },
        JsonLimits::new(4096, 64),
    );
    assert!(matches!(
        EventMessage::parse(&bytes, limits),
        Err(EventMessageError::Body(CodecError::Version(
            VersionGrammarError::UnsupportedProtocolVersion {
                protocol: Protocol::Keri,
                major: 1,
                minor: 1
            }
        )))
    ));
    let mut wrong_protocol = bytes.clone();
    wrong_protocol[6..10].copy_from_slice(b"ACDC");
    codes.saidify(&mut wrong_protocol)?;
    assert!(matches!(
        InceptionEvent::deserialize(&wrong_protocol, JsonLimits::new(4096, 64)),
        Err(CodecError::Version(
            VersionGrammarError::InvalidVersionString(_)
        ))
    ));
    Ok(())
}

#[test]
fn said_valid_other_minor_versions_are_rejected_by_acdc_and_exn_readers() -> Fallible<()> {
    let acdc: serde_json::Value = serde_json::from_str(
        include_str!("corpus/acdc/happy.jsonl")
            .lines()
            .next()
            .ok_or("missing ACDC fixture")?,
    )?;
    let exn: serde_json::Value = serde_json::from_str(
        include_str!("corpus/ipex/happy.jsonl")
            .lines()
            .next()
            .ok_or("missing EXN fixture")?,
    )?;
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    for (raw, protocol) in [
        (
            acdc["raw"].as_str().ok_or("missing ACDC raw")?,
            Protocol::Acdc,
        ),
        (
            exn["raw"].as_str().ok_or("missing EXN raw")?,
            Protocol::Keri,
        ),
    ] {
        let mut bytes = raw.as_bytes().to_vec();
        bytes[11] = b'1';
        codes.saidify(&mut bytes)?;
        codes.verify(&bytes)?;
        let result = if protocol == Protocol::Acdc {
            Acdc::deserialize(&bytes, JsonLimits::new(4096, 64)).map(|_| ())
        } else {
            Exn::deserialize(&bytes, JsonLimits::new(4096, 64)).map(|_| ())
        };
        assert!(matches!(
            result,
            Err(CodecError::Version(
                VersionGrammarError::UnsupportedProtocolVersion {
                    major: 1,
                    minor: 1,
                    ..
                }
            ))
        ));
    }
    Ok(())
}

#[test]
fn v2_json_body_has_a_typed_unsupported_profile_error() -> Fallible<()> {
    let placeholder = VersionStringV2::new(Protocol::Keri, 0, 0, SerializationKind::Json, 0)?;
    let mut body = format!("{{\"v\":\"{}\",\"t\":\"icp\"}}", placeholder.to_str());
    let version = VersionStringV2::new(
        Protocol::Keri,
        0,
        0,
        SerializationKind::Json,
        u32::try_from(body.len())?,
    )?;
    body.replace_range(6..25, &version.to_str());
    let limits = MessageLimits::new(
        FrameLimits {
            max_body_bytes: 1024,
            max_attachment_bytes: 1024,
            max_attachment_groups: 8,
            max_group_elements: 8,
            max_signatures: 8,
            max_nested_groups: 8,
            max_nesting_depth: 2,
        },
        JsonLimits::new(4096, 64),
    );
    assert!(matches!(
        EventMessage::parse(body.as_bytes(), limits),
        Err(EventMessageError::Frame(ParseError::UnsupportedVersion {
            version: CesrVersion::V2
        }))
    ));
    assert!(matches!(
        KeriEvent::deserialize(body.as_bytes(), limits.json),
        Err(CodecError::Version(
            VersionGrammarError::UnsupportedCesrVersion(CesrVersion::V2)
        ))
    ));
    for split in 17..25 {
        let mut framer = MessageFramer::new(limits.frame);
        assert!(framer.advance(&body.as_bytes()[..split], false)?.is_none());
        assert!(matches!(
            framer.advance(body.as_bytes(), true),
            Err(ParseError::UnsupportedVersion {
                version: CesrVersion::V2
            })
        ));
    }
    Ok(())
}

#[test]
fn non_json_bodies_are_rejected_at_typed_message_boundary() -> Fallible<()> {
    let limits = MessageLimits::new(
        FrameLimits {
            max_body_bytes: 1024,
            max_attachment_bytes: 1024,
            max_attachment_groups: 8,
            max_group_elements: 8,
            max_signatures: 8,
            max_nested_groups: 8,
            max_nesting_depth: 2,
        },
        JsonLimits::new(4096, 64),
    );
    for (head, kind, cold) in [
        (
            [0xa2, 0x61, b'v', 0x71],
            SerializationKind::Cbor,
            ColdCode::Cbor,
        ),
        (
            [0x82, 0xa1, b'v', 0xb1],
            SerializationKind::Mgpk,
            ColdCode::MessagePack,
        ),
    ] {
        let mut body = head.to_vec();
        let version = cesr::core::version::VersionString::new(Protocol::Keri, 1, 0, kind, 27)?;
        body.extend_from_slice(version.to_str().as_bytes());
        if cold == ColdCode::Cbor {
            body.extend_from_slice(&[0x61, b't', 0x63, b'i', b'c', b'p']);
        } else {
            body.extend_from_slice(&[0xa1, b't', 0xa3, b'i', b'c', b'p']);
        }
        assert_eq!(body.len(), 27);
        assert!(
            MessageFramer::new(limits.frame)
                .advance(&body, true)?
                .is_some()
        );
        assert!(matches!(
            EventMessage::parse(&body, limits),
            Err(EventMessageError::Frame(ParseError::UnsupportedColdStart {
                domain
            })) if domain == cold
        ));
        for result in [
            KeriEvent::deserialize(&body, limits.json).map(|_| ()),
            InceptionEvent::deserialize(&body, limits.json).map(|_| ()),
            Receipt::deserialize(&body, limits.json).map(|_| ()),
            TelEvent::deserialize(&body, limits.json).map(|_| ()),
            Acdc::deserialize(&body, limits.json).map(|_| ()),
            Exn::deserialize(&body, limits.json).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(CodecError::Version(
                    VersionGrammarError::UnsupportedSerializationKind(found)
                )) if found == kind
            ));
        }
    }
    let binary = [0xf8_u8, 0, 0];
    assert!(matches!(
        EventMessage::parse(&binary, limits),
        Err(EventMessageError::Frame(ParseError::UnsupportedColdStart {
            domain: ColdCode::CesrBinary
        }))
    ));
    assert!(matches!(
        KeriEvent::deserialize(&binary, limits.json),
        Err(CodecError::Version(
            VersionGrammarError::UnsupportedSerializationKind(SerializationKind::Cesr)
        ))
    ));
    Ok(())
}
