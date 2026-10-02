//! The selected V1 JSON/text wire path and its caller-delimited qb2 conversion boundary.

use std::error::Error;

use cesr::b64::error::Error as Base64Error;
use cesr_stream::cold::ColdCode;
use cesr_stream::error::ParseError;
use cesr_stream::group::CesrGroup;
use cesr_stream::qb2::{Qb2, Qb64};
use cesr_stream::{FrameLimits, MessageFramer};
use keri_codec::{EventMessage, EventMessageError, JsonLimits, MessageLimits};

type Fallible<T> = Result<T, Box<dyn Error>>;

const SIGNED_ICP: &[u8] = include_bytes!("fixtures/keripy_icp_signed.cesr");

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
fn pinned_signed_message_survives_exact_attachment_conversion() -> Fallible<()> {
    let policy = limits();
    let span = MessageFramer::new(policy.frame)
        .advance(SIGNED_ICP, true)?
        .ok_or("missing signed frame")?;
    let body_len = span.body_len.ok_or("missing JSON body")?;
    assert_eq!(span.total_len, SIGNED_ICP.len());
    let text = &SIGNED_ICP[body_len..span.total_len];
    let binary = Qb64(text).decode()?;
    let restored = Qb2(&binary).encode()?;
    assert_eq!(restored, text);
    let (_, group_rest) = CesrGroup::parse(&restored)?;
    assert!(group_rest.is_empty());

    let (reference, reference_rest) = EventMessage::parse(SIGNED_ICP, policy)?;
    assert!(reference_rest.is_empty());
    let mut converted_wire = reference.body().to_vec();
    converted_wire.extend_from_slice(&restored);
    let mut concatenated = converted_wire.clone();
    concatenated.extend_from_slice(SIGNED_ICP);
    let (converted, remainder) = EventMessage::parse(&concatenated, policy)?;
    assert_eq!(remainder, SIGNED_ICP);
    assert_eq!(converted.body(), reference.body());
    assert_eq!(converted.event(), reference.event());
    assert_eq!(converted.sigs(), reference.sigs());
    assert_eq!(converted.wigs(), reference.wigs());
    Ok(())
}

#[test]
fn binary_transport_requires_an_exact_external_span() -> Fallible<()> {
    let policy = limits();
    let span = MessageFramer::new(policy.frame)
        .advance(SIGNED_ICP, true)?
        .ok_or("missing signed frame")?;
    let body_len = span.body_len.ok_or("missing JSON body")?;
    let binary = Qb64(&SIGNED_ICP[body_len..]).decode()?;

    assert!(matches!(
        Qb2(&binary[..binary.len() - 1]).encode(),
        Err(Base64Error::Misaligned { unit: 3, .. })
    ));

    let truncated_text = Qb2(&binary[..binary.len() - 3]).encode()?;
    let mut truncated_wire = SIGNED_ICP[..body_len].to_vec();
    truncated_wire.extend_from_slice(&truncated_text);
    assert!(matches!(
        EventMessage::parse(&truncated_wire, policy),
        Err(EventMessageError::Frame(ParseError::Truncated { .. }))
    ));

    let mut mixed_wire = SIGNED_ICP[..body_len].to_vec();
    mixed_wire.extend_from_slice(&binary);
    assert!(matches!(
        EventMessage::parse(&mixed_wire, policy),
        Err(EventMessageError::Frame(ParseError::UnsupportedColdStart {
            domain: ColdCode::CesrBinary
        }))
    ));
    Ok(())
}
