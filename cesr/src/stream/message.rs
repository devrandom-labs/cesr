use crate::core::version::{VERSION_STRING_LEN, VersionString};
use crate::stream::cold::ColdCode;
use crate::stream::cold::detect_cold_code;
use crate::stream::error::ParseError;
use crate::stream::group::CesrGroup;
use crate::stream::group::Groups;
use crate::stream::group::groups;
use crate::stream::group::parse_group;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format};

/// A framed CESR message — either an event with attachments or a bare attachment.
pub enum CesrMessage<'a> {
    /// Serialized event body with CESR attachment groups.
    Event {
        /// Serialization format detected from the first byte.
        format: ColdCode,
        /// Raw event payload bytes (the JSON/CBOR/MSGPACK body).
        payload: &'a [u8],
        /// Iterator over CESR attachment groups following the payload.
        attachments: Groups<'a>,
    },
    /// Bare CESR attachment group (no event payload).
    Attachment(CesrGroup),
}

/// Search the first bytes of `input` for a valid version string.
///
/// In KERI messages, the version string (`PPPPmmKKKKssssss_`) is embedded
/// inside the serialized body (e.g. as the `"v"` field value in JSON).
/// This function scans up to the first 100 bytes to locate it.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if no version string is found
/// within the search range.
fn find_version_string(input: &[u8]) -> Result<usize, ParseError> {
    let search_range = input.len().min(100);
    search_range
        .checked_sub(VERSION_STRING_LEN)
        .and_then(|last| (0..=last).find(|&i| VersionString::parse(&input[i..]).is_ok()))
        .ok_or_else(|| ParseError::Malformed("version string not found".into()))
}

/// Parse a CESR message from input bytes.
///
/// Detects whether the input starts with a serialized event (JSON/CBOR/MSGPACK)
/// or a bare CESR attachment group:
///
/// - **Event**: locates the version string inside the body, extracts payload
///   size, slices the payload bytes, and wraps the remainder in a [`Groups`]
///   iterator for lazy attachment parsing.
/// - **Attachment**: parses a single CESR group.
///
/// # Errors
///
/// Returns [`ParseError::NeedBytes`] if insufficient data,
/// or [`ParseError::Malformed`] for invalid version strings or unknown formats.
pub fn parse_message(input: &[u8]) -> Result<CesrMessage<'_>, ParseError> {
    if input.is_empty() {
        return Err(ParseError::NeedBytes(1));
    }

    let cold = detect_cold_code(input[0])?;
    match cold {
        ColdCode::Json | ColdCode::Cbor | ColdCode::MessagePack => {
            let vs_offset = find_version_string(input)?;
            let (vs, _) = VersionString::parse(&input[vs_offset..])?;
            let size = usize::try_from(vs.size())
                .map_err(|e| ParseError::Malformed(format!("event size overflow: {e}")))?;
            let Some((payload, rest)) = input.split_at_checked(size) else {
                // The split failed, so `size > input.len()` and the
                // subtraction cannot underflow.
                let needed = size
                    .checked_sub(input.len())
                    .ok_or_else(|| ParseError::Malformed("event size underflow".to_owned()))?;
                return Err(ParseError::NeedBytes(needed));
            };
            Ok(CesrMessage::Event {
                format: cold,
                payload,
                attachments: groups(rest),
            })
        }
        ColdCode::CesrBase64 | ColdCode::CesrBinary => {
            let (group, _rest) = parse_group(input)?;
            Ok(CesrMessage::Attachment(group))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::needless_collect,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use crate::core::counter::CounterCodeV1;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use alloc::vec::Vec;
    use core::num::NonZeroUsize;

    use super::*;

    fn build_siger_qb64(index: u32) -> Vec<u8> {
        IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap()
            .to_qb64()
            .into_bytes()
    }

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    #[test]
    fn parse_message_json_event_with_attachments() {
        let template = r#"{"v":"KERI10JSON00004e_","t":"icp","d":"SAID","stuff":"padpadpadpad"}"#;
        let template_len = template.len();

        let size_hex = format!("{template_len:06x}");
        let body = format!(
            r#"{{"v":"KERI10JSON{size_hex}_","t":"icp","d":"SAID","stuff":"padpadpadpad"}}"#
        );
        let body_bytes = body.as_bytes();

        assert_eq!(
            body_bytes.len(),
            usize::from_str_radix(&size_hex, 16).unwrap(),
            "body length must match version string size"
        );

        let mut input = body_bytes.to_vec();
        input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1));
        input.extend_from_slice(&build_siger_qb64(0));

        let msg = parse_message(&input).unwrap();
        match msg {
            CesrMessage::Event {
                format,
                payload,
                attachments,
            } => {
                assert_eq!(format, ColdCode::Json);
                assert_eq!(payload.len(), body_bytes.len());
                let groups: Vec<_> = attachments.collect();
                assert_eq!(groups.len(), 1);
                assert!(groups[0].is_ok());
            }
            CesrMessage::Attachment(_) => panic!("expected Event"),
        }
    }

    #[test]
    fn parse_message_bare_attachment() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));

        let msg = parse_message(&input).unwrap();
        assert!(matches!(msg, CesrMessage::Attachment(_)));
    }

    #[test]
    fn parse_message_empty_returns_need_bytes() {
        let result = parse_message(b"");
        assert!(matches!(result, Err(ParseError::NeedBytes(1))));
    }

    #[test]
    fn parse_message_truncated_event_reports_missing_bytes() {
        // Version string claims 0x100 bytes but only the head is present.
        let body = br#"{"v":"KERI10JSON000100_","t":"icp"}"#;
        let result = parse_message(body);
        assert!(matches!(
            result,
            Err(ParseError::NeedBytes(n)) if n == 0x100 - body.len()
        ));
    }

    #[test]
    fn parse_message_event_no_attachments() {
        let template = r#"{"v":"KERI10JSON000042_","t":"icp","d":"SAID","x":"padding"}"#;
        let template_len = template.len();
        let size_hex = format!("{template_len:06x}");
        let body = format!(r#"{{"v":"KERI10JSON{size_hex}_","t":"icp","d":"SAID","x":"padding"}}"#);
        let body_bytes = body.as_bytes();

        let msg = parse_message(body_bytes).unwrap();
        match msg {
            CesrMessage::Event {
                format,
                payload,
                attachments,
            } => {
                assert_eq!(format, ColdCode::Json);
                assert_eq!(payload, body_bytes);
                let groups: Vec<_> = attachments.collect();
                assert!(groups.is_empty());
            }
            CesrMessage::Attachment(_) => panic!("expected Event"),
        }
    }

    #[test]
    fn parse_message_without_version_string_is_malformed() {
        let body = br#"{"t":"icp","d":"SAID","x":"no version string here"}"#;
        assert!(matches!(parse_message(body), Err(ParseError::Malformed(_))));
    }
}
