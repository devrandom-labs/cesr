use crate::stream::cold::ColdCode;
use crate::stream::cold::detect_cold_code;
use crate::stream::error::ParseError;
use crate::stream::group::Groups;
use crate::stream::group::groups;
use crate::stream::group::parse_group;
use crate::stream::group::types::CesrGroup;
use crate::stream::util::b64_to_int;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec::Vec};

fn b64_to_u8(input: &[u8], field: &str) -> Result<u8, ParseError> {
    let raw = b64_to_int(input)?;
    u8::try_from(raw).map_err(|_| ParseError::Malformed(format!("{field} out of range")))
}

fn b64_to_u16(input: &[u8], field: &str) -> Result<u16, ParseError> {
    let raw = b64_to_int(input)?;
    u16::try_from(raw).map_err(|_| ParseError::Malformed(format!("{field} out of range")))
}

fn b64_to_u32(input: &[u8], field: &str) -> Result<u32, ParseError> {
    let raw = b64_to_int(input)?;
    u32::try_from(raw).map_err(|_| ParseError::Malformed(format!("{field} out of range")))
}

/// Parsed components of a CESR version string.
pub struct VersionString<'a> {
    /// Protocol identifier (e.g., "KERI", "ACDC").
    pub protocol: &'a str,
    /// Major version number.
    pub major: u8,
    /// Minor version number.
    pub minor: u8,
    /// Serialization format.
    pub kind: ColdCode,
    /// Size of the serialized event body in bytes.
    pub size: usize,
}

/// Parse a CESR version string from the first 17 bytes of input.
///
/// Format: `PPPPVVKKKKssssss_` where:
/// - `PPPP` = protocol (4 ASCII chars)
/// - `VV` = version (2 digits: major, minor)
/// - `KKKK` = serialization kind (JSON, CBOR, MGPK, CESR)
/// - `ssssss` = hex-encoded payload size (6 hex chars)
/// - `_` = terminator
///
/// Total: 17 bytes.
///
/// # Errors
///
/// Returns [`ParseError::NeedBytes`] if `input` is shorter than 17 bytes.
/// Returns [`ParseError::Malformed`] if any field is invalid (bad UTF-8,
/// non-digit version, unknown serialization kind, invalid hex size, or
/// missing `_` terminator).
pub fn parse_version_string(input: &[u8]) -> Result<(VersionString<'_>, &[u8]), ParseError> {
    const VS_LEN: usize = 17;
    if input.len() < VS_LEN {
        return Err(ParseError::NeedBytes(VS_LEN - input.len()));
    }

    let proto = core::str::from_utf8(&input[..4])
        .map_err(|_| ParseError::Malformed("invalid protocol in version string".into()))?;

    let major = input[4]
        .checked_sub(b'0')
        .filter(|&v| v <= 9)
        .ok_or_else(|| ParseError::Malformed("invalid major version digit".into()))?;
    let minor = input[5]
        .checked_sub(b'0')
        .filter(|&v| v <= 9)
        .ok_or_else(|| ParseError::Malformed("invalid minor version digit".into()))?;

    let kind = match &input[6..10] {
        b"JSON" => ColdCode::Json,
        b"CBOR" => ColdCode::Cbor,
        b"MGPK" => ColdCode::MessagePack,
        b"CESR" => ColdCode::CesrBase64,
        other => {
            let kind_str = String::from_utf8_lossy(other);
            return Err(ParseError::Malformed(format!(
                "unknown serialization kind: {kind_str}"
            )));
        }
    };

    let size_hex = core::str::from_utf8(&input[10..16])
        .map_err(|_| ParseError::Malformed("invalid hex in version string".into()))?;
    let size = usize::from_str_radix(size_hex, 16)
        .map_err(|_| ParseError::Malformed(format!("invalid hex size: {size_hex}")))?;

    if input[16] != b'_' {
        return Err(ParseError::Malformed(format!(
            "expected '_' terminator at byte 16, got {:?}",
            char::from(input[16])
        )));
    }

    Ok((
        VersionString {
            protocol: proto,
            major,
            minor,
            kind,
            size,
        },
        &input[VS_LEN..],
    ))
}

/// Parsed components of a CESR V2 version string.
///
/// V2 version strings are 19 bytes: `PPPPpmMgmGKKKKssss.` where version and
/// genus fields are CESR B64-encoded and size is a 4-character B64 integer.
pub struct VersionStringV2<'a> {
    /// Protocol identifier (e.g., "KERI", "ACDC").
    pub protocol: &'a str,
    /// Protocol major version number.
    pub proto_major: u8,
    /// Protocol minor version number.
    pub proto_minor: u16,
    /// Genus major version number.
    pub genus_major: u8,
    /// Genus minor version number.
    pub genus_minor: u16,
    /// Serialization format.
    pub kind: ColdCode,
    /// Size of the serialized event body in bytes.
    pub size: u32,
}

/// Parse a CESR V2 version string from the first 19 bytes of input.
///
/// Format: `PPPPpmMgmGKKKKssss.` where:
/// - `PPPP` = protocol (4 ASCII chars, e.g. "KERI" or "ACDC")
/// - `p` = `proto_major` (1 B64 char, must decode to 2)
/// - `mM` = `proto_minor` (2 B64 chars)
/// - `g` = `genus_major` (1 B64 char, must decode to 2)
/// - `mG` = `genus_minor` (2 B64 chars)
/// - `KKKK` = serialization kind (JSON, CBOR, MGPK, CESR)
/// - `ssss` = B64-encoded payload size (4 B64 chars)
/// - `.` = period terminator
///
/// Total: 19 bytes.
///
/// # Errors
///
/// Returns [`ParseError::NeedBytes`] if `input` is shorter than 19 bytes.
/// Returns [`ParseError::Malformed`] if any field is invalid.
pub fn parse_version_string_v2(input: &[u8]) -> Result<(VersionStringV2<'_>, &[u8]), ParseError> {
    const VS_LEN: usize = 19;
    if input.len() < VS_LEN {
        return Err(ParseError::NeedBytes(VS_LEN - input.len()));
    }

    let proto = core::str::from_utf8(&input[..4])
        .map_err(|_| ParseError::Malformed("invalid protocol in V2 version string".into()))?;

    let proto_major = b64_to_u8(&input[4..5], "proto_major")?;
    if proto_major != 2 {
        return Err(ParseError::Malformed(format!(
            "expected V2 proto_major = 2, got {proto_major}"
        )));
    }

    let proto_minor = b64_to_u16(&input[5..7], "proto_minor")?;

    let genus_major = b64_to_u8(&input[7..8], "genus_major")?;
    if genus_major != 2 {
        return Err(ParseError::Malformed(format!(
            "expected V2 genus_major = 2, got {genus_major}"
        )));
    }

    let genus_minor = b64_to_u16(&input[8..10], "genus_minor")?;

    let kind = match &input[10..14] {
        b"JSON" => ColdCode::Json,
        b"CBOR" => ColdCode::Cbor,
        b"MGPK" => ColdCode::MessagePack,
        b"CESR" => ColdCode::CesrBase64,
        other => {
            let kind_str = String::from_utf8_lossy(other);
            return Err(ParseError::Malformed(format!(
                "unknown serialization kind: {kind_str}"
            )));
        }
    };

    let size = b64_to_u32(&input[14..18], "size")?;

    if input[18] != b'.' {
        return Err(ParseError::Malformed(format!(
            "expected '.' terminator at byte 18, got {:?}",
            char::from(input[18])
        )));
    }

    Ok((
        VersionStringV2 {
            protocol: proto,
            proto_major,
            proto_minor,
            genus_major,
            genus_minor,
            kind,
            size,
        },
        &input[VS_LEN..],
    ))
}

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
/// In KERI messages, the version string (`PPPPVVKKKKssssss_`) is embedded
/// inside the serialized body (e.g. as the `"v"` field value in JSON).
/// This function scans up to the first 100 bytes to locate it.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if no version string is found
/// within the search range.
fn find_version_string(input: &[u8]) -> Result<usize, ParseError> {
    let search_range = input.len().min(100);
    let mut i = 0;
    while i + 17 <= search_range {
        if parse_version_string(&input[i..]).is_ok() {
            return Ok(i);
        }
        i += 1;
    }
    Err(ParseError::Malformed("version string not found".into()))
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
            let (vs, _) = parse_version_string(&input[vs_offset..])?;
            let size = vs.size;
            if input.len() < size {
                return Err(ParseError::NeedBytes(size - input.len()));
            }
            let payload = &input[..size];
            let rest = &input[size..];
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
    fn parse_keri_v1_json() {
        let vs = b"KERI10JSON000123_rest";
        let (parsed, rest) = parse_version_string(vs).unwrap();
        assert_eq!(parsed.protocol, "KERI");
        assert_eq!(parsed.major, 1);
        assert_eq!(parsed.minor, 0);
        assert_eq!(parsed.kind, ColdCode::Json);
        assert_eq!(parsed.size, 0x123);
        assert_eq!(rest, b"rest");
    }

    #[test]
    fn parse_acdc_v1_cbor() {
        let vs = b"ACDC10CBOR000050_";
        let (parsed, rest) = parse_version_string(vs).unwrap();
        assert_eq!(parsed.protocol, "ACDC");
        assert_eq!(parsed.kind, ColdCode::Cbor);
        assert_eq!(parsed.size, 0x50);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_keri_v2_msgpack() {
        let vs = b"KERI20MGPK0000ff_";
        let (parsed, _) = parse_version_string(vs).unwrap();
        assert_eq!(parsed.major, 2);
        assert_eq!(parsed.minor, 0);
        assert_eq!(parsed.kind, ColdCode::MessagePack);
        assert_eq!(parsed.size, 0xff);
    }

    #[test]
    fn parse_cesr_kind() {
        let vs = b"KERI10CESR000000_";
        let (parsed, _) = parse_version_string(vs).unwrap();
        assert_eq!(parsed.kind, ColdCode::CesrBase64);
        assert_eq!(parsed.size, 0);
    }

    #[test]
    fn too_short_returns_need_bytes() {
        let result = parse_version_string(b"KERI10JSON00");
        assert!(matches!(result, Err(ParseError::NeedBytes(_))));
    }

    #[test]
    fn unknown_kind_returns_malformed() {
        let vs = b"KERI10XXXX000123_";
        let result = parse_version_string(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn invalid_hex_size_returns_malformed() {
        let vs = b"KERI10JSON00ZZZZ_";
        let result = parse_version_string(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn missing_terminator_returns_malformed() {
        let vs = b"KERI10JSON000123X";
        let result = parse_version_string(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn max_size() {
        let vs = b"KERI10JSONffffff_";
        let (parsed, _) = parse_version_string(vs).unwrap();
        assert_eq!(parsed.size, 0x00ff_ffff);
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

    // ── V2 version string tests (keripy test vectors) ───────────────────

    #[test]
    fn parse_v2_keri_json_size_zero() {
        let vs = b"KERICAACAAJSONAAAA.";
        let (parsed, rest) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.protocol, "KERI");
        assert_eq!(parsed.proto_major, 2);
        assert_eq!(parsed.proto_minor, 0);
        assert_eq!(parsed.genus_major, 2);
        assert_eq!(parsed.genus_minor, 0);
        assert_eq!(parsed.kind, ColdCode::Json);
        assert_eq!(parsed.size, 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_keri_json_size_65() {
        let vs = b"KERICAACAAJSONAABB.";
        let (parsed, rest) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.protocol, "KERI");
        assert_eq!(parsed.proto_major, 2);
        assert_eq!(parsed.proto_minor, 0);
        assert_eq!(parsed.genus_major, 2);
        assert_eq!(parsed.genus_minor, 0);
        assert_eq!(parsed.kind, ColdCode::Json);
        assert_eq!(parsed.size, 65);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_acdc_json_size_86() {
        let vs = b"ACDCCAACAAJSONAABW.";
        let (parsed, rest) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.protocol, "ACDC");
        assert_eq!(parsed.proto_major, 2);
        assert_eq!(parsed.proto_minor, 0);
        assert_eq!(parsed.genus_major, 2);
        assert_eq!(parsed.genus_minor, 0);
        assert_eq!(parsed.kind, ColdCode::Json);
        assert_eq!(parsed.size, 86);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_keri_mgpk_size_zero() {
        let vs = b"KERICAACAAMGPKAAAA.";
        let (parsed, rest) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.protocol, "KERI");
        assert_eq!(parsed.proto_major, 2);
        assert_eq!(parsed.proto_minor, 0);
        assert_eq!(parsed.genus_major, 2);
        assert_eq!(parsed.genus_minor, 0);
        assert_eq!(parsed.kind, ColdCode::MessagePack);
        assert_eq!(parsed.size, 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_keri_json_versioned() {
        // pvrsn=(2,1), gvrsn=(2,1)
        let vs = b"KERICABCABJSONAAAA.";
        let (parsed, rest) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.protocol, "KERI");
        assert_eq!(parsed.proto_major, 2);
        assert_eq!(parsed.proto_minor, 1);
        assert_eq!(parsed.genus_major, 2);
        assert_eq!(parsed.genus_minor, 1);
        assert_eq!(parsed.kind, ColdCode::Json);
        assert_eq!(parsed.size, 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_returns_rest() {
        let vs = b"KERICAACAAJSONAAAA.trailing";
        let (_, rest) = parse_version_string_v2(vs).unwrap();
        assert_eq!(rest, b"trailing");
    }

    #[test]
    fn parse_v2_too_short_returns_need_bytes() {
        let result = parse_version_string_v2(b"KERICAACAAJSON");
        assert!(matches!(result, Err(ParseError::NeedBytes(_))));
    }

    #[test]
    fn parse_v2_wrong_proto_major() {
        // proto_major = 1 (B64 'B') instead of 2 (B64 'C')
        let vs = b"KERIBAACAAJSONAAAA.";
        let result = parse_version_string_v2(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn parse_v2_wrong_genus_major() {
        // genus_major = 1 (B64 'B') instead of 2 (B64 'C')
        let vs = b"KERICAABAAJSONAAAA.";
        let result = parse_version_string_v2(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn parse_v2_unknown_kind() {
        let vs = b"KERICAACAAXXXXAAAA.";
        let result = parse_version_string_v2(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn parse_v2_wrong_terminator() {
        let vs = b"KERICAACAAJSONAAAA_";
        let result = parse_version_string_v2(vs);
        assert!(matches!(result, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn parse_v2_cesr_kind() {
        let vs = b"KERICAACAACESRAAAA.";
        let (parsed, _) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.kind, ColdCode::CesrBase64);
    }

    #[test]
    fn parse_v2_cbor_kind() {
        let vs = b"KERICAACAACBORAAAA.";
        let (parsed, _) = parse_version_string_v2(vs).unwrap();
        assert_eq!(parsed.kind, ColdCode::Cbor);
    }
}
