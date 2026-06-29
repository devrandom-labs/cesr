use bytes::Bytes;
use crate::core::counter::CounterCodeV2;

use crate::error::ParseError;
use crate::group::QuadletGroup;
use crate::group::parse_group;
use crate::group::parse_group_v2;
use crate::group::types::CesrGroup;
use crate::parse::parse_counter_v2;

/// CESR version for dispatch selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CesrVersion {
    /// CESR v1.0 counter codes
    V1,
    /// CESR v2.0 counter codes
    V2,
}

/// Maximum nesting depth for `GenericGroup` unwrapping.
const MAX_DEPTH: usize = 8;

/// Unwrap a `GenericGroup` into its constituent groups, handling
/// genus-version switching via `KERIACDCGenusVersion` counters.
///
/// The `version` parameter determines the initial parsing mode (V1 or V2).
/// If a nested group begins with a `KERIACDCGenusVersion` counter, parsing
/// switches to the version indicated by that counter.
///
/// # Errors
///
/// Returns [`ParseError`] on malformed data, unknown codes, insufficient
/// bytes, or if nesting exceeds [`MAX_DEPTH`].
pub fn unwrap_generic_group(
    group: &QuadletGroup,
    version: CesrVersion,
) -> Result<Vec<CesrGroup>, ParseError> {
    let mut results = Vec::new();
    let initial = Bytes::copy_from_slice(group.raw_bytes());
    // Stack entries: (version, owned bytes remaining at that level, depth)
    let mut stack: Vec<(CesrVersion, Bytes, usize)> = Vec::new();
    let mut current_version = version;
    let mut current_data = initial;
    let mut depth: usize = 0;

    loop {
        if current_data.is_empty() {
            if let Some((prev_version, prev_data, prev_depth)) = stack.pop() {
                current_version = prev_version;
                current_data = prev_data;
                depth = prev_depth;
                continue;
            }
            break;
        }

        let (parsed_group, rest) = match current_version {
            CesrVersion::V1 => parse_group(&current_data)?,
            CesrVersion::V2 => parse_group_v2(&current_data)?,
        };
        let consumed = current_data.len() - rest.len();

        match parsed_group {
            CesrGroup::GenericGroup(g) => {
                if depth >= MAX_DEPTH {
                    return Err(ParseError::Malformed("max nesting depth exceeded".into()));
                }
                let inner_raw = g.0.raw_bytes();
                let (inner_version, genus_size) =
                    check_genus_version_offset(inner_raw, current_version)?;
                let inner_bytes = Bytes::copy_from_slice(&inner_raw[genus_size..]);
                let remaining = current_data.slice(consumed..);
                if !remaining.is_empty() {
                    stack.push((current_version, remaining, depth));
                }
                current_version = inner_version;
                current_data = inner_bytes;
                depth += 1;
            }
            other => {
                results.push(other);
                current_data = current_data.slice(consumed..);
            }
        }
    }

    Ok(results)
}

/// Check if input starts with a `KERIACDCGenusVersion` counter.
/// If so, extract the version and return the number of bytes consumed
/// by the genus counter. Otherwise, return 0.
fn check_genus_version_offset(
    input: &[u8],
    default: CesrVersion,
) -> Result<(CesrVersion, usize), ParseError> {
    // KERIACDCGenusVersion has wire prefix "-_AAA" (hs=5), ss=3, fs=8.
    // It starts with "-_" which is unique among counter codes.
    if input.len() < 8 {
        return Ok((default, 0));
    }

    if input[0] == b'-' && input[1] == b'_' {
        match parse_counter_v2(input) {
            Ok((CounterCodeV2::KERIACDCGenusVersion, _count, rest)) => {
                let genus_size = input.len() - rest.len();
                let soft_bytes = &input[5..8];
                let version = decode_genus_version(soft_bytes)?;
                Ok((version, genus_size))
            }
            _ => Ok((default, 0)),
        }
    } else {
        Ok((default, 0))
    }
}

/// Decode genus version from the 3 B64 soft chars of `KERIACDCGenusVersion`.
///
/// The 3 B64 characters encode an 18-bit integer. keripy splits this as
/// `(value >> 12, value & 0xFFF)` = `(major, minor)`. Major version 1
/// selects V1 parsing; major version 2 selects V2 parsing.
fn decode_genus_version(soft: &[u8]) -> Result<CesrVersion, ParseError> {
    let soft_str = core::str::from_utf8(soft)
        .map_err(|_| ParseError::Malformed("invalid UTF-8 in genus version".into()))?;
    let value: u32 = crate::utils::decode_to_int(soft_str)?;
    let major = value >> 12;
    match major {
        1 => Ok(CesrVersion::V1),
        2 => Ok(CesrVersion::V2),
        _ => Err(ParseError::Malformed(format!(
            "unsupported genus version major={major}"
        ))),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crate::core::counter::CounterCodeV1;
    use crate::core::counter::CounterCodeV2;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use std::num::NonZeroUsize;

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
        let soft = crate::utils::encode_int(count, ss_nz).unwrap();
        format!("{hard}{soft}").into_bytes()
    }

    fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::utils::encode_int(count, ss_nz).unwrap();
        format!("{hard}{soft}").into_bytes()
    }

    fn build_simple_inner_group() -> Vec<u8> {
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        inner
    }

    fn wrap_in_quadlet_group_v1(inner: &[u8]) -> QuadletGroup {
        assert_eq!(inner.len() % 4, 0, "inner must be multiple of 4 bytes");
        let group_bytes = Bytes::copy_from_slice(inner);
        QuadletGroup::new(group_bytes, crate::group::parse_group_inner)
    }

    #[test]
    fn unwrap_simple_v1() {
        let inner = build_simple_inner_group();
        let group = wrap_in_quadlet_group_v1(&inner);
        let results = unwrap_generic_group(&group, CesrVersion::V1).unwrap();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CesrGroup::ControllerIdxSigs(_)));
    }

    #[test]
    fn unwrap_multiple_groups_inside() {
        let mut inner = build_simple_inner_group();
        inner.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1));
        inner.extend_from_slice(&build_siger_qb64(1));
        let group = wrap_in_quadlet_group_v1(&inner);
        let results = unwrap_generic_group(&group, CesrVersion::V1).unwrap();
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], CesrGroup::ControllerIdxSigs(_)));
        assert!(matches!(results[1], CesrGroup::WitnessIdxSigs(_)));
    }

    #[test]
    fn unwrap_nested_generic_groups() {
        let inner_content = build_simple_inner_group();
        let inner_quadlets = inner_content.len() / 4;
        let mut nested = build_counter_qb64(CounterCodeV1::GenericGroup, inner_quadlets as u32);
        nested.extend_from_slice(&inner_content);

        let outer = wrap_in_quadlet_group_v1(&nested);
        let results = unwrap_generic_group(&outer, CesrVersion::V1).unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CesrGroup::ControllerIdxSigs(_)));
    }

    #[test]
    fn unwrap_empty_group() {
        let group_bytes = Bytes::new();
        let group = QuadletGroup::new(group_bytes, crate::group::parse_group_inner);
        let results = unwrap_generic_group(&group, CesrVersion::V1).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn unwrap_v2_mode() {
        let mut inner = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let group_bytes = Bytes::copy_from_slice(&inner);
        let group = QuadletGroup::new(group_bytes, crate::group::parse_group_inner_v2);
        let results = unwrap_generic_group(&group, CesrVersion::V2).unwrap();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CesrGroup::ControllerIdxSigs(_)));
    }

    #[test]
    fn genus_version_decode_v1() {
        // Major=1, minor=0: value = (1 << 12) | 0 = 4096
        // 4096 in B64 with 3 chars = "BAA"
        let soft = b"BAA";
        let version = decode_genus_version(soft).unwrap();
        assert_eq!(version, CesrVersion::V1);
    }

    #[test]
    fn genus_version_decode_v2() {
        // Major=2, minor=0: value = (2 << 12) | 0 = 8192
        // 8192 in B64 with 3 chars = "CAA"
        let soft = b"CAA";
        let version = decode_genus_version(soft).unwrap();
        assert_eq!(version, CesrVersion::V2);
    }

    #[test]
    fn genus_version_decode_unsupported() {
        // Major=0: value = 0
        let soft = b"AAA";
        let result = decode_genus_version(soft);
        assert!(result.is_err());
    }

    #[test]
    fn genus_version_switches_parsing() {
        // Build inner content that starts with a KERIACDCGenusVersion counter
        // indicating V2, followed by a V2-encoded ControllerIdxSigs group.
        let genus_counter = build_genus_version_counter(2, 0);
        let mut v2_group = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        v2_group.extend_from_slice(&build_siger_qb64(0));

        // Wrap genus counter + V2 group inside a GenericGroup counter (V1)
        let mut inner_of_nested = genus_counter;
        inner_of_nested.extend_from_slice(&v2_group);
        let nested_quadlets = inner_of_nested.len() / 4;
        let mut nested_group =
            build_counter_qb64(CounterCodeV1::GenericGroup, nested_quadlets as u32);
        nested_group.extend_from_slice(&inner_of_nested);

        // Wrap in outer QuadletGroup
        let outer = wrap_in_quadlet_group_v1(&nested_group);
        let results = unwrap_generic_group(&outer, CesrVersion::V1).unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CesrGroup::ControllerIdxSigs(_)));
    }

    fn build_genus_version_counter(major: u32, minor: u32) -> Vec<u8> {
        // KERIACDCGenusVersion: hard = "-_AAA" (hs=5), ss=3, fs=8
        // Soft encodes (major << 12 | minor) as 3 B64 chars
        let value = (major << 12) | minor;
        let ss_nz = NonZeroUsize::new(3).unwrap();
        let soft = crate::utils::encode_int(value, ss_nz).unwrap();
        format!("-_AAA{soft}").into_bytes()
    }

    #[test]
    fn max_depth_exceeded() {
        // Build deeply nested GenericGroups exceeding MAX_DEPTH
        // Start with the innermost content
        let mut content = build_simple_inner_group();

        // Wrap in MAX_DEPTH + 1 layers of GenericGroup
        for _ in 0..=MAX_DEPTH {
            let quadlets = content.len() / 4;
            let mut wrapped = build_counter_qb64(CounterCodeV1::GenericGroup, quadlets as u32);
            wrapped.extend_from_slice(&content);
            content = wrapped;
        }

        let outer = wrap_in_quadlet_group_v1(&content);
        let result = unwrap_generic_group(&outer, CesrVersion::V1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::Malformed(msg) => {
                assert!(msg.contains("max nesting depth exceeded"));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }
}
