//! CESR qb64 counter and version-string encoding.
//!
//! Group encoding lives on the group carriers themselves — see
//! [`CesrEncode`](crate::stream::version::CesrEncode) and
//! [`crate::stream::group`]. This module owns the shared counter encoders
//! they build on, plus the V2 version-string encoder.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec, vec::Vec};
use core::num::NonZeroUsize;

use crate::b64::encode_int;
use crate::core::counter::CounterCodeV1;
use crate::core::counter::CounterCodeV2;

use crate::core::version::VersionStringV2;
use crate::stream::error::ParseError;

// ── Counter encoding ─────────────────────────────────────────────────────

/// Validate that `count` fits the `ss`-character soft field (the counter
/// capacity keripy enforces at `counting.py:878-880` — count in
/// `[0, 64^ss - 1]`), returning the soft size as [`NonZeroUsize`].
///
/// Without this check `encode_int` would grow past the soft width and emit
/// a corrupt (over-long) counter.
fn check_counter_capacity(hard: &str, ss: usize, count: u32) -> Result<NonZeroUsize, ParseError> {
    let ss_nz = NonZeroUsize::new(ss)
        .ok_or_else(|| ParseError::Malformed(format!("counter code {hard} has zero soft size")))?;
    let capacity = u32::try_from(ss)
        .ok()
        .and_then(|bits| 64_u64.checked_pow(bits))
        .and_then(|full| full.checked_sub(1))
        .ok_or_else(|| {
            ParseError::Malformed(format!("counter code {hard} soft size {ss} out of range"))
        })?;
    if u64::from(count) > capacity {
        return Err(ParseError::Malformed(format!(
            "count {count} exceeds capacity {capacity} of counter code {hard}"
        )));
    }
    Ok(ss_nz)
}

/// Encode a V1 counter code + count as qb64 bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_counter_v1(code: CounterCodeV1, count: u32) -> Result<Vec<u8>, ParseError> {
    let hard = code.as_str();
    let ss_nz = check_counter_capacity(hard, code.soft_size(), count)?;
    let soft = encode_int(count, ss_nz);
    Ok(format!("{hard}{soft}").into_bytes())
}

/// Encode a V2 counter code + count as qb64 bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_counter_v2(code: CounterCodeV2, count: u32) -> Result<Vec<u8>, ParseError> {
    let hard = code.as_str();
    let ss_nz = check_counter_capacity(hard, code.soft_size(), count)?;
    let soft = encode_int(count, ss_nz);
    Ok(format!("{hard}{soft}").into_bytes())
}

// ── Counter auto-promotion ───────────────────────────────────────────────

/// Encode a counter, auto-promoting to big variant if count > 4095.
///
/// Small codes have ss=2 (max count 4095). When count exceeds this,
/// the code is promoted to its big variant (ss=5, max count 1,073,741,823).
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if count exceeds small limit and no
/// big variant exists for the code, or if count exceeds the big limit.
pub fn encode_counter_auto_v1(code: CounterCodeV1, count: u32) -> Result<Vec<u8>, ParseError> {
    if count > 4095 {
        if let Some(big) = code.to_big() {
            return encode_counter_v1(big, count);
        }
        return Err(ParseError::Malformed(format!(
            "count {count} exceeds small limit and no big variant for {}",
            code.as_str()
        )));
    }
    encode_counter_v1(code, count)
}

/// Encode a V2 counter, auto-promoting to big variant if count > 4095.
///
/// Same logic as [`encode_counter_auto_v1`] but for V2 counter codes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if count exceeds small limit and no
/// big variant exists for the code, or if count exceeds the big limit.
pub fn encode_counter_auto_v2(code: CounterCodeV2, count: u32) -> Result<Vec<u8>, ParseError> {
    if count > 4095 {
        if let Some(big) = code.to_big() {
            return encode_counter_v2(big, count);
        }
        return Err(ParseError::Malformed(format!(
            "count {count} exceeds small limit and no big variant for {}",
            code.as_str()
        )));
    }
    encode_counter_v2(code, count)
}

// ── V2 version string encoding ───────────────────────────────────────

/// Encode a [`VersionStringV2`] as a 19-byte CESR V2 version string.
///
/// Format: `PPPPpmMgmGKKKKssss.` — delegates to
/// [`VersionStringV2::to_str`], the single owner of the V2 frame layout.
#[must_use]
pub fn encode_version_string_v2(vs: &VersionStringV2) -> Vec<u8> {
    vs.to_str().into_bytes()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn encode_v1_controller_idx_sigs_count_2() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 2).unwrap();
        assert_eq!(&bytes, b"-AAC");
    }

    #[test]
    fn encode_v1_controller_idx_sigs_count_0() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 0).unwrap();
        assert_eq!(&bytes, b"-AAA");
    }

    #[test]
    fn encode_v1_controller_idx_sigs_count_1() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 1).unwrap();
        assert_eq!(&bytes, b"-AAB");
    }

    #[test]
    fn encode_v1_witness_idx_sigs() {
        let bytes = encode_counter_v1(CounterCodeV1::WitnessIdxSigs, 3).unwrap();
        assert_eq!(&bytes, b"-BAD");
    }

    #[test]
    fn encode_v1_attachment_group() {
        let bytes = encode_counter_v1(CounterCodeV1::AttachmentGroup, 23).unwrap();
        assert_eq!(&bytes, b"-VAX");
    }

    #[test]
    fn encode_v2_controller_idx_sigs_count_2() {
        let bytes = encode_counter_v2(CounterCodeV2::ControllerIdxSigs, 2).unwrap();
        assert_eq!(&bytes, b"-KAC");
    }

    #[test]
    fn encode_v2_attachment_group() {
        let bytes = encode_counter_v2(CounterCodeV2::AttachmentGroup, 23).unwrap();
        assert_eq!(&bytes, b"-CAX");
    }

    #[test]
    fn encode_v1_roundtrip() {
        use crate::stream::parse::parse_counter;

        let original_code = CounterCodeV1::SealSourceCouples;
        let original_count = 5_u32;
        let encoded = encode_counter_v1(original_code, original_count).unwrap();
        let (decoded_code, decoded_count, rest) = parse_counter(&encoded).unwrap();
        assert_eq!(decoded_code, original_code);
        assert_eq!(decoded_count, original_count);
        assert!(rest.is_empty());
    }

    #[test]
    fn encode_v2_roundtrip() {
        use crate::stream::parse::parse_counter_v2;

        let original_code = CounterCodeV2::SealSourceCouples;
        let original_count = 5_u32;
        let encoded = encode_counter_v2(original_code, original_count).unwrap();
        let (decoded_code, decoded_count, rest) = parse_counter_v2(&encoded).unwrap();
        assert_eq!(decoded_code, original_code);
        assert_eq!(decoded_count, original_count);
        assert!(rest.is_empty());
    }

    // ── Counter capacity tests ────────────────────────────────────────────

    #[test]
    fn encode_v1_small_counter_at_capacity_boundary() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 4095).unwrap();
        assert_eq!(&bytes, b"-A__");
    }

    #[test]
    fn encode_v1_small_counter_over_capacity_is_rejected() {
        // Without the capacity check the soft field would grow to 3 chars and
        // emit a corrupt 5-byte counter (keripy raises InvalidVarIndexError
        // for the same shape, counting.py:878-880).
        let err = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 4096).unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn encode_v1_big_counter_at_capacity_boundary() {
        let bytes = encode_counter_v1(CounterCodeV1::BigAttachmentGroup, 1_073_741_823).unwrap();
        assert_eq!(&bytes, b"--V_____");
    }

    #[test]
    fn encode_v1_big_counter_over_capacity_is_rejected() {
        let err = encode_counter_v1(CounterCodeV1::BigAttachmentGroup, 1_073_741_824).unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn encode_v2_small_counter_over_capacity_is_rejected() {
        let err = encode_counter_v2(CounterCodeV2::ControllerIdxSigs, 4096).unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    // ── Counter auto-promotion tests ──────────────────────────────────────

    #[test]
    fn auto_promote_v1_small_count_stays_small() {
        let result = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 100).unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.starts_with(b"-T"));
    }

    #[test]
    fn auto_promote_v1_large_count_promotes() {
        let result = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 8193).unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.starts_with(b"--T"));
    }

    #[test]
    fn auto_promote_v1_boundary() {
        let small = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 4095).unwrap();
        assert_eq!(small.len(), 4);
        let big = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 4096).unwrap();
        assert_eq!(big.len(), 8);
    }

    #[test]
    fn auto_promote_v1_no_big_variant_errors() {
        let result = encode_counter_auto_v1(CounterCodeV1::ControllerIdxSigs, 5000);
        assert!(result.is_err());
    }

    #[test]
    fn auto_promote_v2_large_count_promotes() {
        let result = encode_counter_auto_v2(CounterCodeV2::ControllerIdxSigs, 8193).unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.starts_with(b"--K"));
    }

    #[test]
    fn auto_promote_v2_small_count_stays_small() {
        let result = encode_counter_auto_v2(CounterCodeV2::ControllerIdxSigs, 100).unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.starts_with(b"-K"));
    }

    // ── V2 version string encoding tests ─────────────────────────────────

    mod version_string_v2 {
        use super::*;
        use crate::core::version::{Protocol, SerializationKind};

        fn make_vs(
            proto: Protocol,
            proto_minor: u16,
            genus_minor: u16,
            kind: SerializationKind,
            size: u32,
        ) -> VersionStringV2 {
            VersionStringV2::new(proto, proto_minor, genus_minor, kind, size).unwrap()
        }

        #[test]
        fn encode_delegates_to_core_renderer() {
            let vs = make_vs(Protocol::Keri, 0, 0, SerializationKind::Json, 0);
            assert_eq!(encode_version_string_v2(&vs), b"KERICAACAAJSONAAAA.");
            assert_eq!(encode_version_string_v2(&vs), vs.to_str().as_bytes());
        }

        #[test]
        fn encode_length_is_19() {
            let vs = make_vs(Protocol::Keri, 0, 0, SerializationKind::Json, 0);
            assert_eq!(encode_version_string_v2(&vs).len(), 19);
        }

        #[test]
        fn roundtrip_through_core_parser() {
            let vs = make_vs(Protocol::Acdc, 1, 1, SerializationKind::Json, 86);
            let encoded = encode_version_string_v2(&vs);
            let (parsed, rest) = VersionStringV2::parse(&encoded).unwrap();
            assert_eq!(parsed, vs);
            assert!(rest.is_empty());
        }
    }
}
