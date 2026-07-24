//! CESR qb64 counter encoding, attached to the counter-code enums.
//!
//! Group encoding lives on the group carriers themselves — see
//! [`CesrEncode`](crate::version::CesrEncode) and
//! [`crate::group`]. This module owns the shared counter encoders
//! they build on: [`CounterCodeV1::encode_count`] /
//! [`CounterCodeV2::encode_count`] and their auto-promoting twins.
//! (V2 version strings render via
//! [`VersionStringV2::to_str`](cesr::core::version::VersionStringV2::to_str),
//! the single owner of the V2 frame layout.)

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec, vec::Vec};
use core::num::NonZeroUsize;

use cesr::b64::encode_int;
use cesr::core::counter::CounterCodeV1;
use cesr::core::counter::CounterCodeV2;

use crate::error::{ParseError, SpanKind};

// ── Counter encoding ─────────────────────────────────────────────────────

/// Validate that `count` fits the `ss`-character soft field (the counter
/// capacity keripy enforces at `counting.py:878-880` — count in
/// `[0, 64^ss - 1]`), returning the soft size as [`NonZeroUsize`].
///
/// Without this check `encode_int` would grow past the soft width and emit
/// a corrupt (over-long) counter.
fn check_counter_capacity(ss: usize, count: u32) -> Result<NonZeroUsize, ParseError> {
    let ss_nz = NonZeroUsize::new(ss).ok_or(ParseError::Overflow(SpanKind::CounterSoftSize))?;
    let capacity = u32::try_from(ss)
        .ok()
        .and_then(|bits| 64_u64.checked_pow(bits))
        .and_then(|full| full.checked_sub(1))
        .ok_or(ParseError::Overflow(SpanKind::CounterSoftSize))?;
    if u64::from(count) > capacity {
        return Err(ParseError::CountExceedsCapacity {
            count: u64::from(count),
            capacity,
        });
    }
    Ok(ss_nz)
}

/// qb64 encoding for the core-owned counter-code enums.
///
/// A crate-local extension trait over [`CounterCodeV1`]/[`CounterCodeV2`]:
/// the encoding is stream behavior (it returns [`ParseError`] and shares this
/// module's helpers), so it cannot be an inherent impl on a type defined in
/// `cesr::core` (orphan rules).
pub trait EncodeCount {
    /// Encode this counter code + count as qb64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::CountExceedsCapacity`] if the count does not fit
    /// in the counter's soft field.
    fn encode_count(self, count: u32) -> Result<Vec<u8>, ParseError>;

    /// Encode this counter, auto-promoting to the big variant when `count`
    /// overflows this code's own soft field.
    ///
    /// The capacity is always derived from [`soft_size`](CounterCodeV1::soft_size)
    /// (`64^ss - 1`), never assumed: ss=2 codes hold 4095, the genus-version
    /// code (ss=3) holds 262,143, and the big codes (ss=5) hold
    /// 1,073,741,823. Only a code that both overflows and has a big variant
    /// is promoted; one that already fits encodes in place.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::CountExceedsCapacity`] — carrying the derived
    /// capacity of the code that failed — when `count` overflows and no big
    /// variant exists, or overflows the big variant too.
    fn encode_count_auto(self, count: u32) -> Result<Vec<u8>, ParseError>;
}

impl EncodeCount for CounterCodeV1 {
    fn encode_count(self, count: u32) -> Result<Vec<u8>, ParseError> {
        let hard = self.as_str();
        let ss_nz = check_counter_capacity(self.soft_size(), count)?;
        let soft = encode_int(count, ss_nz);
        Ok(format!("{hard}{soft}").into_bytes())
    }

    fn encode_count_auto(self, count: u32) -> Result<Vec<u8>, ParseError> {
        match self.encode_count(count) {
            Err(overflow @ ParseError::CountExceedsCapacity { .. }) => self
                .to_big()
                .map_or(Err(overflow), |big| big.encode_count(count)),
            other => other,
        }
    }
}

impl EncodeCount for CounterCodeV2 {
    fn encode_count(self, count: u32) -> Result<Vec<u8>, ParseError> {
        let hard = self.as_str();
        let ss_nz = check_counter_capacity(self.soft_size(), count)?;
        let soft = encode_int(count, ss_nz);
        Ok(format!("{hard}{soft}").into_bytes())
    }

    fn encode_count_auto(self, count: u32) -> Result<Vec<u8>, ParseError> {
        match self.encode_count(count) {
            Err(overflow @ ParseError::CountExceedsCapacity { .. }) => self
                .to_big()
                .map_or(Err(overflow), |big| big.encode_count(count)),
            other => other,
        }
    }
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
        let bytes = CounterCodeV1::ControllerIdxSigs.encode_count(2).unwrap();
        assert_eq!(&bytes, b"-AAC");
    }

    #[test]
    fn encode_v1_controller_idx_sigs_count_0() {
        let bytes = CounterCodeV1::ControllerIdxSigs.encode_count(0).unwrap();
        assert_eq!(&bytes, b"-AAA");
    }

    #[test]
    fn encode_v1_controller_idx_sigs_count_1() {
        let bytes = CounterCodeV1::ControllerIdxSigs.encode_count(1).unwrap();
        assert_eq!(&bytes, b"-AAB");
    }

    #[test]
    fn encode_v1_witness_idx_sigs() {
        let bytes = CounterCodeV1::WitnessIdxSigs.encode_count(3).unwrap();
        assert_eq!(&bytes, b"-BAD");
    }

    #[test]
    fn encode_v1_attachment_group() {
        let bytes = CounterCodeV1::AttachmentGroup.encode_count(23).unwrap();
        assert_eq!(&bytes, b"-VAX");
    }

    #[test]
    fn encode_v2_controller_idx_sigs_count_2() {
        let bytes = CounterCodeV2::ControllerIdxSigs.encode_count(2).unwrap();
        assert_eq!(&bytes, b"-KAC");
    }

    #[test]
    fn encode_v2_attachment_group() {
        let bytes = CounterCodeV2::AttachmentGroup.encode_count(23).unwrap();
        assert_eq!(&bytes, b"-CAX");
    }

    #[test]
    fn encode_v1_roundtrip() {
        use crate::parse::TextStream;

        let original_code = CounterCodeV1::SealSourceCouples;
        let original_count = 5_u32;
        let encoded = original_code.encode_count(original_count).unwrap();
        let mut ts = TextStream::new(&encoded);
        let (decoded_code, decoded_count) = ts.read_counter_v1().unwrap();
        assert_eq!(decoded_code, original_code);
        assert_eq!(decoded_count, original_count);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn encode_v2_roundtrip() {
        use crate::parse::TextStream;

        let original_code = CounterCodeV2::SealSourceCouples;
        let original_count = 5_u32;
        let encoded = original_code.encode_count(original_count).unwrap();
        let mut ts = TextStream::new(&encoded);
        let (decoded_code, decoded_count) = ts.read_counter_v2().unwrap();
        assert_eq!(decoded_code, original_code);
        assert_eq!(decoded_count, original_count);
        assert!(ts.remaining().is_empty());
    }

    // ── Counter capacity tests ────────────────────────────────────────────

    #[test]
    fn encode_v1_small_counter_at_capacity_boundary() {
        let bytes = CounterCodeV1::ControllerIdxSigs.encode_count(4095).unwrap();
        assert_eq!(&bytes, b"-A__");
    }

    #[test]
    fn encode_v1_small_counter_over_capacity_is_rejected() {
        // Without the capacity check the soft field would grow to 3 chars and
        // emit a corrupt 5-byte counter (keripy raises InvalidVarIndexError
        // for the same shape, counting.py:878-880).
        let err = CounterCodeV1::ControllerIdxSigs
            .encode_count(4096)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
        );
    }

    #[test]
    fn encode_v1_big_counter_at_capacity_boundary() {
        let bytes = CounterCodeV1::BigAttachmentGroup
            .encode_count(1_073_741_823)
            .unwrap();
        assert_eq!(&bytes, b"--V_____");
    }

    #[test]
    fn encode_v1_big_counter_over_capacity_is_rejected() {
        let err = CounterCodeV1::BigAttachmentGroup
            .encode_count(1_073_741_824)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 1_073_741_824,
                capacity: 1_073_741_823
            }
        );
    }

    #[test]
    fn encode_v2_small_counter_over_capacity_is_rejected() {
        let err = CounterCodeV2::ControllerIdxSigs
            .encode_count(4096)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
        );
    }

    // ── Counter auto-promotion tests ──────────────────────────────────────

    #[test]
    fn auto_promote_v1_small_count_stays_small() {
        let result = CounterCodeV1::GenericGroup.encode_count_auto(100).unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.starts_with(b"-T"));
    }

    #[test]
    fn auto_promote_v1_large_count_promotes() {
        let result = CounterCodeV1::GenericGroup.encode_count_auto(8193).unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.starts_with(b"--T"));
    }

    #[test]
    fn auto_promote_v1_boundary() {
        let small = CounterCodeV1::GenericGroup.encode_count_auto(4095).unwrap();
        assert_eq!(small.len(), 4);
        let big = CounterCodeV1::GenericGroup.encode_count_auto(4096).unwrap();
        assert_eq!(big.len(), 8);
    }

    #[test]
    fn auto_promote_v1_no_big_variant_errors() {
        let err = CounterCodeV1::ControllerIdxSigs
            .encode_count_auto(4096)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
        );
    }

    #[test]
    fn auto_promote_v1_already_big_accepts_count_over_4095() {
        use crate::parse::TextStream;

        let encoded = CounterCodeV1::BigAttachmentGroup
            .encode_count_auto(5000)
            .unwrap();
        assert_eq!(&encoded, b"--VAABOI");
        let mut ts = TextStream::new(&encoded);
        assert_eq!(
            ts.read_counter_v1().unwrap(),
            (CounterCodeV1::BigAttachmentGroup, 5000)
        );
    }

    #[test]
    fn auto_promote_v1_genus_version_accepts_count_over_4095() {
        use crate::parse::TextStream;

        let encoded = CounterCodeV1::KERIACDCGenusVersion
            .encode_count_auto(5000)
            .unwrap();
        assert_eq!(&encoded, b"-_AAABOI");
        let mut ts = TextStream::new(&encoded);
        assert_eq!(
            ts.read_counter_v1().unwrap(),
            (CounterCodeV1::KERIACDCGenusVersion, 5000)
        );
    }

    #[test]
    fn auto_promote_v1_genus_version_over_its_own_capacity_is_rejected() {
        let err = CounterCodeV1::KERIACDCGenusVersion
            .encode_count_auto(262_144)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 262_144,
                capacity: 262_143
            }
        );
    }

    #[test]
    fn auto_promote_v1_attachment_group_still_promotes() {
        use crate::parse::TextStream;

        let encoded = CounterCodeV1::AttachmentGroup
            .encode_count_auto(5000)
            .unwrap();
        let mut ts = TextStream::new(&encoded);
        assert_eq!(
            ts.read_counter_v1().unwrap(),
            (CounterCodeV1::BigAttachmentGroup, 5000)
        );
    }

    #[test]
    fn auto_promote_v2_already_big_accepts_count_over_4095() {
        use crate::parse::TextStream;

        let encoded = CounterCodeV2::BigControllerIdxSigs
            .encode_count_auto(5000)
            .unwrap();
        let mut ts = TextStream::new(&encoded);
        assert_eq!(
            ts.read_counter_v2().unwrap(),
            (CounterCodeV2::BigControllerIdxSigs, 5000)
        );
    }

    #[test]
    fn auto_promote_v2_genus_version_accepts_count_over_4095() {
        use crate::parse::TextStream;

        let encoded = CounterCodeV2::KERIACDCGenusVersion
            .encode_count_auto(5000)
            .unwrap();
        let mut ts = TextStream::new(&encoded);
        assert_eq!(
            ts.read_counter_v2().unwrap(),
            (CounterCodeV2::KERIACDCGenusVersion, 5000)
        );
    }

    #[test]
    fn auto_promote_v2_big_over_its_own_capacity_is_rejected() {
        let err = CounterCodeV2::BigControllerIdxSigs
            .encode_count_auto(1_073_741_824)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 1_073_741_824,
                capacity: 1_073_741_823
            }
        );
    }

    #[test]
    fn auto_promote_v2_large_count_promotes() {
        let result = CounterCodeV2::ControllerIdxSigs
            .encode_count_auto(8193)
            .unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.starts_with(b"--K"));
    }

    #[test]
    fn auto_promote_v2_small_count_stays_small() {
        let result = CounterCodeV2::ControllerIdxSigs
            .encode_count_auto(100)
            .unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.starts_with(b"-K"));
    }
}
