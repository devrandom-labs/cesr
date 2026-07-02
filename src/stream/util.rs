use crate::b64::alphabet::B64_REVERSE;
use crate::b64::encode_int;
use crate::stream::error::ParseError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};
use core::num::NonZeroUsize;

/// Decode a CESR Base64 string to an integer.
///
/// Each character contributes 6 bits, with the first character being the most
/// significant. Leading `A` characters (zero-valued) are effectively ignored,
/// just like leading zeros in decimal.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if any byte is not a valid CESR Base64
/// character.
pub(crate) fn b64_to_int(s: &[u8]) -> Result<u64, ParseError> {
    let mut value: u64 = 0;
    for &b in s {
        let digit = b64_char_to_value(b)?;
        value = value
            .checked_mul(64)
            .and_then(|v| v.checked_add(u64::from(digit)))
            .ok_or_else(|| ParseError::Malformed("B64 integer overflow".into()))?;
    }
    Ok(value)
}

/// Encode an integer as a CESR Base64 byte string of at least `width` chars.
///
/// The result is left-padded with `A` (zero) to reach at least `width` bytes,
/// widening if the value needs more. Thin byte-oriented adapter over the
/// canonical [`encode_int`]; `width` 0 is treated as 1.
pub(crate) fn int_to_b64(value: u64, width: usize) -> Vec<u8> {
    let min = NonZeroUsize::new(width.max(1)).unwrap_or(NonZeroUsize::MIN);
    encode_int(value, min).into_bytes()
}

fn b64_char_to_value(b: u8) -> Result<u8, ParseError> {
    let val = B64_REVERSE[usize::from(b)];
    if val == 255 {
        return Err(ParseError::Malformed(format!(
            "invalid B64 character: 0x{b:02x}"
        )));
    }
    Ok(val)
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

    // ── int_to_b64 keripy test vectors ──────────────────────────────────

    #[test]
    fn int_to_b64_zero_width_1() {
        assert_eq!(int_to_b64(0, 1), b"A");
    }

    #[test]
    fn int_to_b64_zero_width_4() {
        assert_eq!(int_to_b64(0, 4), b"AAAA");
    }

    #[test]
    fn int_to_b64_two_width_1() {
        assert_eq!(int_to_b64(2, 1), b"C");
    }

    #[test]
    fn int_to_b64_two_width_2() {
        assert_eq!(int_to_b64(2, 2), b"AC");
    }

    #[test]
    fn int_to_b64_65_width_2() {
        assert_eq!(int_to_b64(65, 2), b"BB");
    }

    #[test]
    fn int_to_b64_65_width_4() {
        assert_eq!(int_to_b64(65, 4), b"AABB");
    }

    #[test]
    fn int_to_b64_86_width_4() {
        // 86 = 1*64 + 22 → "BW"
        assert_eq!(int_to_b64(86, 4), b"AABW");
    }

    #[test]
    fn int_to_b64_4095_width_2() {
        // 4095 = 63*64 + 63 → "__"
        assert_eq!(int_to_b64(4095, 2), b"__");
    }

    #[test]
    fn int_to_b64_262143_width_3() {
        // 262143 = 64^3 - 1 = max 3-char B64 value → "___"
        assert_eq!(int_to_b64(262_143, 3), b"___");
    }

    #[test]
    fn int_to_b64_max_4_char() {
        // Max 4-char B64 value: 64^4 - 1 = 16777215
        assert_eq!(int_to_b64(16_777_215, 4), b"____");
    }

    // ── b64_to_int keripy test vectors ──────────────────────────────────

    #[test]
    fn b64_to_int_c() {
        assert_eq!(b64_to_int(b"C").unwrap(), 2);
    }

    #[test]
    fn b64_to_int_ac() {
        assert_eq!(b64_to_int(b"AC").unwrap(), 2);
    }

    #[test]
    fn b64_to_int_bb() {
        assert_eq!(b64_to_int(b"BB").unwrap(), 65);
    }

    #[test]
    fn b64_to_int_aabb() {
        assert_eq!(b64_to_int(b"AABB").unwrap(), 65);
    }

    #[test]
    fn b64_to_int_aabw() {
        assert_eq!(b64_to_int(b"AABW").unwrap(), 86);
    }

    #[test]
    fn b64_to_int_underscore_underscore() {
        assert_eq!(b64_to_int(b"__").unwrap(), 4095);
    }

    // ── Roundtrip tests ─────────────────────────────────────────────────

    #[test]
    fn roundtrip_zero() {
        let encoded = int_to_b64(0, 2);
        assert_eq!(b64_to_int(&encoded).unwrap(), 0);
    }

    #[test]
    fn roundtrip_small() {
        for v in 0..=100 {
            let encoded = int_to_b64(v, 2);
            assert_eq!(b64_to_int(&encoded).unwrap(), v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn roundtrip_large() {
        let value = 1_000_000_u64;
        let encoded = int_to_b64(value, 4);
        assert_eq!(b64_to_int(&encoded).unwrap(), value);
    }

    // ── Error cases ─────────────────────────────────────────────────────

    #[test]
    fn b64_to_int_invalid_char() {
        assert!(b64_to_int(b"A!B").is_err());
    }

    #[test]
    fn b64_to_int_empty_is_zero() {
        assert_eq!(b64_to_int(b"").unwrap(), 0);
    }

    // ── Width behavior ──────────────────────────────────────────────────

    #[test]
    fn int_to_b64_natural_width_exceeds_requested() {
        // 4096 = 64^2 = "BAA" (3 chars), requesting width 2
        let result = int_to_b64(4096, 2);
        assert_eq!(result, b"BAA");
    }

    #[test]
    fn int_to_b64_width_zero_nonzero_value() {
        let result = int_to_b64(1, 0);
        assert_eq!(result, b"B");
    }

    #[test]
    fn int_to_b64_width_zero_zero_value() {
        let result = int_to_b64(0, 0);
        assert_eq!(result, b"A");
    }
}
