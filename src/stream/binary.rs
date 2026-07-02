//! Binary domain (qb2) conversion utilities for CESR.
//!
//! Converts between qb64 (Base64 text) and qb2 (binary) domains.
//! Every 4 qb64 characters encode 3 qb2 bytes.

use crate::stream::error::ParseError;
use crate::utils::utils::{B64_ALPHABET, B64_REVERSE};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};

/// Convert qb64 (Base64 text) to qb2 (binary).
///
/// Input length must be a multiple of 4. Each group of 4 B64 characters
/// produces 3 binary bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the input length is not a multiple
/// of 4 or contains invalid Base64 characters.
pub fn qb64_to_qb2(qb64: &[u8]) -> Result<Vec<u8>, ParseError> {
    if !qb64.len().is_multiple_of(4) {
        return Err(ParseError::Malformed(
            "qb64 length must be a multiple of 4".into(),
        ));
    }

    let mut out = Vec::with_capacity(qb64.len() / 4 * 3);
    for chunk in qb64.chunks_exact(4) {
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        let v2 = b64_val(chunk[2])?;
        let v3 = b64_val(chunk[3])?;

        let bits =
            (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);
        out.push(truncate_u32_to_u8(bits >> 16));
        out.push(truncate_u32_to_u8(bits >> 8));
        out.push(truncate_u32_to_u8(bits));
    }
    Ok(out)
}

/// Convert qb2 (binary) to qb64 (Base64 text).
///
/// Input length must be a multiple of 3. Each group of 3 binary bytes
/// produces 4 B64 characters.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the input length is not a multiple of 3.
pub fn qb2_to_qb64(qb2: &[u8]) -> Result<Vec<u8>, ParseError> {
    if !qb2.len().is_multiple_of(3) {
        return Err(ParseError::Malformed(
            "qb2 length must be a multiple of 3".into(),
        ));
    }

    let mut out = Vec::with_capacity(qb2.len() / 3 * 4);
    for chunk in qb2.chunks_exact(3) {
        let bits = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(B64_ALPHABET[usize_from_u32((bits >> 18) & 0x3F)]);
        out.push(B64_ALPHABET[usize_from_u32((bits >> 12) & 0x3F)]);
        out.push(B64_ALPHABET[usize_from_u32((bits >> 6) & 0x3F)]);
        out.push(B64_ALPHABET[usize_from_u32(bits & 0x3F)]);
    }
    Ok(out)
}

/// Truncate a `u32` to `u8` by masking the low byte.
#[allow(
    clippy::as_conversions,
    reason = "masked to u8 range; `as` is the only option for bit truncation"
)]
const fn truncate_u32_to_u8(v: u32) -> u8 {
    (v & 0xFF) as u8
}

/// Convert a `u32` known to be in `[0, 63]` to `usize` for indexing.
#[allow(
    clippy::as_conversions,
    reason = "value masked to 6 bits, always fits in usize"
)]
const fn usize_from_u32(v: u32) -> usize {
    v as usize
}

fn b64_val(byte: u8) -> Result<u8, ParseError> {
    let val = B64_REVERSE[usize::from(byte)];
    if val == 255 {
        return Err(ParseError::Malformed(format!(
            "invalid Base64 character: 0x{byte:02x}"
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

    #[test]
    fn qb64_to_qb2_counter() {
        // '-AAB' -> '-' = 62, 'A' = 0, 'A' = 0, 'B' = 1
        // Bits: 111110_000000_000000_000001 = 0xF8_0x00_0x01
        let qb64 = b"-AAB";
        let qb2 = qb64_to_qb2(qb64).unwrap();
        assert_eq!(qb2, vec![0xF8, 0x00, 0x01]);
    }

    #[test]
    fn qb64_to_qb2_all_zeros() {
        let qb64 = b"AAAA";
        let qb2 = qb64_to_qb2(qb64).unwrap();
        assert_eq!(qb2, vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn qb64_to_qb2_all_ones() {
        // '____' -> 63,63,63,63 = 0xFF,0xFF,0xFF
        let qb64 = b"____";
        let qb2 = qb64_to_qb2(qb64).unwrap();
        assert_eq!(qb2, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn qb2_to_qb64_roundtrip() {
        let original = b"-AAF";
        let binary = qb64_to_qb2(original).unwrap();
        let text = qb2_to_qb64(&binary).unwrap();
        assert_eq!(&text, original);
    }

    #[test]
    fn qb2_to_qb64_counter_roundtrip() {
        // 8 chars for a big counter
        let original = b"--TAACAB";
        let binary = qb64_to_qb2(original).unwrap();
        let text = qb2_to_qb64(&binary).unwrap();
        assert_eq!(&text, original);
    }

    #[test]
    fn qb64_length_must_be_multiple_of_4() {
        assert!(qb64_to_qb2(b"-AA").is_err());
        assert!(qb64_to_qb2(b"-").is_err());
        assert!(qb64_to_qb2(b"-AABB-").is_err());
    }

    #[test]
    fn qb2_length_must_be_multiple_of_3() {
        assert!(qb2_to_qb64(&[0xF8, 0x00]).is_err());
        assert!(qb2_to_qb64(&[0x00]).is_err());
    }

    #[test]
    fn qb64_invalid_character() {
        assert!(qb64_to_qb2(b"-A!B").is_err());
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(qb64_to_qb2(b"").unwrap(), Vec::<u8>::new());
        assert_eq!(qb2_to_qb64(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn multi_block_roundtrip() {
        // 8 chars = 2 blocks -> 6 bytes
        let original = b"-AAB-AAC";
        let binary = qb64_to_qb2(original).unwrap();
        assert_eq!(binary.len(), 6);
        let text = qb2_to_qb64(&binary).unwrap();
        assert_eq!(&text, original);
    }
}
