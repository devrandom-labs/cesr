//! Binary domain (qb2) conversion between the CESR text and binary domains.
//!
//! Every 4 qb64 characters encode 3 qb2 bytes. The two domains are modelled as
//! borrowed newtypes rather than free functions so the conversion verbs hang
//! off the value being converted and each offers both an owned result and a
//! `*_into` variant that appends into a caller-supplied buffer (letting hot
//! paths reuse one allocation across many conversions):
//!
//! - [`Qb64`] wraps qb64 text and [`decode`](Qb64::decode)s it to binary.
//! - [`Qb2`] wraps qb2 binary and [`encode`](Qb2::encode)s it to qb64 text.

use crate::error::ParseError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use cesr::b64::alphabet::{B64_ALPHABET, b64_byte_to_index};

/// A borrowed span of qb64 (Base64 text) awaiting conversion to the binary
/// (qb2) domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qb64<'a>(pub &'a [u8]);

/// A borrowed span of qb2 (binary) awaiting conversion to the text (qb64)
/// domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qb2<'a>(pub &'a [u8]);

impl Qb64<'_> {
    /// Decode this qb64 text to qb2 binary.
    ///
    /// Length must be a multiple of 4; each group of 4 B64 characters produces
    /// 3 binary bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Misaligned`] if the length is not a multiple of 4,
    /// or [`ParseError::Base64`] if it contains invalid Base64 characters.
    pub fn decode(self) -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::new();
        self.decode_into(&mut out)?;
        Ok(out)
    }

    /// Decode this qb64 text to qb2 binary, appending to `out`.
    ///
    /// `out` is never cleared — the decoded bytes are appended after any
    /// existing contents, so a caller can reuse one buffer across conversions.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Misaligned`] (before touching `out`) if the length
    /// is not a multiple of 4, or [`ParseError::Base64`] on an invalid
    /// character. On a `Base64` error `out` may hold bytes decoded before the
    /// offending character; discard it if the whole conversion must be atomic.
    pub fn decode_into(self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        let qb64 = self.0;
        if !qb64.len().is_multiple_of(4) {
            return Err(ParseError::Misaligned {
                len: qb64.len(),
                unit: 4,
            });
        }

        out.reserve(qb64.len() / 4 * 3);
        for chunk in qb64.chunks_exact(4) {
            let v0 = b64_byte_to_index(chunk[0])?;
            let v1 = b64_byte_to_index(chunk[1])?;
            let v2 = b64_byte_to_index(chunk[2])?;
            let v3 = b64_byte_to_index(chunk[3])?;

            let bits = (u32::from(v0) << 18)
                | (u32::from(v1) << 12)
                | (u32::from(v2) << 6)
                | u32::from(v3);
            out.push(truncate_u32_to_u8(bits >> 16));
            out.push(truncate_u32_to_u8(bits >> 8));
            out.push(truncate_u32_to_u8(bits));
        }
        Ok(())
    }
}

impl Qb2<'_> {
    /// Encode this qb2 binary to qb64 text.
    ///
    /// Length must be a multiple of 3; each group of 3 binary bytes produces 4
    /// B64 characters.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Misaligned`] if the length is not a multiple of 3.
    pub fn encode(self) -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Encode this qb2 binary to qb64 text, appending to `out`.
    ///
    /// `out` is never cleared — the text bytes are appended after any existing
    /// contents, so a caller can reuse one buffer across conversions.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Misaligned`] (before touching `out`) if the length
    /// is not a multiple of 3.
    pub fn encode_into(self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        let qb2 = self.0;
        if !qb2.len().is_multiple_of(3) {
            return Err(ParseError::Misaligned {
                len: qb2.len(),
                unit: 3,
            });
        }

        out.reserve(qb2.len() / 3 * 4);
        for chunk in qb2.chunks_exact(3) {
            let bits =
                (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            out.push(B64_ALPHABET[usize_from_u32((bits >> 18) & 0x3F)]);
            out.push(B64_ALPHABET[usize_from_u32((bits >> 12) & 0x3F)]);
            out.push(B64_ALPHABET[usize_from_u32((bits >> 6) & 0x3F)]);
            out.push(B64_ALPHABET[usize_from_u32(bits & 0x3F)]);
        }
        Ok(())
    }
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
    fn decode_counter() {
        // '-AAB' -> '-' = 62, 'A' = 0, 'A' = 0, 'B' = 1
        // Bits: 111110_000000_000000_000001 = 0xF8_0x00_0x01
        let qb2 = Qb64(b"-AAB").decode().unwrap();
        assert_eq!(qb2, vec![0xF8, 0x00, 0x01]);
    }

    #[test]
    fn decode_all_zeros() {
        let qb2 = Qb64(b"AAAA").decode().unwrap();
        assert_eq!(qb2, vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn decode_all_ones() {
        // '____' -> 63,63,63,63 = 0xFF,0xFF,0xFF
        let qb2 = Qb64(b"____").decode().unwrap();
        assert_eq!(qb2, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn encode_roundtrip() {
        let original = b"-AAF";
        let binary = Qb64(original).decode().unwrap();
        let text = Qb2(&binary).encode().unwrap();
        assert_eq!(&text, original);
    }

    #[test]
    fn encode_counter_roundtrip() {
        // 8 chars for a big counter
        let original = b"--TAACAB";
        let binary = Qb64(original).decode().unwrap();
        let text = Qb2(&binary).encode().unwrap();
        assert_eq!(&text, original);
    }

    #[test]
    fn decode_length_must_be_multiple_of_4() {
        assert!(Qb64(b"-AA").decode().is_err());
        assert!(Qb64(b"-").decode().is_err());
        assert!(Qb64(b"-AABB-").decode().is_err());
    }

    #[test]
    fn encode_length_must_be_multiple_of_3() {
        assert!(Qb2(&[0xF8, 0x00]).encode().is_err());
        assert!(Qb2(&[0x00]).encode().is_err());
    }

    #[test]
    fn decode_invalid_character() {
        assert!(Qb64(b"-A!B").decode().is_err());
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(Qb64(b"").decode().unwrap(), Vec::<u8>::new());
        assert_eq!(Qb2(&[]).encode().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn multi_block_roundtrip() {
        // 8 chars = 2 blocks -> 6 bytes
        let original = b"-AAB-AAC";
        let binary = Qb64(original).decode().unwrap();
        assert_eq!(binary.len(), 6);
        let text = Qb2(&binary).encode().unwrap();
        assert_eq!(&text, original);
    }

    #[test]
    fn decode_rejects_misaligned_length() {
        // 3 bytes, not a multiple of 4.
        assert_eq!(
            Qb64(b"ABC").decode().unwrap_err(),
            ParseError::Misaligned { len: 3, unit: 4 }
        );
    }

    #[test]
    fn encode_rejects_misaligned_length() {
        // 2 bytes, not a multiple of 3.
        assert_eq!(
            Qb2(&[0u8, 1]).encode().unwrap_err(),
            ParseError::Misaligned { len: 2, unit: 3 }
        );
    }

    #[test]
    fn decode_into_appends_and_reuses_buffer() {
        let mut buf = vec![0xAA, 0xBB];
        Qb64(b"-AAB").decode_into(&mut buf).unwrap();
        // Existing bytes preserved; decoded bytes appended.
        assert_eq!(buf, vec![0xAA, 0xBB, 0xF8, 0x00, 0x01]);
        // Second conversion into the same buffer keeps appending.
        Qb64(b"AAAA").decode_into(&mut buf).unwrap();
        assert_eq!(buf, vec![0xAA, 0xBB, 0xF8, 0x00, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_into_appends_and_reuses_buffer() {
        let mut buf = b"pre".to_vec();
        Qb2(&[0xF8, 0x00, 0x01]).encode_into(&mut buf).unwrap();
        assert_eq!(&buf, b"pre-AAB");
    }

    #[test]
    fn decode_into_leaves_buffer_untouched_on_misaligned() {
        let mut buf = vec![0x01, 0x02];
        assert!(Qb64(b"ABC").decode_into(&mut buf).is_err());
        assert_eq!(buf, vec![0x01, 0x02]);
    }

    #[test]
    fn owned_and_into_agree() {
        let original = b"--TAACAB";
        let owned = Qb64(original).decode().unwrap();
        let mut into = Vec::new();
        Qb64(original).decode_into(&mut into).unwrap();
        assert_eq!(owned, into);
    }
}
