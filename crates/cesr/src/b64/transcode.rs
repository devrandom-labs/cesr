//! Whole-blob conversion between the CESR text (qb64) and binary (qb2) domains.
//!
//! Every 4 qb64 characters encode 3 qb2 bytes. Modelled as borrowed newtypes so
//! the verbs hang off the value being converted, each offering an owned result
//! and a `*_into` variant that appends into a caller buffer (hot paths reuse one
//! allocation). The single-primitive fixed-length encoder is
//! [`super::binary::encode_binary`]; both share the 3↔4 block routines here.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec::Vec;

use super::alphabet::{B64_ALPHABET, b64_byte_to_index};
use super::error::Error;

/// A borrowed span of qb64 (Base64 text) awaiting conversion to qb2 binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qb64<'a>(pub &'a [u8]);

/// A borrowed span of qb2 (binary) awaiting conversion to qb64 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qb2<'a>(pub &'a [u8]);

/// Decode one aligned block of 4 Base64 bytes (indices 0..4) into 3 binary
/// bytes, appending to `out`. Only ever called with a `chunks_exact(4)` slice.
fn decode_block(chunk: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let v0 = b64_byte_to_index(chunk[0])?;
    let v1 = b64_byte_to_index(chunk[1])?;
    let v2 = b64_byte_to_index(chunk[2])?;
    let v3 = b64_byte_to_index(chunk[3])?;
    let bits = (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);
    out.push(truncate_u32_to_u8(bits >> 16));
    out.push(truncate_u32_to_u8(bits >> 8));
    out.push(truncate_u32_to_u8(bits));
    Ok(())
}

/// Encode one aligned block of 3 binary bytes (indices 0..3) into 4 Base64
/// bytes, appending to `out`. Only ever called with a `chunks_exact(3)` slice.
fn encode_block(chunk: &[u8], out: &mut Vec<u8>) {
    let bits = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
    out.push(B64_ALPHABET[usize_from_u32((bits >> 18) & 0x3F)]);
    out.push(B64_ALPHABET[usize_from_u32((bits >> 12) & 0x3F)]);
    out.push(B64_ALPHABET[usize_from_u32((bits >> 6) & 0x3F)]);
    out.push(B64_ALPHABET[usize_from_u32(bits & 0x3F)]);
}

impl Qb64<'_> {
    /// Decode this qb64 text to qb2 binary. Length must be a multiple of 4.
    ///
    /// # Errors
    /// [`Error::Misaligned`] if the length is not a multiple of 4, or
    /// [`Error::InvalidBase64Char`]/[`Error::InvalidBase64Value`] on a bad character.
    pub fn decode(self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.decode_into(&mut out)?;
        Ok(out)
    }

    /// Decode this qb64 text to qb2 binary, appending to `out` (never cleared).
    ///
    /// # Errors
    /// [`Error::Misaligned`] (before touching `out`) if the length is not a
    /// multiple of 4, or a character error partway through.
    pub fn decode_into(self, out: &mut Vec<u8>) -> Result<(), Error> {
        let qb64 = self.0;
        if !qb64.len().is_multiple_of(4) {
            return Err(Error::Misaligned {
                len: qb64.len(),
                unit: 4,
            });
        }
        out.reserve(qb64.len() / 4 * 3);
        for chunk in qb64.chunks_exact(4) {
            decode_block(chunk, out)?;
        }
        Ok(())
    }
}

impl Qb2<'_> {
    /// Encode this qb2 binary to qb64 text. Length must be a multiple of 3.
    ///
    /// # Errors
    /// [`Error::Misaligned`] if the length is not a multiple of 3.
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Encode this qb2 binary to qb64 text, appending to `out` (never cleared).
    ///
    /// # Errors
    /// [`Error::Misaligned`] (before touching `out`) if the length is not a
    /// multiple of 3.
    pub fn encode_into(self, out: &mut Vec<u8>) -> Result<(), Error> {
        let qb2 = self.0;
        if !qb2.len().is_multiple_of(3) {
            return Err(Error::Misaligned {
                len: qb2.len(),
                unit: 3,
            });
        }
        out.reserve(qb2.len() / 3 * 4);
        for chunk in qb2.chunks_exact(3) {
            encode_block(chunk, out);
        }
        Ok(())
    }
}

#[allow(
    clippy::as_conversions,
    reason = "masked to u8 range; `as` is the only option for bit truncation"
)]
const fn truncate_u32_to_u8(v: u32) -> u8 {
    (v & 0xFF) as u8
}

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
    reason = "test code: panics acceptable"
)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn decode_counter() {
        assert_eq!(Qb64(b"-AAB").decode().unwrap(), vec![0xF8, 0x00, 0x01]);
    }

    #[test]
    fn roundtrip_multi_block() {
        let original = b"-AAB-AAC";
        let binary = Qb64(original).decode().unwrap();
        assert_eq!(binary.len(), 6);
        assert_eq!(&Qb2(&binary).encode().unwrap(), original);
    }

    #[test]
    fn decode_rejects_misaligned() {
        assert_eq!(
            Qb64(b"ABC").decode().unwrap_err(),
            Error::Misaligned { len: 3, unit: 4 }
        );
    }

    #[test]
    fn encode_rejects_misaligned() {
        assert_eq!(
            Qb2(&[0u8, 1]).encode().unwrap_err(),
            Error::Misaligned { len: 2, unit: 3 }
        );
    }

    #[test]
    fn decode_into_leaves_buffer_untouched_on_misaligned() {
        let mut buf = vec![0x01, 0x02];
        assert!(Qb64(b"ABC").decode_into(&mut buf).is_err());
        assert_eq!(buf, vec![0x01, 0x02]);
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
}
