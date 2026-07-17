use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, vec, vec::Vec};
use core::num::NonZeroUsize;

use base64::{Engine, engine::general_purpose as b64};

use super::code::{IndexMode, IndexedSigCode, hardage};
use super::error::{IndexerParseError, IndexerValidationError};
use super::indexer::Indexer;
use super::xizage::XizageSize;
use crate::b64::{decode_int, encode_binary};

// ── Type states ────────────────────────────────────────────────────────

/// Initial type-state for [`IndexerBuilder`]: no code or index set yet.
#[derive(Debug)]
pub struct IStart;

/// Type-state for [`IndexerBuilder`] after a code has been selected.
#[derive(Debug)]
pub struct IWithCode {
    code: IndexedSigCode,
}

/// Type-state for [`IndexerBuilder`] after a code and index have been set.
#[derive(Debug)]
pub struct IWithIndex {
    code: IndexedSigCode,
    index: u32,
    ondex: Option<u32>,
}

// ── Builder ────────────────────────────────────────────────────────────

/// Type-state builder for constructing and parsing [`Indexer`] primitives.
#[derive(Debug)]
pub struct IndexerBuilder<S> {
    state: S,
}

impl Default for IndexerBuilder<IStart> {
    fn default() -> Self {
        Self { state: IStart }
    }
}

impl IndexerBuilder<IStart> {
    /// Creates a new `IndexerBuilder` in the initial state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the indexed signature code, advancing the builder to the next state.
    #[must_use]
    pub const fn with_code(self, code: IndexedSigCode) -> IndexerBuilder<IWithCode> {
        IndexerBuilder {
            state: IWithCode { code },
        }
    }

    /// Parse an [`Indexer`] from a qualified Base64 (qb64) stream.
    ///
    /// Returns the parsed `Indexer` and the number of bytes consumed from the
    /// input.
    ///
    /// # Errors
    ///
    /// Returns [`IndexerParseError`] if the stream is empty, too short, contains
    /// invalid Base64, or has an unrecognized code.
    #[allow(
        clippy::too_many_lines,
        reason = "sequential parsing steps that are clearer together"
    )]
    pub fn from_qb64(self, stream: &[u8]) -> Result<(Indexer<'static>, usize), IndexerParseError> {
        let &first_byte = stream.first().ok_or(IndexerParseError::EmptyStream)?;

        let first_char = char::from(first_byte);
        let hard_size = hardage(first_char)
            .ok_or_else(|| IndexerParseError::UnknownCode(format!("{first_char}")))?;

        if stream.len() < hard_size {
            return Err(IndexerParseError::StreamTooShort {
                need: hard_size,
                got: stream.len(),
            });
        }

        let hard = core::str::from_utf8(&stream[..hard_size])
            .map_err(|_| IndexerParseError::InvalidBase64)?;
        let code = IndexedSigCode::from_hard(hard).map_err(IndexerParseError::from)?;

        let xizage = code.get_xizage();
        let hs = usize::from(xizage.hs);
        let ss = usize::from(xizage.ss);
        let os = usize::from(xizage.os);
        let ls = usize::from(xizage.ls);
        let cs = hs + ss;
        let ms = ss - os;

        if stream.len() < cs {
            return Err(IndexerParseError::StreamTooShort {
                need: cs,
                got: stream.len(),
            });
        }

        let index_str = core::str::from_utf8(&stream[hs..hs + ms])
            .map_err(|_| IndexerParseError::InvalidBase64)?;
        let index: u32 = decode_int(index_str).map_err(IndexerParseError::from)?;

        let ondex = match code.mode() {
            IndexMode::CurrentOnly => {
                if os > 0 {
                    let ondex_str = core::str::from_utf8(&stream[hs + ms..hs + ms + os])
                        .map_err(|_| IndexerParseError::InvalidBase64)?;
                    let ondex_val: u32 = decode_int(ondex_str).map_err(IndexerParseError::from)?;
                    if ondex_val != 0 {
                        return Err(IndexerParseError::OndexNotZeroForCurrentOnly(ondex_val));
                    }
                }
                None
            }
            IndexMode::Both => {
                if os > 0 {
                    let ondex_str = core::str::from_utf8(&stream[hs + ms..hs + ms + os])
                        .map_err(|_| IndexerParseError::InvalidBase64)?;
                    let ondex_val: u32 = decode_int(ondex_str).map_err(IndexerParseError::from)?;
                    Some(ondex_val)
                } else {
                    Some(index)
                }
            }
        };

        let fs = match xizage.fs {
            XizageSize::Fixed(n) => usize::from(n),
            XizageSize::Variable => {
                #[allow(
                    clippy::as_conversions,
                    reason = "u32 to usize is a safe widening cast"
                )]
                let idx = index as usize;
                compute_full_size(idx, cs)?
            }
        };

        if stream.len() < fs {
            return Err(IndexerParseError::StreamTooShort {
                need: fs,
                got: stream.len(),
            });
        }

        let ps = cs % 4;
        let payload = &stream[cs..fs];
        let mut temp = Vec::with_capacity(ps + payload.len());
        temp.extend(core::iter::repeat_n(b'A', ps));
        temp.extend_from_slice(payload);
        let decoded = b64::URL_SAFE_NO_PAD
            .decode(&temp)
            .map_err(|_| IndexerParseError::InvalidBase64)?;
        let skip = if ps != 0 { ps } else { ls };
        let raw = decoded[skip..].to_vec();

        Ok((Indexer::new(code, index, ondex, Cow::Owned(raw)), fs))
    }

    /// Parse an [`Indexer`] from a qualified binary (qb2) stream.
    ///
    /// Returns the parsed `Indexer` and the number of binary bytes consumed
    /// from the input.
    ///
    /// # Errors
    ///
    /// Returns [`IndexerParseError`] if the stream is empty, too short, contains
    /// invalid data, or has an unrecognized code.
    pub fn from_qb2(self, stream: &[u8]) -> Result<(Indexer<'static>, usize), IndexerParseError> {
        let &first_byte = stream.first().ok_or(IndexerParseError::EmptyStream)?;

        let first_sextet = first_byte >> 2;
        let hs: usize = match first_sextet {
            0..=51 => 1,
            52..=56 => 2,
            _ => {
                return Err(IndexerParseError::UnknownCode(format!(
                    "binary lead byte 0x{first_byte:02x}",
                )));
            }
        };

        let bhs = (hs * 3).div_ceil(4);
        if stream.len() < bhs {
            return Err(IndexerParseError::StreamTooShort {
                need: bhs,
                got: stream.len(),
            });
        }

        let char_len = NonZeroUsize::new(hs)
            .ok_or_else(|| IndexerParseError::UnknownCode("zero hard size".to_owned()))?;
        let hard_b64 = encode_binary(&stream[..bhs], char_len).map_err(IndexerParseError::from)?;
        let hard = &hard_b64[..hs];
        let code = IndexedSigCode::from_hard(hard).map_err(IndexerParseError::from)?;

        let xizage = code.get_xizage();
        let ss = usize::from(xizage.ss);
        let cs = hs + ss;

        let bcs = (cs * 3).div_ceil(4);
        if stream.len() < bcs {
            return Err(IndexerParseError::StreamTooShort {
                need: bcs,
                got: stream.len(),
            });
        }

        let cs_nz = NonZeroUsize::new(cs)
            .ok_or_else(|| IndexerParseError::UnknownCode("zero code size".to_owned()))?;
        let both_b64 = encode_binary(&stream[..bcs], cs_nz).map_err(IndexerParseError::from)?;

        let soft = &both_b64[hs..cs];
        let os = usize::from(xizage.os);
        let ms = ss - os;

        let index: u32 = decode_int(&soft[..ms]).map_err(IndexerParseError::from)?;

        let fs: usize = match xizage.fs {
            XizageSize::Fixed(n) => usize::from(n),
            XizageSize::Variable => {
                #[allow(
                    clippy::as_conversions,
                    reason = "u32 to usize is a safe widening cast"
                )]
                let idx = index as usize;
                compute_full_size(idx, cs)?
            }
        };

        let bfs = fs * 3 / 4;
        if stream.len() < bfs {
            return Err(IndexerParseError::StreamTooShort {
                need: bfs,
                got: stream.len(),
            });
        }

        let qb64 = b64::URL_SAFE_NO_PAD.encode(&stream[..bfs]);
        let (indexer, _) = Self::new().from_qb64(qb64.as_bytes())?;

        Ok((indexer, bfs))
    }
}

/// Checked full char size `fs = index * 4 + cs`. `index` is attacker-controlled,
/// so the arithmetic is checked (mirrors matter's `compute_full_size`).
#[inline]
fn compute_full_size(index: usize, cs: usize) -> Result<usize, IndexerParseError> {
    index
        .checked_mul(4)
        .and_then(|quad| quad.checked_add(cs))
        .ok_or(IndexerParseError::SizeOverflow)
}

impl IndexedSigCode {
    /// Full qb64 character size of the indexed primitive at the head of `stream`,
    /// without decoding raw bytes.
    ///
    /// # Errors
    /// `IndexerParseError` on unknown code, short stream, bad UTF-8, or size overflow.
    pub fn frame_size(stream: &[u8]) -> Result<usize, IndexerParseError> {
        let &first = stream.first().ok_or(IndexerParseError::EmptyStream)?;
        let hard_size = hardage(char::from(first))
            .ok_or_else(|| IndexerParseError::UnknownCode(format!("{}", char::from(first))))?;
        if stream.len() < hard_size {
            return Err(IndexerParseError::StreamTooShort {
                need: hard_size,
                got: stream.len(),
            });
        }
        let hard = core::str::from_utf8(&stream[..hard_size])
            .map_err(|_| IndexerParseError::InvalidBase64)?;
        Self::from_hard(hard)
            .map_err(IndexerParseError::from)?
            .frame_size_of(stream)
    }

    /// `frame_size` for an already-known code — shared with `from_qb64` so there
    /// is exactly one size implementation.
    pub(crate) fn frame_size_of(self, stream: &[u8]) -> Result<usize, IndexerParseError> {
        let xizage = self.get_xizage();
        let hs = usize::from(xizage.hs);
        let ss = usize::from(xizage.ss);
        let os = usize::from(xizage.os);
        let cs = hs + ss;
        let ms = ss - os;
        match xizage.fs {
            XizageSize::Fixed(n) => Ok(usize::from(n)),
            XizageSize::Variable => {
                if stream.len() < cs {
                    return Err(IndexerParseError::StreamTooShort {
                        need: cs,
                        got: stream.len(),
                    });
                }
                let index_str = core::str::from_utf8(&stream[hs..hs + ms])
                    .map_err(|_| IndexerParseError::InvalidBase64)?;
                let index: usize = decode_int(index_str).map_err(IndexerParseError::from)?;
                compute_full_size(index, cs)
            }
        }
    }
}

impl IndexerBuilder<IWithCode> {
    /// Sets the signer index.
    ///
    /// For `Both` codes the ondex is automatically set equal to the index.
    /// For `CurrentOnly` codes the ondex is set to `None`.
    ///
    /// # Errors
    ///
    /// Returns [`IndexerValidationError::IndexTooLarge`] if `index` exceeds the
    /// code's maximum.
    pub const fn with_index(
        self,
        index: u32,
    ) -> Result<IndexerBuilder<IWithIndex>, IndexerValidationError> {
        if index > self.state.code.max_index() {
            return Err(IndexerValidationError::IndexTooLarge {
                code: self.state.code,
                index,
                max: self.state.code.max_index(),
            });
        }
        let ondex = match self.state.code.mode() {
            IndexMode::Both => Some(index),
            IndexMode::CurrentOnly => None,
        };
        Ok(IndexerBuilder {
            state: IWithIndex {
                code: self.state.code,
                index,
                ondex,
            },
        })
    }

    /// Sets both the signer index and the explicit ondex.
    ///
    /// Only valid for `Both` codes. Returns an error if the code is
    /// `CurrentOnly`, or if either index exceeds its maximum.
    ///
    /// # Errors
    ///
    /// Returns [`IndexerValidationError`] if the code is `CurrentOnly`, or if
    /// either index or ondex exceeds the code's maximum capacity.
    pub fn with_indices(
        self,
        index: u32,
        ondex: u32,
    ) -> Result<IndexerBuilder<IWithIndex>, IndexerValidationError> {
        // Reject CurrentOnly codes — they have no ondex field.
        if self.state.code.mode() == IndexMode::CurrentOnly {
            return Err(IndexerValidationError::OndexOnCurrentOnly(self.state.code));
        }
        // Validate index.
        if index > self.state.code.max_index() {
            return Err(IndexerValidationError::IndexTooLarge {
                code: self.state.code,
                index,
                max: self.state.code.max_index(),
            });
        }
        // Validate ondex.
        if let Some(max_ondex) = self.state.code.max_ondex()
            && ondex > max_ondex
        {
            return Err(IndexerValidationError::OndexTooLarge {
                code: self.state.code,
                ondex,
                max: max_ondex,
            });
        }
        // When os=0 the wire format has no space for a separate ondex, so
        // ondex must equal index (matching keripy's InvalidVarIndexError).
        if self.state.code.get_xizage().os() == 0 && ondex != index {
            return Err(IndexerValidationError::OndexMustEqualIndex {
                code: self.state.code,
                index,
                ondex,
            });
        }
        Ok(IndexerBuilder {
            state: IWithIndex {
                code: self.state.code,
                index,
                ondex: Some(ondex),
            },
        })
    }
}

impl IndexerBuilder<IWithIndex> {
    /// Terminal step: validates the raw byte length and returns the finished
    /// [`Indexer`].
    ///
    /// # Errors
    ///
    /// Returns [`IndexerValidationError::UnexpectedRawSize`] if the raw byte slice
    /// length does not match the code's expected size.
    pub fn with_raw<'a>(
        self,
        raw: impl Into<Cow<'a, [u8]>>,
    ) -> Result<Indexer<'a>, IndexerValidationError> {
        let raw_bytes = raw.into();
        let expected = self.state.code.raw_size();
        if raw_bytes.len() != expected {
            return Err(IndexerValidationError::UnexpectedRawSize {
                code: self.state.code,
                expected,
                got: raw_bytes.len(),
            });
        }
        Ok(Indexer::new(
            self.state.code,
            self.state.index,
            self.state.ondex,
            raw_bytes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use rstest::rstest;

    use super::*;

    // ── Happy paths ────────────────────────────────────────────────────

    /// Ed25519 (Both, small): index=0, ondex auto-set to 0.
    #[test]
    fn ed25519_both_index_0() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        assert_eq!(indexer.code(), IndexedSigCode::Ed25519);
        assert_eq!(indexer.index(), 0);
        assert_eq!(indexer.ondex(), Some(0));
        assert_eq!(indexer.raw().len(), 64);
    }

    /// `Ed25519Crt` (`CurrentOnly`, small): ondex is `None`.
    #[test]
    fn ed25519crt_current_only() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Crt)
            .with_index(5)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        assert_eq!(indexer.code(), IndexedSigCode::Ed25519Crt);
        assert_eq!(indexer.index(), 5);
        assert_eq!(indexer.ondex(), None);
    }

    /// `Ed448` has `raw_size` 114.
    #[test]
    fn ed448_raw_size() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448)
            .with_index(4)
            .unwrap()
            .with_raw(&[0u8; 114])
            .unwrap();
        assert_eq!(indexer.raw().len(), 114);
    }

    /// Big code with large index.
    #[test]
    fn big_code_large_index() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_index(4000)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        assert_eq!(indexer.index(), 4000);
        assert_eq!(indexer.ondex(), Some(4000));
    }

    /// Max valid index for small Ed25519: 63.
    #[test]
    fn max_valid_index_small() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(63);
        assert!(result.is_ok());
    }

    /// Explicit ondex via `with_indices` on a Big Both code.
    #[test]
    fn explicit_ondex_big() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448Big)
            .with_indices(5, 10)
            .unwrap()
            .with_raw(&[0u8; 114])
            .unwrap();
        assert_eq!(indexer.index(), 5);
        assert_eq!(indexer.ondex(), Some(10));
    }

    /// `with_indices` on a small Both code (`Ed25519`, `os`=0) where ondex == index.
    #[test]
    fn with_indices_small_both_same() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_indices(7, 7)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        assert_eq!(indexer.index(), 7);
        assert_eq!(indexer.ondex(), Some(7));
    }

    // ── Validation errors ──────────────────────────────────────────────

    /// Index too large for small code (max is 63).
    #[test]
    fn index_too_large() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(64);
        assert!(result.is_err());
    }

    /// Wrong raw size.
    #[test]
    fn wrong_raw_size() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 32]); // Ed25519 sig is 64 bytes
        assert!(result.is_err());
    }

    /// `with_indices` on `CurrentOnly` code is rejected.
    #[test]
    fn ondex_on_current_only() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Crt)
            .with_indices(0, 0);
        assert!(result.is_err());
    }

    /// Ondex too large for big code.
    #[test]
    fn ondex_too_large() {
        // Ed448Big: max_ondex = 64^3 - 1 = 262_143
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448Big)
            .with_indices(0, 262_144);
        assert!(result.is_err());
    }

    /// Index too large when using `with_indices`.
    #[test]
    fn index_too_large_with_indices() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_indices(4096, 0); // max_index for Ed25519Big is 4095
        assert!(result.is_err());
    }

    // ── Error variant checks ───────────────────────────────────────────

    #[test]
    fn index_too_large_error_variant() {
        let err = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(64)
            .err()
            .unwrap();
        assert_eq!(
            err,
            IndexerValidationError::IndexTooLarge {
                code: IndexedSigCode::Ed25519,
                index: 64,
                max: 63,
            }
        );
    }

    #[test]
    fn wrong_raw_size_error_variant() {
        let err = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .err()
            .unwrap();
        assert_eq!(
            err,
            IndexerValidationError::UnexpectedRawSize {
                code: IndexedSigCode::Ed448,
                expected: 114,
                got: 64,
            }
        );
    }

    #[test]
    fn ondex_on_current_only_error_variant() {
        let err = IndexerBuilder::new()
            .with_code(IndexedSigCode::ECDSA256k1Crt)
            .with_indices(0, 0)
            .err()
            .unwrap();
        assert_eq!(
            err,
            IndexerValidationError::OndexOnCurrentOnly(IndexedSigCode::ECDSA256k1Crt)
        );
    }

    #[test]
    fn ondex_too_large_error_variant() {
        let err = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_indices(0, 4096) // max_ondex for Ed25519Big (os=2) is 4095
            .err()
            .unwrap();
        assert_eq!(
            err,
            IndexerValidationError::OndexTooLarge {
                code: IndexedSigCode::Ed25519Big,
                ondex: 4096,
                max: 4095,
            }
        );
    }

    // ── Boundary conditions ────────────────────────────────────────────

    /// Max valid index for big Ed25519: 4095.
    #[test]
    fn max_valid_index_big() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_index(4095);
        assert!(result.is_ok());
    }

    /// Max valid ondex for big `Ed448`: `262_143`.
    #[test]
    fn max_valid_ondex_big() {
        let result = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448Big)
            .with_indices(0, 262_143);
        assert!(result.is_ok());
    }

    /// All ECDSA codes work through the builder.
    #[test]
    fn ecdsa_codes() {
        for code in [
            IndexedSigCode::ECDSA256k1,
            IndexedSigCode::ECDSA256r1,
            IndexedSigCode::ECDSA256k1Big,
            IndexedSigCode::ECDSA256r1Big,
        ] {
            let indexer = IndexerBuilder::new()
                .with_code(code)
                .with_index(0)
                .unwrap()
                .with_raw(&[0u8; 64])
                .unwrap();
            assert_eq!(indexer.code(), code);
            assert_eq!(indexer.ondex(), Some(0));
        }
    }

    /// All `CurrentOnly` codes produce `ondex`=`None`.
    #[test]
    fn all_current_only_ondex_none() {
        for code in [
            IndexedSigCode::Ed25519Crt,
            IndexedSigCode::ECDSA256k1Crt,
            IndexedSigCode::ECDSA256r1Crt,
            IndexedSigCode::Ed448Crt,
            IndexedSigCode::Ed25519BigCrt,
            IndexedSigCode::ECDSA256k1BigCrt,
            IndexedSigCode::ECDSA256r1BigCrt,
            IndexedSigCode::Ed448BigCrt,
        ] {
            let raw_size = code.raw_size();
            let raw = vec![0u8; raw_size];
            let indexer = IndexerBuilder::new()
                .with_code(code)
                .with_index(0)
                .unwrap()
                .with_raw(&raw)
                .unwrap();
            assert_eq!(
                indexer.ondex(),
                None,
                "code {code:?} should have ondex=None"
            );
        }
    }

    // ── compute_full_size overflow probe ──────────────────────────────

    #[test]
    fn indexer_compute_full_size_rejects_overflow() {
        // `index` is decoded from the attacker-controlled soft field; the
        // arithmetic `index * 4 + cs` is checked, so overflow must be a typed
        // Err, never a panic (debug) or a silently-wrapped (truncated) frame.
        assert_eq!(compute_full_size(1, 4).unwrap(), 8);
        assert!(compute_full_size(usize::MAX / 4, 4).is_err());
        assert!(compute_full_size(usize::MAX, 0).is_err());
    }

    // ── frame_size tests ──────────────────────────────────────────────

    #[test]
    fn indexer_frame_size_fixed_and_truncated() {
        // 'A' = Ed25519 indexed sig, fixed fs = 88 (verified)
        let full = String::from("A") + &"A".repeat(87);
        assert_eq!(IndexedSigCode::frame_size(full.as_bytes()).unwrap(), 88);
        assert!(IndexedSigCode::frame_size(b"").is_err());
        assert!(IndexedSigCode::frame_size(b"9").is_err()); // '9' -> hardage None
    }

    // ── from_qb64 tests ───────────────────────────────────────────────

    /// Known cesride test vector: Ed25519, index=0.
    #[test]
    fn from_qb64_cesride_vector() {
        let qb64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let (indexer, consumed) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(consumed, 88);
        assert_eq!(indexer.code(), IndexedSigCode::Ed25519);
        assert_eq!(indexer.index(), 0);
        assert_eq!(indexer.ondex(), Some(0));
        // Roundtrip.
        assert_eq!(indexer.to_qb64(), qb64);
    }

    /// Construct a qb64 with index=5, then parse it.
    #[test]
    fn from_qb64_with_index() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(5)
            .unwrap()
            .with_raw(&[0xAB; 64])
            .unwrap();
        let qb64 = original.to_qb64();
        let (parsed, consumed) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(consumed, 88);
        assert_eq!(parsed.code(), IndexedSigCode::Ed25519);
        assert_eq!(parsed.index(), 5);
        assert_eq!(parsed.ondex(), Some(5));
        assert_eq!(parsed.raw(), original.raw());
    }

    /// Big Ed25519 variant with index=100.
    #[test]
    fn from_qb64_big_variant() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_index(100)
            .unwrap()
            .with_raw(&[0xCD; 64])
            .unwrap();
        let qb64 = original.to_qb64();
        let (parsed, _) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(parsed.code(), IndexedSigCode::Ed25519Big);
        assert_eq!(parsed.index(), 100);
        assert_eq!(parsed.ondex(), Some(100));
    }

    /// Ed448 with separate ondex values.
    #[test]
    fn from_qb64_ed448_separate_ondex() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448)
            .with_indices(2, 5)
            .unwrap()
            .with_raw(&[0xEE; 114])
            .unwrap();
        let qb64 = original.to_qb64();
        let (parsed, _) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(parsed.index(), 2);
        assert_eq!(parsed.ondex(), Some(5));
    }

    /// Empty stream returns `EmptyStream` error.
    #[test]
    fn from_qb64_empty_stream() {
        let result = IndexerBuilder::new().from_qb64(b"");
        assert!(result.is_err());
    }

    /// Stream too short returns `StreamTooShort` error.
    #[test]
    fn from_qb64_stream_too_short() {
        let result = IndexerBuilder::new().from_qb64(b"A");
        assert!(result.is_err());
    }

    /// Invalid code returns an error.
    #[test]
    fn from_qb64_unknown_code() {
        let result = IndexerBuilder::new().from_qb64(b"#invalid");
        assert!(result.is_err());
    }

    /// Stream longer than needed: consumed should be exactly the full size.
    #[test]
    fn from_qb64_consumes_exact_bytes() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let mut stream = original.to_qb64().into_bytes();
        stream.extend_from_slice(b"EXTRA_STUFF");
        let (_, consumed) = IndexerBuilder::new().from_qb64(&stream).unwrap();
        assert_eq!(consumed, 88);
    }

    /// `CurrentOnly` code parsed from qb64 has `ondex`=`None`.
    #[test]
    fn from_qb64_current_only_ondex_none() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Crt)
            .with_index(3)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let qb64 = original.to_qb64();
        let (parsed, _) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(parsed.code(), IndexedSigCode::Ed25519Crt);
        assert_eq!(parsed.index(), 3);
        assert_eq!(parsed.ondex(), None);
    }

    /// Roundtrip all 16 codes through qb64 encode/decode.
    #[rstest]
    #[case(IndexedSigCode::Ed25519)]
    #[case(IndexedSigCode::Ed25519Crt)]
    #[case(IndexedSigCode::ECDSA256k1)]
    #[case(IndexedSigCode::ECDSA256k1Crt)]
    #[case(IndexedSigCode::ECDSA256r1)]
    #[case(IndexedSigCode::ECDSA256r1Crt)]
    #[case(IndexedSigCode::Ed448)]
    #[case(IndexedSigCode::Ed448Crt)]
    #[case(IndexedSigCode::Ed25519Big)]
    #[case(IndexedSigCode::Ed25519BigCrt)]
    #[case(IndexedSigCode::ECDSA256k1Big)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt)]
    #[case(IndexedSigCode::ECDSA256r1Big)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt)]
    #[case(IndexedSigCode::Ed448Big)]
    #[case(IndexedSigCode::Ed448BigCrt)]
    fn from_qb64_roundtrip_all_codes(#[case] code: IndexedSigCode) {
        let raw = vec![0xAB_u8; code.raw_size()];
        let original = IndexerBuilder::new()
            .with_code(code)
            .with_index(0)
            .unwrap()
            .with_raw(&raw)
            .unwrap();
        let qb64 = original.to_qb64();
        let (parsed, _) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(parsed.code(), original.code());
        assert_eq!(parsed.raw(), original.raw());
        assert_eq!(parsed.to_qb64(), qb64);
    }

    /// `Ed448Big` with large distinct index and ondex roundtrips correctly.
    #[test]
    fn from_qb64_ed448_big_distinct_indices() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448Big)
            .with_indices(1000, 500)
            .unwrap()
            .with_raw(&[0xFF; 114])
            .unwrap();
        let qb64 = original.to_qb64();
        let (parsed, consumed) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(consumed, 160);
        assert_eq!(parsed.index(), 1000);
        assert_eq!(parsed.ondex(), Some(500));
        assert_eq!(parsed.raw(), original.raw());
    }

    // ── from_qb2 tests ────────────────────────────────────────────────

    /// Ed25519 roundtrip through qb2.
    #[test]
    fn from_qb2_roundtrip() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0xAB; 64])
            .unwrap();
        let qb2 = original.to_qb2();
        let (parsed, consumed) = IndexerBuilder::new().from_qb2(&qb2).unwrap();
        assert_eq!(consumed, 66); // 88 * 3 / 4
        assert_eq!(parsed.code(), original.code());
        assert_eq!(parsed.index(), original.index());
        assert_eq!(parsed.raw(), original.raw());
    }

    /// `from_qb2` empty stream returns error.
    #[test]
    fn from_qb2_empty_stream() {
        let result = IndexerBuilder::new().from_qb2(b"");
        assert!(result.is_err());
    }

    /// Roundtrip all 16 codes through qb2 encode/decode.
    #[rstest]
    #[case(IndexedSigCode::Ed25519)]
    #[case(IndexedSigCode::Ed25519Crt)]
    #[case(IndexedSigCode::ECDSA256k1)]
    #[case(IndexedSigCode::ECDSA256k1Crt)]
    #[case(IndexedSigCode::ECDSA256r1)]
    #[case(IndexedSigCode::ECDSA256r1Crt)]
    #[case(IndexedSigCode::Ed448)]
    #[case(IndexedSigCode::Ed448Crt)]
    #[case(IndexedSigCode::Ed25519Big)]
    #[case(IndexedSigCode::Ed25519BigCrt)]
    #[case(IndexedSigCode::ECDSA256k1Big)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt)]
    #[case(IndexedSigCode::ECDSA256r1Big)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt)]
    #[case(IndexedSigCode::Ed448Big)]
    #[case(IndexedSigCode::Ed448BigCrt)]
    fn from_qb2_roundtrip_all_codes(#[case] code: IndexedSigCode) {
        let raw = vec![0xCD_u8; code.raw_size()];
        let original = IndexerBuilder::new()
            .with_code(code)
            .with_index(0)
            .unwrap()
            .with_raw(&raw)
            .unwrap();
        let qb2 = original.to_qb2();
        let qb64_len = original.to_qb64().len();
        let expected_bfs = qb64_len * 3 / 4;
        let (parsed, consumed) = IndexerBuilder::new().from_qb2(&qb2).unwrap();
        assert_eq!(
            consumed, expected_bfs,
            "consumed mismatch for code {code:?}"
        );
        assert_eq!(parsed.code(), original.code());
        assert_eq!(parsed.raw(), original.raw());
    }

    /// `from_qb2` with extra trailing bytes only consumes expected amount.
    #[test]
    fn from_qb2_consumes_exact_bytes() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let mut qb2 = original.to_qb2();
        qb2.extend_from_slice(&[0xFF; 20]);
        let (_, consumed) = IndexerBuilder::new().from_qb2(&qb2).unwrap();
        assert_eq!(consumed, 66); // 88 * 3/4
    }

    /// `from_qb2` on a big code roundtrips correctly.
    #[test]
    fn from_qb2_big_code() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_index(100)
            .unwrap()
            .with_raw(&[0xAB; 64])
            .unwrap();
        let qb2 = original.to_qb2();
        let (parsed, consumed) = IndexerBuilder::new().from_qb2(&qb2).unwrap();
        assert_eq!(consumed, 69); // 92 * 3 / 4
        assert_eq!(parsed.code(), IndexedSigCode::Ed25519Big);
        assert_eq!(parsed.index(), 100);
    }

    /// Cross-format roundtrip: encode to qb64, decode from qb64,
    /// re-encode to qb2, decode from qb2, compare.
    #[test]
    fn cross_format_roundtrip() {
        let original = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448)
            .with_indices(7, 3)
            .unwrap()
            .with_raw(&[0x42; 114])
            .unwrap();

        // qb64 roundtrip.
        let qb64 = original.to_qb64();
        let (from_b64, _) = IndexerBuilder::new().from_qb64(qb64.as_bytes()).unwrap();
        assert_eq!(from_b64.raw(), original.raw());
        assert_eq!(from_b64.index(), 7);
        assert_eq!(from_b64.ondex(), Some(3));

        // qb2 roundtrip.
        let qb2 = original.to_qb2();
        let (from_b2, _) = IndexerBuilder::new().from_qb2(&qb2).unwrap();
        assert_eq!(from_b2.raw(), original.raw());
        assert_eq!(from_b2.index(), 7);
        assert_eq!(from_b2.ondex(), Some(3));

        // Both parse results should be identical.
        assert_eq!(from_b64, from_b2);
    }
}
