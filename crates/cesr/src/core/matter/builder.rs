use super::{
    MatterPart,
    code::{CesrCode, MatterCode},
    error::{MatterBuildError, ParsingError, ValidationError},
    matter::Matter,
    sizage::{Sizage, SizeType},
};
use crate::b64::{charset::is_b64_url_safe_charset, decode_int, encode_binary};
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use base64::{Engine, decoded_len_estimate, engine::general_purpose as b64};
use core::num::NonZeroUsize;

/// Marker trait for the type-state pattern used by [`MatterBuilder`].
pub trait MatterBuilderState {}

/// Initial state: no code, raw, or soft has been set.
pub struct Start {}

impl MatterBuilderState for Start {}

/// State after setting a CESR code.
pub struct WithCode<C: CesrCode> {
    code: C,
}

impl<C: CesrCode> MatterBuilderState for WithCode<C> {}

/// State after setting a code and soft value.
pub struct WithSoft<'a, C: CesrCode> {
    code: C,
    soft: &'a str,
}

impl<C: CesrCode> MatterBuilderState for WithSoft<'_, C> {}

/// State after setting a code and raw bytes.
pub struct WithRaw<'a, C: CesrCode> {
    code: C,
    raw: Cow<'a, [u8]>,
}

impl<C: CesrCode> MatterBuilderState for WithRaw<'_, C> {}

/// State after setting a code, raw bytes, and soft value.
pub struct WithRawAndSoft<'a, C: CesrCode> {
    code: C,
    raw: Cow<'a, [u8]>,
    soft: &'a str,
}

impl<C: CesrCode> MatterBuilderState for WithRawAndSoft<'_, C> {}

/// A type-state builder for constructing [`Matter`] primitives.
pub struct MatterBuilder<M>
where
    M: MatterBuilderState,
{
    state: M,
}

impl Default for MatterBuilder<Start> {
    fn default() -> Self {
        Self { state: Start {} }
    }
}

impl MatterBuilder<Start> {
    /// Creates a new `MatterBuilder` in the initial state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the CESR code, advancing to the next builder state.
    pub const fn with_code<C: CesrCode>(self, code: C) -> MatterBuilder<WithCode<C>> {
        MatterBuilder {
            state: WithCode { code },
        }
    }

    /// Parses a [`Matter`] from a qualified Base64 (qb64) byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError`] or [`ValidationError`] if the stream is
    /// malformed, truncated, or fails canonicality checks.
    #[allow(
        clippy::too_many_lines,
        reason = "sequential parsing steps that are clearer together"
    )]
    pub fn from_qualified_base64<'a>(
        self,
        input: impl Into<Cow<'a, [u8]>>,
    ) -> Result<Matter<'a, MatterCode>, MatterBuildError> {
        let stream = input.into();
        if stream.is_empty() {
            return Err(MatterBuildError::from(ParsingError::EmptyStream));
        }
        let code = MatterCode::from_base64_stream(&stream)?;
        let hs = code.get_sizage().hs();
        let ss = code.get_sizage().ss();
        let cs = hs + ss;
        if stream.len() < cs {
            return Err(MatterBuildError::from(ParsingError::StreamTooShort(
                MatterPart::Soft,
            )));
        }
        let soft_full = &stream[hs..cs];
        let xs = code.get_sizage().xs();
        let xtra = &soft_full[..xs];
        let soft_tail = &soft_full[xs..];
        if xtra != Matter::<MatterCode>::PAD.repeat(xs).as_bytes() {
            return Err(MatterBuildError::from(ParsingError::MalformedCode {
                part: MatterPart::Xtra,
                found: Matter::<MatterCode>::PAD.repeat(xs),
            }));
        }
        // frame_size_of returns early for fixed codes without checking soft UTF-8;
        // validate it here so fixed-code soft fields still reject non-UTF-8 as before.
        str::from_utf8(soft_tail)
            .map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?;

        let fs = code.frame_size_of(&stream)?;
        if stream.len() < fs {
            return Err(MatterBuildError::from(ValidationError::IncorrectRawSize {
                code: code.to_string(),
                expected: fs,
                found: stream.len(),
            }));
        }
        let trim = &stream[..fs];
        let ps = cs % 4;

        let paw = &trim[cs..];
        let mut temp: Vec<u8> = Vec::with_capacity(ps + paw.len());
        temp.resize(ps, b'A');
        temp.extend_from_slice(paw);
        let estimate = decoded_len_estimate(temp.len());
        let mut buf: Vec<u8> = Vec::with_capacity(estimate);
        b64::URL_SAFE
            .decode_vec(temp, &mut buf)
            .map_err(|err| MatterBuildError::from(ParsingError::Base64(err)))?;

        if ps != 0 {
            let pbs = 2 * ps;
            let mask = (1u32 << pbs) - 1;
            let mut pi: u32 = 0;
            for &byte in buf.iter().take(ps) {
                pi = (pi << 8) | u32::from(byte);
            }
            if (pi & mask) != 0 {
                return Err(MatterBuildError::from(
                    ValidationError::NonCanonicalEncoding(MatterPart::PadBits),
                ));
            }
            let ls = code.get_sizage().ls();
            let Some(lead_bytes) = buf.get(ps..(ps + ls)) else {
                return Err(MatterBuildError::from(
                    ValidationError::StructuralIntegrityError,
                ));
            };
            if ls > 0 && lead_bytes.iter().any(|&b| b != 0) {
                return Err(MatterBuildError::from(
                    ValidationError::NonCanonicalEncoding(MatterPart::LeadBytes),
                ));
            }
            buf.drain(..(ps + ls));
        } else {
            let ls = code.get_sizage().ls();
            if ls > 0 {
                let Some(lead_bytes) = buf.get(..ls) else {
                    return Err(MatterBuildError::from(
                        ValidationError::StructuralIntegrityError,
                    ));
                };
                if lead_bytes.iter().any(|&b| b != 0) {
                    return Err(MatterBuildError::from(
                        ValidationError::NonCanonicalEncoding(MatterPart::LeadBytes),
                    ));
                }
                buf.drain(..ls);
            }
        }
        let raw: Cow<'a, [u8]> = Cow::Owned(buf);

        let soft_start = hs + xs;
        let soft_end = cs;

        let soft: Cow<'a, str> = match &stream {
            Cow::Borrowed(b) => {
                let s = str::from_utf8(&b[soft_start..soft_end])
                    .map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?;
                Cow::Borrowed(s)
            }
            Cow::Owned(v) => {
                let s = str::from_utf8(&v[soft_start..soft_end])
                    .map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?;
                Cow::Owned(s.to_owned())
            }
        };

        Ok(Matter::new(code, raw, soft))
    }

    /// Parses a [`Matter`] from a qualified binary (qb2) byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError`] or [`ValidationError`] if the stream is
    /// malformed, truncated, or fails canonicality checks.
    #[allow(
        clippy::too_many_lines,
        reason = "sequential parsing steps that are clearer together"
    )]
    pub fn from_qualified_base2(
        self,
        stream: &[u8],
    ) -> Result<Matter<'_, MatterCode>, MatterBuildError> {
        if stream.is_empty() {
            return Err(MatterBuildError::from(ParsingError::EmptyStream));
        }
        let code = MatterCode::from_stream(stream)?;
        let hs = code.get_sizage().hs();
        let ss = code.get_sizage().ss();
        let cs = hs + ss;
        let bcs = (cs * 3).div_ceil(4);
        if stream.len() < bcs {
            return Err(MatterBuildError::from(ParsingError::StreamTooShort(
                MatterPart::Soft,
            )));
        }

        let char_len = NonZeroUsize::new(cs)
            .ok_or_else(|| MatterBuildError::from(ParsingError::EmptyStream))?;
        let both = encode_binary(&stream[..bcs], char_len)
            .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;

        let soft_full = &both[hs..cs];
        let xs = code.get_sizage().xs();
        let xtra = &soft_full[..xs];
        let soft_tail = &soft_full[xs..];
        if xtra != Matter::<MatterCode>::PAD.repeat(xs) {
            return Err(MatterBuildError::from(ParsingError::MalformedCode {
                part: MatterPart::Xtra,
                found: Matter::<MatterCode>::PAD.repeat(xs),
            }));
        }
        let fs = if let SizeType::Fixed(fixed) = code.get_sizage().fs() {
            usize::from(*fixed)
        } else {
            let size: usize = decode_int(soft_tail)
                .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
            compute_full_size(size, cs)?
        };
        let bfs = compute_qb2_byte_size(fs)?;
        if stream.len() < bfs {
            return Err(MatterBuildError::from(ValidationError::IncorrectRawSize {
                code: code.to_string(),
                expected: bfs,
                found: stream.len(),
            }));
        }
        let trimmed = &stream[..bfs];
        let ls = code.get_sizage().ls();
        let lead_end = bcs
            .checked_add(ls)
            .ok_or_else(|| MatterBuildError::from(ValidationError::StructuralIntegrityError))?;
        if lead_end > trimmed.len() {
            return Err(MatterBuildError::from(ValidationError::IncorrectRawSize {
                code: code.to_string(),
                expected: lead_end,
                found: trimmed.len(),
            }));
        }
        let ps = cs % 4;
        if ps != 0 {
            #[allow(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "2 * ps is always <= 6 which fits in u32"
            )]
            let pbs = (2 * ps) as u32;
            let mut pi = trimmed[bcs - 1];
            pi &= 2_u8.pow(pbs) - 1;
            if pi != 0 {
                return Err(MatterBuildError::from(
                    ValidationError::NonCanonicalEncoding(MatterPart::PadBits),
                ));
            }
        }
        let li = &trimmed[bcs..lead_end];
        if ls > 0 && li.iter().any(|&b| b != 0) {
            return Err(MatterBuildError::from(
                ValidationError::NonCanonicalEncoding(MatterPart::LeadBytes),
            ));
        }
        let raw = &trimmed[lead_end..];

        if raw.len() != trimmed.len() - lead_end {
            return Err(MatterBuildError::from(
                ValidationError::StructuralIntegrityError,
            ));
        }

        Ok(Matter::new(
            code,
            Cow::Borrowed(raw),
            Cow::Owned(soft_tail.to_owned()),
        ))
    }
}

impl<C: CesrCode> MatterBuilder<WithCode<C>> {
    /// Provides the raw bytes for the primitive.
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError::EmptyStream`] if `raw` is empty.
    pub fn with_raw<'a>(
        self,
        raw: impl Into<Cow<'a, [u8]>>,
    ) -> Result<MatterBuilder<WithRaw<'a, C>>, ParsingError> {
        let raw_bytes = raw.into();
        // Reject empty raw only for codes that actually carry a payload. Fixed
        // zero-rawsize codes (e.g. `1AAP`) encode to just their code string, so
        // empty raw is valid — keripy accepts it (differential-tested). A code
        // whose raw size is unknown (variable) or non-zero still requires input.
        if raw_bytes.is_empty() && !matches!(self.state.code.raw_size(), Ok(0)) {
            return Err(ParsingError::EmptyStream);
        }
        Ok(MatterBuilder {
            state: WithRaw {
                code: self.state.code,
                raw: raw_bytes,
            },
        })
    }

    /// Provides the soft value for the primitive.
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError::EmptyStream`] if `soft` is empty.
    pub const fn with_soft(
        self,
        soft: &str,
    ) -> Result<MatterBuilder<WithSoft<'_, C>>, ParsingError> {
        if soft.is_empty() {
            return Err(ParsingError::EmptyStream);
        }
        let state = WithSoft {
            code: self.state.code,
            soft,
        };
        Ok(MatterBuilder { state })
    }
}

impl<'a, C: CesrCode> MatterBuilder<WithRaw<'a, C>> {
    /// Builds the [`Matter`] from raw bytes alone (no soft value).
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError`] or [`ValidationError`] if the code requires
    /// a soft value, or the raw size is incorrect.
    pub fn build(self) -> Result<Matter<'a, C>, MatterBuildError> {
        let WithRaw { code, raw: raw_val } = self.state;
        let mc = code.to_matter_code();
        let Sizage { ss, fs, .. } = mc.get_sizage();
        match fs {
            SizeType::Fixed(_) => {
                if ss > 0 {
                    return Err(MatterBuildError::from(ValidationError::MissingSoft {
                        code: mc.to_string(),
                    }));
                }
                let raw_size = mc.raw_size()?;
                let trimmed = validate_and_trim_raw(mc, raw_val, raw_size)?;
                Ok(Matter::new(code, trimmed, Cow::from("")))
            }
            _ => Err(MatterBuildError::from(
                ValidationError::InvalidSizingOperation(mc.to_string()),
            )),
        }
    }

    /// Adds a soft value to the builder.
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError::EmptyStream`] if `soft` is empty.
    pub fn with_soft(
        self,
        soft: &'a str,
    ) -> Result<MatterBuilder<WithRawAndSoft<'a, C>>, ParsingError> {
        if soft.is_empty() {
            return Err(ParsingError::EmptyStream);
        }
        let state = WithRawAndSoft {
            code: self.state.code,
            raw: self.state.raw,
            soft,
        };
        Ok(MatterBuilder { state })
    }
}

impl<'a, C: CesrCode> MatterBuilder<WithRawAndSoft<'a, C>> {
    /// Builds the [`Matter`] from raw bytes and a soft value.
    ///
    /// # Errors
    ///
    /// Returns [`ParsingError`] or [`ValidationError`] if sizes are invalid
    /// or the soft format is incorrect.
    pub fn build(self) -> Result<Matter<'a, C>, MatterBuildError> {
        let WithRawAndSoft {
            soft,
            code,
            raw: raw_val,
        } = self.state;
        let mc = code.to_matter_code();
        let Sizage { ss, fs, xs, .. } = mc.get_sizage();
        match fs {
            SizeType::Fixed(_) => {
                if ss == 0 {
                    let raw_size = mc.raw_size()?;
                    let trimmed = validate_and_trim_raw(mc, raw_val, raw_size)?;
                    return Ok(Matter::new(code, trimmed, Cow::from("")));
                }
                let final_soft = extract_soft(mc, ss, xs, soft)?;
                let raw_size = mc.raw_size()?;
                let trimmed = validate_and_trim_raw(mc, raw_val, raw_size)?;
                Ok(Matter::new(code, trimmed, Cow::Borrowed(final_soft)))
            }
            _ => Err(MatterBuildError::from(
                ValidationError::InvalidSizingOperation(mc.to_string()),
            )),
        }
    }
}

impl<'a, C: CesrCode> MatterBuilder<WithSoft<'a, C>> {
    /// Builds the [`Matter`] from a soft value alone (no raw bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the code does not support soft-only
    /// construction, or the soft format is invalid.
    pub fn build(self) -> Result<Matter<'a, C>, ValidationError> {
        let WithSoft { code, soft } = self.state;
        let mc = code.to_matter_code();
        let Sizage {
            ss,
            fs: size_type,
            hs,
            xs,
            ..
        } = mc.get_sizage();
        match size_type {
            SizeType::Fixed(fixed_size) if ss > 0 && fixed_size == (hs + ss) => {
                let final_soft = extract_soft(mc, ss, xs, soft)?;
                Ok(Matter::new(
                    code,
                    Cow::Borrowed(b""),
                    Cow::Borrowed(final_soft),
                ))
            }
            SizeType::Fixed(_) => Err(ValidationError::InvalidSoftFormat {
                code: mc.to_string(),
            }),
            _ => Err(ValidationError::UnknownMatterCode(mc.to_string())),
        }
    }
}

#[inline]
#[allow(dead_code, reason = "utility kept for future encoding use")]
const fn get_lead_size(raw_len: usize) -> usize {
    (3 - (raw_len % 3)) % 3
}

#[inline]
#[allow(dead_code, reason = "utility kept for future encoding use")]
const fn get_size(raw_len: usize, lead_len: usize) -> usize {
    (raw_len + lead_len) / 3
}

/// Computes the full character size `fs` of a variable-size primitive from its
/// decoded soft `size` (`fs = size * 4 + cs`).
///
/// `size` is decoded from the attacker-controlled soft field, so the arithmetic
/// is checked: an overflow yields [`ValidationError::SizeOverflow`] rather than a
/// debug panic or a silently-wrapped (truncated) frame.
#[inline]
fn compute_full_size(size: usize, cs: usize) -> Result<usize, ValidationError> {
    size.checked_mul(4)
        .and_then(|quad| quad.checked_add(cs))
        .ok_or(ValidationError::SizeOverflow)
}

/// Computes the full binary (qb2) byte size `bfs` from the character size `fs`
/// (`bfs = ceil(fs * 3 / 4)`).
///
/// `fs` derives from the attacker-controlled soft field via [`compute_full_size`],
/// so the multiplication is checked; an overflow yields
/// [`ValidationError::SizeOverflow`].
#[inline]
fn compute_qb2_byte_size(fs: usize) -> Result<usize, ValidationError> {
    fs.checked_mul(3)
        .map(|tripled| tripled.div_ceil(4))
        .ok_or(ValidationError::SizeOverflow)
}

#[inline]
fn extract_soft(code: MatterCode, ss: u8, xs: u8, soft: &str) -> Result<&str, ValidationError> {
    let expected_len = usize::from(ss - xs);

    if soft.len() < expected_len {
        return Err(ValidationError::IncorrectSoftLength {
            code: code.to_string(),
            expected: expected_len,
            found: soft.len(),
        });
    }

    let final_soft = &soft[..expected_len];

    if !is_b64_url_safe_charset(final_soft.as_bytes()) {
        return Err(ValidationError::InvalidSoftFormat {
            code: code.to_string(),
        });
    }

    Ok(final_soft)
}

#[inline]
fn validate_and_trim_raw(
    code: MatterCode,
    raw: Cow<'_, [u8]>,
    raw_size: usize,
) -> Result<Cow<'_, [u8]>, ValidationError> {
    if raw.len() < raw_size {
        return Err(ValidationError::IncorrectRawSize {
            found: raw.len(),
            expected: raw_size,
            code: code.to_string(),
        });
    }
    if raw.len() == raw_size {
        return Ok(raw);
    }
    match raw {
        Cow::Borrowed(s) => Ok(Cow::Borrowed(&s[..raw_size])),
        Cow::Owned(mut v) => {
            v.truncate(raw_size);
            Ok(Cow::Owned(v))
        }
    }
}

impl MatterCode {
    /// Full qb64 character size of the Matter primitive at the head of `stream`,
    /// without decoding the raw body or validating pad/lead bits.
    ///
    /// # Errors
    /// `MatterBuildError` on unknown code, short soft field, non-UTF-8 soft, or size overflow.
    pub fn frame_size(stream: &[u8]) -> Result<usize, MatterBuildError> {
        let code = Self::from_base64_stream(stream)?;
        code.frame_size_of(stream)
    }

    /// `frame_size` for an already-known code — shared with `from_qualified_base64`
    /// so there is exactly one size implementation.
    pub(crate) fn frame_size_of(self, stream: &[u8]) -> Result<usize, MatterBuildError> {
        let sizage = self.get_sizage();
        if let SizeType::Fixed(fixed) = sizage.fs() {
            return Ok(usize::from(*fixed));
        }
        let hs = sizage.hs();
        let ss = sizage.ss();
        let cs = hs + ss;
        if stream.len() < cs {
            return Err(MatterBuildError::from(ParsingError::StreamTooShort(
                MatterPart::Soft,
            )));
        }
        let xs = sizage.xs();
        let soft_tail = str::from_utf8(&stream[hs + xs..cs])
            .map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?;
        let size: usize = decode_int(soft_tail)
            .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
        compute_full_size(size, cs).map_err(MatterBuildError::from)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "tests use panic via unwrap/assert macros")]
mod tests {
    use super::{
        MatterBuildError, MatterBuilder, Start, ValidationError, compute_full_size,
        compute_qb2_byte_size, validate_and_trim_raw,
    };
    use crate::core::matter::code::MatterCode;
    use std::{format, string::String, vec, vec::Vec};

    #[test]
    fn qb64_lead_bytes_slice_does_not_panic_on_short_buffer() {
        // Regression (deep-fuzz `matter_from_qb64`): input `5BAA` panicked with
        // "range end index 1 out of range for slice of length 0" — the lead-byte
        // slice indexed past a decoded buffer shorter than the code's declared lead
        // size. Parsing untrusted bytes must never panic; it must return a typed error.
        let err = MatterBuilder::new()
            .from_qualified_base64(b"5BAA".as_slice())
            .expect_err("`5BAA` must be rejected, not accepted");
        assert!(
            matches!(
                err,
                MatterBuildError::Validation(ValidationError::StructuralIntegrityError)
            ),
            "expected StructuralIntegrityError, got {err:?}"
        );
    }

    #[test]
    fn matter_frame_size_fixed_and_truncated() {
        // 'B' = Ed25519 non-transferable verkey, fixed fs = 44
        let full = String::from("B") + &"A".repeat(43);
        assert_eq!(MatterCode::frame_size(full.as_bytes()).unwrap(), 44);
        assert!(MatterCode::frame_size(b"").is_err()); // empty -> error, no panic
        assert!(MatterCode::frame_size(b"\x00\x00").is_err()); // unknown code -> error
    }

    // ── Size-arithmetic overflow tests (#76) ────────────────────────────
    // `size` is decoded from the attacker-controlled soft field. Computing the
    // frame size with bare arithmetic panics on overflow (debug) or wraps to a
    // small bogus size (release) that then slices a truncated frame as valid.
    // These probe the checked helpers directly because the parse API caps the
    // soft field at ss=4 (size <= 2^24-1), so overflow is unreachable through
    // `from_qualified_base64`/`from_qualified_base2` today — it is latent, and
    // must still be rejected as a typed error, never panic or wrap.

    #[test]
    fn compute_full_size_rejects_overflow() {
        // size * 4 overflows usize.
        let err = compute_full_size(usize::MAX / 2, 4)
            .expect_err("size * 4 overflow must be a typed Err, not a panic or wrap");
        assert_eq!(err, ValidationError::SizeOverflow);
    }

    #[test]
    fn compute_full_size_rejects_add_overflow() {
        // size * 4 fits but + cs overflows.
        let err = compute_full_size(usize::MAX / 4, 8)
            .expect_err("+ cs overflow must be a typed Err, not a panic or wrap");
        assert_eq!(err, ValidationError::SizeOverflow);
    }

    #[test]
    fn compute_full_size_in_range_is_exact() {
        assert_eq!(compute_full_size(10, 4), Ok(44));
        assert_eq!(compute_full_size(0, 2), Ok(2));
        // Widest real variable code: ss=4 => size <= 2^24-1, must not overflow.
        let max_real = 64_usize.pow(4) - 1;
        assert_eq!(compute_full_size(max_real, 4), Ok((max_real * 4) + 4));
    }

    #[test]
    fn compute_qb2_byte_size_rejects_overflow() {
        // fs * 3 overflows usize.
        let err = compute_qb2_byte_size(usize::MAX / 2)
            .expect_err("fs * 3 overflow must be a typed Err, not a panic or wrap");
        assert_eq!(err, ValidationError::SizeOverflow);
    }

    #[test]
    fn compute_qb2_byte_size_in_range_is_exact() {
        // ceil(44 * 3 / 4) = 33.
        assert_eq!(compute_qb2_byte_size(44), Ok(33));
        // ceil(2 * 3 / 4) = 2.
        assert_eq!(compute_qb2_byte_size(2), Ok(2));
    }

    #[test]
    fn should_extract_raw_size_based() {
        use alloc::borrow::Cow;
        let code = MatterCode::Ed25519;
        let raw = b"18923yjkahds7612378612983189237669jyasgdutgjashgjg";
        let result = validate_and_trim_raw(code, Cow::Borrowed(&raw[..]), 44);
        assert!(result.is_ok());
        let raw_result = result.unwrap();
        assert_eq!(&*raw_result, &raw[..44]);
    }

    // TODO: write tests to extract soft
    // TODO: write test to build matter  with only code and soft
    // TODO: write test to build matter with qb64
    // TODO: write test to build matter with qb2

    #[test]
    fn should_be_able_to_build_code_raw_matter() {
        let code = MatterCode::Ed25519;
        let raw = b"18923yjkahds7612378612983189237669jyasgdutgjashgjg";
        let result = MatterBuilder::<Start>::new()
            .with_code(code)
            .with_raw(&raw[..])
            .unwrap()
            .build();

        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), &code);
        assert_eq!(matter.raw(), &raw[..32]); // thats how much ed25519 raw length should be.
    }

    #[test]
    fn should_build_typed_matter_from_code_and_raw() {
        use crate::core::matter::code::VerKeyCode;
        let code = VerKeyCode::Ed25519;
        let raw = &[0u8; 32];
        let result = MatterBuilder::<Start>::new()
            .with_code(code)
            .with_raw(&raw[..])
            .unwrap()
            .build();
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(*matter.code(), VerKeyCode::Ed25519);
    }

    // ── ParsingError tests ─────────────────────────────────────────────

    #[test]
    fn qb64_empty_stream_returns_parsing_error() {
        let result = MatterBuilder::new().from_qualified_base64(b"");
        assert!(result.is_err());
    }

    #[test]
    fn qb2_empty_stream_returns_parsing_error() {
        let result = MatterBuilder::new().from_qualified_base2(b"");
        assert!(result.is_err());
    }

    #[test]
    fn builder_with_raw_rejects_empty_raw() {
        let result = MatterBuilder::new()
            .with_code(MatterCode::Ed25519)
            .with_raw(b"");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            crate::core::matter::error::ParsingError::EmptyStream
        );
    }

    #[test]
    fn builder_with_soft_rejects_empty_soft() {
        let result = MatterBuilder::new()
            .with_code(MatterCode::Tag3)
            .with_soft("");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            crate::core::matter::error::ParsingError::EmptyStream
        );
    }

    // ── ValidationError tests ──────────────────────────────────────────

    #[test]
    fn builder_variable_code_in_with_raw_build_fails() {
        // Variable-size codes should fail in WithRaw::build()
        let result = MatterBuilder::new()
            .with_code(MatterCode::Bytes_L0)
            .with_raw(b"abcdef")
            .unwrap()
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_short_raw_for_ed25519() {
        // Ed25519 needs 32 bytes
        let result = MatterBuilder::new()
            .with_code(MatterCode::Ed25519)
            .with_raw(&[0u8; 3])
            .unwrap()
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_missing_soft_for_special_code() {
        // Tag3 needs soft (ss=3) but only raw provided via WithRaw::build()
        let result = MatterBuilder::new()
            .with_code(MatterCode::Tag3)
            .with_raw(b"abc")
            .unwrap()
            .build();
        assert!(result.is_err());
    }

    // ── QB64 validation tests ──────────────────────────────────────────

    #[test]
    fn qb64_non_zero_pad_bits_rejected() {
        // 'B' code (Ed25519N) has hs=1, ss=0, cs=1, ps=cs%4=1
        // Prepending 'A' to payload and decoding: first payload char '_' (=63)
        // yields first byte 0x03 with lower 2 bits set -> non-zero pad bits
        let bad_qb64 = b"B_AAY2RlZmdoaWprbG1ub3BxcnN0dXYwMTIzNDU2Nzg5";
        let result = MatterBuilder::new().from_qualified_base64(bad_qb64);
        assert!(result.is_err());
    }

    #[test]
    fn qb64_non_zero_lead_bytes_tbd1_rejected() {
        // TBD1 (2___) has ls=1, cs=4, ps=0
        // Payload '_2Fi' decodes to [0xFF, ...] -> non-zero lead byte
        let bad_qb64 = b"2____2Fi";
        let result = MatterBuilder::new().from_qualified_base64(bad_qb64);
        assert!(result.is_err());
    }

    #[test]
    fn qb64_non_zero_lead_bytes_tbd2_rejected() {
        // TBD2 (3___) has ls=2, cs=4, ps=0
        // Payload '__96' decodes to [0xFF, 0xFF, 0x7A] -> non-zero lead bytes
        let bad_qb64 = b"3_____96";
        let result = MatterBuilder::new().from_qualified_base64(bad_qb64);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_stream_too_short_rejected() {
        // Ed25519N needs bfs = ceil(44*3/4) = 33 bytes in QB2
        // Providing only 3 bytes should fail
        let truncated: &[u8] = &[0x04, 0x69, 0x4e];
        let result = MatterBuilder::new().from_qualified_base2(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_short_bfs_lead_does_not_panic() {
        // Regression for #43: a variable-size code whose soft-encoded size
        // decodes small enough that bfs < bcs + ls. The old code sliced
        // trimmed[bcs..bcs+ls] (and trimmed[(bcs+ls)..]) without checking
        // bcs + ls <= bfs, panicking with an out-of-bounds slice on crafted
        // input. Parsing untrusted bytes must return a typed Err, never panic.
        // Exact reproducing input captured from the matter_from_qb2 bolero
        // fuzz target (#26).
        let crafted: &[u8] = &[
            0xe4, 0x70, 0x00, 0x21, 0x58, 0xff, 0xcd, 0x77, 0x4c, 0xa5, 0x50, 0x69, 0xd5, 0x8f,
            0x3e, 0x87, 0xd4, 0x00, 0xb9, 0xff, 0xf8, 0xcd, 0x94, 0x81, 0xb2, 0xfe, 0x3e, 0x45,
            0x2f, 0x40, 0x31, 0x6c, 0xb0, 0x69, 0xe4, 0x43, 0x40, 0x7b, 0x70, 0x9c, 0x38, 0x0f,
            0x00, 0xc3, 0x67, 0x41, 0x21, 0xfb, 0xee, 0xe8, 0x58, 0xee, 0x9e, 0x8c, 0xff, 0x88,
            0xbd, 0xb1, 0xcd, 0xd0, 0x67, 0x4a, 0x77, 0xe2, 0xea, 0x14, 0x4c, 0x64, 0xb3, 0x8b,
            0xa5, 0x28, 0xe9, 0xd7, 0x50, 0xc2, 0x07, 0x3b, 0x69, 0xa7, 0xad, 0xc1, 0xd5, 0x25,
            0xde, 0xc9, 0x8f, 0x58, 0xf3, 0xe4, 0x3e, 0xe4, 0x74, 0x03, 0x87, 0x24, 0x7c, 0xa6,
            0xd4, 0xd4, 0x18, 0x8c, 0x00, 0x2e, 0xaf, 0x17, 0xb9, 0x1f, 0x79, 0x7d, 0xff, 0x0f,
            0x35, 0xb0, 0xf8, 0x19, 0x1b, 0x14, 0xcd, 0x25, 0x88, 0xc8, 0x94, 0xf6, 0x80, 0x52,
            0x81, 0xc3, 0x05, 0xfd, 0xb2, 0xe4, 0xf9, 0x0c, 0xfe, 0xcd, 0x7a, 0x23,
        ];
        let err = MatterBuilder::new()
            .from_qualified_base2(crafted)
            .expect_err("crafted qb2 with bfs < bcs + ls must be rejected, not parsed");
        let crate::core::matter::error::MatterBuildError::Validation(validation) = err else {
            panic!("expected Validation variant, got {err:?}");
        };
        assert!(
            matches!(
                validation,
                crate::core::matter::error::ValidationError::IncorrectRawSize { .. }
            ),
            "expected IncorrectRawSize, got {validation:?}"
        );
    }

    // ── Task 5: Builder raw+code fixed-size tests ────────────────────────

    #[test]
    fn builder_raw_code_fixed_vectors() {
        use crate::core::matter::test_vectors::FIXED_VECTORS;
        use core::str::FromStr;

        for (i, vector) in FIXED_VECTORS.iter().enumerate() {
            // Skip vectors with empty raw (e.g. Null, No, Yes, Escape, Empty)
            // since with_raw() rejects empty slices.
            if vector.raw.is_empty() {
                continue;
            }

            let code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!("FIXED_VECTORS[{i}]: unknown code_str '{}'", vector.code_str)
            });

            let matter = MatterBuilder::new()
                .with_code(code)
                .with_raw(vector.raw)
                .unwrap_or_else(|e| {
                    panic!(
                        "FIXED_VECTORS[{i}] ({}): with_raw failed: {e:?}",
                        vector.rust_variant
                    )
                })
                .build()
                .unwrap_or_else(|e| {
                    panic!(
                        "FIXED_VECTORS[{i}] ({}): build failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "FIXED_VECTORS[{i}] ({}): raw mismatch",
                vector.rust_variant
            );
            assert_eq!(
                matter.code(),
                &code,
                "FIXED_VECTORS[{i}] ({}): code mismatch",
                vector.rust_variant
            );
        }
    }

    // ── Task 6: Builder code+soft special code tests ─────────────────────

    #[test]
    fn builder_soft_only_tag_codes() {
        use crate::core::matter::test_vectors::SPECIAL_VECTORS;
        use core::str::FromStr;

        let soft_only_variants = [
            "Tag3", "Tag7", "Tag11", "Tag1", "Tag2", "Tag4", "Tag5", "Tag6", "Tag8", "Tag9",
            "Tag10",
        ];

        for vector in SPECIAL_VECTORS {
            if !soft_only_variants.contains(&vector.rust_variant) {
                continue;
            }

            let code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "SPECIAL_VECTORS ({}): unknown code_str '{}'",
                    vector.rust_variant, vector.code_str
                )
            });

            let matter = MatterBuilder::new()
                .with_code(code)
                .with_soft(vector.soft)
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS ({}): with_soft failed: {e:?}",
                        vector.rust_variant
                    )
                })
                .build()
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS ({}): build failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.soft(),
                vector.soft,
                "SPECIAL_VECTORS ({}): soft mismatch",
                vector.rust_variant
            );
            assert!(
                matter.raw().is_empty(),
                "SPECIAL_VECTORS ({}): expected empty raw for soft-only code",
                vector.rust_variant
            );
            assert_eq!(
                matter.code(),
                &code,
                "SPECIAL_VECTORS ({}): code mismatch",
                vector.rust_variant
            );
        }
    }

    // ── Task 7: Builder raw+soft tests (GramHead*, TBD*S) ───────────────

    #[test]
    fn builder_raw_and_soft_special_vectors() {
        use crate::core::matter::test_vectors::SPECIAL_VECTORS;
        use core::str::FromStr;

        let raw_and_soft_variants = [
            "GramHeadNeck",
            "GramHead",
            "GramHeadAIDNeck",
            "GramHeadAID",
            "TBD0S",
            "TBD1S",
            "TBD2S",
        ];

        for vector in SPECIAL_VECTORS {
            if !raw_and_soft_variants.contains(&vector.rust_variant) {
                continue;
            }
            assert!(
                !vector.raw.is_empty(),
                "SPECIAL_VECTORS ({}): expected non-empty raw for raw+soft code",
                vector.rust_variant
            );

            let code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "SPECIAL_VECTORS ({}): unknown code_str '{}'",
                    vector.rust_variant, vector.code_str
                )
            });

            let matter = MatterBuilder::new()
                .with_code(code)
                .with_raw(vector.raw)
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS ({}): with_raw failed: {e:?}",
                        vector.rust_variant
                    )
                })
                .with_soft(vector.soft)
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS ({}): with_soft failed: {e:?}",
                        vector.rust_variant
                    )
                })
                .build()
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS ({}): build failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "SPECIAL_VECTORS ({}): raw mismatch",
                vector.rust_variant
            );
            assert_eq!(
                matter.soft(),
                vector.soft,
                "SPECIAL_VECTORS ({}): soft mismatch",
                vector.rust_variant
            );
            assert_eq!(
                matter.code(),
                &code,
                "SPECIAL_VECTORS ({}): code mismatch",
                vector.rust_variant
            );
        }
    }

    // ── Task 8: QB64 round-trip tests ────────────────────────────────────

    #[test]
    fn qb64_round_trip_fixed_vectors() {
        use crate::core::matter::test_vectors::FIXED_VECTORS;
        use core::str::FromStr;

        for (i, vector) in FIXED_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base64(vector.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "FIXED_VECTORS[{i}] ({}): QB64 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "FIXED_VECTORS[{i}] ({}): raw mismatch from QB64",
                vector.rust_variant
            );
            assert_eq!(
                matter.soft(),
                vector.soft,
                "FIXED_VECTORS[{i}] ({}): soft mismatch from QB64",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!("FIXED_VECTORS[{i}]: unknown code_str '{}'", vector.code_str)
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "FIXED_VECTORS[{i}] ({}): code mismatch from QB64",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn qb64_round_trip_special_vectors() {
        use crate::core::matter::test_vectors::SPECIAL_VECTORS;
        use core::str::FromStr;

        for (i, vector) in SPECIAL_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base64(vector.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS[{i}] ({}): QB64 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "SPECIAL_VECTORS[{i}] ({}): raw mismatch from QB64",
                vector.rust_variant
            );
            assert_eq!(
                matter.soft(),
                vector.soft,
                "SPECIAL_VECTORS[{i}] ({}): soft mismatch from QB64",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "SPECIAL_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "SPECIAL_VECTORS[{i}] ({}): code mismatch from QB64",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn qb64_round_trip_variable_vectors() {
        use crate::core::matter::test_vectors::VARIABLE_VECTORS;
        use core::str::FromStr;

        for (i, vector) in VARIABLE_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base64(vector.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "VARIABLE_VECTORS[{i}] ({}): QB64 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "VARIABLE_VECTORS[{i}] ({}): raw mismatch from QB64",
                vector.rust_variant
            );
            assert_eq!(
                matter.soft(),
                vector.soft,
                "VARIABLE_VECTORS[{i}] ({}): soft mismatch from QB64",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "VARIABLE_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "VARIABLE_VECTORS[{i}] ({}): code mismatch from QB64",
                vector.rust_variant
            );
        }
    }

    // ── Task 9: QB2 round-trip tests ─────────────────────────────────────

    #[test]
    fn qb2_round_trip_fixed_vectors() {
        use crate::core::matter::test_vectors::FIXED_VECTORS;
        use core::str::FromStr;

        for (i, vector) in FIXED_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "FIXED_VECTORS[{i}] ({}): QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "FIXED_VECTORS[{i}] ({}): raw mismatch from QB2",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!("FIXED_VECTORS[{i}]: unknown code_str '{}'", vector.code_str)
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "FIXED_VECTORS[{i}] ({}): code mismatch from QB2",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn qb2_handles_ls_gt0_and_short_bfs_codes() {
        // Verifies that from_qualified_base2() correctly handles:
        // - codes with ls > 0 (e.g. Label1 ls=1, TBD1 ls=1, TBD2 ls=2)
        // - zero-payload 4-char codes where bfs < hs (Null, No, Yes, Escape, Empty)
        use crate::core::matter::test_vectors::FIXED_VECTORS;
        use core::str::FromStr;

        // ls > 0 vectors
        let ls_gt0_vectors: Vec<_> = FIXED_VECTORS.iter().filter(|v| v.ls > 0).collect();
        assert!(
            !ls_gt0_vectors.is_empty(),
            "Expected at least one fixed vector with ls > 0"
        );
        for vector in &ls_gt0_vectors {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "FIXED ({}) with ls={}: QB2 parse failed: {e:?}",
                        vector.rust_variant, vector.ls
                    )
                });
            assert_eq!(
                matter.raw(),
                vector.raw,
                "FIXED ({}) with ls={}: raw mismatch",
                vector.rust_variant,
                vector.ls
            );
        }

        // zero-payload 4-char codes where bfs < hs
        let short_qb2_vectors: Vec<_> = FIXED_VECTORS
            .iter()
            .filter(|v| v.ls == 0 && v.qb2.len() < usize::from(v.hs))
            .collect();
        assert!(
            !short_qb2_vectors.is_empty(),
            "Expected at least one fixed vector with bfs < hs"
        );
        for vector in &short_qb2_vectors {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "FIXED ({}) with bfs < hs: QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });
            let expected_code = MatterCode::from_str(vector.code_str).unwrap();
            assert_eq!(
                matter.code(),
                &expected_code,
                "FIXED ({}) with bfs < hs: code mismatch",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn qb2_round_trip_special_vectors() {
        use crate::core::matter::test_vectors::SPECIAL_VECTORS;
        use core::str::FromStr;

        for (i, vector) in SPECIAL_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL_VECTORS[{i}] ({}): QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "SPECIAL_VECTORS[{i}] ({}): raw mismatch from QB2",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "SPECIAL_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "SPECIAL_VECTORS[{i}] ({}): code mismatch from QB2",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn qb2_round_trip_variable_vectors() {
        use crate::core::matter::test_vectors::VARIABLE_VECTORS;
        use core::str::FromStr;

        for (i, vector) in VARIABLE_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "VARIABLE_VECTORS[{i}] ({}): QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "VARIABLE_VECTORS[{i}] ({}): raw mismatch from QB2",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "VARIABLE_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "VARIABLE_VECTORS[{i}] ({}): code mismatch from QB2",
                vector.rust_variant
            );
        }
    }

    // ── Cross-format invariant tests (exhaustive over all vectors) ─────

    #[test]
    fn all_fixed_vectors_qb64_and_qb2_produce_identical_matter() {
        use crate::core::matter::test_vectors::FIXED_VECTORS;

        for (i, v) in FIXED_VECTORS.iter().enumerate() {
            let from_qb64 = MatterBuilder::new()
                .from_qualified_base64(v.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!("FIXED[{i}] ({}): QB64 parse failed: {e:?}", v.rust_variant)
                });
            let from_qb2 = MatterBuilder::new()
                .from_qualified_base2(v.qb2)
                .unwrap_or_else(|e| {
                    panic!("FIXED[{i}] ({}): QB2 parse failed: {e:?}", v.rust_variant)
                });

            assert_eq!(
                from_qb64.code(),
                from_qb2.code(),
                "FIXED[{i}] ({}): code mismatch between QB64 and QB2",
                v.rust_variant
            );
            assert_eq!(
                from_qb64.raw(),
                from_qb2.raw(),
                "FIXED[{i}] ({}): raw mismatch between QB64 and QB2",
                v.rust_variant
            );
            assert_eq!(
                from_qb64.soft(),
                from_qb2.soft(),
                "FIXED[{i}] ({}): soft mismatch between QB64 and QB2",
                v.rust_variant
            );
        }
    }

    #[test]
    fn all_special_vectors_qb64_and_qb2_produce_identical_matter() {
        use crate::core::matter::test_vectors::SPECIAL_VECTORS;

        for (i, v) in SPECIAL_VECTORS.iter().enumerate() {
            let from_qb64 = MatterBuilder::new()
                .from_qualified_base64(v.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "SPECIAL[{i}] ({}): QB64 parse failed: {e:?}",
                        v.rust_variant
                    )
                });
            let from_qb2 = MatterBuilder::new()
                .from_qualified_base2(v.qb2)
                .unwrap_or_else(|e| {
                    panic!("SPECIAL[{i}] ({}): QB2 parse failed: {e:?}", v.rust_variant)
                });

            assert_eq!(
                from_qb64.code(),
                from_qb2.code(),
                "SPECIAL[{i}] ({}): code mismatch between QB64 and QB2",
                v.rust_variant
            );
            assert_eq!(
                from_qb64.raw(),
                from_qb2.raw(),
                "SPECIAL[{i}] ({}): raw mismatch between QB64 and QB2",
                v.rust_variant
            );
            assert_eq!(
                from_qb64.soft(),
                from_qb2.soft(),
                "SPECIAL[{i}] ({}): soft mismatch between QB64 and QB2",
                v.rust_variant
            );
        }
    }

    #[test]
    fn all_variable_vectors_qb64_and_qb2_produce_identical_matter() {
        use crate::core::matter::test_vectors::VARIABLE_VECTORS;

        for (i, v) in VARIABLE_VECTORS.iter().enumerate() {
            let from_qb64 = MatterBuilder::new()
                .from_qualified_base64(v.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "VARIABLE[{i}] ({}): QB64 parse failed: {e:?}",
                        v.rust_variant
                    )
                });
            let from_qb2 = MatterBuilder::new()
                .from_qualified_base2(v.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "VARIABLE[{i}] ({}): QB2 parse failed: {e:?}",
                        v.rust_variant
                    )
                });

            assert_eq!(
                from_qb64.code(),
                from_qb2.code(),
                "VARIABLE[{i}] ({}): code mismatch between QB64 and QB2",
                v.rust_variant
            );
            assert_eq!(
                from_qb64.raw(),
                from_qb2.raw(),
                "VARIABLE[{i}] ({}): raw mismatch between QB64 and QB2",
                v.rust_variant
            );
            assert_eq!(
                from_qb64.soft(),
                from_qb2.soft(),
                "VARIABLE[{i}] ({}): soft mismatch between QB64 and QB2",
                v.rust_variant
            );
        }
    }

    // ── Task 14: Variable-size code promotion tests ──────────────────────

    #[test]
    fn variable_size_qb64_round_trip_preserves_soft_size_encoding() {
        use crate::core::matter::test_vectors::VARIABLE_VECTORS;
        use core::str::FromStr;

        for (i, vector) in VARIABLE_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base64(vector.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "VARIABLE_VECTORS[{i}] ({}): QB64 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            // Verify raw round-trips correctly
            assert_eq!(
                matter.raw(),
                vector.raw,
                "VARIABLE_VECTORS[{i}] ({}): raw mismatch",
                vector.rust_variant
            );

            // Verify the soft field contains the size encoding
            assert_eq!(
                matter.soft(),
                vector.soft,
                "VARIABLE_VECTORS[{i}] ({}): soft (size encoding) mismatch",
                vector.rust_variant
            );

            // Verify the code was correctly identified/promoted
            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "VARIABLE_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "VARIABLE_VECTORS[{i}] ({}): code mismatch after promotion",
                vector.rust_variant
            );

            // Verify fs is None (variable-size) per the test vector
            assert!(
                vector.fs.is_none(),
                "VARIABLE_VECTORS[{i}] ({}): expected variable-size (fs=None)",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn variable_size_qb2_round_trip_preserves_raw_and_code() {
        use crate::core::matter::test_vectors::VARIABLE_VECTORS;
        use core::str::FromStr;

        for (i, vector) in VARIABLE_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "VARIABLE_VECTORS[{i}] ({}): QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                matter.raw(),
                vector.raw,
                "VARIABLE_VECTORS[{i}] ({}): raw mismatch from QB2",
                vector.rust_variant
            );

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "VARIABLE_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "VARIABLE_VECTORS[{i}] ({}): code mismatch from QB2",
                vector.rust_variant
            );
        }
    }

    // ── Boundary-size variable code tests (Small→Big promotion) ─────────

    #[test]
    fn boundary_vectors_qb64_round_trip() {
        use crate::core::matter::test_vectors_boundary::BOUNDARY_VECTORS;
        use core::str::FromStr;

        for (i, vector) in BOUNDARY_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base64(vector.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "BOUNDARY_VECTORS[{i}] ({}): QB64 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "BOUNDARY_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "BOUNDARY_VECTORS[{i}] ({}): code mismatch from QB64",
                vector.rust_variant
            );
            assert_eq!(
                matter.raw(),
                vector.raw,
                "BOUNDARY_VECTORS[{i}] ({}): raw mismatch from QB64",
                vector.rust_variant
            );
            assert_eq!(
                matter.soft(),
                vector.soft,
                "BOUNDARY_VECTORS[{i}] ({}): soft mismatch from QB64",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn boundary_vectors_qb2_round_trip() {
        use crate::core::matter::test_vectors_boundary::BOUNDARY_VECTORS;
        use core::str::FromStr;

        for (i, vector) in BOUNDARY_VECTORS.iter().enumerate() {
            let matter = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "BOUNDARY_VECTORS[{i}] ({}): QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            let expected_code = MatterCode::from_str(vector.code_str).unwrap_or_else(|_| {
                panic!(
                    "BOUNDARY_VECTORS[{i}]: unknown code_str '{}'",
                    vector.code_str
                )
            });
            assert_eq!(
                matter.code(),
                &expected_code,
                "BOUNDARY_VECTORS[{i}] ({}): code mismatch from QB2",
                vector.rust_variant
            );
            assert_eq!(
                matter.raw(),
                vector.raw,
                "BOUNDARY_VECTORS[{i}] ({}): raw mismatch from QB2",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn boundary_vectors_qb64_and_qb2_produce_identical_matter() {
        use crate::core::matter::test_vectors_boundary::BOUNDARY_VECTORS;

        for (i, vector) in BOUNDARY_VECTORS.iter().enumerate() {
            let from_qb64 = MatterBuilder::new()
                .from_qualified_base64(vector.qb64.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "BOUNDARY_VECTORS[{i}] ({}): QB64 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });
            let from_qb2 = MatterBuilder::new()
                .from_qualified_base2(vector.qb2)
                .unwrap_or_else(|e| {
                    panic!(
                        "BOUNDARY_VECTORS[{i}] ({}): QB2 parse failed: {e:?}",
                        vector.rust_variant
                    )
                });

            assert_eq!(
                from_qb64.code(),
                from_qb2.code(),
                "BOUNDARY_VECTORS[{i}] ({}): code mismatch between QB64 and QB2",
                vector.rust_variant
            );
            assert_eq!(
                from_qb64.raw(),
                from_qb2.raw(),
                "BOUNDARY_VECTORS[{i}] ({}): raw mismatch between QB64 and QB2",
                vector.rust_variant
            );
            assert_eq!(
                from_qb64.soft(),
                from_qb2.soft(),
                "BOUNDARY_VECTORS[{i}] ({}): soft mismatch between QB64 and QB2",
                vector.rust_variant
            );
        }
    }

    #[test]
    fn boundary_vector_code_promotion_is_correct() {
        use crate::core::matter::test_vectors_boundary::BOUNDARY_VECTORS;

        // Vector 0: 12285 bytes (4095 triplets) — should stay Small (StrB64_L0, "4A")
        assert_eq!(
            BOUNDARY_VECTORS[0].code_str, "4A",
            "12285-byte vector should use Small code '4A'"
        );
        assert_eq!(BOUNDARY_VECTORS[0].ss, 2, "Small code should have ss=2");

        // Vector 1: 12288 bytes (4096 triplets) — should promote to Big (StrB64Big_L0, "7AAA")
        assert_eq!(
            BOUNDARY_VECTORS[1].code_str, "7AAA",
            "12288-byte vector should promote to Big code '7AAA'"
        );
        assert_eq!(BOUNDARY_VECTORS[1].ss, 4, "Big code should have ss=4");

        // Vector 2: 12291 bytes (4097 triplets) — should also be Big
        assert_eq!(
            BOUNDARY_VECTORS[2].code_str, "7AAA",
            "12291-byte vector should use Big code '7AAA'"
        );
        assert_eq!(BOUNDARY_VECTORS[2].ss, 4, "Big code should have ss=4");
    }

    // ── QB2 parsing edge case tests ──────────────────────────────────────
    // These tests verify that the QB2 parser handles malformed, truncated,
    // and boundary-condition binary streams without panicking.

    #[test]
    fn qb2_parsing_rejects_single_byte() {
        // A single byte is never enough for any CESR code (minimum 1-char
        // code still needs raw data bytes following the code byte).
        let result = MatterBuilder::new().from_qualified_base2(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_parsing_rejects_two_bytes() {
        // Two bytes may parse a 1-char code header but will have insufficient
        // data for even the smallest fixed-size primitive (Short = 4 b64 chars
        // = 3 bytes in QB2).
        let result = MatterBuilder::new().from_qualified_base2(&[0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_parsing_rejects_truncated_2char_code() {
        // A 2-char code needs 2 bytes for the header (hs=2 -> 2*6/8 rounded
        // up = 2 bytes). Providing only the first byte of a 2-char code
        // should fail with StreamTooShort.
        // 0xD0 is the first byte of Salt128 ("0A") in QB2.
        let result = MatterBuilder::new().from_qualified_base2(&[0xD0]);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_parsing_rejects_truncated_4char_code() {
        // A 4-char code needs 3 bytes for the header. Providing only 2 bytes
        // should fail.
        // 0xD4, 0x00 is the start of ECDSA256k1N ("1AAA") in QB2.
        let result = MatterBuilder::new().from_qualified_base2(&[0xD4, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_parsing_rejects_header_only_no_payload() {
        // Provide exactly the header bytes for Ed25519Seed (1-char code, "A")
        // but no payload data. The code needs 32 raw bytes.
        // In QB2: bhs = ceil(1*3/4) = 1 byte for the code, then 32 raw bytes.
        // Only providing the code byte should fail.
        let result = MatterBuilder::new().from_qualified_base2(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_all_0xff_bytes_rejected() {
        // A stream of all 0xFF bytes maps to sextet value 63 in the first
        // position, which should not match any valid CESR code.
        let all_ff = [0xFF; 64];
        let result = MatterBuilder::new().from_qualified_base2(&all_ff);
        assert!(result.is_err());
    }

    #[test]
    fn qb2_high_bit_patterns_do_not_panic() {
        // Various high-bit patterns that could trigger edge cases in the
        // sextet extraction logic.
        let patterns: Vec<Vec<u8>> = vec![
            vec![0x80; 4],
            vec![0xC0; 4],
            vec![0xE0; 4],
            vec![0xF0; 4],
            vec![0xFE; 4],
            vec![0x80, 0x00, 0x00, 0x00],
            vec![0xFF, 0x00, 0xFF, 0x00],
        ];
        for pattern in &patterns {
            // Should not panic -- errors are acceptable
            let _ = MatterBuilder::new().from_qualified_base2(pattern);
        }
    }

    // ── proptest: Builder construction with random raw bytes ─────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        // One proptest per representative code, each generating random raw bytes
        // of sufficient length and verifying builder construction succeeds.

        macro_rules! proptest_builder_raw {
            ($name:ident, $code:expr, $raw_size:expr) => {
                proptest! {
                    #[test]
                    fn $name(
                        raw_bytes in proptest::collection::vec(any::<u8>(), $raw_size..=$raw_size + 64)
                    ) {
                        let code = $code;
                        let matter = MatterBuilder::new()
                            .with_code(code)
                            .with_raw(&raw_bytes)
                            .unwrap()
                            .build()
                            .unwrap();

                        prop_assert_eq!(matter.raw(), &raw_bytes[..$raw_size]);
                        prop_assert_eq!(matter.code(), &code);
                    }
                }
            };
        }

        // 1-char codes
        proptest_builder_raw!(random_raw_ed25519_seed, MatterCode::Ed25519Seed, 32);
        proptest_builder_raw!(random_raw_blake3_256, MatterCode::Blake3_256, 32);
        proptest_builder_raw!(random_raw_short, MatterCode::Short, 2);

        // 2-char codes
        proptest_builder_raw!(random_raw_salt128, MatterCode::Salt128, 16);
        proptest_builder_raw!(random_raw_ed25519_sig, MatterCode::Ed25519Sig, 64);
        proptest_builder_raw!(random_raw_long, MatterCode::Long, 4);

        // 4-char codes
        proptest_builder_raw!(random_raw_ed448_sig, MatterCode::Ed448Sig, 114);
        proptest_builder_raw!(random_raw_ecdsa256k1n, MatterCode::ECDSA256k1N, 33);

        proptest! {
            #[test]
            fn qb2_parsing_never_panics_on_random_bytes(
                random_bytes in proptest::collection::vec(any::<u8>(), 0..256)
            ) {
                // The QB2 parser must never panic on arbitrary input.
                // It should either succeed or return an error.
                let _ = MatterBuilder::new().from_qualified_base2(&random_bytes);
            }
        }

        proptest! {
            #[test]
            fn qb64_parsing_never_panics_on_random_payload(
                idx in 0usize..50,
                random_bytes in proptest::collection::vec(any::<u8>(), 0..256)
            ) {
                use crate::core::matter::test_vectors::FIXED_VECTORS;

                let vector = &FIXED_VECTORS[idx % FIXED_VECTORS.len()];

                // Build a QB64 stream with the correct code prefix but random payload
                let cs = usize::from(vector.hs) + usize::from(vector.ss);
                let prefix = &vector.qb64[..cs];
                let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let payload: String = random_bytes.iter()
                    .map(|&b| char::from(b64_chars[usize::from(b) % 64]))
                    .collect();

                // Pad to correct fs length if needed
                if let Some(fs) = vector.fs {
                    let needed = usize::from(fs) - cs;
                    if payload.len() >= needed {
                        let stream = format!("{prefix}{}", &payload[..needed]);
                        // Should not panic — errors are fine
                        let _ = MatterBuilder::new()
                            .from_qualified_base64(stream.as_bytes());
                    }
                }
            }
        }
    }
}
