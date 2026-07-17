//! Text-domain (qb64) primitive reading: the checked [`TextStream`] cursor.
//!
//! The CESR spec calls the qb64 representation the **text domain** (T);
//! [`TextStream`] is a checked cursor over one text-domain byte stream.
//! Every advance funnels through [`TextStream::take`] — the single bounds
//! check — and each primitive is consumed by a typed `read_*` method or a
//! lenient `skip_*` method (framing only: size by code class, no decode, no
//! narrowing to a family's typed codes).

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};
use cesr::b64::decode_int;
use cesr::core::counter::CounterCodeV1;
use cesr::core::counter::CounterCodeV2;
use cesr::core::indexer::Indexer;
use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::core::indexer::code::hardage;
use cesr::core::indexer::xizage::XizageSize;
use cesr::core::matter::Matter;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::DigestCode;
use cesr::core::matter::code::LabelerCode;
use cesr::core::matter::code::MatterCode;
use cesr::core::matter::code::NoncerCode;
use cesr::core::matter::code::NumberCode;
use cesr::core::matter::code::SignatureCode;
use cesr::core::matter::code::TexterCode;
use cesr::core::matter::code::VerKeyCode;
use cesr::core::matter::code::VerserCode;
use cesr::core::matter::error::MatterBuildError;
use cesr::core::matter::sizage::SizeType;
use cesr::core::primitives::Cigar;
use cesr::core::primitives::Diger;
use cesr::core::primitives::Labeler;
use cesr::core::primitives::Noncer;
use cesr::core::primitives::Number;
use cesr::core::primitives::Prefixer;
use cesr::core::primitives::Saider;
use cesr::core::primitives::Siger;
use cesr::core::primitives::Texter;
use cesr::core::primitives::Verfer;
use cesr::core::primitives::Verser;

use crate::error::ParseError;

/// Extract the hard code string and hard size from a counter prefix.
///
/// All CESR counter versions share the same wire framing:
/// - `b'-'` followed by `b'-'` → hs=3 (big variant `--X`)
/// - `b'-'` followed by `b'_'` → hs=5 (genus `-_AAA`)
/// - `b'-'` followed by anything else → hs=2 (small variant `-X`)
fn extract_hard(input: &[u8]) -> Result<(&str, usize), ParseError> {
    if input.is_empty() {
        return Err(ParseError::NeedBytes(1));
    }
    if input[0] != b'-' {
        return Err(ParseError::Malformed(format!(
            "expected counter '-', got '{}'",
            char::from(input[0])
        )));
    }

    let hs = if input.len() >= 2 {
        match input[1] {
            b'-' => 3,
            b'_' => 5,
            _ => 2,
        }
    } else {
        return Err(ParseError::NeedBytes(1));
    };

    if input.len() < hs {
        return Err(ParseError::NeedBytes(hs - input.len()));
    }

    let hard = core::str::from_utf8(&input[..hs])
        .map_err(|_| ParseError::Malformed("invalid UTF-8 in counter".into()))?;
    Ok((hard, hs))
}

/// Compute the full qb64 size of the Matter primitive at the head of
/// `input` — code lookup and size computation only, no base64 decode.
fn matter_full_size(input: &[u8]) -> Result<usize, ParseError> {
    let code = MatterCode::from_base64_stream(input)?;

    let sizage = code.get_sizage();
    let hs = sizage.hs();
    let ss = sizage.ss();
    let cs = hs + ss;

    let fs = if let SizeType::Fixed(n) = sizage.fs() {
        usize::from(*n)
    } else {
        if input.len() < cs {
            return Err(ParseError::NeedBytes(cs - input.len()));
        }
        let soft = core::str::from_utf8(&input[hs..cs])
            .map_err(|_| ParseError::Malformed("invalid UTF-8 in soft field".into()))?;
        let xs = sizage.xs();
        let soft_value = &soft[xs..];
        let size: usize = decode_int(soft_value)?;
        (size * 4) + cs
    };

    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }

    Ok(fs)
}

/// Compute the full qb64 size of the Indexer primitive at the head of
/// `input` — mirrors the size logic of `IndexerBuilder::from_qb64` but stops
/// after determining the full size. No base64 decode or construction.
fn indexer_full_size(input: &[u8]) -> Result<usize, ParseError> {
    let &first_byte = input.first().ok_or(ParseError::NeedBytes(1))?;

    let first_char = char::from(first_byte);
    let hard_size = hardage(first_char).ok_or_else(|| {
        ParseError::Malformed(format!("unknown indexer code lead: '{first_char}'"))
    })?;

    if input.len() < hard_size {
        return Err(ParseError::NeedBytes(hard_size - input.len()));
    }

    let hard = core::str::from_utf8(&input[..hard_size])
        .map_err(|_| ParseError::Malformed("invalid UTF-8 in indexer hard field".into()))?;
    let code = IndexedSigCode::from_hard(hard)
        .map_err(|e| ParseError::Malformed(format!("unknown indexer code: {e}")))?;

    let xizage = code.get_xizage();
    let hs = usize::from(xizage.hs);
    let ss = usize::from(xizage.ss);
    let cs = hs + ss;

    let fs = match xizage.fs {
        XizageSize::Fixed(n) => usize::from(n),
        XizageSize::Variable => {
            if input.len() < cs {
                return Err(ParseError::NeedBytes(cs - input.len()));
            }
            let os = usize::from(xizage.os);
            let ms = ss - os;
            let index_str = core::str::from_utf8(&input[hs..hs + ms])
                .map_err(|_| ParseError::Malformed("invalid UTF-8 in indexer soft".into()))?;
            let index: usize = decode_int(index_str)?;
            index * 4 + cs
        }
    };

    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }

    Ok(fs)
}

/// A checked cursor over one CESR **text-domain** (qb64) byte stream.
///
/// Owns the input slice and the current position. Every advance goes through
/// [`Self::take`] — the one place bounds are checked — so a `read_*`/`skip_*`
/// method can never move the cursor past the end of the input.
///
/// Two consumption regimes, preserved from the free-function surface this
/// cursor replaced:
///
/// - **Typed reads** (`read_matter`, `read_siger`, …) decode the primitive
///   and narrow it to its typed code, erroring with
///   [`ParseError::UnexpectedCodeType`] on a family mismatch.
/// - **Lenient skips** (`skip_matter`, `skip_indexer`, `skip_counter`) are
///   the framing grammar: they size the primitive by code class without
///   decoding or narrowing, deliberately cheaper and more lenient than the
///   reads. Group kinds frame with skips and type lazily on iteration.
pub(crate) struct TextStream<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> TextStream<'a> {
    /// Open a cursor at the start of `input`.
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// The bytes not yet consumed.
    pub(crate) fn remaining(&self) -> &'a [u8] {
        // `pos <= input.len()` is the cursor invariant: `pos` starts at 0 and
        // only `take` advances it, after proving the span is in bounds.
        &self.input[self.pos..]
    }

    /// The number of bytes consumed so far.
    pub(crate) const fn offset(&self) -> usize {
        self.pos
    }

    /// The single checked advance: consume exactly `n` bytes, returning the
    /// consumed span.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::NeedBytes`] with the shortfall if fewer than
    /// `n` bytes remain.
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let rem = self.remaining();
        if rem.len() < n {
            return Err(ParseError::NeedBytes(n - rem.len()));
        }
        let pos = self
            .pos
            .checked_add(n)
            .ok_or_else(|| ParseError::Malformed("text-stream cursor position overflows".into()))?;
        self.pos = pos;
        Ok(&rem[..n])
    }

    // ── Typed reads ──────────────────────────────────────────────────────

    /// Read one Matter primitive.
    ///
    /// Passes the qb64 slice by reference (zero copy) to
    /// `from_qualified_base64`, then calls `into_static()` to detach from the
    /// input buffer. This is near-zero cost: `raw` is already owned (base64
    /// decode), so only the `soft` field (0-4 bytes) is cloned.
    pub(crate) fn read_matter(&mut self) -> Result<Matter<'static, MatterCode>, ParseError> {
        let fs = matter_full_size(self.remaining())?;
        let span = self.take(fs)?;
        let matter = MatterBuilder::new()
            .from_qualified_base64(span)
            .map_err(|err| match err {
                MatterBuildError::Parsing(pe) => ParseError::from(pe),
                MatterBuildError::Validation(ve) => ParseError::from(ve),
            })?
            .into_static();
        Ok(matter)
    }

    /// Read one Indexer primitive.
    pub(crate) fn read_indexer(&mut self) -> Result<Indexer<'static>, ParseError> {
        if self.remaining().is_empty() {
            return Err(ParseError::NeedBytes(1));
        }
        let (indexer, consumed) = IndexerBuilder::new()
            .from_qb64(self.remaining())
            .map_err(ParseError::from)?;
        self.take(consumed)?;
        Ok(indexer)
    }

    /// Read a V1.0 counter code and element count.
    pub(crate) fn read_counter_v1(&mut self) -> Result<(CounterCodeV1, u32), ParseError> {
        let input = self.remaining();
        let (hard, hs) = extract_hard(input)?;
        let code = CounterCodeV1::from_hard(hard)?;
        let ss = code.soft_size();
        let fs = hs + ss;
        if input.len() < fs {
            return Err(ParseError::NeedBytes(fs - input.len()));
        }
        let count_str = core::str::from_utf8(&input[hs..fs])
            .map_err(|_| ParseError::Malformed("invalid UTF-8 in counter soft field".into()))?;
        let count: u32 = decode_int(count_str)?;
        self.take(fs)?;
        Ok((code, count))
    }

    /// Read a V2.0 counter code and element count.
    pub(crate) fn read_counter_v2(&mut self) -> Result<(CounterCodeV2, u32), ParseError> {
        let input = self.remaining();
        let (hard, hs) = extract_hard(input)?;
        let code = CounterCodeV2::from_hard(hard)?;
        let ss = code.soft_size();
        let fs = hs + ss;
        if input.len() < fs {
            return Err(ParseError::NeedBytes(fs - input.len()));
        }
        let count_str = core::str::from_utf8(&input[hs..fs])
            .map_err(|_| ParseError::Malformed("invalid UTF-8 in counter soft field".into()))?;
        let count: u32 = decode_int(count_str)?;
        self.take(fs)?;
        Ok((code, count))
    }

    /// Read a Verfer (verification key).
    pub(crate) fn read_verfer(&mut self) -> Result<Verfer<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<VerKeyCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "VerKeyCode",
                got: e.to_string(),
            })
    }

    /// Read a Prefixer (AID prefix, same wire shape as Verfer).
    pub(crate) fn read_prefixer(&mut self) -> Result<Prefixer<'static>, ParseError> {
        self.read_verfer()
    }

    /// Read a Diger (digest).
    pub(crate) fn read_diger(&mut self) -> Result<Diger<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<DigestCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "DigestCode",
                got: e.to_string(),
            })
    }

    /// Read a Saider (SAID, same wire shape as Diger).
    pub(crate) fn read_saider(&mut self) -> Result<Saider<'static>, ParseError> {
        self.read_diger()
    }

    /// Read a Cigar (non-indexed signature).
    pub(crate) fn read_cigar(&mut self) -> Result<Cigar<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<SignatureCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "SignatureCode",
                got: e.to_string(),
            })
    }

    /// Read a Siger (indexed signature).
    pub(crate) fn read_siger(&mut self) -> Result<Siger<'static>, ParseError> {
        let indexer = self.read_indexer()?;
        Ok(Siger::new(indexer))
    }

    /// Read a Verser (version/protocol primitive).
    pub(crate) fn read_verser(&mut self) -> Result<Verser<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<VerserCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "VerserCode",
                got: e.to_string(),
            })
    }

    /// Read a Noncer (nonce/randomness primitive).
    pub(crate) fn read_noncer(&mut self) -> Result<Noncer<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<NoncerCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "NoncerCode",
                got: e.to_string(),
            })
    }

    /// Read a Labeler (field name/tag primitive).
    pub(crate) fn read_labeler(&mut self) -> Result<Labeler<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<LabelerCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "LabelerCode",
                got: e.to_string(),
            })
    }

    /// Read a Texter (variable-length byte string primitive).
    pub(crate) fn read_texter(&mut self) -> Result<Texter<'static>, ParseError> {
        let matter = self.read_matter()?;
        matter
            .narrow::<TexterCode>()
            .map_err(|e| ParseError::UnexpectedCodeType {
                expected: "TexterCode",
                got: e.to_string(),
            })
    }

    /// Read a Number (unsigned integer): a Matter narrowed to `NumberCode`,
    /// with the raw big-endian bytes converted to a `u128` value.
    pub(crate) fn read_number(&mut self) -> Result<Number, ParseError> {
        let matter = self.read_matter()?;
        let narrowed =
            matter
                .narrow::<NumberCode>()
                .map_err(|e| ParseError::UnexpectedCodeType {
                    expected: "NumberCode",
                    got: e.to_string(),
                })?;
        let raw = narrowed.raw();
        let mut value: u128 = 0;
        for &byte in raw {
            value = (value << 8) | u128::from(byte);
        }
        Ok(Number::with_code(*narrowed.code(), value))
    }

    // ── Lenient skips (framing grammar) ──────────────────────────────────

    /// Skip one Matter primitive: size by code class only — no base64
    /// decode, no `MatterBuilder` construction, no typed narrowing.
    pub(crate) fn skip_matter(&mut self) -> Result<(), ParseError> {
        let fs = matter_full_size(self.remaining())?;
        self.take(fs)?;
        Ok(())
    }

    /// Skip `arity` consecutive Matter primitives.
    pub(crate) fn skip_matters(&mut self, arity: usize) -> Result<(), ParseError> {
        for _ in 0..arity {
            self.skip_matter()?;
        }
        Ok(())
    }

    /// Skip one Indexer primitive: size computation only, no decode.
    pub(crate) fn skip_indexer(&mut self) -> Result<(), ParseError> {
        let fs = indexer_full_size(self.remaining())?;
        self.take(fs)?;
        Ok(())
    }

    /// Skip one counter (code + soft field) without decoding the count.
    ///
    /// Tries V1 first, then V2 — lenient across counter tables, exactly like
    /// the framing pass it serves.
    pub(crate) fn skip_counter(&mut self) -> Result<(), ParseError> {
        let input = self.remaining();
        let (hard, hs) = extract_hard(input)?;

        let ss = if let Ok(code) = CounterCodeV1::from_hard(hard) {
            code.soft_size()
        } else if let Ok(code) = CounterCodeV2::from_hard(hard) {
            code.soft_size()
        } else {
            return Err(ParseError::UnknownCounterCode(hard.to_owned()));
        };

        let fs = hs + ss;
        self.take(fs)?;
        Ok(())
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
    use cesr::core::indexer::code::IndexedSigCode;
    use core::num::NonZeroUsize;

    // -- helpers --

    /// Extract the error from a Result whose Ok type may not implement Debug.
    /// Panics (via assert!) if the result is Ok.
    fn expect_err<T>(result: Result<T, ParseError>) -> ParseError {
        assert!(result.is_err(), "expected Err, got Ok");
        // SAFETY: we just asserted is_err()
        match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        }
    }

    /// Read one Matter with a fresh cursor, returning it and the rest.
    fn read_matter(input: &[u8]) -> Result<(Matter<'static, MatterCode>, &[u8]), ParseError> {
        let mut ts = TextStream::new(input);
        let matter = ts.read_matter()?;
        Ok((matter, ts.remaining()))
    }

    /// Skip one Matter with a fresh cursor, returning the consumed size.
    fn skip_matter(input: &[u8]) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matter()?;
        Ok(ts.offset())
    }

    /// Skip one Indexer with a fresh cursor, returning the consumed size.
    fn skip_indexer(input: &[u8]) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_indexer()?;
        Ok(ts.offset())
    }

    /// Skip one counter with a fresh cursor, returning the consumed size.
    fn skip_counter(input: &[u8]) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_counter()?;
        Ok(ts.offset())
    }

    fn build_ed25519_qb64() -> Vec<u8> {
        // Ed25519: code "D", hs=1, ss=0, cs=1, ps=1, fs=44
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xAB_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_blake3_256_qb64() -> Vec<u8> {
        // Blake3_256: code "E", hs=1, ss=0, cs=1, ps=1, fs=44
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_ed25519_sig_qb64() -> Vec<u8> {
        // Ed25519Sig: code "0B", hs=2, ss=0, cs=2, ps=2, fs=88
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xAB_u8; 64];
        let ps = 2_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("0B{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_indexer_qb64() -> (Vec<u8>, IndexedSigCode, u32) {
        let code = IndexedSigCode::Ed25519;
        let index = 3_u32;
        let raw = [0u8; 64];
        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(index)
            .unwrap()
            .with_raw(&raw[..])
            .unwrap();
        let qb64 = indexer.to_qb64();
        (qb64.into_bytes(), code, index)
    }

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = cesr::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    // ====================================================================
    // read_matter tests
    // ====================================================================

    #[test]
    fn parse_matter_ed25519_roundtrip() {
        let qb64 = build_ed25519_qb64();
        let (matter, rest) = read_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Ed25519);
        assert_eq!(matter.raw(), &[0xAB_u8; 32]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_matter_with_trailing_bytes() {
        let mut qb64 = build_ed25519_qb64();
        qb64.extend_from_slice(b"TRAILING");
        let (matter, rest) = read_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Ed25519);
        assert_eq!(rest, b"TRAILING");
    }

    #[test]
    fn parse_matter_need_bytes_empty() {
        let result = read_matter(b"");
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    #[test]
    fn parse_matter_need_bytes_truncated() {
        let qb64 = build_ed25519_qb64();
        let result = read_matter(&qb64[..10]);
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(34)));
    }

    #[test]
    fn parse_matter_ed25519_sig() {
        let qb64 = build_ed25519_sig_qb64();
        assert_eq!(qb64.len(), 88);
        let (matter, rest) = read_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Ed25519Sig);
        assert_eq!(matter.raw().len(), 64);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_matter_unknown_code() {
        let result = read_matter(b"!AAAAAAA");
        assert!(result.is_err());
    }

    #[test]
    fn parse_matter_blake3_256() {
        let qb64 = build_blake3_256_qb64();
        assert_eq!(qb64.len(), 44);
        let (matter, rest) = read_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Blake3_256);
        assert_eq!(matter.raw(), &[0xCD_u8; 32]);
        assert!(rest.is_empty());
    }

    // ====================================================================
    // read_indexer tests
    // ====================================================================

    #[test]
    fn parse_indexer_roundtrip() {
        let (qb64, code, index) = build_indexer_qb64();
        let mut ts = TextStream::new(&qb64);
        let indexer = ts.read_indexer().unwrap();
        assert_eq!(indexer.code(), code);
        assert_eq!(indexer.index(), index);
        assert_eq!(indexer.raw().len(), 64);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_indexer_with_trailing_bytes() {
        let (mut qb64, _, _) = build_indexer_qb64();
        qb64.extend_from_slice(b"EXTRA");
        let mut ts = TextStream::new(&qb64);
        let _ = ts.read_indexer().unwrap();
        assert_eq!(ts.remaining(), b"EXTRA");
    }

    #[test]
    fn parse_indexer_need_bytes_empty() {
        let result = TextStream::new(b"").read_indexer();
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_indexer_need_bytes_truncated() {
        let (qb64, _, _) = build_indexer_qb64();
        let result = TextStream::new(&qb64[..4]).read_indexer();
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    // ====================================================================
    // read_counter_v1 tests
    // ====================================================================

    #[test]
    fn parse_counter_standard() {
        let qb64 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2);
        assert_eq!(qb64.len(), 4);
        let mut ts = TextStream::new(&qb64);
        let (code, count) = ts.read_counter_v1().unwrap();
        assert_eq!(code, CounterCodeV1::ControllerIdxSigs);
        assert_eq!(count, 2);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_counter_big_variant() {
        let qb64 = build_counter_qb64(CounterCodeV1::BigAttachmentGroup, 100);
        assert_eq!(qb64.len(), 8);
        let mut ts = TextStream::new(&qb64);
        let (code, count) = ts.read_counter_v1().unwrap();
        assert_eq!(code, CounterCodeV1::BigAttachmentGroup);
        assert_eq!(count, 100);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_counter_with_trailing_data() {
        let mut qb64 = build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 5);
        qb64.extend_from_slice(b"MORESTUFF");
        let mut ts = TextStream::new(&qb64);
        let (code, count) = ts.read_counter_v1().unwrap();
        assert_eq!(code, CounterCodeV1::WitnessIdxSigs);
        assert_eq!(count, 5);
        assert_eq!(ts.remaining(), b"MORESTUFF");
    }

    #[test]
    fn parse_counter_need_bytes_empty() {
        let result = TextStream::new(b"").read_counter_v1();
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_counter_need_bytes_one_byte() {
        let result = TextStream::new(b"-").read_counter_v1();
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_counter_need_bytes_short_soft() {
        // "-A" is ControllerIdxSigs: hs=2, ss=2, fs=4 but only 3 bytes given
        let result = TextStream::new(b"-AB").read_counter_v1();
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_counter_error_non_counter_input() {
        let result = TextStream::new(b"AABC").read_counter_v1();
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn parse_counter_unknown_code() {
        let result = TextStream::new(b"-JAB").read_counter_v1();
        assert!(result.is_err());
        assert!(matches!(
            expect_err(result),
            ParseError::UnknownCounterCode(_)
        ));
    }

    #[test]
    fn parse_counter_zero_count() {
        let qb64 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 0);
        let mut ts = TextStream::new(&qb64);
        let (code, count) = ts.read_counter_v1().unwrap();
        assert_eq!(code, CounterCodeV1::ControllerIdxSigs);
        assert_eq!(count, 0);
        assert!(ts.remaining().is_empty());
    }

    // ====================================================================
    // read_verfer tests
    // ====================================================================

    #[test]
    fn parse_verfer_success() {
        let qb64 = build_ed25519_qb64();
        let mut ts = TextStream::new(&qb64);
        let verfer = ts.read_verfer().unwrap();
        assert_eq!(*verfer.code(), VerKeyCode::Ed25519);
        assert_eq!(verfer.raw(), &[0xAB_u8; 32]);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_verfer_wrong_code_type() {
        let qb64 = build_blake3_256_qb64();
        let result = TextStream::new(&qb64).read_verfer();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "VerKeyCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_prefixer tests
    // ====================================================================

    #[test]
    fn parse_prefixer_success() {
        let qb64 = build_ed25519_qb64();
        let mut ts = TextStream::new(&qb64);
        let prefixer = ts.read_prefixer().unwrap();
        assert_eq!(*prefixer.code(), VerKeyCode::Ed25519);
        assert!(ts.remaining().is_empty());
    }

    // ====================================================================
    // read_diger tests
    // ====================================================================

    #[test]
    fn parse_diger_success() {
        let qb64 = build_blake3_256_qb64();
        let mut ts = TextStream::new(&qb64);
        let diger = ts.read_diger().unwrap();
        assert_eq!(*diger.code(), DigestCode::Blake3_256);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_diger_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_diger();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "DigestCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_saider tests
    // ====================================================================

    #[test]
    fn parse_saider_success() {
        let qb64 = build_blake3_256_qb64();
        let mut ts = TextStream::new(&qb64);
        let saider = ts.read_saider().unwrap();
        assert_eq!(*saider.code(), DigestCode::Blake3_256);
        assert!(ts.remaining().is_empty());
    }

    // ====================================================================
    // read_cigar tests
    // ====================================================================

    #[test]
    fn parse_cigar_success() {
        let qb64 = build_ed25519_sig_qb64();
        let mut ts = TextStream::new(&qb64);
        let cigar = ts.read_cigar().unwrap();
        assert_eq!(*cigar.code(), SignatureCode::Ed25519Sig);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_cigar_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_cigar();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "SignatureCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_siger tests
    // ====================================================================

    #[test]
    fn parse_siger_roundtrip() {
        let (qb64, code, index) = build_indexer_qb64();
        let mut ts = TextStream::new(&qb64);
        let siger = ts.read_siger().unwrap();
        assert_eq!(siger.code(), code);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.raw().len(), 64);
        assert!(siger.verfer().is_none());
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_siger_with_trailing_bytes() {
        let (mut qb64, _, _) = build_indexer_qb64();
        qb64.extend_from_slice(b"TRAIL");
        let mut ts = TextStream::new(&qb64);
        let _ = ts.read_siger().unwrap();
        assert_eq!(ts.remaining(), b"TRAIL");
    }

    #[test]
    fn parse_siger_need_bytes_empty() {
        let result = TextStream::new(b"").read_siger();
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    // ====================================================================
    // read_verser tests
    // ====================================================================

    #[test]
    fn parse_verser_tag7_success() {
        // Tag7: code "Y", soft = 7 chars, fs=8, raw is empty
        let qb64 = b"YAAAAAAA";
        let mut ts = TextStream::new(qb64);
        let verser = ts.read_verser().unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag7);
        assert!(verser.raw().is_empty());
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_verser_tag10_success() {
        // Tag10: code "0O", soft = 10 chars, fs=12
        let qb64 = b"0OAAAAAAAAAA";
        let mut ts = TextStream::new(qb64);
        let verser = ts.read_verser().unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag10);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_verser_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_verser();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "VerserCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_noncer tests
    // ====================================================================

    #[test]
    fn parse_noncer_blake3_256_success() {
        // Blake3_256 is a valid NoncerCode
        let qb64 = build_blake3_256_qb64();
        let mut ts = TextStream::new(&qb64);
        let noncer = ts.read_noncer().unwrap();
        assert_eq!(*noncer.code(), NoncerCode::Blake3_256);
        assert_eq!(noncer.raw(), &[0xCD_u8; 32]);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_noncer_wrong_code_type() {
        // Ed25519 is not a NoncerCode
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_noncer();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "NoncerCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_labeler tests
    // ====================================================================

    #[test]
    fn parse_labeler_tag3_success() {
        // Tag3: code "X", soft = "AAA", fs=4
        let qb64 = b"XAAA";
        let mut ts = TextStream::new(qb64);
        let labeler = ts.read_labeler().unwrap();
        assert_eq!(*labeler.code(), LabelerCode::Tag3);
        assert!(labeler.raw().is_empty());
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_labeler_tag7_success() {
        // Tag7 is also a valid LabelerCode
        let qb64 = b"YAAAAAAA";
        let mut ts = TextStream::new(qb64);
        let labeler = ts.read_labeler().unwrap();
        assert_eq!(*labeler.code(), LabelerCode::Tag7);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_labeler_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_labeler();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "LabelerCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_texter tests
    // ====================================================================

    #[test]
    fn parse_texter_bytes_l0_success() {
        // Bytes_L0: code "4B", soft = "AC" (size), raw = 6 bytes
        // From test vector: qb64 = "4BACW19uJT6H"
        let qb64 = b"4BACW19uJT6H";
        let mut ts = TextStream::new(qb64);
        let texter = ts.read_texter().unwrap();
        assert_eq!(*texter.code(), TexterCode::Bytes_L0);
        assert_eq!(texter.raw(), &[0x5b, 0x5f, 0x6e, 0x25, 0x3e, 0x87]);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_texter_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_texter();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "TexterCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // read_number tests
    // ====================================================================

    #[test]
    fn parse_number_short_success() {
        // Short (M): hs=1, ss=0, fs=4, raw_size=2
        // qb64 "MAAB" = code "M", raw = [0x00, 0x01] = value 1
        let qb64 = b"MAAB";
        let mut ts = TextStream::new(qb64);
        let number = ts.read_number().unwrap();
        assert_eq!(*number.code(), cesr::core::matter::code::NumberCode::Short);
        assert_eq!(number.value(), 1);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_number_short_value_five() {
        // qb64 "MAAF" = code "M", raw = [0x00, 0x05] = value 5
        let qb64 = b"MAAF";
        let mut ts = TextStream::new(qb64);
        let number = ts.read_number().unwrap();
        assert_eq!(*number.code(), cesr::core::matter::code::NumberCode::Short);
        assert_eq!(number.value(), 5);
        assert!(ts.remaining().is_empty());
    }

    #[test]
    fn parse_number_with_trailing_bytes() {
        let mut qb64 = b"MAAB".to_vec();
        qb64.extend_from_slice(b"EXTRA");
        let mut ts = TextStream::new(&qb64);
        let number = ts.read_number().unwrap();
        assert_eq!(number.value(), 1);
        assert_eq!(ts.remaining(), b"EXTRA");
    }

    #[test]
    fn parse_number_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = TextStream::new(&qb64).read_number();
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "NumberCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // keripy conformance vectors — exact qb64 strings
    // ====================================================================

    /// keripy: Verser(proto='KERI', pvrsn=(2,0))
    /// Tag7 code "Y" with soft encoding the proto+version bytes
    /// qb64 = "YKERICAA"
    #[test]
    fn keripy_verser_keri_v2() {
        let qb64 = b"YKERICAA";
        let mut ts = TextStream::new(qb64);
        let verser = ts.read_verser().unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag7);
        assert!(ts.remaining().is_empty());
        assert_eq!(verser.soft(), "KERICAA");
    }

    /// keripy: Verser with all-zero soft
    #[test]
    fn keripy_verser_all_zero_soft() {
        let qb64 = b"YAAAAAAA";
        let mut ts = TextStream::new(qb64);
        let verser = ts.read_verser().unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag7);
        assert!(ts.remaining().is_empty());
        assert_eq!(verser.soft(), "AAAAAAA");
    }

    /// keripy: Texter(text="") with zero-length payload, qb64 = "4BAA"
    #[test]
    fn keripy_texter_empty() {
        let qb64 = b"4BAA";
        let mut ts = TextStream::new(qb64);
        let texter = ts.read_texter().unwrap();
        assert_eq!(*texter.code(), TexterCode::Bytes_L0);
        assert!(texter.raw().is_empty());
        assert!(ts.remaining().is_empty());
    }

    /// keripy: Texter with 6 bytes of payload → qb64 = "4BACW19uJT6H"
    #[test]
    fn keripy_texter_6_bytes() {
        let qb64 = b"4BACW19uJT6H";
        let mut ts = TextStream::new(qb64);
        let texter = ts.read_texter().unwrap();
        assert_eq!(*texter.code(), TexterCode::Bytes_L0);
        assert_eq!(texter.raw(), &[0x5b, 0x5f, 0x6e, 0x25, 0x3e, 0x87]);
        assert!(ts.remaining().is_empty());
    }

    /// keripy: Number(num=0) → Short code "M", raw = [0, 0]
    #[test]
    fn keripy_number_zero() {
        let qb64 = b"MAAA";
        let mut ts = TextStream::new(qb64);
        let number = ts.read_number().unwrap();
        assert_eq!(*number.code(), cesr::core::matter::code::NumberCode::Short);
        assert_eq!(number.value(), 0);
        assert!(ts.remaining().is_empty());
    }

    /// keripy: Number(num=256) → raw = [0x01, 0x00]
    #[test]
    fn keripy_number_256() {
        // 256 = 0x0100, encoded as 2 raw bytes: [0x01, 0x00]
        // B64 of [0x00, 0x01, 0x00] (with 1 lead byte for ps=1) = "AAEA"
        // But Short has ps=0, cs=1, fs=4, raw_size=2
        // padding: cs=1, ps = cs % 4 = 1
        // padded = [0x00, 0x01, 0x00] → b64 = "AAEA"
        // stripped = "AEA" (skip ps=1 chars from b64)
        // qb64 = "M" + "AEA" = "MAEA"
        let qb64 = b"MAEA";
        let mut ts = TextStream::new(qb64);
        let number = ts.read_number().unwrap();
        assert_eq!(number.value(), 256);
        assert!(ts.remaining().is_empty());
    }

    /// keripy: Labeler Tag3 with soft "AAA" (empty label)
    #[test]
    fn keripy_labeler_tag3_empty() {
        let qb64 = b"XAAA";
        let mut ts = TextStream::new(qb64);
        let labeler = ts.read_labeler().unwrap();
        assert_eq!(*labeler.code(), LabelerCode::Tag3);
        assert!(labeler.raw().is_empty());
        assert_eq!(labeler.soft(), "AAA");
        assert!(ts.remaining().is_empty());
    }

    /// keripy: Noncer using blake3-256 (same wire format as Diger)
    #[test]
    fn keripy_noncer_blake3_256() {
        let qb64 = build_blake3_256_qb64();
        let mut ts = TextStream::new(&qb64);
        let noncer = ts.read_noncer().unwrap();
        assert_eq!(*noncer.code(), NoncerCode::Blake3_256);
        assert_eq!(noncer.raw(), &[0xCD_u8; 32]);
        assert!(ts.remaining().is_empty());
    }

    // ====================================================================
    // V2 counter tests
    // ====================================================================

    /// V2 counter round-trip for all new seal group codes
    #[test]
    fn parse_counter_v2_seal_group_codes() {
        use cesr::core::counter::CounterCodeV2;

        let seal_codes = [
            CounterCodeV2::DigestSealSingles,
            CounterCodeV2::MerkleRootSealSingles,
            CounterCodeV2::SealSourceLastSingles,
            CounterCodeV2::BackerRegistrarSealCouples,
            CounterCodeV2::TypedDigestSealCouples,
            CounterCodeV2::BlindedStateQuadruples,
            CounterCodeV2::BoundStateSextuples,
            CounterCodeV2::TypedMediaQuadruples,
        ];

        for code in seal_codes {
            let hard = code.as_str();
            let ss = code.soft_size();
            let ss_nz = NonZeroUsize::new(ss).unwrap();
            let count = 7_u32;
            let soft = cesr::b64::encode_int(count, ss_nz);
            let qb64 = format!("{hard}{soft}");
            let mut ts = TextStream::new(qb64.as_bytes());
            let (parsed_code, parsed_count) = ts.read_counter_v2().unwrap();
            assert_eq!(parsed_code, code, "code mismatch for {hard}");
            assert_eq!(parsed_count, count, "count mismatch for {hard}");
            assert!(ts.remaining().is_empty(), "trailing bytes for {hard}");
        }
    }

    // ====================================================================
    // skip_matter tests
    // ====================================================================

    #[test]
    fn skip_matter_ed25519() {
        let qb64 = build_ed25519_qb64();
        assert_eq!(skip_matter(&qb64).unwrap(), 44);
    }

    #[test]
    fn skip_matter_ed25519_with_trailing() {
        let mut qb64 = build_ed25519_qb64();
        qb64.extend_from_slice(b"TRAILING");
        assert_eq!(skip_matter(&qb64).unwrap(), 44);
    }

    #[test]
    fn skip_matter_blake3_256() {
        let qb64 = build_blake3_256_qb64();
        assert_eq!(skip_matter(&qb64).unwrap(), 44);
    }

    #[test]
    fn skip_matter_ed25519_sig() {
        let qb64 = build_ed25519_sig_qb64();
        assert_eq!(skip_matter(&qb64).unwrap(), 88);
    }

    #[test]
    fn skip_matter_need_bytes_empty() {
        let err = expect_err(skip_matter(b""));
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    #[test]
    fn skip_matter_need_bytes_truncated() {
        let qb64 = build_ed25519_qb64();
        let err = expect_err(skip_matter(&qb64[..10]));
        assert!(matches!(err, ParseError::NeedBytes(34)));
    }

    #[test]
    fn skip_matter_variable_size_texter() {
        let qb64 = b"4BACW19uJT6H";
        assert_eq!(skip_matter(qb64).unwrap(), 12);
    }

    #[test]
    fn skip_matter_variable_size_texter_empty() {
        let qb64 = b"4BAA";
        assert_eq!(skip_matter(qb64).unwrap(), 4);
    }

    // ====================================================================
    // skip_indexer tests
    // ====================================================================

    #[test]
    fn skip_indexer_ed25519() {
        let (qb64, _, _) = build_indexer_qb64();
        assert_eq!(skip_indexer(&qb64).unwrap(), qb64.len());
    }

    #[test]
    fn skip_indexer_with_trailing() {
        let (mut qb64, _, _) = build_indexer_qb64();
        let expected_len = qb64.len();
        qb64.extend_from_slice(b"EXTRA");
        assert_eq!(skip_indexer(&qb64).unwrap(), expected_len);
    }

    #[test]
    fn skip_indexer_need_bytes_empty() {
        let err = expect_err(skip_indexer(b""));
        assert!(matches!(err, ParseError::NeedBytes(1)));
    }

    // ====================================================================
    // skip_counter tests
    // ====================================================================

    #[test]
    fn skip_counter_standard() {
        let qb64 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2);
        assert_eq!(skip_counter(&qb64).unwrap(), 4);
    }

    #[test]
    fn skip_counter_big() {
        let qb64 = build_counter_qb64(CounterCodeV1::BigAttachmentGroup, 100);
        assert_eq!(skip_counter(&qb64).unwrap(), 8);
    }
}
