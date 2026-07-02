use crate::core::counter::CounterCodeV1;
use crate::core::counter::CounterCodeV2;
use crate::core::indexer::Indexer;
use crate::core::indexer::IndexerBuilder;
use crate::core::indexer::code::IndexedSigCode;
use crate::core::indexer::code::hardage;
use crate::core::indexer::xizage::XizageSize;
use crate::core::matter::Matter;
use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::DigestCode;
use crate::core::matter::code::LabelerCode;
use crate::core::matter::code::MatterCode;
use crate::core::matter::code::NoncerCode;
use crate::core::matter::code::NumberCode;
use crate::core::matter::code::SignatureCode;
use crate::core::matter::code::TexterCode;
use crate::core::matter::code::VerKeyCode;
use crate::core::matter::code::VerserCode;
use crate::core::matter::error::ParsingError as MatterParsingError;
use crate::core::matter::error::ValidationError as MatterValidationError;
use crate::core::matter::sizage::SizeType;
use crate::core::primitives::Cigar;
use crate::core::primitives::Diger;
use crate::core::primitives::Labeler;
use crate::core::primitives::Noncer;
use crate::core::primitives::Number;
use crate::core::primitives::Prefixer;
use crate::core::primitives::Saider;
use crate::core::primitives::Siger;
use crate::core::primitives::Texter;
use crate::core::primitives::Verfer;
use crate::core::primitives::Verser;
use crate::utils::decode_to_int;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};

use crate::stream::error::ParseError;

/// Parse one Matter primitive from a CESR base64 byte stream.
///
/// Passes the qb64 slice by reference (zero copy) to `from_qualified_base64`,
/// then calls `into_static()` to detach from the input buffer. This is
/// near-zero cost: `raw` is already owned (base64 decode), so only the `soft`
/// field (0-4 bytes) is cloned.
///
/// Returns `(Matter<'static, MatterCode>, remaining_bytes)`.
pub(crate) fn parse_matter(
    input: &[u8],
) -> Result<(Matter<'static, MatterCode>, &[u8]), ParseError> {
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
        let size: usize = decode_to_int(soft_value)?;
        (size * 4) + cs
    };

    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }

    let matter = MatterBuilder::new()
        .from_qualified_base64(&input[..fs])
        .map_err(
            |oneof_err| match oneof_err.narrow::<MatterParsingError, _>() {
                Ok(pe) => ParseError::from(pe),
                Err(remaining) => remaining
                    .narrow::<MatterValidationError, _>()
                    .map_or_else(|_| unreachable!(), ParseError::from),
            },
        )?
        .into_static();

    Ok((matter, &input[fs..]))
}

/// Parse one Indexer primitive from a CESR base64 byte stream.
///
/// Returns `(Indexer<'static>, remaining_bytes)`.
pub(crate) fn parse_indexer(input: &[u8]) -> Result<(Indexer<'static>, &[u8]), ParseError> {
    if input.is_empty() {
        return Err(ParseError::NeedBytes(1));
    }
    let (indexer, consumed) = IndexerBuilder::new()
        .from_qb64(input)
        .map_err(|e| ParseError::from(e.take()))?;
    Ok((indexer, &input[consumed..]))
}

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

/// Compute the full size (in bytes) of a Matter primitive without decoding it.
///
/// Performs only code lookup and size computation — no base64 decode, no
/// `MatterBuilder` construction. Returns the number of qb64 bytes the
/// primitive occupies.
#[allow(dead_code, reason = "used by upcoming Bytes-backed group refactor")]
pub(crate) fn skip_matter(input: &[u8]) -> Result<usize, ParseError> {
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
        let size: usize = decode_to_int(soft_value)?;
        (size * 4) + cs
    };

    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }

    Ok(fs)
}

/// Compute the full size (in bytes) of an Indexer primitive without decoding it.
///
/// Mirrors the size-computation logic in `IndexerBuilder::from_qb64` but stops
/// after determining the full size. No base64 decode or `Indexer` construction.
pub(crate) fn skip_indexer(input: &[u8]) -> Result<usize, ParseError> {
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
            let index: usize = decode_to_int(index_str)?;
            index * 4 + cs
        }
    };

    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }

    Ok(fs)
}

/// Compute the full size (in bytes) of a counter (code + soft field) without
/// decoding the count value.
///
/// Tries V1 first, then V2, returning the total byte length of the counter
/// prefix (hard + soft).
#[allow(dead_code, reason = "used by upcoming Bytes-backed group refactor")]
pub(crate) fn skip_counter(input: &[u8]) -> Result<usize, ParseError> {
    let (hard, hs) = extract_hard(input)?;

    let ss = if let Ok(code) = CounterCodeV1::from_hard(hard) {
        code.soft_size()
    } else if let Ok(code) = CounterCodeV2::from_hard(hard) {
        code.soft_size()
    } else {
        return Err(ParseError::UnknownCounterCode(hard.to_owned()));
    };

    let fs = hs + ss;
    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }

    Ok(fs)
}

/// Parse a V1.0 counter code and element count from a CESR base64 stream.
///
/// Returns `(CounterCodeV1, count, remaining_bytes)`.
pub(crate) fn parse_counter(input: &[u8]) -> Result<(CounterCodeV1, u32, &[u8]), ParseError> {
    let (hard, hs) = extract_hard(input)?;
    let code = CounterCodeV1::from_hard(hard)?;
    let ss = code.soft_size();
    let fs = hs + ss;
    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }
    let count_str = core::str::from_utf8(&input[hs..fs])
        .map_err(|_| ParseError::Malformed("invalid UTF-8 in counter soft field".into()))?;
    let count: u32 = decode_to_int(count_str)?;
    Ok((code, count, &input[fs..]))
}

/// Parse a V2.0 counter code and element count from a CESR base64 stream.
///
/// Returns `(CounterCodeV2, count, remaining_bytes)`.
pub(crate) fn parse_counter_v2(input: &[u8]) -> Result<(CounterCodeV2, u32, &[u8]), ParseError> {
    let (hard, hs) = extract_hard(input)?;
    let code = CounterCodeV2::from_hard(hard)?;
    let ss = code.soft_size();
    let fs = hs + ss;
    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }
    let count_str = core::str::from_utf8(&input[hs..fs])
        .map_err(|_| ParseError::Malformed("invalid UTF-8 in counter soft field".into()))?;
    let count: u32 = decode_to_int(count_str)?;
    Ok((code, count, &input[fs..]))
}

/// Parse a Verfer (verification key) from the stream.
pub(crate) fn parse_verfer(input: &[u8]) -> Result<(Verfer<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let verfer = matter
        .narrow::<VerKeyCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "VerKeyCode",
            got: e.to_string(),
        })?;
    Ok((verfer, rest))
}

/// Parse a Prefixer (AID prefix, same as Verfer) from the stream.
pub(crate) fn parse_prefixer(input: &[u8]) -> Result<(Prefixer<'static>, &[u8]), ParseError> {
    parse_verfer(input)
}

/// Parse a Diger (digest) from the stream.
pub(crate) fn parse_diger(input: &[u8]) -> Result<(Diger<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let diger = matter
        .narrow::<DigestCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "DigestCode",
            got: e.to_string(),
        })?;
    Ok((diger, rest))
}

/// Parse a Saider (SAID, same as Diger) from the stream.
pub(crate) fn parse_saider(input: &[u8]) -> Result<(Saider<'static>, &[u8]), ParseError> {
    parse_diger(input)
}

/// Parse a Cigar (non-indexed signature) from the stream.
pub(crate) fn parse_cigar(input: &[u8]) -> Result<(Cigar<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let cigar = matter
        .narrow::<SignatureCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "SignatureCode",
            got: e.to_string(),
        })?;
    Ok((cigar, rest))
}

/// Parse a Siger (indexed signature) from the stream.
pub(crate) fn parse_siger(input: &[u8]) -> Result<(Siger<'static>, &[u8]), ParseError> {
    let (indexer, rest) = parse_indexer(input)?;
    Ok((Siger::new(indexer), rest))
}

/// Parse a Verser (version/protocol primitive) from the stream.
pub(crate) fn parse_verser(input: &[u8]) -> Result<(Verser<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let verser = matter
        .narrow::<VerserCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "VerserCode",
            got: e.to_string(),
        })?;
    Ok((verser, rest))
}

/// Parse a Noncer (nonce/randomness primitive) from the stream.
pub(crate) fn parse_noncer(input: &[u8]) -> Result<(Noncer<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let noncer = matter
        .narrow::<NoncerCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "NoncerCode",
            got: e.to_string(),
        })?;
    Ok((noncer, rest))
}

/// Parse a Labeler (field name/tag primitive) from the stream.
pub(crate) fn parse_labeler(input: &[u8]) -> Result<(Labeler<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let labeler = matter
        .narrow::<LabelerCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "LabelerCode",
            got: e.to_string(),
        })?;
    Ok((labeler, rest))
}

/// Parse a Texter (variable-length byte string primitive) from the stream.
pub(crate) fn parse_texter(input: &[u8]) -> Result<(Texter<'static>, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let texter = matter
        .narrow::<TexterCode>()
        .map_err(|e| ParseError::UnexpectedCodeType {
            expected: "TexterCode",
            got: e.to_string(),
        })?;
    Ok((texter, rest))
}

/// Parse a Number (unsigned integer) from the stream.
///
/// Parses a Matter primitive, narrows to `NumberCode`, then converts the
/// raw big-endian bytes into a `u128` value.
pub(crate) fn parse_number(input: &[u8]) -> Result<(Number, &[u8]), ParseError> {
    let (matter, rest) = parse_matter(input)?;
    let narrowed = matter
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
    Ok((Number::with_code(*narrowed.code(), value), rest))
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
    use crate::core::indexer::code::IndexedSigCode;
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
        let soft = crate::utils::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    // ====================================================================
    // parse_matter tests
    // ====================================================================

    #[test]
    fn parse_matter_ed25519_roundtrip() {
        let qb64 = build_ed25519_qb64();
        let (matter, rest) = parse_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Ed25519);
        assert_eq!(matter.raw(), &[0xAB_u8; 32]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_matter_with_trailing_bytes() {
        let mut qb64 = build_ed25519_qb64();
        qb64.extend_from_slice(b"TRAILING");
        let (matter, rest) = parse_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Ed25519);
        assert_eq!(rest, b"TRAILING");
    }

    #[test]
    fn parse_matter_need_bytes_empty() {
        let result = parse_matter(b"");
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    #[test]
    fn parse_matter_need_bytes_truncated() {
        let qb64 = build_ed25519_qb64();
        let result = parse_matter(&qb64[..10]);
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(34)));
    }

    #[test]
    fn parse_matter_ed25519_sig() {
        let qb64 = build_ed25519_sig_qb64();
        assert_eq!(qb64.len(), 88);
        let (matter, rest) = parse_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Ed25519Sig);
        assert_eq!(matter.raw().len(), 64);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_matter_unknown_code() {
        let result = parse_matter(b"!AAAAAAA");
        assert!(result.is_err());
    }

    #[test]
    fn parse_matter_blake3_256() {
        let qb64 = build_blake3_256_qb64();
        assert_eq!(qb64.len(), 44);
        let (matter, rest) = parse_matter(&qb64).unwrap();
        assert_eq!(*matter.code(), MatterCode::Blake3_256);
        assert_eq!(matter.raw(), &[0xCD_u8; 32]);
        assert!(rest.is_empty());
    }

    // ====================================================================
    // parse_indexer tests
    // ====================================================================

    #[test]
    fn parse_indexer_roundtrip() {
        let (qb64, code, index) = build_indexer_qb64();
        let (indexer, rest) = parse_indexer(&qb64).unwrap();
        assert_eq!(indexer.code(), code);
        assert_eq!(indexer.index(), index);
        assert_eq!(indexer.raw().len(), 64);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_indexer_with_trailing_bytes() {
        let (mut qb64, _, _) = build_indexer_qb64();
        qb64.extend_from_slice(b"EXTRA");
        let (_, rest) = parse_indexer(&qb64).unwrap();
        assert_eq!(rest, b"EXTRA");
    }

    #[test]
    fn parse_indexer_need_bytes_empty() {
        let result = parse_indexer(b"");
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_indexer_need_bytes_truncated() {
        let (qb64, _, _) = build_indexer_qb64();
        let result = parse_indexer(&qb64[..4]);
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    // ====================================================================
    // parse_counter tests
    // ====================================================================

    #[test]
    fn parse_counter_standard() {
        let qb64 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2);
        assert_eq!(qb64.len(), 4);
        let (code, count, rest) = parse_counter(&qb64).unwrap();
        assert_eq!(code, CounterCodeV1::ControllerIdxSigs);
        assert_eq!(count, 2);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_counter_big_variant() {
        let qb64 = build_counter_qb64(CounterCodeV1::BigAttachmentGroup, 100);
        assert_eq!(qb64.len(), 8);
        let (code, count, rest) = parse_counter(&qb64).unwrap();
        assert_eq!(code, CounterCodeV1::BigAttachmentGroup);
        assert_eq!(count, 100);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_counter_with_trailing_data() {
        let mut qb64 = build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 5);
        qb64.extend_from_slice(b"MORESTUFF");
        let (code, count, rest) = parse_counter(&qb64).unwrap();
        assert_eq!(code, CounterCodeV1::WitnessIdxSigs);
        assert_eq!(count, 5);
        assert_eq!(rest, b"MORESTUFF");
    }

    #[test]
    fn parse_counter_need_bytes_empty() {
        let result = parse_counter(b"");
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_counter_need_bytes_one_byte() {
        let result = parse_counter(b"-");
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_counter_need_bytes_short_soft() {
        // "-A" is ControllerIdxSigs: hs=2, ss=2, fs=4 but only 3 bytes given
        let result = parse_counter(b"-AB");
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    #[test]
    fn parse_counter_error_non_counter_input() {
        let result = parse_counter(b"AABC");
        assert!(result.is_err());
        let err = expect_err(result);
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn parse_counter_unknown_code() {
        let result = parse_counter(b"-JAB");
        assert!(result.is_err());
        assert!(matches!(
            expect_err(result),
            ParseError::UnknownCounterCode(_)
        ));
    }

    #[test]
    fn parse_counter_zero_count() {
        let qb64 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 0);
        let (code, count, rest) = parse_counter(&qb64).unwrap();
        assert_eq!(code, CounterCodeV1::ControllerIdxSigs);
        assert_eq!(count, 0);
        assert!(rest.is_empty());
    }

    // ====================================================================
    // parse_verfer tests
    // ====================================================================

    #[test]
    fn parse_verfer_success() {
        let qb64 = build_ed25519_qb64();
        let (verfer, rest) = parse_verfer(&qb64).unwrap();
        assert_eq!(*verfer.code(), VerKeyCode::Ed25519);
        assert_eq!(verfer.raw(), &[0xAB_u8; 32]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_verfer_wrong_code_type() {
        let qb64 = build_blake3_256_qb64();
        let result = parse_verfer(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "VerKeyCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_prefixer tests
    // ====================================================================

    #[test]
    fn parse_prefixer_success() {
        let qb64 = build_ed25519_qb64();
        let (prefixer, rest) = parse_prefixer(&qb64).unwrap();
        assert_eq!(*prefixer.code(), VerKeyCode::Ed25519);
        assert!(rest.is_empty());
    }

    // ====================================================================
    // parse_diger tests
    // ====================================================================

    #[test]
    fn parse_diger_success() {
        let qb64 = build_blake3_256_qb64();
        let (diger, rest) = parse_diger(&qb64).unwrap();
        assert_eq!(*diger.code(), DigestCode::Blake3_256);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_diger_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = parse_diger(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "DigestCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_saider tests
    // ====================================================================

    #[test]
    fn parse_saider_success() {
        let qb64 = build_blake3_256_qb64();
        let (saider, rest) = parse_saider(&qb64).unwrap();
        assert_eq!(*saider.code(), DigestCode::Blake3_256);
        assert!(rest.is_empty());
    }

    // ====================================================================
    // parse_cigar tests
    // ====================================================================

    #[test]
    fn parse_cigar_success() {
        let qb64 = build_ed25519_sig_qb64();
        let (cigar, rest) = parse_cigar(&qb64).unwrap();
        assert_eq!(*cigar.code(), SignatureCode::Ed25519Sig);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_cigar_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = parse_cigar(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "SignatureCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_siger tests
    // ====================================================================

    #[test]
    fn parse_siger_roundtrip() {
        let (qb64, code, index) = build_indexer_qb64();
        let (siger, rest) = parse_siger(&qb64).unwrap();
        assert_eq!(siger.code(), code);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.raw().len(), 64);
        assert!(siger.verfer().is_none());
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_siger_with_trailing_bytes() {
        let (mut qb64, _, _) = build_indexer_qb64();
        qb64.extend_from_slice(b"TRAIL");
        let (_, rest) = parse_siger(&qb64).unwrap();
        assert_eq!(rest, b"TRAIL");
    }

    #[test]
    fn parse_siger_need_bytes_empty() {
        let result = parse_siger(b"");
        assert!(result.is_err());
        assert!(matches!(expect_err(result), ParseError::NeedBytes(1)));
    }

    // ====================================================================
    // parse_verser tests
    // ====================================================================

    #[test]
    fn parse_verser_tag7_success() {
        // Tag7: code "Y", soft = 7 chars, fs=8, raw is empty
        let qb64 = b"YAAAAAAA";
        let (verser, rest) = parse_verser(qb64).unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag7);
        assert!(verser.raw().is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_verser_tag10_success() {
        // Tag10: code "0O", soft = 10 chars, fs=12
        let qb64 = b"0OAAAAAAAAAA";
        let (verser, rest) = parse_verser(qb64).unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag10);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_verser_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = parse_verser(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "VerserCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_noncer tests
    // ====================================================================

    #[test]
    fn parse_noncer_blake3_256_success() {
        // Blake3_256 is a valid NoncerCode
        let qb64 = build_blake3_256_qb64();
        let (noncer, rest) = parse_noncer(&qb64).unwrap();
        assert_eq!(*noncer.code(), NoncerCode::Blake3_256);
        assert_eq!(noncer.raw(), &[0xCD_u8; 32]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_noncer_wrong_code_type() {
        // Ed25519 is not a NoncerCode
        let qb64 = build_ed25519_qb64();
        let result = parse_noncer(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "NoncerCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_labeler tests
    // ====================================================================

    #[test]
    fn parse_labeler_tag3_success() {
        // Tag3: code "X", soft = "AAA", fs=4
        let qb64 = b"XAAA";
        let (labeler, rest) = parse_labeler(qb64).unwrap();
        assert_eq!(*labeler.code(), LabelerCode::Tag3);
        assert!(labeler.raw().is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_labeler_tag7_success() {
        // Tag7 is also a valid LabelerCode
        let qb64 = b"YAAAAAAA";
        let (labeler, rest) = parse_labeler(qb64).unwrap();
        assert_eq!(*labeler.code(), LabelerCode::Tag7);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_labeler_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = parse_labeler(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "LabelerCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_texter tests
    // ====================================================================

    #[test]
    fn parse_texter_bytes_l0_success() {
        // Bytes_L0: code "4B", soft = "AC" (size), raw = 6 bytes
        // From test vector: qb64 = "4BACW19uJT6H"
        let qb64 = b"4BACW19uJT6H";
        let (texter, rest) = parse_texter(qb64).unwrap();
        assert_eq!(*texter.code(), TexterCode::Bytes_L0);
        assert_eq!(texter.raw(), &[0x5b, 0x5f, 0x6e, 0x25, 0x3e, 0x87]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_texter_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = parse_texter(&qb64);
        assert!(result.is_err());
        match expect_err(result) {
            ParseError::UnexpectedCodeType { expected, .. } => {
                assert_eq!(expected, "TexterCode");
            }
            other => unreachable!("expected UnexpectedCodeType, got {other:?}"),
        }
    }

    // ====================================================================
    // parse_number tests
    // ====================================================================

    #[test]
    fn parse_number_short_success() {
        // Short (M): hs=1, ss=0, fs=4, raw_size=2
        // qb64 "MAAB" = code "M", raw = [0x00, 0x01] = value 1
        let qb64 = b"MAAB";
        let (number, rest) = parse_number(qb64).unwrap();
        assert_eq!(*number.code(), crate::core::matter::code::NumberCode::Short);
        assert_eq!(number.value(), 1);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_number_short_value_five() {
        // qb64 "MAAF" = code "M", raw = [0x00, 0x05] = value 5
        let qb64 = b"MAAF";
        let (number, rest) = parse_number(qb64).unwrap();
        assert_eq!(*number.code(), crate::core::matter::code::NumberCode::Short);
        assert_eq!(number.value(), 5);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_number_with_trailing_bytes() {
        let mut qb64 = b"MAAB".to_vec();
        qb64.extend_from_slice(b"EXTRA");
        let (number, rest) = parse_number(&qb64).unwrap();
        assert_eq!(number.value(), 1);
        assert_eq!(rest, b"EXTRA");
    }

    #[test]
    fn parse_number_wrong_code_type() {
        let qb64 = build_ed25519_qb64();
        let result = parse_number(&qb64);
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
        let (verser, rest) = parse_verser(qb64).unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag7);
        assert!(rest.is_empty());
        assert_eq!(verser.soft(), "KERICAA");
    }

    /// keripy: Verser with all-zero soft
    #[test]
    fn keripy_verser_all_zero_soft() {
        let qb64 = b"YAAAAAAA";
        let (verser, rest) = parse_verser(qb64).unwrap();
        assert_eq!(*verser.code(), VerserCode::Tag7);
        assert!(rest.is_empty());
        assert_eq!(verser.soft(), "AAAAAAA");
    }

    /// keripy: Texter(text="") with zero-length payload, qb64 = "4BAA"
    #[test]
    fn keripy_texter_empty() {
        let qb64 = b"4BAA";
        let (texter, rest) = parse_texter(qb64).unwrap();
        assert_eq!(*texter.code(), TexterCode::Bytes_L0);
        assert!(texter.raw().is_empty());
        assert!(rest.is_empty());
    }

    /// keripy: Texter with 6 bytes of payload → qb64 = "4BACW19uJT6H"
    #[test]
    fn keripy_texter_6_bytes() {
        let qb64 = b"4BACW19uJT6H";
        let (texter, rest) = parse_texter(qb64).unwrap();
        assert_eq!(*texter.code(), TexterCode::Bytes_L0);
        assert_eq!(texter.raw(), &[0x5b, 0x5f, 0x6e, 0x25, 0x3e, 0x87]);
        assert!(rest.is_empty());
    }

    /// keripy: Number(num=0) → Short code "M", raw = [0, 0]
    #[test]
    fn keripy_number_zero() {
        let qb64 = b"MAAA";
        let (number, rest) = parse_number(qb64).unwrap();
        assert_eq!(*number.code(), crate::core::matter::code::NumberCode::Short);
        assert_eq!(number.value(), 0);
        assert!(rest.is_empty());
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
        let (number, rest) = parse_number(qb64).unwrap();
        assert_eq!(number.value(), 256);
        assert!(rest.is_empty());
    }

    /// keripy: Labeler Tag3 with soft "AAA" (empty label)
    #[test]
    fn keripy_labeler_tag3_empty() {
        let qb64 = b"XAAA";
        let (labeler, rest) = parse_labeler(qb64).unwrap();
        assert_eq!(*labeler.code(), LabelerCode::Tag3);
        assert!(labeler.raw().is_empty());
        assert_eq!(labeler.soft(), "AAA");
        assert!(rest.is_empty());
    }

    /// keripy: Noncer using blake3-256 (same wire format as Diger)
    #[test]
    fn keripy_noncer_blake3_256() {
        let qb64 = build_blake3_256_qb64();
        let (noncer, rest) = parse_noncer(&qb64).unwrap();
        assert_eq!(*noncer.code(), NoncerCode::Blake3_256);
        assert_eq!(noncer.raw(), &[0xCD_u8; 32]);
        assert!(rest.is_empty());
    }

    // ====================================================================
    // V2 counter tests
    // ====================================================================

    /// V2 counter round-trip for all new seal group codes
    #[test]
    fn parse_counter_v2_seal_group_codes() {
        use crate::core::counter::CounterCodeV2;

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
            let soft = crate::utils::encode_int(count, ss_nz);
            let qb64 = format!("{hard}{soft}");
            let (parsed_code, parsed_count, rest) = parse_counter_v2(qb64.as_bytes()).unwrap();
            assert_eq!(parsed_code, code, "code mismatch for {hard}");
            assert_eq!(parsed_count, count, "count mismatch for {hard}");
            assert!(rest.is_empty(), "trailing bytes for {hard}");
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
