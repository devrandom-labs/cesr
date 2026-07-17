//! SAID (Self-Addressing IDentifier) computation and verification.
//!
//! A SAID is a content-addressable digest that appears in the `d` field of a
//! KERI event. On the write path, the `d` field (and, for self-addressing
//! `icp`/`dip` events, the `i` field too) is first filled with a placeholder
//! string of the correct length ([`said_placeholder`]), the event is
//! serialized, and the digest of that serialization becomes the final field
//! value. On the read path, verification parses the event with the strict
//! canonical parser and fills the same byte spans in place over a single
//! scratch copy of the raw input, rather than re-rendering the event.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
use cesr::core::matter::code::CesrCode;
use cesr::core::matter::code::DigestCode;
use cesr::core::matter::sizage::SizeType;
use cesr::core::primitives::Saider;
use cesr::crypto::digest::digest;
use core::ops::Range;

use crate::deserialize::canonical::{ParsedDip, ParsedEvent, Spanned, parse_event};
use crate::error::SerderError;
use crate::primitives::to_qb64_string;

/// Placeholder character used to fill the `d` field before hashing.
///
/// `#` is not a valid Base64 character, so a placeholder string is
/// unambiguously distinguishable from a real SAID.
pub const DUMMY_CHAR: char = '#';

/// Byte form of [`DUMMY_CHAR`] for in-place span filling.
pub(crate) const DUMMY_BYTE: u8 = b'#';

/// Generate a placeholder string of the correct qb64 length for `code`.
///
/// For `Blake3_256` the result is 44 `#` characters.
///
/// # Errors
///
/// Returns [`SerderError::DigestError`] if the code has a variable-size
/// `SizeType` (all digest codes are fixed-size, so this should never
/// occur in practice).
pub fn said_placeholder(code: DigestCode) -> Result<String, SerderError> {
    let sizage = code.get_sizage();
    let len = match *sizage.fs() {
        SizeType::Fixed(n) => usize::from(n),
        SizeType::Small | SizeType::Large => {
            return Err(SerderError::DigestError(
                "digest code has variable size, expected fixed".to_owned(),
            ));
        }
    };
    Ok(core::iter::repeat_n(DUMMY_CHAR, len).collect())
}

/// Compute a cryptographic digest of `data` and return it as a [`Saider`].
///
/// # Errors
///
/// Returns [`SerderError::DigestError`] if the underlying digest computation
/// fails.
pub fn compute_digest(data: &[u8], code: DigestCode) -> Result<Saider<'static>, SerderError> {
    digest(code, data).map_err(|e| SerderError::DigestError(e.to_string()))
}

/// Verify that the `d` field of a serialized canonical event matches a
/// freshly computed SAID.
///
/// Parses the event with the strict canonical parser, fills the `d` (and,
/// for `icp`/`dip` events whose prefix equals their SAID, the `i`) value
/// span with [`DUMMY_CHAR`] in a single scratch copy, hashes, and compares.
///
/// Unlike the deserializers — which infer the digest code from the `d`
/// value's own qb64 prefix — `code` is caller-supplied: a caller that
/// knows the expected algorithm out-of-band can reject events recomputed
/// under a different (possibly weaker) digest, which self-describing
/// inference cannot. Passing a code that does not match the SAID's own
/// derivation always yields [`SerderError::SaidMismatch`], never a false
/// accept: the computed qb64's code prefix differs from the `d` value's.
///
/// # Errors
///
/// Returns [`SerderError::SaidMismatch`] if the digest differs,
/// [`SerderError::NonCanonical`] or [`SerderError::InvalidVersionString`]
/// if the input is not a canonical event, or [`SerderError::DigestError`]
/// on hash failure.
pub fn verify_said(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    match parse_event(raw)? {
        ParsedEvent::Inception(p) => {
            let prefix = (p.said.value == p.prefix.value).then_some(&p.prefix);
            verify_said_spans(raw, &p.said, prefix, code)
        }
        ParsedEvent::DelegatedInception(ParsedDip { icp, .. }) => {
            let prefix = (icp.said.value == icp.prefix.value).then_some(&icp.prefix);
            verify_said_spans(raw, &icp.said, prefix, code)
        }
        ParsedEvent::Rotation(p) | ParsedEvent::DelegatedRotation(p) => {
            verify_said_spans(raw, &p.said, None, code)
        }
        ParsedEvent::Interaction(p) => verify_said_spans(raw, &p.said, None, code),
    }
}

/// Verify a SAID by span: copy `raw` once into a scratch buffer, overwrite
/// the SAID value span (and the prefix span for double-SAID events) with
/// [`DUMMY_BYTE`], hash, and compare against the SAID value.
///
/// Spans come from the canonical parser and must address the qb64 value
/// bytes exactly (quotes excluded). This replaces the historical
/// parse-mutate-re-render verification with one raw copy and one hash.
///
/// # Errors
///
/// Returns [`SerderError::SaidMismatch`] if the computed digest differs,
/// [`SerderError::InvalidEventLayout`] if a span is out of bounds, or
/// [`SerderError::DigestError`] on hash failure.
pub(crate) fn verify_said_spans(
    raw: &[u8],
    said: &Spanned<'_>,
    prefix: Option<&Spanned<'_>>,
    code: DigestCode,
) -> Result<(), SerderError> {
    let mut scratch = raw.to_vec();
    fill_span(&mut scratch, &said.span)?;
    if let Some(p) = prefix {
        fill_span(&mut scratch, &p.span)?;
    }
    let computed = compute_digest(&scratch, code)?;
    let computed_qb64 = to_qb64_string(&computed);
    if said.value == computed_qb64 {
        Ok(())
    } else {
        Err(SerderError::SaidMismatch {
            expected: said.value.to_owned(),
            computed: computed_qb64,
        })
    }
}

fn fill_span(scratch: &mut [u8], span: &Range<usize>) -> Result<(), SerderError> {
    scratch
        .get_mut(span.clone())
        .ok_or(SerderError::InvalidEventLayout("SAID span out of bounds"))?
        .fill(DUMMY_BYTE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::icp::InceptionBuilder;
    use crate::traits::KeriSerialize;
    use alloc::borrow::Cow;
    use alloc::vec;
    use alloc::vec::Vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use keri_events::InteractionEvent;
    use keri_events::sequence::SequenceNumber;

    #[test]
    fn placeholder_blake3_256_is_44_chars() {
        let ph = said_placeholder(DigestCode::Blake3_256).expect("fixed-size code");
        assert_eq!(ph.len(), 44);
        assert!(ph.chars().all(|c| c == DUMMY_CHAR));
    }

    #[test]
    fn placeholder_sha3_256_is_44_chars() {
        let ph = said_placeholder(DigestCode::SHA3_256).expect("fixed-size code");
        assert_eq!(ph.len(), 44);
        assert!(ph.chars().all(|c| c == DUMMY_CHAR));
    }

    #[test]
    fn compute_digest_produces_valid_qb64() {
        let data = b"hello KERI world";
        let saider = compute_digest(data, DigestCode::Blake3_256).expect("digest should succeed");
        let qb64 = to_qb64_string(&saider);
        assert_eq!(qb64.len(), 44);
        assert!(
            qb64.starts_with('E'),
            "Blake3_256 qb64 should start with 'E'"
        );
    }

    #[test]
    fn compute_digest_deterministic() {
        let data = b"deterministic input";
        let a = compute_digest(data, DigestCode::Blake3_256).expect("digest a");
        let b = compute_digest(data, DigestCode::Blake3_256).expect("digest b");
        assert_eq!(to_qb64_string(&a), to_qb64_string(&b));
    }

    #[test]
    fn different_data_different_said() {
        let a = compute_digest(b"alpha", DigestCode::Blake3_256).expect("digest alpha");
        let b = compute_digest(b"bravo", DigestCode::Blake3_256).expect("digest bravo");
        assert_ne!(to_qb64_string(&a), to_qb64_string(&b));
    }

    fn probe_ixn_raw() -> (Vec<u8>, String) {
        let prefixer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let saider_fixture = compute_digest(b"seed", DigestCode::Blake3_256).unwrap();
        let event = InteractionEvent::new(
            prefixer.into(),
            SequenceNumber::new(1),
            saider_fixture.clone(),
            saider_fixture,
            vec![],
        );
        let ser = event.serialize().unwrap();
        let said = to_qb64_string(ser.said());
        (ser.as_bytes().to_vec(), said)
    }

    #[test]
    fn verify_said_spans_accepts_writer_output() {
        let (raw, said) = probe_ixn_raw();
        let start = raw
            .windows(6)
            .position(|w| w == b"\"d\":\"E")
            .expect("d field present")
            + 5;
        let span = start..start + 44;
        assert_eq!(&raw[span.clone()], said.as_bytes());
        let spanned = Spanned { value: &said, span };
        verify_said_spans(&raw, &spanned, None, DigestCode::Blake3_256)
            .expect("writer output must verify");
    }

    #[test]
    fn verify_said_spans_rejects_tamper() {
        let (mut raw, said) = probe_ixn_raw();
        let start = raw.windows(6).position(|w| w == b"\"d\":\"E").unwrap() + 5;
        let span = start..start + 44;
        let s_pos = raw.windows(8).position(|w| w == b",\"s\":\"1\"").unwrap();
        raw[s_pos + 6] = b'2';
        let spanned = Spanned { value: &said, span };
        assert!(matches!(
            verify_said_spans(&raw, &spanned, None, DigestCode::Blake3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_spans_rejects_out_of_bounds_span() {
        let (raw, said) = probe_ixn_raw();
        let bogus = Spanned {
            value: &said,
            span: raw.len()..raw.len() + 44,
        };
        assert!(matches!(
            verify_said_spans(&raw, &bogus, None, DigestCode::Blake3_256),
            Err(SerderError::InvalidEventLayout(_))
        ));
    }

    #[test]
    fn verify_said_spans_wrong_width_span_is_said_mismatch() {
        // An in-bounds span of the wrong width (43 instead of 44 bytes) fills
        // the wrong bytes and therefore computes a different digest — the
        // failure surfaces as SaidMismatch, not a panic or a separate variant.
        let (raw, said) = probe_ixn_raw();
        let start = raw.windows(6).position(|w| w == b"\"d\":\"E").unwrap() + 5;
        let short = Spanned {
            value: &said,
            span: start..start + 43,
        };
        assert!(matches!(
            verify_said_spans(&raw, &short, None, DigestCode::Blake3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_spans_double_said_matches_reference() {
        // For an icp whose d == i (self-addressing), filling BOTH spans must
        // reproduce the SAID the writer computed (the writer patches both
        // slots from one digest over a double-placeholder render).
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![7u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let icp = InceptionBuilder::new().keys(vec![verfer]).build().unwrap();
        let raw = icp.as_bytes().to_vec();
        let said = to_qb64_string(icp.said());
        let d_start = raw.windows(5).position(|w| w == b"\"d\":\"").unwrap() + 5;
        let i_start = raw.windows(5).position(|w| w == b"\"i\":\"").unwrap() + 5;
        let d_span = d_start..d_start + 44;
        let i_span = i_start..i_start + 44;
        assert_eq!(&raw[d_span.clone()], said.as_bytes());
        assert_eq!(&raw[i_span.clone()], said.as_bytes());
        let d_spanned = Spanned {
            value: &said,
            span: d_span,
        };
        let i_spanned = Spanned {
            value: &said,
            span: i_span,
        };
        verify_said_spans(&raw, &d_spanned, Some(&i_spanned), DigestCode::Blake3_256)
            .expect("double-SAID writer output must verify by span");
    }

    #[test]
    fn verify_said_accepts_serialized_event() {
        let (raw, _) = probe_ixn_raw();
        verify_said(&raw, DigestCode::Blake3_256).expect("writer output must verify");
    }

    #[test]
    fn verify_said_rejects_tampered_event() {
        let (mut raw, _) = probe_ixn_raw();
        let s_pos = raw.windows(8).position(|w| w == b",\"s\":\"1\"").unwrap();
        raw[s_pos + 6] = b'2';
        assert!(matches!(
            verify_said(&raw, DigestCode::Blake3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_wrong_code_is_said_mismatch() {
        let (raw, _) = probe_ixn_raw();
        assert!(matches!(
            verify_said(&raw, DigestCode::SHA3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_rejects_non_canonical_input() {
        assert!(matches!(
            verify_said(b"not an event", DigestCode::Blake3_256),
            Err(SerderError::NonCanonical { .. } | SerderError::InvalidVersionString(_))
        ));
    }

    #[test]
    fn verify_said_double_said_inception_verifies() {
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![7u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let icp = InceptionBuilder::new().keys(vec![verfer]).build().unwrap();
        verify_said(icp.as_bytes(), DigestCode::Blake3_256)
            .expect("double-SAID inception must verify through the strict path");
    }
}
