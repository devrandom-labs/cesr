//! SAID (Self-Addressing IDentifier) computation and verification.
//!
//! A SAID is a content-addressable digest that appears in the `d` field of a
//! KERI event. On the write path, the `d` field (and, for self-addressing
//! `icp`/`dip` events, the `i` field too) is first filled with a placeholder
//! string of the correct length ([`DigestCode::placeholder`]), the event is
//! serialized, and the digest of that serialization becomes the final field
//! value. On the read path, verification parses the event with the strict
//! canonical parser and fills the same byte spans in place over a single
//! scratch copy of the raw input, rather than re-rendering the event.
//!
//! [`DigestCode::placeholder`]: cesr::core::matter::code::CesrCode::placeholder

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
use cesr::core::matter::code::{DigestCode, MatterCode};
use cesr::core::matter::error::ValidationError;
use cesr::core::primitives::Saider;
use core::ops::Range;

use crate::codec::event::{ParsedDip, ParsedEvent, ParsedIcp, ParsedIxn, ParsedRot};
use crate::codec::scanner::Spanned;
use crate::error::SerderError;

/// Placeholder character for self-addressing fields — re-exported from cesr,
/// where the `#` convention (a character deliberately outside the Base64
/// alphabet) is defined. See [`DigestCode::placeholder`] for the write-path
/// producer.
///
/// [`DigestCode::placeholder`]: cesr::core::matter::code::CesrCode::placeholder
pub use cesr::core::matter::code::DUMMY_CHAR;

/// Byte form of [`DUMMY_CHAR`] for in-place span filling.
pub(crate) const DUMMY_BYTE: u8 = b'#';

impl ParsedIcp<'_> {
    /// Verify this inception's SAID, inferring the digest code from the `d`
    /// value's own qb64 prefix. Double-fills the `i` span too when `d == i`
    /// (self-addressing prefix), matching the write path and keripy.
    ///
    /// `raw` must be the exact bytes this event was parsed from.
    ///
    /// # Errors
    ///
    /// [`SerderError::SaidMismatch`] if the digest differs,
    /// [`SerderError::InvalidPrimitive`] if the code is unknown, or
    /// [`SerderError::InvalidEventLayout`] if a span is out of bounds.
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), SerderError> {
        let code = infer_digest_code(self.said.value)?;
        let prefix = (self.said.value == self.prefix.value).then_some(&self.prefix);
        verify_said_spans(raw, &self.said, prefix, code)
    }
}

impl ParsedRot<'_> {
    /// Verify this rotation's single SAID, inferring the digest code from the
    /// `d` value's own qb64 prefix. See [`ParsedIcp::verify_said`].
    ///
    /// # Errors
    ///
    /// See [`ParsedIcp::verify_said`].
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), SerderError> {
        let code = infer_digest_code(self.said.value)?;
        verify_said_spans(raw, &self.said, None, code)
    }
}

impl ParsedIxn<'_> {
    /// Verify this interaction's single SAID, inferring the digest code from
    /// the `d` value's own qb64 prefix. See [`ParsedIcp::verify_said`].
    ///
    /// # Errors
    ///
    /// See [`ParsedIcp::verify_said`].
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), SerderError> {
        let code = infer_digest_code(self.said.value)?;
        verify_said_spans(raw, &self.said, None, code)
    }
}

impl ParsedEvent<'_> {
    /// Verify the SAID(s) of this parsed event, dispatching to the per-ilk
    /// verifier. Each infers its digest code from the `d` value's own qb64
    /// prefix; `icp`/`dip` additionally fill the `i` span when `d == i`.
    ///
    /// `raw` must be the exact bytes this event was parsed from.
    ///
    /// # Errors
    ///
    /// See [`ParsedIcp::verify_said`].
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), SerderError> {
        match self {
            Self::Inception(p) => p.verify_said(raw),
            Self::DelegatedInception(ParsedDip { icp, .. }) => icp.verify_said(raw),
            Self::Rotation(p) | Self::DelegatedRotation(p) => p.verify_said(raw),
            Self::Interaction(p) => p.verify_said(raw),
        }
    }
}

/// Infer the [`DigestCode`] from a qb64 SAID string by parsing its code prefix.
///
/// Shared by the strict read path ([`ParsedIcp::verify_said`] et al.) and the
/// test-only tolerant reference oracle.
///
/// # Errors
///
/// Returns [`SerderError::InvalidPrimitive`] if the prefix is not a known
/// digest code.
pub(crate) fn infer_digest_code(qb64_said: &str) -> Result<DigestCode, SerderError> {
    let matter_code = MatterCode::from_base64_stream(qb64_said.as_bytes()).map_err(|e| {
        SerderError::InvalidPrimitive {
            field: "d",
            source: ValidationError::UnknownMatterCode(e.to_string()),
        }
    })?;
    DigestCode::try_from(matter_code).map_err(|e| SerderError::InvalidPrimitive {
        field: "d",
        source: e,
    })
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
/// [`SerderError::Digest`] on hash failure.
fn verify_said_spans(
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
    let computed = Saider::digest(code, &scratch)?;
    let computed_qb64 = computed.to_qb64();
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

/// Test-only convenience: parse `raw`, then verify the SAID on the resulting
/// [`ParsedEvent`]. Shared by builder/serialize/codec tests that check a
/// freshly serialized event verifies. Production callers already hold a parsed
/// event and call [`ParsedEvent::verify_said`] directly.
#[cfg(test)]
pub(crate) fn verify_said_raw(raw: &[u8]) -> Result<(), SerderError> {
    ParsedEvent::parse(raw)?.verify_said(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::icp::InceptionBuilder;
    use crate::traits::Serialize;
    use alloc::borrow::Cow;
    use alloc::vec;
    use alloc::vec::Vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use keri_events::InteractionEvent;
    use keri_events::sequence::SequenceNumber;

    // Placeholder-width and digest-determinism invariants live in their
    // canonical cesr homes (`DigestCode::placeholder`, `Diger::digest`); this
    // module now only tests SAID *verification* over serialized events.

    fn probe_ixn_raw() -> (Vec<u8>, String) {
        let prefixer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let saider_fixture = Saider::digest(DigestCode::Blake3_256, b"seed").unwrap();
        let event = InteractionEvent::new(
            prefixer.into(),
            SequenceNumber::new(1),
            saider_fixture.clone(),
            saider_fixture,
            vec![],
        );
        let ser = event.serialize().unwrap();
        let said = ser.said().to_qb64();
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
        let said = icp.said().to_qb64();
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
        verify_said_raw(&raw).expect("writer output must verify");
    }

    #[test]
    fn verify_said_rejects_tampered_event() {
        let (mut raw, _) = probe_ixn_raw();
        let s_pos = raw.windows(8).position(|w| w == b",\"s\":\"1\"").unwrap();
        raw[s_pos + 6] = b'2';
        assert!(matches!(
            verify_said_raw(&raw),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_rejects_non_canonical_input() {
        assert!(matches!(
            verify_said_raw(b"not an event"),
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
        verify_said_raw(icp.as_bytes())
            .expect("double-SAID inception must verify through the strict path");
    }
}
