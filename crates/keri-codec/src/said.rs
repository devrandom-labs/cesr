//! SAID (Self-Addressing IDentifier) computation and verification.
//!
//! A SAID is a content-addressable digest that appears in the `d` field of a
//! KERI event. Every said field carries its own digest code: on the write
//! path each said field (`d`, and for self-addressing `icp`/`dip` events the
//! `i` field too) is first filled with the placeholder of ITS code's length
//! ([`DigestCode::placeholder`]), the event is serialized once, and each
//! field's value becomes the digest of that single dummied serialization
//! under the field's OWN code — so `i == d` only when both codes coincide,
//! matching keripy's `makify`. On the read path, verification parses the
//! event with the strict canonical parser and dummies every said field whose
//! code is digestive (keripy's rule — not value equality) in place over a
//! single scratch copy of the raw input, then verifies each field under its
//! own code.
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
#[cfg(test)]
use crate::error::VersionGrammarError;
use crate::error::{CodecError, DeserializeError, InternalError, SaidError};

/// Byte form of the self-addressing placeholder character
/// ([`cesr::core::matter::code::DUMMY_CHAR`], the `#` convention) for in-place
/// span filling.
pub(crate) const DUMMY_BYTE: u8 = b'#';

impl ParsedIcp<'_> {
    /// Verify this inception's SAID(s), inferring each digest code from the
    /// field value's own qb64 prefix. The `d` span is always dummied and
    /// verified; the `i` span is dummied and verified under its OWN code
    /// exactly when that code is digestive (keripy's rule: dummy every said
    /// field whose code is digestive), which covers both same-code (`i == d`)
    /// and mixed-code (`i != d`) self-addressing inceptions. A basic
    /// (non-digestive) prefix is left intact.
    ///
    /// `raw` must be the exact bytes this event was parsed from.
    ///
    /// # Errors
    ///
    /// [`SaidError::SaidMismatch`] if a digest differs,
    /// [`DeserializeError::InvalidPrimitive`] if the `d` code is unknown, or
    /// [`InternalError::EventLayout`] if a span is out of bounds.
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), CodecError> {
        let d_code = infer_digest_code(self.said.value)?;
        probe_digest_code(self.prefix.value).map_or_else(
            || verify_said_spans(raw, &[(&self.said, d_code)]),
            |i_code| verify_said_spans(raw, &[(&self.said, d_code), (&self.prefix, i_code)]),
        )
    }
}

impl ParsedRot<'_> {
    /// Verify this rotation's single SAID, inferring the digest code from the
    /// `d` value's own qb64 prefix. See [`ParsedIcp::verify_said`].
    ///
    /// # Errors
    ///
    /// See [`ParsedIcp::verify_said`].
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), CodecError> {
        let code = infer_digest_code(self.said.value)?;
        verify_said_spans(raw, &[(&self.said, code)])
    }
}

impl ParsedIxn<'_> {
    /// Verify this interaction's single SAID, inferring the digest code from
    /// the `d` value's own qb64 prefix. See [`ParsedIcp::verify_said`].
    ///
    /// # Errors
    ///
    /// See [`ParsedIcp::verify_said`].
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), CodecError> {
        let code = infer_digest_code(self.said.value)?;
        verify_said_spans(raw, &[(&self.said, code)])
    }
}

impl ParsedEvent<'_> {
    /// Verify the SAID(s) of this parsed event, dispatching to the per-message_type
    /// verifier. Each infers its digest code from the `d` value's own qb64
    /// prefix; `icp`/`dip` additionally dummy and verify the `i` span under
    /// its own code when that code is digestive.
    ///
    /// `raw` must be the exact bytes this event was parsed from.
    ///
    /// # Errors
    ///
    /// See [`ParsedIcp::verify_said`].
    pub(crate) fn verify_said(&self, raw: &[u8]) -> Result<(), CodecError> {
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
/// Returns [`DeserializeError::InvalidPrimitive`] if the prefix is not a known
/// digest code.
pub(crate) fn infer_digest_code(qb64_said: &str) -> Result<DigestCode, DeserializeError> {
    let matter_code = MatterCode::from_base64_stream(qb64_said.as_bytes()).map_err(|e| {
        DeserializeError::InvalidPrimitive {
            field: "d",
            source: ValidationError::UnknownMatterCode(e.to_string()),
        }
    })?;
    DigestCode::try_from(matter_code).map_err(|e| DeserializeError::InvalidPrimitive {
        field: "d",
        source: e,
    })
}

/// Probe whether a qb64 value's code prefix is digestive, returning its
/// [`DigestCode`] — WITHOUT building an error when it is not: the read
/// path's "dummy every digestive said field" gate
/// ([`ParsedIcp::verify_said`]) runs this on every `i` value, and a
/// basic-derivation prefix must not pay for a discarded error string.
/// Non-digestive known codes (basic derivation) and unknown codes both
/// yield `None`; the strict field decode later rejects genuinely unknown
/// codes, unchanged.
fn probe_digest_code(qb64: &str) -> Option<DigestCode> {
    let code = MatterCode::from_base64_stream(qb64.as_bytes()).ok()?;
    if code.is_digest() {
        DigestCode::try_from(code).ok()
    } else {
        None
    }
}

/// Verify N said fields by span over ONE scratch: copy `raw` once, overwrite
/// EVERY field's value span with [`DUMMY_BYTE`], then for each
/// `(span, code)` pair hash the dummied render under the pair's own code and
/// compare against the pair's value. Every field digests the SAME dummied
/// render — mirroring keripy's `makify`, where each said field is computed
/// independently over one fully dummied serialization.
///
/// Spans come from the canonical parser and must address the qb64 value
/// bytes exactly (quotes excluded). This replaces the historical
/// parse-mutate-re-render verification with one raw copy and one hash per
/// said field.
///
/// # Errors
///
/// Returns [`SaidError::SaidMismatch`] on the first field whose computed
/// digest differs, [`InternalError::EventLayout`] if a span is out of
/// bounds, or [`SaidError::Digest`] on hash failure.
fn verify_said_spans(raw: &[u8], fields: &[(&Spanned<'_>, DigestCode)]) -> Result<(), CodecError> {
    let mut scratch = raw.to_vec();
    for (spanned, _) in fields {
        fill_span(&mut scratch, &spanned.span)?;
    }
    for (spanned, code) in fields {
        let computed = Saider::digest(*code, &scratch).map_err(SaidError::from)?;
        let computed_qb64 = computed.to_qb64();
        if spanned.value != computed_qb64 {
            return Err(SaidError::SaidMismatch {
                expected: spanned.value.to_owned(),
                computed: computed_qb64,
            }
            .into());
        }
    }
    Ok(())
}

fn fill_span(scratch: &mut [u8], span: &Range<usize>) -> Result<(), CodecError> {
    scratch
        .get_mut(span.clone())
        .ok_or(InternalError::EventLayout("SAID span out of bounds"))?
        .fill(DUMMY_BYTE);
    Ok(())
}

/// Test-only convenience: parse `raw`, then verify the SAID on the resulting
/// [`ParsedEvent`]. Shared by builder/serialize/codec tests that check a
/// freshly serialized event verifies. Production callers already hold a parsed
/// event and call [`ParsedEvent::verify_said`] directly.
#[cfg(test)]
pub(crate) fn verify_said_raw(raw: &[u8]) -> Result<(), CodecError> {
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
    use cesr::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
    use cesr::core::primitives::Number;
    use keri_events::InteractionEvent;
    use keri_events::threshold_form::ThresholdForm;
    use keri_events::toad::Toad;
    use keri_events::{BasicPrefix, Said};
    use keri_events::{Digest, Identifier, InceptionEvent, SigningThreshold, VerifyingKey};

    // Placeholder-width and digest-determinism invariants live in their
    // canonical cesr homes (`DigestCode::placeholder`, `Diger::digest`); this
    // module now only tests SAID *verification* over serialized events.

    fn probe_ixn_raw() -> (Vec<u8>, String) {
        let prefixer: BasicPrefix<'static> = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
            .into();
        let saider_fixture: Said<'static> = Saider::digest(DigestCode::Blake3_256, b"seed")
            .unwrap()
            .into();
        let event = InteractionEvent::new(
            prefixer.into(),
            Number::new(1),
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
        verify_said_spans(&raw, &[(&spanned, DigestCode::Blake3_256)])
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
            verify_said_spans(&raw, &[(&spanned, DigestCode::Blake3_256)]),
            Err(CodecError::Said(SaidError::SaidMismatch { .. }))
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
            verify_said_spans(&raw, &[(&bogus, DigestCode::Blake3_256)]),
            Err(CodecError::Internal(InternalError::EventLayout(_)))
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
            verify_said_spans(&raw, &[(&short, DigestCode::Blake3_256)]),
            Err(CodecError::Said(SaidError::SaidMismatch { .. }))
        ));
    }

    #[test]
    fn verify_said_spans_double_said_matches_reference() {
        // For an icp whose d == i (self-addressing), filling BOTH spans must
        // reproduce the SAID the writer computed (the writer patches both
        // slots from digests over a double-placeholder render; same code, so
        // the two digests are equal).
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![7u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let icp = InceptionBuilder::new()
            .keys(vec![verfer.into()])
            .build()
            .unwrap();
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
        verify_said_spans(
            &raw,
            &[
                (&d_spanned, DigestCode::Blake3_256),
                (&i_spanned, DigestCode::Blake3_256),
            ],
        )
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
            Err(CodecError::Said(SaidError::SaidMismatch { .. }))
        ));
    }

    #[test]
    fn verify_said_rejects_non_canonical_input() {
        assert!(matches!(
            verify_said_raw(b"not an event"),
            Err(
                CodecError::Deserialize(DeserializeError::NonCanonical { .. })
                    | CodecError::Version(VersionGrammarError::InvalidVersionString(_))
            )
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
        let icp = InceptionBuilder::new()
            .keys(vec![verfer.into()])
            .build()
            .unwrap();
        verify_said_raw(icp.as_bytes())
            .expect("double-SAID inception must verify through the strict path");
    }

    /// An inception whose self-addressing `i` carries a DIFFERENT (and
    /// wider) digest code than `d`: `d` under Blake3-256 (44 chars), `i`
    /// under SHA3-512 (88 chars) — keripy's `incept(code=…)` mixed-code
    /// shape, exercising unequal `d`/`i` spans.
    fn mixed_code_icp() -> InceptionEvent<'static> {
        let prefix_said = Said::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::SHA3_512)
                .with_raw(Cow::<[u8]>::Owned(vec![9u8; 64]))
                .unwrap()
                .build()
                .unwrap(),
        );
        let d_said = Said::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        );
        let verfer = VerifyingKey::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        );
        let diger = Digest::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        );
        InceptionEvent::new(
            Identifier::SelfAddressing(prefix_said),
            Number::new(0),
            d_said,
            vec![verfer],
            SigningThreshold::Simple(1),
            vec![diger],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        )
    }

    #[test]
    fn verify_said_accepts_mixed_code_inception() {
        let ser = mixed_code_icp().serialize().unwrap();
        let raw = ser.as_bytes().to_vec();
        verify_said_raw(&raw).expect("mixed-code inception must verify");
        // `d` stays at Blake3-256 (`E`), `i` carries the SHA3-512 override
        // (`0F`) — a mixed-code event has i != d at unequal widths.
        let i_width = DigestCode::SHA3_512.placeholder().unwrap().len();
        let d_start = raw.windows(5).position(|w| w == b"\"d\":\"").unwrap() + 5;
        let i_start = raw.windows(5).position(|w| w == b"\"i\":\"").unwrap() + 5;
        assert_eq!(raw[d_start], b'E', "d stays at the Blake3-256 code");
        assert_eq!(
            &raw[i_start..i_start + 2],
            b"0F",
            "i carries the override code"
        );
        let d_val = &raw[d_start..d_start + 44];
        let i_val = &raw[i_start..i_start + i_width];
        assert_ne!(d_val, i_val, "mixed-code event must have i != d");
        let prefix_qb64 = ser.prefix().expect("self-addressing prefix").to_qb64();
        assert!(prefix_qb64.starts_with("0F"));
        assert_eq!(prefix_qb64.len(), i_width);
        assert_ne!(prefix_qb64, ser.said().to_qb64());
    }

    #[test]
    fn verify_said_rejects_tampered_mixed_code_prefix() {
        // Probe for the independent-`i` invariant: corrupting the `i` VALUE
        // must fail verification. This test FAILS if `i` is dummied but not
        // verified — the dummy fill would erase the tamper and the forged
        // value would slip through.
        let ser = mixed_code_icp().serialize().unwrap();
        let mut raw = ser.as_bytes().to_vec();
        let i_start = raw.windows(5).position(|w| w == b"\"i\":\"").unwrap() + 5;
        let pos = i_start + 10;
        raw[pos] = if raw[pos] == b'A' { b'B' } else { b'A' };
        assert!(matches!(
            verify_said_raw(&raw),
            Err(CodecError::Said(SaidError::SaidMismatch { .. }))
        ));
    }
}
