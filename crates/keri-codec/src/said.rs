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
//! The same law is exposed generically: [`SadCodes::saidify`] and
//! [`SadCodes::verify`]
//! apply it to any canonical-JSON SAD — a document with a `v` version string
//! and configurable digestive labels (an ACDC SAD, not just a KEL event) —
//! under a caller-supplied [`SadCodes`] per-label configuration. The typed
//! event paths are the configured special case of the generic one: both
//! share [`compute_said_fields`]'s dummy-everything-then-digest-each core.
//!
//! [`DigestCode::placeholder`]: cesr::core::matter::code::CesrCode::placeholder

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec::Vec};
use cesr::core::matter::code::{CesrCode, DigestCode, MatterCode};
use cesr::core::matter::error::ValidationError;
use cesr::core::primitives::Saider;
use cesr::core::version::{SerializationKind, VERSION_SIZE_MAX, VersionError, VersionString};
use core::ops::Range;
#[cfg(feature = "alloc")]
use core::str::from_utf8;

use crate::codec::event::{ParsedDip, ParsedEvent, ParsedIcp, ParsedIxn, ParsedRot};
use crate::codec::scanner::{Scanner, Spanned};
use crate::error::{
    CodecError, DeserializeError, InternalError, SadCodesError, SaidError, VersionGrammarError,
};

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

/// Byte offset of the six-hex-digit size field inside a v1 version string
/// value: protocol (4) + major (1) + minor (1) + kind (4). Grounded in
/// [`VersionString::parse`]'s fixed 17-byte frame.
const VERSION_SIZE_FIELD: Range<usize> = 10..16;

/// The top-level version label. Grammar-owned: the version string is
/// validated and size-patched by the codec and is never a digest slot.
const VERSION_LABEL: &str = "v";

/// Maximum number of configured digestive labels in a [`SadCodes`].
///
/// KERI events need at most two (`d` and the double-SAID `i`); the generic
/// SAD path allows a few more (an ACDC edge or attachment map) without
/// heap-allocating the configuration. Construction is fallible beyond this
/// cap.
#[cfg(feature = "alloc")]
pub const SAD_CODES_MAX: usize = 4;

/// Per-label digest-code configuration for the generic SAD path.
///
/// Maps top-level JSON labels to the [`DigestCode`] that labels the field's
/// SAID — the data-driven analog of keripy's `saids` code map. Every
/// configured label is dummied and digested under its OWN code over one
/// shared canonical serialization, whatever the SAD's ilk; there are no
/// per-type special cases. `v` is reserved.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SadCodes {
    /// The `(label, code)` slots, in configuration order.
    slots: [Option<(&'static str, DigestCode)>; SAD_CODES_MAX],
}

#[cfg(feature = "alloc")]
impl SadCodes {
    /// Build the configuration from `(label, code)` pairs.
    ///
    /// # Errors
    ///
    /// [`SadCodesError::Capacity`] beyond [`SAD_CODES_MAX`] labels,
    /// [`SadCodesError::ReservedVersionLabel`] for the reserved `v` label.
    pub fn from_pairs(pairs: &[(&'static str, DigestCode)]) -> Result<Self, SadCodesError> {
        if pairs.len() > SAD_CODES_MAX {
            return Err(SadCodesError::Capacity);
        }
        let mut slots = [None; SAD_CODES_MAX];
        for (slot, (label, code)) in slots.iter_mut().zip(pairs) {
            if *label == VERSION_LABEL {
                return Err(SadCodesError::ReservedVersionLabel);
            }
            *slot = Some((*label, *code));
        }
        Ok(Self { slots })
    }

    /// The configured digest code for `label`, if configured.
    #[must_use]
    pub fn code_for(&self, label: &str) -> Option<DigestCode> {
        self.index_of(label)
            .and_then(|index| self.slots.get(index))
            .and_then(|slot| slot.as_ref().map(|(_, code)| *code))
    }

    /// The slot index of a configured label, if configured.
    fn index_of(&self, label: &str) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.is_some_and(|(l, _)| l == label))
    }

    /// Overwrite a fixed-width slot in place, verifying bounds and width.
    /// Internal splice helper shared by the write spine and the event
    /// serializer.
    pub(crate) fn patch_slot(
        buf: &mut [u8],
        slot: &Range<usize>,
        replacement: &[u8],
    ) -> Result<(), CodecError> {
        let dst = buf
            .get_mut(slot.clone())
            .ok_or(InternalError::EventLayout("slot out of bounds"))?;
        if dst.len() != replacement.len() {
            return Err(InternalError::EventLayout("slot width does not match replacement").into());
        }
        dst.copy_from_slice(replacement);
        Ok(())
    }

    /// Saidify a canonical-JSON SAD in place — keripy's `Saider.saidify`
    /// analog.
    ///
    /// The law: dummy every configured digestive field, serialize once, and
    /// backfill each field with the digest of that single rendering under
    /// the field's OWN code.
    ///
    /// `sad` holds the SAD bytes; every configured digestive field's slot
    /// must already carry a fixed-width value of its code's placeholder
    /// width (the content is overwritten — mirroring keripy's
    /// dummy-and-backfill). A top-level `v` version string is validated
    /// (17-byte v1 JSON frame) and its size field patched to the final
    /// render length before digesting. The SAD need not be versioned.
    ///
    /// Returns the parsed SAD whose [`ParsedSad::said`] reports each
    /// backfilled value and whose [`ParsedSad::as_bytes`] is the canonical
    /// rendering.
    ///
    /// # Examples
    ///
    /// ```
    /// use cesr::core::matter::code::DigestCode;
    /// use keri_codec::SadCodes;
    ///
    /// // Each configured slot starts at its code's placeholder width; the
    /// // contents are overwritten by the digest.
    /// let mut sad = br#"{"v":"KERI10JSON000000_","t":"cred","d":"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.to_vec();
    /// let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)]).unwrap();
    ///
    /// codes.saidify(&mut sad).unwrap();
    /// assert!(codes.verify(&sad).is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// [`SaidError::MissingDigestiveField`] if a configured label is absent,
    /// [`SaidError::InvalidSlotWidth`] if a slot does not fit its code's
    /// placeholder, [`SaidError::Digest`] on hash failure, or any
    /// canonical-JSON grammar rejection (whitespace, escapes, duplicate
    /// labels, malformed values, trailing bytes) as a [`DeserializeError`].
    #[cfg(feature = "alloc")]
    pub fn saidify<'a>(&self, sad: &'a mut [u8]) -> Result<ParsedSad<'a>, CodecError> {
        let scan = scan_sad(sad, self)?;
        require_all_configured(self, &scan)?;
        require_slot_widths(sad, self, &scan)?;

        // Patch the version size to the full render length BEFORE digesting —
        // the digests cover the size-corrected bytes (the event writer's law).
        if let Some((v_span, _)) = &scan.version {
            let size_u32 = u32::try_from(sad.len())
                .ok()
                .filter(|size| *size <= VERSION_SIZE_MAX)
                .ok_or(VersionGrammarError::Version(VersionError::FieldOverflow {
                    field: "size",
                    max: VERSION_SIZE_MAX,
                }))?;
            let size_span =
                v_span.start + VERSION_SIZE_FIELD.start..v_span.start + VERSION_SIZE_FIELD.end;
            Self::patch_slot(sad, &size_span, format!("{size_u32:06x}").as_bytes())?;
        }

        let fields = scan_fields(self, &scan);
        // Dummy every digestive span, digest every field over the ONE shared
        // render, then splice — splicing an earlier result before computing a
        // later digest would corrupt that digest.
        for (span, _) in &fields {
            fill_span(sad, span)?;
        }
        let computed = compute_said_fields(sad, &fields)?;
        for ((span, _), said_matter) in fields.iter().zip(computed.iter()) {
            let said_qb64 = said_matter.to_qb64();
            Self::patch_slot(sad, span, said_qb64.as_bytes())?;
        }

        Ok(ParsedSad {
            raw: sad,
            fields: scan_fields_labeled(self, &scan),
        })
    }

    /// Verify the SAIDs of a canonical-JSON SAD — the read-path analog of
    /// [`SadCodes::saidify`].
    ///
    /// Every configured digestive field is dummied in one scratch copy of
    /// `raw` and each field's digest is recomputed under its own code over
    /// that shared render; the first mismatch is
    /// [`SaidError::SaidMismatch`]. The input must be canonical — any
    /// grammar violation (whitespace, escapes, duplicate labels, non-JSON
    /// version kinds, trailing bytes) is rejected before digesting — and a
    /// top-level `v` version string's declared size must equal `raw.len()`.
    ///
    /// Returns the parsed SAD whose [`ParsedSad::said`] reports each
    /// verified value.
    ///
    /// # Errors
    ///
    /// [`SaidError::MissingDigestiveField`] if a configured label is absent,
    /// [`SaidError::SaidMismatch`] on the first digest mismatch,
    /// [`SaidError::Digest`] on hash failure, or any canonical-JSON grammar
    /// rejection as a [`DeserializeError`].
    #[cfg(feature = "alloc")]
    pub fn verify<'a>(&self, raw: &'a [u8]) -> Result<ParsedSad<'a>, CodecError> {
        let scan = scan_sad(raw, self)?;
        require_all_configured(self, &scan)?;
        if let Some((_, version)) = &scan.version
            && !u32::try_from(raw.len()).is_ok_and(|len| version.size() == len)
        {
            return Err(VersionGrammarError::InvalidVersionString(format!(
                "version string size {} does not match actual size {}",
                version.size(),
                raw.len()
            ))
            .into());
        }

        let fields = scan_fields(self, &scan);
        let mut scratch = raw.to_vec();
        for (span, _) in &fields {
            fill_span(&mut scratch, span)?;
        }
        let computed = compute_said_fields(&scratch, &fields)?;
        for ((span, _), said_matter) in fields.iter().zip(computed.iter()) {
            let claimed_bytes = raw
                .get(span.clone())
                .ok_or(InternalError::EventLayout("digestive span out of bounds"))?;
            // [`Scanner::string`] validated UTF-8 at scan time; a scanned
            // span cannot fail this conversion.
            let claimed = from_utf8(claimed_bytes)
                .map_err(|_| InternalError::EventLayout("scanned span is not UTF-8"))?;
            let computed_qb64 = said_matter.to_qb64();
            if claimed != computed_qb64.as_str() {
                return Err(SaidError::SaidMismatch {
                    expected: String::from(claimed),
                    computed: computed_qb64,
                }
                .into());
            }
        }

        Ok(ParsedSad {
            raw,
            fields: scan_fields_labeled(self, &scan),
        })
    }
}

/// A parsed canonical-JSON SAD: the raw bytes plus the scanned spans of the
/// configured digestive fields. Returned by [`SadCodes::saidify`] (values
/// backfilled) and [`SadCodes::verify`] (values verified).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct ParsedSad<'a> {
    raw: &'a [u8],
    /// The configured `(label, span)` pairs that were found, in slot order.
    fields: Vec<(&'static str, Range<usize>)>,
}

#[cfg(feature = "alloc")]
impl ParsedSad<'_> {
    /// The canonical SAD bytes: for [`SadCodes::saidify`], the rendering with
    /// every SAID backfilled; for [`SadCodes::verify`], the verified input
    /// unchanged.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.raw
    }

    /// The qb64 SAID of a configured digestive field, if present.
    #[must_use]
    pub fn said(&self, label: &str) -> Option<&str> {
        let span = self
            .fields
            .iter()
            .find(|(field_label, _)| *field_label == label)
            .map(|(_, span)| span.clone())?;
        // [`Scanner::string`] validated UTF-8 at scan time; a scanned span
        // cannot fail this conversion.
        let value = self.raw.get(span)?;
        from_utf8(value).ok()
    }
}

/// The found digestive fields as configured `(label, span)` pairs — what
/// [`ParsedSad`] stores, in slot order.
#[cfg(feature = "alloc")]
fn scan_fields_labeled(codes: &SadCodes, scan: &SadScan) -> Vec<(&'static str, Range<usize>)> {
    codes
        .slots
        .iter()
        .zip(scan.spans.iter())
        .filter_map(|(configured, scanned)| match (configured, scanned) {
            (Some((label, _)), Some(found)) => Some((*label, found.clone())),
            _ => None,
        })
        .collect()
}

/// The found digestive fields as (span, code) digest fields — the shape
/// [`compute_said_fields`] consumes, in slot order.
#[cfg(feature = "alloc")]
fn scan_fields(codes: &SadCodes, scan: &SadScan) -> Vec<(Range<usize>, DigestCode)> {
    codes
        .slots
        .iter()
        .zip(scan.spans.iter())
        .filter_map(|(configured, scanned)| match (configured, scanned) {
            (Some((_, code)), Some(found)) => Some((found.clone(), *code)),
            _ => None,
        })
        .collect()
}

/// The SAID law over every digestive field of one render: digest each field
/// under its own code over the SAME dummied serialization. `render` must
/// carry every span in `fields` already overwritten with [`DUMMY_BYTE`].
/// Returns the digest primitives in field order.
#[cfg(feature = "alloc")]
fn compute_said_fields(
    render: &[u8],
    fields: &[(Range<usize>, DigestCode)],
) -> Result<Vec<Saider<'static>>, SaidError> {
    fields
        .iter()
        .map(|(_, code)| Saider::digest(*code, render).map_err(SaidError::from))
        .collect()
}

/// Every configured digestive label must have been found — keripy's
/// `Saider.saidify` raises on a missing label rather than silently skipping.
#[cfg(feature = "alloc")]
fn require_all_configured(codes: &SadCodes, scan: &SadScan) -> Result<(), SaidError> {
    for (slot, span) in codes.slots.iter().zip(scan.spans.iter()) {
        if let (Some((label, _)), None) = (slot, span) {
            return Err(SaidError::MissingDigestiveField {
                label: String::from(*label),
            });
        }
    }
    Ok(())
}

/// Every configured slot must be exactly its code's placeholder width —
/// [`SadCodes::saidify`] splices fixed-width qb64 values into the slots it
/// dummies.
/// The read path needs no width check: a wrong-width value cannot match any
/// digest computed over its own render.
#[cfg(feature = "alloc")]
fn require_slot_widths(sad: &[u8], codes: &SadCodes, scan: &SadScan) -> Result<(), CodecError> {
    for (configured, scanned) in codes.slots.iter().zip(scan.spans.iter()) {
        if let (Some((label, code)), Some(span)) = (configured, scanned) {
            let expected = code
                .placeholder()
                .map_err(|e| InternalError::PlaceholderPrimitive { source: e.into() })?
                .len();
            let found = sad
                .get(span.clone())
                .ok_or(InternalError::EventLayout("digestive span out of bounds"))?
                .len();
            if found != expected {
                return Err(SaidError::InvalidSlotWidth {
                    label: String::from(*label),
                    expected,
                    found,
                }
                .into());
            }
        }
    }
    Ok(())
}

/// One canonical-JSON SAD scan: the absolute byte spans of the configured
/// digestive fields (aligned with [`SadCodes::slots`]) and the version
/// string, collected in ONE strict pass over the raw input.
#[cfg(feature = "alloc")]
struct SadScan {
    /// Per configured label: the field value's span in the scanned buffer.
    spans: [Option<Range<usize>>; SAD_CODES_MAX],
    /// The `v` field's value span and its parsed version string, if present.
    version: Option<(Range<usize>, VersionString)>,
}

/// Scan one canonical-JSON SAD: validate the full structure (top level and
/// nested), collect the configured digestive spans and the version string,
/// and reject duplicates and grammar violations in one strict pass. The
/// nested walk reuses the strict event scanner — every nested value is fully
/// validated but not dummied; nested sub-SADs are their own saidify/verify
/// calls (keripy semantics).
#[cfg(feature = "alloc")]
fn scan_sad(raw: &[u8], codes: &SadCodes) -> Result<SadScan, CodecError> {
    let mut sc = Scanner::new(raw);
    sc.expect("{")?;
    let mut scan = SadScan {
        spans: [const { None }; SAD_CODES_MAX],
        version: None,
    };
    let mut containers = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    if !sc.take_lit("}") {
        loop {
            let key = sc.string()?;
            if seen.contains(&key.value) {
                return Err(sc.err_at(key.span.start, "unique field label").into());
            }
            seen.push(key.value);
            sc.expect(":")?;
            if key.value == VERSION_LABEL {
                let value = sc.string()?;
                let (version, rest) = VersionString::parse(value.value.as_bytes())
                    .map_err(VersionGrammarError::from)?;
                if !rest.is_empty() {
                    return Err(VersionGrammarError::InvalidVersionString(format!(
                        "expected exactly a 17-byte version string, got {} bytes",
                        value.value.len()
                    ))
                    .into());
                }
                if version.kind() != SerializationKind::Json {
                    return Err(VersionGrammarError::InvalidVersionString(format!(
                        "expected JSON, got {}",
                        version.kind().as_str()
                    ))
                    .into());
                }
                scan.version = Some((value.span, version));
            } else if let Some(index) = codes.index_of(key.value) {
                let value = sc.string()?;
                scan.spans[index] = Some(value.span);
            } else {
                sc.canonical_value(&mut containers)?;
            }
            if !sc.take_lit(",") {
                break;
            }
        }
        sc.expect("}")?;
    }
    sc.finish()?;
    Ok(scan)
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
