//! The ACDC wire grammar — both directions in one place.
//!
//! Write form: keripy's credential factory at the pin
//! (`src/keri/vc/proving.py:20-108` `credential`, `src/keri/core/serdering.py`
//! `SerderACDC`, keripy `de59bc7d`) renders the canonical-JSON body in fixed
//! spec order; [`AcdcBodyRef::render`] reproduces those bytes exactly, with a
//! placeholder slot where the SAID splices in. Read form: a strict single-pass
//! scanner in the same field order — any deviation is a typed
//! [`DeserializeError::NonCanonical`].
//!
//! The version string pins protocol `ACDC`, major 1, minor 0: keripy's
//! `Protocols.acdc` and default `Versionage(major=1, minor=0)` (`kering.py:24`,
//! `proving.py:53`) — the credential factory has no other wire version at this
//! pin. A credential has no `t` ilk and no sequence number; `v` and `d` lead
//! the body, exactly as `SerderACDC` lays them out.
//!
//! The SAID lifecycle (dummy → size-patch → digest → splice; verify) is NOT
//! here: it is the generic [`SadCodes`](crate::SadCodes) machinery, configured
//! with the single digestive label `d` — no ACDC-specific digest logic. Nested
//! blocks render verbatim on the write path; the read path verifies each
//! nested block's own top-level `d` (or `$id` for schema blocks) through the
//! same generic machinery when that label carries a qb64 digest, and leaves
//! the payload byte-for-byte otherwise.

use core::ops::Range;
use core::str;

use crate::codec::scanner::Scanner;
use crate::codec::{Encode, JsonWriter};
use crate::error::{CodecError, InternalError, VersionGrammarError};
use crate::said::SadCodes;
use cesr::core::matter::code::DigestCode;
use cesr::core::version::{Protocol, SerializationKind, VersionString};
use keri_events::Acdc;
use keri_events::acdc::{AcdcField, SadBlock};

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, format, vec::Vec};

/// A scanned ACDC body — the strict wire-view of a v1 credential SAD. Every
/// field is a borrowed span; lift to domain types happens after SAID
/// verification (the [`Field`](crate::codec::field::Field) pipeline).
#[derive(Debug)]
pub(crate) struct ParsedAcdc<'a> {
    /// The credential's SAID (`d`).
    pub(crate) said: &'a str,
    /// Salty uuid nonce (`u`).
    pub(crate) nonce: Option<&'a str>,
    /// Issuer identifier (`i`).
    pub(crate) issuer: Option<&'a str>,
    /// Registry reference (`ri`) — block-or-SAID.
    pub(crate) registry: Option<AcdcFieldSpan<'a>>,
    /// Schema (`s`) — block-or-SAID, required.
    pub(crate) schema: AcdcFieldSpan<'a>,
    /// Attributes (`a`) — block-or-SAID.
    pub(crate) attributes: Option<AcdcFieldSpan<'a>>,
    /// Aggregate attributes (`A`).
    pub(crate) aggregate_attributes: Option<&'a str>,
    /// Edges (`e`) — block-or-SAID.
    pub(crate) edges: Option<AcdcFieldSpan<'a>>,
    /// Aggregate edges (`E`).
    pub(crate) aggregate_edges: Option<&'a str>,
    /// Rules (`r`) — block-or-SAID.
    pub(crate) rules: Option<AcdcFieldSpan<'a>>,
    /// Aggregate rules (`R`).
    pub(crate) aggregate_rules: Option<&'a str>,
    /// Prior chained-data SAID (`p`).
    pub(crate) prior: Option<&'a str>,
}

/// One block-or-SAID field as scanned: either a string span (the bare-Said
/// compact form) or an object byte span (the full block, carried verbatim).
#[derive(Debug)]
pub(crate) enum AcdcFieldSpan<'a> {
    /// A bare SAID string span.
    Said(&'a str),
    /// The full block's byte span in the raw input.
    Block(&'a [u8]),
}

impl<'a> ParsedAcdc<'a> {
    /// The credential's digestive-field configuration: the single `d` slot
    /// under the SAID's own wire derivation code. The shared home for both
    /// wire directions — the read side infers the code from the scanned
    /// `d`, the write side from the model's SAID. Mirrors
    /// `TelSadConfig::tel_sad_config` — the static shape can never violate
    /// `SadCodes`' capacity or label rules, so a rejection reports as the
    /// internal layout error it would be.
    ///
    /// # Errors
    ///
    /// [`InternalError::EventLayout`] if `SadCodes` rejects the single-slot
    /// configuration (a broken invariant, not wire input).
    pub(crate) fn sad_config(code: DigestCode) -> Result<crate::SadCodes, CodecError> {
        crate::SadCodes::from_pairs(&[("d", code)]).map_err(|_| {
            InternalError::EventLayout("static ACDC SAID configuration rejected").into()
        })
    }

    /// Verify every nested block's own top-level SAID.
    ///
    /// keripy leaves nested-block SAID checks to the consumer; the codec
    /// enforces them at the read boundary so a caller can trust every SAID
    /// it reads, not just the outer `d`. A block without a top-level
    /// `d`/`$id` digest (schema blocks carry `$id`; registry status blocks
    /// may reference rather than embed) verifies trivially.
    ///
    /// # Errors
    ///
    /// [`SaidError::SaidMismatch`] when a nested block's digest does not
    /// verify; [`InternalError::EventLayout`] for configuration breakage.
    pub(crate) fn verify_nested_blocks(&self) -> Result<(), CodecError> {
        let spans = [
            self.registry.as_ref(),
            Some(&self.schema),
            self.attributes.as_ref(),
            self.edges.as_ref(),
            self.rules.as_ref(),
        ];
        for span in spans.into_iter().flatten() {
            if let AcdcFieldSpan::Block(payload) = span {
                SadCodes::verify_nested_block(payload)?;
            }
        }
        Ok(())
    }

    /// Parse and validate one credential body.
    ///
    /// # Errors
    ///
    /// [`DeserializeError::NonCanonical`] for any deviation from the fixed
    /// field order, version grammar, or canonical value grammar; a missing
    /// required `s` is reported at the offset where it should have appeared.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, CodecError> {
        let mut sc = Scanner::new(raw);
        Self::head(&mut sc)?;
        let said = sc.string()?;

        let nonce = Self::optional(&mut sc, ",\"u\":", |inner| Ok(inner.string()?.value))?;
        let issuer = Self::optional(&mut sc, ",\"i\":", |inner| Ok(inner.string()?.value))?;
        let registry = Self::optional(&mut sc, ",\"ri\":", Self::field_span)?;
        // `s` is required: absent is rejected at the offset where the field
        // should have started, naming the exact expectation.
        let s_at = sc.pos;
        let schema_span = Self::optional(&mut sc, ",\"s\":", Self::field_span)?;
        let Some(schema) = schema_span else {
            return Err(sc.err_at(s_at, ",\"s\":").into());
        };
        let attributes = Self::optional(&mut sc, ",\"a\":", Self::field_span)?;
        let aggregate_attributes =
            Self::optional(&mut sc, ",\"A\":", |inner| Ok(inner.string()?.value))?;
        let edges = Self::optional(&mut sc, ",\"e\":", Self::field_span)?;
        let aggregate_edges =
            Self::optional(&mut sc, ",\"E\":", |inner| Ok(inner.string()?.value))?;
        let rules = Self::optional(&mut sc, ",\"r\":", Self::field_span)?;
        let aggregate_rules =
            Self::optional(&mut sc, ",\"R\":", |inner| Ok(inner.string()?.value))?;
        let prior = Self::optional(&mut sc, ",\"p\":", |inner| Ok(inner.string()?.value))?;
        sc.expect("}")?;

        Ok(Self {
            said: said.value,
            nonce,
            issuer,
            registry,
            schema,
            attributes,
            aggregate_attributes,
            edges,
            aggregate_edges,
            rules,
            aggregate_rules,
            prior,
        })
    }

    /// Scan and validate the fixed head `{"v":"<17-byte ACDC JSON vstring>"`.
    fn head(sc: &mut Scanner<'a>) -> Result<(), CodecError> {
        sc.expect("{\"v\":\"")?;
        let vs_start = sc.pos;
        let vs_end = vs_start
            .checked_add(17)
            .ok_or_else(|| sc.err("17-byte version string"))?;
        let vs_bytes = sc
            .input
            .get(vs_start..vs_end)
            .ok_or_else(|| sc.err("17-byte version string"))?;
        let (vs, rest) = VersionString::parse(vs_bytes).map_err(VersionGrammarError::from)?;
        if !rest.is_empty() {
            return Err(VersionGrammarError::InvalidVersionString(
                "expected exactly a 17-byte version string".to_owned(),
            )
            .into());
        }
        if vs.proto() != Protocol::Acdc {
            return Err(VersionGrammarError::InvalidVersionString(format!(
                "expected ACDC protocol, got {}",
                vs.proto().as_str()
            ))
            .into());
        }
        if vs.kind() != SerializationKind::Json {
            return Err(VersionGrammarError::InvalidVersionString(format!(
                "expected JSON, got {}",
                vs.kind().as_str()
            ))
            .into());
        }
        sc.pos = vs_end;
        sc.expect("\",\"d\":")?;
        Ok(())
    }

    /// Scan an optional `,"<label>":<value>` field; `None` leaves the cursor
    /// untouched, so the next expectation sees the same bytes.
    fn optional<T>(
        sc: &mut Scanner<'a>,
        lit: &'static str,
        value: impl Fn(&mut Scanner<'a>) -> Result<T, CodecError>,
    ) -> Result<Option<T>, CodecError> {
        if sc.take_lit(lit) {
            Ok(Some(value(sc)?))
        } else {
            Ok(None)
        }
    }

    /// A block-or-SAID value: a quoted string span or a canonical object span.
    fn field_span(sc: &mut Scanner<'a>) -> Result<AcdcFieldSpan<'a>, CodecError> {
        match sc.peek() {
            Some(b'"') => Ok(AcdcFieldSpan::Said(sc.string()?.value)),
            Some(b'{') => {
                let span: Range<usize> = sc.object_value_span()?;
                Ok(AcdcFieldSpan::Block(sc.input.get(span).ok_or(
                    crate::error::InternalError::EventLayout("block span out of bounds"),
                )?))
            }
            _ => Err(sc.err("SAID string or JSON object").into()),
        }
    }
}

/// The write-side view of an ACDC body: render the canonical JSON.
///
/// The vstring carries a zero size (`ACDC10JSON000000_`); the generic SAID
/// orchestration backpatches it before digesting. Blocks render verbatim —
/// their payloads are already canonical JSON owned by the caller.
pub(crate) struct AcdcBodyRef<'a>(pub(crate) &'a Acdc<'a>);

impl AcdcBodyRef<'_> {
    /// The digest code of the credential's `d` field — the derivation code
    /// for the SAID splice. Builders pin keripy's default
    /// ([`DigestCode::Blake3_256`], the `Saider.saidify` default the
    /// credential factory uses); parsed credentials carry their wire code.
    pub(crate) const fn said_code(&self) -> cesr::core::matter::code::DigestCode {
        *self.0.said().as_matter().code()
    }

    /// Render the body into `buf` (appending).
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for version-grammar failures only — the
    /// size slot is backpatched by the generic [`crate::SadCodes`] saidify.
    pub(crate) fn render(
        &self,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        let vs = VersionString::new(Protocol::Acdc, 1, 0, SerializationKind::Json, 0)
            .map_err(VersionGrammarError::from)?
            .to_str();
        buf.extend_from_slice(b"{\"v\":\"");
        buf.extend_from_slice(vs.as_bytes());
        buf.extend_from_slice(b"\",\"d\":\"");
        buf.extend_from_slice(said_placeholder.as_bytes());
        buf.push(b'"');

        if let Some(nonce) = self.0.nonce() {
            buf.extend_from_slice(b",\"u\":");
            nonce.encode(buf);
        }
        if let Some(issuer) = self.0.issuer() {
            buf.extend_from_slice(b",\"i\":");
            issuer.encode(buf);
        }
        if let Some(registry) = self.0.registry() {
            buf.extend_from_slice(b",\"ri\":");
            Self::encode_field(registry, buf);
        }
        buf.extend_from_slice(b",\"s\":");
        Self::encode_field(self.0.schema(), buf);
        if let Some(attributes) = self.0.attributes() {
            buf.extend_from_slice(b",\"a\":");
            Self::encode_field(attributes, buf);
        }
        if let Some(digest) = self.0.aggregate_attributes() {
            buf.extend_from_slice(b",\"A\":");
            digest.encode(buf);
        }
        if let Some(edges) = self.0.edges() {
            buf.extend_from_slice(b",\"e\":");
            Self::encode_field(edges, buf);
        }
        if let Some(digest) = self.0.aggregate_edges() {
            buf.extend_from_slice(b",\"E\":");
            digest.encode(buf);
        }
        if let Some(rules) = self.0.rules() {
            buf.extend_from_slice(b",\"r\":");
            Self::encode_field(rules, buf);
        }
        if let Some(digest) = self.0.aggregate_rules() {
            buf.extend_from_slice(b",\"R\":");
            digest.encode(buf);
        }
        if let Some(prior) = self.0.prior() {
            buf.extend_from_slice(b",\"p\":");
            prior.encode(buf);
        }
        buf.push(b'}');
        Ok(())
    }

    /// Render one block-or-SAID field: a quoted qb64 string, or the block's
    /// payload bytes verbatim (canonical JSON — re-rendering would not be
    /// guaranteed byte-identical for nested-SAID blocks).
    fn encode_field(field: &AcdcField<'_, SadBlock<'_>>, buf: &mut Vec<u8>) {
        match field {
            AcdcField::Said(said) => JsonWriter::write_str(buf, &said.to_qb64()),
            AcdcField::Block(block) => buf.extend_from_slice(block.payload().as_bytes()),
        }
    }
}
