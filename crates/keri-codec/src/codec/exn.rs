//! Strict wire scanning and canonical rendering for the exn envelope.
//!
//! Mirrors `codec::acdc`: a borrowed span parser over the fixed v1 field
//! order, verification through the generic [`crate::SadCodes`] machinery,
//! and a render side that emits keripy's exact bytes (embeds and `a`-block
//! payloads verbatim).

use core::ops::Range;

use crate::codec::scanner::Scanner;
use crate::codec::{Encode, JsonWriter};
use crate::error::{CodecError, InternalError, VersionGrammarError};
use crate::said::{SadCodes, infer_digest_code};
use alloc::{
    borrow::{Cow, ToOwned},
    format,
    vec::Vec,
};
use cesr::core::matter::code::DigestCode;
use cesr::core::version::{Protocol, SerializationKind, VERSION_STRING_LEN, VersionString};
use keri_events::MessageType;
use keri_events::acdc::SadBlock;

use crate::exn::{Exn, ExnAttributes, ExnEmbeds};

/// A scanned exn body — the strict wire-view of a v1 exchange envelope.
/// Every field is a borrowed span; lift to domain types happens after SAID
/// verification (the [`Field`](crate::codec::field::Field) pipeline).
#[derive(Debug)]
pub(crate) struct ParsedExn<'a> {
    /// The envelope's SAID (`d`).
    pub(crate) said: &'a str,
    /// Sender identifier (`i`).
    pub(crate) issuer: &'a str,
    /// Receiver identifier (`rp`) — `None` for the wire `""` form.
    pub(crate) reply_to: Option<&'a str>,
    /// Prior exchange SAID (`p`) — `None` for the wire `""` form.
    pub(crate) prior: Option<&'a str>,
    /// Creation timestamp (`dt`).
    pub(crate) datetime: &'a str,
    /// Route (`r`).
    pub(crate) route: &'a str,
    /// Modifiers map (`q`) — canonical object span.
    pub(crate) modifiers: &'a str,
    /// Attributes (`a`) — payload-map span or the ESSR SAID string.
    pub(crate) attributes: ExnAttributeSpan<'a>,
    /// Embeds (`e`) — absent, empty, or the SAIDified per-label map.
    pub(crate) embeds: ExnEmbedsSpan<'a>,
}

/// One `a` (attributes) value as scanned: the ESSR SAID string form or the
/// payload-map object span.
#[derive(Debug)]
pub(crate) enum ExnAttributeSpan<'a> {
    Said(&'a str),
    Block(&'a str),
}

/// The `e` (embeds) value as scanned, in its three wire forms.
#[derive(Debug)]
pub(crate) enum ExnEmbedsSpan<'a> {
    /// The `e` key is absent (`core.exchange`).
    Absent,
    /// The wire `e` is `{}` (`specialExchange`, no embeds).
    Empty,
    /// The embeds map: entries in wire order plus the map's own SAID
    /// (pinned keripy law — `d` is the map's last key). `map` carries the
    /// full canonical map bytes so SAID verification runs over exactly what
    /// was scanned, not a reconstruction.
    Map {
        map: &'a str,
        said: &'a str,
        entries: Vec<(&'a str, &'a str)>,
    },
}

impl<'a> ParsedExn<'a> {
    /// The envelope's digestive-field configuration: the single `d` slot
    /// under the SAID's own wire derivation code. Mirrors
    /// `TelSadConfig::tel_sad_config` and `ParsedAcdc::sad_config` — the
    /// static shape can never violate `SadCodes`' capacity or label rules,
    /// so a rejection reports as the internal layout error it would be.
    ///
    /// # Errors
    ///
    /// [`InternalError::EventLayout`] if `SadCodes` rejects the single-slot
    /// configuration (a broken invariant, not wire input).
    pub(crate) fn sad_config(code: DigestCode) -> Result<crate::SadCodes, CodecError> {
        crate::SadCodes::from_pairs(&[("d", code)]).map_err(|_| {
            InternalError::EventLayout("static exn SAID configuration rejected").into()
        })
    }

    /// Verify the embeds map's own SAID and every embedded SAD's own
    /// top-level SAID.
    ///
    /// keripy leaves embedded-SAD checks to the consumer; the codec enforces
    /// them at the read boundary so a caller can trust every SAID it reads:
    /// the embeds map's `d` binds the per-label map, and each embedded
    /// message is a SAD in its own right whose `d` must verify under its
    /// own wire code.
    ///
    /// # Errors
    ///
    /// [`SaidError::SaidMismatch`](crate::SaidError) when any digest does
    /// not verify; [`InternalError::EventLayout`] for configuration
    /// breakage.
    pub(crate) fn verify_embeds(&self) -> Result<(), CodecError> {
        let ExnEmbedsSpan::Map { map, said, entries } = &self.embeds else {
            return Ok(());
        };
        // The embeds map's own `d` — a bare map (no version string), which
        // the generic machinery verifies without a size slot.
        let code = infer_digest_code(said)?;
        let config: crate::SadCodes = crate::SadCodes::from_pairs(&[("d", code)])
            .map_err(|_| InternalError::EventLayout("embeds map SAID configuration rejected"))?;
        config.verify(map.as_bytes()).map(|_| ())?;
        for (_, payload) in entries {
            // Each embedded message is a SAD in its own right: verify its
            // own top-level SAID under its own code (a shared owner —
            // `SadCodes::verify_nested_block` — with the ACDC block path).
            SadCodes::verify_nested_block(payload.as_bytes())?;
        }
        Ok(())
    }

    /// Parse and validate one exn body.
    ///
    /// # Errors
    ///
    /// [`DeserializeError::NonCanonical`] for any deviation from the fixed
    /// field order, version grammar, or canonical value grammar; a missing
    /// `e`-map `d` is rejected where it should have appeared.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, CodecError> {
        let mut sc = Scanner::new(raw);
        Self::head(&mut sc)?;
        let said = sc.string()?;
        sc.expect(",\"i\":")?;
        let issuer = sc.string()?;
        sc.expect(",\"rp\":")?;
        let reply_to = sc.string()?;
        sc.expect(",\"p\":")?;
        let prior = sc.string()?;
        sc.expect(",\"dt\":")?;
        let datetime = sc.string()?;
        sc.expect(",\"r\":")?;
        let route = sc.string()?;
        sc.expect(",\"q\":")?;
        let q_span = sc.object_value_span()?;
        let modifiers = Self::span_str(&sc, q_span)?;
        sc.expect(",\"a\":")?;
        let attributes = Self::attribute_span(&mut sc)?;
        let embeds = if sc.take_lit(",\"e\":") {
            Self::embeds_span(&mut sc)?
        } else {
            ExnEmbedsSpan::Absent
        };
        sc.expect("}")?;

        Ok(Self {
            said: said.value,
            issuer: issuer.value,
            reply_to: Self::optional_str(reply_to.value),
            prior: Self::optional_str(prior.value),
            datetime: datetime.value,
            route: route.value,
            modifiers,
            attributes,
            embeds,
        })
    }

    /// Scan and validate the fixed head `{"v":"<17-byte KERI JSON vstring>","t":"exn","d":`.
    ///
    /// The protocol must be `KERI` (the envelope is a `SerderKERI` event)
    /// and the serialization JSON. The `d` value's opening quote is left
    /// for the [`Scanner::string`] call that follows — same as the event
    /// head, which stops after `"t":`. The vstring's declared size is
    /// checked later by the generic `SadCodes::verify` — same as the ACDC
    /// path.
    fn head(sc: &mut Scanner<'a>) -> Result<(), CodecError> {
        sc.expect("{\"v\":\"")?;
        let vs_start = sc.pos;
        let vs_end = vs_start
            .checked_add(VERSION_STRING_LEN)
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
        if vs.proto() != Protocol::Keri {
            return Err(VersionGrammarError::InvalidVersionString(format!(
                "expected KERI protocol, got {}",
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
        sc.expect("\",\"t\":\"exn\",\"d\":")?;
        Ok(())
    }

    /// A required field's optional semantics: the wire `""` form means
    /// absent. keripy always emits the `rp` and `p` keys.
    const fn optional_str(value: &'a str) -> Option<&'a str> {
        if value.is_empty() { None } else { Some(value) }
    }

    /// A canonical object span as a `&str` — the scanner guarantees
    /// canonical JSON, so the UTF-8 conversion cannot fail for any parsed
    /// span; a failure is the internal layout error it would be.
    fn span_str(sc: &Scanner<'a>, span: Range<usize>) -> Result<&'a str, CodecError> {
        core::str::from_utf8(
            sc.input
                .get(span)
                .ok_or(InternalError::EventLayout("object span out of bounds"))?,
        )
        .map_err(|_| InternalError::EventLayout("object span is not UTF-8").into())
    }

    /// The `a` (attributes) value: a quoted string span (the ESSR SAID
    /// form) or a canonical object span (the payload map).
    fn attribute_span(sc: &mut Scanner<'a>) -> Result<ExnAttributeSpan<'a>, CodecError> {
        match sc.peek() {
            Some(b'"') => Ok(ExnAttributeSpan::Said(sc.string()?.value)),
            Some(b'{') => {
                let span: Range<usize> = sc.object_value_span()?;
                Ok(ExnAttributeSpan::Block(Self::span_str(sc, span)?))
            }
            _ => Err(sc.err("SAID string or JSON object").into()),
        }
    }

    /// The `e` (embeds) value: `{}`, or the embeds map scanned in wire
    /// order with its own `d` required as the last key.
    fn embeds_span(sc: &mut Scanner<'a>) -> Result<ExnEmbedsSpan<'a>, CodecError> {
        let span: Range<usize> = sc.object_value_span()?;
        let map = Self::span_str(sc, span)?;
        if map == "{}" {
            return Ok(ExnEmbedsSpan::Empty);
        }
        let mut sub = Scanner::new(map.as_bytes());
        sub.expect("{")?;
        let mut entries = Vec::new();
        loop {
            let key = sub.string()?;
            sub.expect(":")?;
            if key.value == "d" {
                // Pinned keripy law: the map's own SAID is the last key.
                let said = sub.string()?;
                sub.expect("}")?;
                return Ok(ExnEmbedsSpan::Map {
                    map,
                    said: said.value,
                    entries,
                });
            }
            let value: Range<usize> = sub.object_value_span()?;
            entries.push((key.value, Self::span_str(&sub, value)?));
            if sub.take_lit(",") {
                continue;
            }
            // A map without its own `d` — keripy always appends it.
            return Err(sub.err_at(sub.pos, ",\"d\":").into());
        }
    }
}

/// The write-side view of an exn body: render one route's canonical JSON.
///
/// The vstring carries a zero size (`KERI10JSON000000_`); the generic SAID
/// orchestration backpatches it before digesting. The `a` payload map and
/// every embed render verbatim — their payloads are already canonical JSON
/// (SAIDified by whoever built them), and re-rendering them would not be
/// byte-guaranteed.
pub(crate) struct ExnBodyRef<'a>(pub(crate) &'a Exn<'a>);

impl ExnBodyRef<'_> {
    /// The digest code of the envelope's `d` field — the derivation code
    /// for the SAID splice. Builders pin keripy's default
    /// (`DigestCode::Blake3_256`, the `Saider.saidify` default); parsed
    /// envelopes carry their wire code.
    pub(crate) const fn said_code(&self) -> DigestCode {
        *self.0.said().as_matter().code()
    }

    /// Render the body into `buf` (appending): the shared
    /// `{"v":"<zero-size>","t":"exn","d":"<placeholder>` head, then the
    /// fixed v1 field order `i,rp,p,dt,r,q,a[,e]`. Returns the byte ranges
    /// of the backpatchable slots: the version string's size field and the
    /// outer SAID — both spliced by the [`crate::Serialize`] orchestration
    /// (size first, then the digest over the size-patched body).
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for version-grammar failures, or
    /// [`InternalError::EventLayout`] if a `Map` embeds value carries no
    /// entries (unrepresentable through the builders and parser).
    pub(crate) fn render(
        &self,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<ExnLayout, CodecError> {
        let (size, said) = crate::serialize::EventRef::write_head(
            buf,
            MessageType::Exn,
            said_placeholder,
            SerializationKind::Json,
        )?;

        buf.extend_from_slice(b",\"i\":");
        self.0.issuer().encode(buf);
        buf.extend_from_slice(b",\"rp\":");
        match self.0.reply_to() {
            Some(reply_to) => reply_to.encode(buf),
            None => JsonWriter::write_str(buf, ""),
        }
        buf.extend_from_slice(b",\"p\":");
        match self.0.prior() {
            Some(prior) => JsonWriter::write_str(buf, &prior.to_qb64()),
            None => JsonWriter::write_str(buf, ""),
        }
        buf.extend_from_slice(b",\"dt\":");
        JsonWriter::write_str(buf, self.0.datetime());
        buf.extend_from_slice(b",\"r\":");
        JsonWriter::write_str(buf, self.0.route());
        buf.extend_from_slice(b",\"q\":");
        buf.extend_from_slice(self.0.modifiers().payload().as_bytes());
        buf.extend_from_slice(b",\"a\":");
        match self.0.attributes() {
            ExnAttributes::Said(attr_said) => JsonWriter::write_str(buf, &attr_said.to_qb64()),
            ExnAttributes::Block(block) => buf.extend_from_slice(block.payload().as_bytes()),
        }
        match self.0.embeds() {
            ExnEmbeds::Absent => {}
            ExnEmbeds::Empty => buf.extend_from_slice(b",\"e\":{}"),
            ExnEmbeds::Map {
                said: embeds_said,
                entries,
            } => {
                buf.extend_from_slice(b",\"e\":{");
                for (index, (label, block)) in entries.iter().enumerate() {
                    if index > 0 {
                        buf.push(b',');
                    }
                    JsonWriter::write_str(buf, label.as_ref());
                    buf.push(b':');
                    buf.extend_from_slice(block.payload().as_bytes());
                }
                // The pinned keripy order: entries first, the map's own `d`
                // last.
                buf.extend_from_slice(b",\"d\":");
                JsonWriter::write_str(buf, &embeds_said.to_qb64());
                buf.push(b'}');
            }
        }
        buf.push(b'}');
        Ok(ExnLayout { size, said })
    }
}

/// The byte ranges of the two backpatchable slots inside a rendered exn
/// body, as reported by [`ExnBodyRef::render`].
pub(crate) struct ExnLayout {
    /// The version string's six-hex size field.
    pub(crate) size: Range<usize>,
    /// The outer SAID placeholder in the `d` field.
    pub(crate) said: Range<usize>,
}

impl<'a> ParsedExn<'a> {
    /// Build the typed envelope from its scanned spans.
    ///
    /// # Errors
    ///
    /// [`DeserializeError`] when a CESR field fails to decode; the embeds map
    /// variant is unreachable for an empty scan (the scanner classifies `{}` as
    /// [`ExnEmbedsSpan::Empty`]).
    pub(crate) fn build(&self) -> Result<Exn<'a>, CodecError> {
        use crate::codec::field::Field;
        use keri_events::primitive::Said;

        // `Identifier` is re-exported from the keri-events root, not
        // `primitive` — the crate's own split.
        use keri_events::Identifier;

        let said = Field::new("d", self.said).decode::<Said>()?;
        let issuer = Field::new("i", self.issuer).decode::<Identifier>()?;
        let reply_to = self
            .reply_to
            .map(|value| Field::new("rp", value).decode::<Identifier>())
            .transpose()?;
        let prior = self
            .prior
            .map(|value| Field::new("p", value).decode::<Said>())
            .transpose()?;
        let attributes = match &self.attributes {
            ExnAttributeSpan::Said(value) => {
                ExnAttributes::Said(Field::new("a", *value).decode::<Said>()?)
            }
            ExnAttributeSpan::Block(payload) => {
                ExnAttributes::Block(SadBlock::new(Cow::Borrowed(*payload)))
            }
        };
        let embeds = match &self.embeds {
            ExnEmbedsSpan::Absent => ExnEmbeds::Absent,
            ExnEmbedsSpan::Empty => ExnEmbeds::Empty,
            ExnEmbedsSpan::Map {
                map: _,
                said: said_span,
                entries,
            } => ExnEmbeds::Map {
                said: Field::new("d", *said_span).decode::<Said>()?,
                entries: entries
                    .iter()
                    .map(|(label, payload)| {
                        (
                            Cow::Borrowed(*label),
                            SadBlock::new(Cow::Borrowed(*payload)),
                        )
                    })
                    .collect(),
            },
        };
        Ok(Exn::new(
            said,
            issuer,
            reply_to,
            prior,
            Cow::Borrowed(self.datetime),
            Cow::Borrowed(self.route),
            SadBlock::new(Cow::Borrowed(self.modifiers)),
            attributes,
            embeds,
        ))
    }
}
