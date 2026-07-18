//! The five fixed canonical KERI event grammars (`icp`, `rot`, `ixn`,
//! `dip`, `drt`) — both wire directions in one module.
//!
//! Canonical event JSON is byte-deterministic: compact (no whitespace),
//! spec field order, and values that never require string escaping (qb64,
//! hex, ASCII constants — design §2.3 of the #79 write-up). The strict
//! parser accepts exactly that language, plus JSON integers for
//! `kt`/`nt`/`bt` (keripy `intive=True` emits them; their SAIDs are
//! computed over the integer form, so rejecting them would be a
//! conformance gap). The writer emits the same language straight into the
//! caller's buffer — no intermediate tree — recording the backpatchable
//! slot offsets by construction as it writes, never by re-scanning.
//!
//! Every parsed field is a borrowed `&str`; the `d` (and `i` for
//! `icp`/`dip`) value byte spans are reported so SAID verification can
//! copy the raw once, overwrite the spans with `#`, and hash — the
//! read-path mirror of the write path's `EventLayout` slots.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use core::ops::Range;
use core::str;

use crate::codec::scanner::{Scanner, Spanned};
use crate::codec::threshold::{CountField, ParsedCount, ParsedTholder, ThresholdField};
use crate::codec::{Decode as _, Encode as _, JsonWriter};
use crate::error::SerderError;
use crate::serialize::{EventLayout, EventRef};
use cesr::core::version::{Protocol, SerializationKind, VERSION_STRING_LEN, VersionString};
use keri_events::{Identifier, Ilk, InceptionEvent, InteractionEvent, RotationEvent};

/// A seal object: one of the seven fixed codex shapes, or a verbatim
/// opaque capture of a non-codex anchor.
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedSeal<'a> {
    /// Event digest seal.
    Digest {
        /// SAID digest, qb64.
        d: &'a str,
    },
    /// Merkle tree root seal.
    Root {
        /// Root digest, qb64.
        rd: &'a str,
    },
    /// Delegation source seal.
    Source {
        /// Sequence number, hex.
        s: &'a str,
        /// SAID digest of the delegating event, qb64.
        d: &'a str,
    },
    /// Full key event seal.
    Event {
        /// Identifier prefix, qb64.
        i: &'a str,
        /// Sequence number, hex.
        s: &'a str,
        /// SAID digest, qb64.
        d: &'a str,
    },
    /// Last-establishment-event seal.
    Last {
        /// Identifier prefix, qb64.
        i: &'a str,
    },
    /// Registrar-backer seal.
    Back {
        /// Backer identifier prefix, qb64.
        bi: &'a str,
        /// Metadata digest, qb64.
        d: &'a str,
    },
    /// Typed digest seal.
    Kind {
        /// Digest type tag, qb64 (Verser).
        t: &'a str,
        /// SAID digest, qb64.
        d: &'a str,
    },
    /// Non-codex anchor: the verbatim compact-JSON object span.
    Opaque {
        /// Raw object text.
        raw: &'a str,
    },
}

/// A parsed inception (`icp`) body: borrowed field views plus SAID spans.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedIcp<'a> {
    /// The `d` field: SAID digest, value and byte span.
    pub(crate) said: Spanned<'a>,
    /// The `i` field: identifier prefix, value and byte span.
    pub(crate) prefix: Spanned<'a>,
    /// The `s` field: sequence number, hex.
    pub(crate) sn: &'a str,
    /// The `kt` field: signing threshold.
    pub(crate) threshold: ParsedTholder<'a>,
    /// The `k` field: signing keys, qb64.
    pub(crate) keys: Vec<&'a str>,
    /// The `nt` field: next signing threshold.
    pub(crate) next_threshold: ParsedTholder<'a>,
    /// The `n` field: next key digests, qb64.
    pub(crate) next_keys: Vec<&'a str>,
    /// The `bt` field: witness threshold.
    pub(crate) witness_threshold: ParsedCount<'a>,
    /// The `b` field: witness identifiers, qb64.
    pub(crate) witnesses: Vec<&'a str>,
    /// The `c` field: configuration traits.
    pub(crate) config: Vec<&'a str>,
    /// The `a` field: anchored seals.
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// A parsed delegated inception (`dip`): an inception plus the delegator.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedDip<'a> {
    /// The inception fields shared with `icp`.
    pub(crate) icp: ParsedIcp<'a>,
    /// The `di` field: delegator identifier, qb64.
    pub(crate) delegator: &'a str,
}

/// A parsed rotation (`rot`) or delegated rotation (`drt`) body.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedRot<'a> {
    /// The `d` field: SAID digest, value and byte span.
    pub(crate) said: Spanned<'a>,
    /// The `i` field: identifier prefix, qb64.
    pub(crate) prefix: &'a str,
    /// The `s` field: sequence number, hex.
    pub(crate) sn: &'a str,
    /// The `p` field: prior event SAID, qb64.
    pub(crate) prior: &'a str,
    /// The `kt` field: signing threshold.
    pub(crate) threshold: ParsedTholder<'a>,
    /// The `k` field: signing keys, qb64.
    pub(crate) keys: Vec<&'a str>,
    /// The `nt` field: next signing threshold.
    pub(crate) next_threshold: ParsedTholder<'a>,
    /// The `n` field: next key digests, qb64.
    pub(crate) next_keys: Vec<&'a str>,
    /// The `bt` field: witness threshold.
    pub(crate) witness_threshold: ParsedCount<'a>,
    /// The `br` field: witness removals, qb64.
    pub(crate) witness_removals: Vec<&'a str>,
    /// The `ba` field: witness additions, qb64.
    pub(crate) witness_additions: Vec<&'a str>,
    /// The `a` field: anchored seals.
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// A parsed interaction (`ixn`) body.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedIxn<'a> {
    /// The `d` field: SAID digest, value and byte span.
    pub(crate) said: Spanned<'a>,
    /// The `i` field: identifier prefix, qb64.
    pub(crate) prefix: &'a str,
    /// The `s` field: sequence number, hex.
    pub(crate) sn: &'a str,
    /// The `p` field: prior event SAID, qb64.
    pub(crate) prior: &'a str,
    /// The `a` field: anchored seals.
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// Any parsed event, dispatched on the wire ilk.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedEvent<'a> {
    /// `icp`.
    Inception(ParsedIcp<'a>),
    /// `rot`.
    Rotation(ParsedRot<'a>),
    /// `ixn`.
    Interaction(ParsedIxn<'a>),
    /// `dip`.
    DelegatedInception(ParsedDip<'a>),
    /// `drt`.
    DelegatedRotation(ParsedRot<'a>),
}

impl<'a> ParsedEvent<'a> {
    /// Parse and validate the fixed head `{"v":"<17-byte version string>","t":`
    /// and return the scanner positioned after the ilk value, plus the ilk.
    fn head(raw: &'a [u8]) -> Result<(Scanner<'a>, Spanned<'a>), SerderError> {
        let mut sc = Scanner::new(raw);
        sc.expect("{\"v\":\"")?;
        let vs_start = sc.pos;
        let vs_end = vs_start
            .checked_add(VERSION_STRING_LEN)
            .ok_or(SerderError::InvalidEventLayout("version span overflow"))?;
        let vs_bytes = raw
            .get(vs_start..vs_end)
            .ok_or_else(|| sc.err("17-byte version string"))?;
        let (vs, _) = VersionString::parse(vs_bytes)?;
        if vs.kind() != SerializationKind::Json {
            return Err(SerderError::InvalidVersionString(format!(
                "expected JSON, got {}",
                vs.kind().as_str()
            )));
        }
        let expected_size = usize::try_from(vs.size())
            .map_err(|e| SerderError::InvalidVersionString(e.to_string()))?;
        if expected_size != raw.len() {
            return Err(SerderError::InvalidVersionString(format!(
                "version string size {} does not match actual size {}",
                expected_size,
                raw.len()
            )));
        }
        sc.pos = vs_end;
        sc.expect("\",\"t\":")?;
        let ilk = sc.string()?;
        Ok((sc, ilk))
    }
}

impl<'a> ParsedIcp<'a> {
    fn fields(sc: &mut Scanner<'a>) -> Result<Self, SerderError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?;
        sc.expect(",\"i\":")?;
        let prefix = sc.string()?;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"kt\":")?;
        let threshold = ParsedTholder::decode(sc)?;
        sc.expect(",\"k\":")?;
        let keys = sc.string_array()?;
        sc.expect(",\"nt\":")?;
        let next_threshold = ParsedTholder::decode(sc)?;
        sc.expect(",\"n\":")?;
        let next_keys = sc.string_array()?;
        sc.expect(",\"bt\":")?;
        let witness_threshold = ParsedCount::decode(sc)?;
        sc.expect(",\"b\":")?;
        let witnesses = sc.string_array()?;
        sc.expect(",\"c\":")?;
        let config = sc.string_array()?;
        sc.expect(",\"a\":")?;
        let anchors = sc.delimited_list(ParsedSeal::decode)?;
        Ok(ParsedIcp {
            said,
            prefix,
            sn,
            threshold,
            keys,
            next_threshold,
            next_keys,
            witness_threshold,
            witnesses,
            config,
            anchors,
        })
    }
}

impl<'a> ParsedIcp<'a> {
    fn body(mut sc: Scanner<'a>) -> Result<Self, SerderError> {
        let fields = Self::fields(&mut sc)?;
        sc.expect("}")?;
        sc.finish()?;
        Ok(fields)
    }
}

impl<'a> ParsedDip<'a> {
    fn body(mut sc: Scanner<'a>) -> Result<Self, SerderError> {
        let icp = ParsedIcp::fields(&mut sc)?;
        sc.expect(",\"di\":")?;
        let delegator = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedDip { icp, delegator })
    }
}

impl<'a> ParsedRot<'a> {
    fn body(mut sc: Scanner<'a>) -> Result<Self, SerderError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?;
        sc.expect(",\"i\":")?;
        let prefix = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"p\":")?;
        let prior = sc.string()?.value;
        sc.expect(",\"kt\":")?;
        let threshold = ParsedTholder::decode(&mut sc)?;
        sc.expect(",\"k\":")?;
        let keys = sc.string_array()?;
        sc.expect(",\"nt\":")?;
        let next_threshold = ParsedTholder::decode(&mut sc)?;
        sc.expect(",\"n\":")?;
        let next_keys = sc.string_array()?;
        sc.expect(",\"bt\":")?;
        let witness_threshold = ParsedCount::decode(&mut sc)?;
        sc.expect(",\"br\":")?;
        let witness_removals = sc.string_array()?;
        sc.expect(",\"ba\":")?;
        let witness_additions = sc.string_array()?;
        sc.expect(",\"a\":")?;
        let anchors = sc.delimited_list(ParsedSeal::decode)?;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedRot {
            said,
            prefix,
            sn,
            prior,
            threshold,
            keys,
            next_threshold,
            next_keys,
            witness_threshold,
            witness_removals,
            witness_additions,
            anchors,
        })
    }
}

impl<'a> ParsedIxn<'a> {
    fn body(mut sc: Scanner<'a>) -> Result<Self, SerderError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?;
        sc.expect(",\"i\":")?;
        let prefix = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"p\":")?;
        let prior = sc.string()?.value;
        sc.expect(",\"a\":")?;
        let anchors = sc.delimited_list(ParsedSeal::decode)?;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedIxn {
            said,
            prefix,
            sn,
            prior,
            anchors,
        })
    }
}

impl ParsedEvent<'_> {
    /// On mismatch the error's offset addresses the ilk value's first byte
    /// (inside the quotes) and `expected` carries the bare ilk name — the same
    /// start-offset convention as [`Scanner::expect`].
    fn require_ilk(
        sc: &Scanner<'_>,
        ilk: &Spanned<'_>,
        expected: &'static str,
    ) -> Result<(), SerderError> {
        if ilk.value == expected {
            Ok(())
        } else {
            Err(sc.err_at(ilk.span.start, expected))
        }
    }
}

impl<'a> ParsedEvent<'a> {
    /// Parse any of the five fixed canonical event grammars, dispatched on the
    /// wire `t` (ilk) field.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::NonCanonical`] if the input deviates from the
    /// strict grammar, [`SerderError::InvalidVersionString`] if the version
    /// header is malformed or its size does not match the input length, or
    /// [`SerderError::UnknownIlk`] if `t` is not one of `icp`/`rot`/`ixn`/`dip`/`drt`.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, SerderError> {
        let (sc, ilk) = Self::head(raw)?;
        match ilk.value {
            "icp" => Ok(ParsedEvent::Inception(ParsedIcp::body(sc)?)),
            "rot" => Ok(ParsedEvent::Rotation(ParsedRot::body(sc)?)),
            "ixn" => Ok(ParsedEvent::Interaction(ParsedIxn::body(sc)?)),
            "dip" => Ok(ParsedEvent::DelegatedInception(ParsedDip::body(sc)?)),
            "drt" => Ok(ParsedEvent::DelegatedRotation(ParsedRot::body(sc)?)),
            other => Err(SerderError::UnknownIlk(other.to_owned())),
        }
    }
}

impl<'a> ParsedIcp<'a> {
    /// Parse a strict canonical `icp` body.
    ///
    /// # Errors
    ///
    /// See [`ParsedEvent::parse`]. Additionally returns [`SerderError::NonCanonical`]
    /// if the wire `t` field is not `"icp"`.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, SerderError> {
        let (sc, ilk) = ParsedEvent::head(raw)?;
        ParsedEvent::require_ilk(&sc, &ilk, "icp")?;
        Self::body(sc)
    }
}

impl<'a> ParsedRot<'a> {
    /// Parse a strict canonical `rot` body.
    ///
    /// # Errors
    ///
    /// See [`ParsedEvent::parse`]. Additionally returns [`SerderError::NonCanonical`]
    /// if the wire `t` field is not `"rot"`.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, SerderError> {
        let (sc, ilk) = ParsedEvent::head(raw)?;
        ParsedEvent::require_ilk(&sc, &ilk, "rot")?;
        Self::body(sc)
    }
}

impl<'a> ParsedIxn<'a> {
    /// Parse a strict canonical `ixn` body.
    ///
    /// # Errors
    ///
    /// See [`ParsedEvent::parse`]. Additionally returns [`SerderError::NonCanonical`]
    /// if the wire `t` field is not `"ixn"`.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, SerderError> {
        let (sc, ilk) = ParsedEvent::head(raw)?;
        ParsedEvent::require_ilk(&sc, &ilk, "ixn")?;
        Self::body(sc)
    }
}

impl<'a> ParsedDip<'a> {
    /// Parse a strict canonical `dip` body.
    ///
    /// # Errors
    ///
    /// See [`ParsedEvent::parse`]. Additionally returns [`SerderError::NonCanonical`]
    /// if the wire `t` field is not `"dip"`.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, SerderError> {
        let (sc, ilk) = ParsedEvent::head(raw)?;
        ParsedEvent::require_ilk(&sc, &ilk, "dip")?;
        Self::body(sc)
    }
}

impl<'a> ParsedRot<'a> {
    /// Parse a strict canonical `drt` body.
    ///
    /// # Errors
    ///
    /// See [`ParsedEvent::parse`]. Additionally returns [`SerderError::NonCanonical`]
    /// if the wire `t` field is not `"drt"`.
    pub(crate) fn parse_delegated(raw: &'a [u8]) -> Result<Self, SerderError> {
        let (sc, ilk) = ParsedEvent::head(raw)?;
        ParsedEvent::require_ilk(&sc, &ilk, "drt")?;
        ParsedRot::body(sc)
    }
}

impl EventRef<'_> {
    /// Render one event's canonical JSON body into `buf` (appending),
    /// reporting the backpatchable slot layout. Slots are recorded by
    /// construction as the writer emits them — never by re-scanning.
    pub(crate) fn render(
        &self,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        match self {
            Self::Inception(e) => Self::render_icp(buf, e, said_placeholder, Ilk::Icp, None),
            Self::Rotation(e) => Self::render_rot(buf, e, said_placeholder, Ilk::Rot),
            Self::Interaction(e) => Self::render_ixn(buf, e, said_placeholder),
            Self::DelegatedInception(e) => Self::render_icp(
                buf,
                e.inception(),
                said_placeholder,
                Ilk::Dip,
                Some(e.delegator()),
            ),
            Self::DelegatedRotation(e) => {
                Self::render_rot(buf, e.rotation(), said_placeholder, Ilk::Drt)
            }
        }
    }
}

impl EventRef<'_> {
    /// Write the shared `{"v":"<zero-size vstring>","t":"<ilk>","d":"<placeholder>`
    /// head and return the size slot plus the `d` slot.
    fn write_head(
        buf: &mut Vec<u8>,
        ilk: Ilk,
        placeholder: &str,
        kind: SerializationKind,
    ) -> Result<(Range<usize>, Range<usize>), SerderError> {
        let vs = VersionString::new(Protocol::Keri, 1, 0, kind, 0)?.to_str();
        buf.extend_from_slice(b"{\"v\":\"");
        let vs_start = buf.len();
        buf.extend_from_slice(vs.as_bytes());
        let size_start = vs_start
            .checked_add(10)
            .ok_or(SerderError::InvalidEventLayout("size slot offset overflow"))?;
        let size_end = size_start
            .checked_add(6)
            .ok_or(SerderError::InvalidEventLayout("size slot offset overflow"))?;

        buf.extend_from_slice(b"\",\"t\":");
        JsonWriter::write_str(buf, ilk.code());
        buf.extend_from_slice(b",\"d\":\"");
        let d_start = buf.len();
        buf.extend_from_slice(placeholder.as_bytes());
        let d_end = buf.len();
        buf.push(b'"');
        Ok((size_start..size_end, d_start..d_end))
    }
}

impl EventRef<'_> {
    fn render_icp(
        buf: &mut Vec<u8>,
        e: &InceptionEvent,
        placeholder: &str,
        ilk: Ilk,
        delegator: Option<&Identifier<'_>>,
    ) -> Result<EventLayout, SerderError> {
        let form = e.threshold_form();
        let (size_slot, said_slot) =
            Self::write_head(buf, ilk, placeholder, SerializationKind::Json)?;

        let prefix_slot = match e.prefix() {
            Identifier::SelfAddressing(_) => {
                buf.extend_from_slice(b",\"i\":\"");
                let i_start = buf.len();
                buf.extend_from_slice(placeholder.as_bytes());
                let slot = i_start..buf.len();
                buf.push(b'"');
                Some(slot)
            }
            Identifier::Basic(p) => {
                buf.extend_from_slice(b",\"i\":");
                p.encode(buf);
                None
            }
        };

        buf.extend_from_slice(b",\"s\":");
        JsonWriter::write_str(buf, &e.sn().to_string());
        buf.extend_from_slice(b",\"kt\":");
        ThresholdField {
            threshold: e.threshold(),
            form,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"k\":");
        e.keys().encode(buf);
        buf.extend_from_slice(b",\"nt\":");
        ThresholdField {
            threshold: e.next_threshold(),
            form,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"n\":");
        e.next_keys().encode(buf);
        buf.extend_from_slice(b",\"bt\":");
        CountField {
            toad: e.witness_threshold(),
            form,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"b\":");
        e.witnesses().encode(buf);
        buf.extend_from_slice(b",\"c\":");
        e.config().encode(buf);
        buf.extend_from_slice(b",\"a\":");
        e.anchors().encode(buf);
        if let Some(di) = delegator {
            buf.extend_from_slice(b",\"di\":");
            di.encode(buf);
        }
        buf.push(b'}');

        Ok(EventLayout {
            size: size_slot,
            said: said_slot,
            prefix: prefix_slot,
        })
    }
}

impl EventRef<'_> {
    fn render_rot(
        buf: &mut Vec<u8>,
        e: &RotationEvent,
        placeholder: &str,
        ilk: Ilk,
    ) -> Result<EventLayout, SerderError> {
        let form = e.threshold_form();
        let (size_slot, said_slot) =
            Self::write_head(buf, ilk, placeholder, SerializationKind::Json)?;

        buf.extend_from_slice(b",\"i\":");
        e.prefix().encode(buf);
        buf.extend_from_slice(b",\"s\":");
        JsonWriter::write_str(buf, &e.sn().to_string());
        buf.extend_from_slice(b",\"p\":");
        e.prior_event_said().encode(buf);
        buf.extend_from_slice(b",\"kt\":");
        ThresholdField {
            threshold: e.threshold(),
            form,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"k\":");
        e.keys().encode(buf);
        buf.extend_from_slice(b",\"nt\":");
        ThresholdField {
            threshold: e.next_threshold(),
            form,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"n\":");
        e.next_keys().encode(buf);
        buf.extend_from_slice(b",\"bt\":");
        CountField {
            toad: e.witness_threshold(),
            form,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"br\":");
        e.witness_removals().encode(buf);
        buf.extend_from_slice(b",\"ba\":");
        e.witness_additions().encode(buf);
        buf.extend_from_slice(b",\"a\":");
        e.anchors().encode(buf);
        buf.push(b'}');

        Ok(EventLayout {
            size: size_slot,
            said: said_slot,
            prefix: None,
        })
    }
}

impl EventRef<'_> {
    fn render_ixn(
        buf: &mut Vec<u8>,
        e: &InteractionEvent,
        placeholder: &str,
    ) -> Result<EventLayout, SerderError> {
        let (size_slot, said_slot) =
            Self::write_head(buf, Ilk::Ixn, placeholder, SerializationKind::Json)?;

        buf.extend_from_slice(b",\"i\":");
        e.prefix().encode(buf);
        buf.extend_from_slice(b",\"s\":");
        JsonWriter::write_str(buf, &e.sn().to_string());
        buf.extend_from_slice(b",\"p\":");
        e.prior_event_said().encode(buf);
        buf.extend_from_slice(b",\"a\":");
        e.anchors().encode(buf);
        buf.push(b'}');

        Ok(EventLayout {
            size: size_slot,
            said: said_slot,
            prefix: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Serialize;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::{Prefixer, Saider, Verfer};
    use keri_events::SigningThreshold;
    use keri_events::threshold_form::ThresholdForm;
    use keri_events::toad::Toad;
    use keri_events::{
        ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, InceptionEvent,
        InteractionEvent, RotationEvent, Seal, SequenceNumber,
    };

    #[test]
    fn seal_array_shapes() {
        assert!(
            Scanner::new(b"[]")
                .delimited_list(ParsedSeal::decode)
                .unwrap()
                .is_empty()
        );
        let seals = Scanner::new(b"[{\"d\":\"X\"},{\"i\":\"I\"}]")
            .delimited_list(ParsedSeal::decode)
            .unwrap();
        assert_eq!(seals.len(), 2);
        assert!(matches!(seals[0], ParsedSeal::Digest { d: "X" }));
        assert!(matches!(seals[1], ParsedSeal::Last { i: "I" }));
    }

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verfer() -> Verfer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn probe_icp_bytes() -> Vec<u8> {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: make_saider() }],
            ThresholdForm::HexString,
        );
        event.serialize().unwrap().as_bytes().to_vec()
    }

    fn probe_ixn_bytes() -> Vec<u8> {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(3),
            make_saider(),
            make_saider(),
            vec![],
        );
        event.serialize().unwrap().as_bytes().to_vec()
    }

    fn make_rot() -> RotationEvent<'static> {
        RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(2),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            vec![make_prefixer()],
            Toad::from_wire(1),
            vec![Seal::Digest { d: make_saider() }],
            ThresholdForm::HexString,
        )
    }

    fn probe_rot_bytes() -> Vec<u8> {
        make_rot().serialize().unwrap().as_bytes().to_vec()
    }

    fn probe_dip_bytes() -> Vec<u8> {
        let icp = InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        );
        let delegator: Identifier<'static> = make_prefixer().into();
        let dip = DelegatedInceptionEvent::new(icp, delegator);
        dip.serialize().unwrap().as_bytes().to_vec()
    }

    fn probe_drt_bytes() -> Vec<u8> {
        let drt = DelegatedRotationEvent::new(make_rot());
        drt.serialize().unwrap().as_bytes().to_vec()
    }

    /// Rewrite the six size hex digits (bytes 16..22) to the buffer's actual
    /// length so grammar probes are not masked by the version-size check.
    fn fix_size(raw: &mut [u8]) {
        let size = raw.len();
        let hex = format!("{size:06x}");
        raw[16..22].copy_from_slice(hex.as_bytes());
    }

    #[test]
    fn parse_event_reads_writer_output_icp() {
        let raw = probe_icp_bytes();
        let ParsedEvent::Inception(p) = ParsedEvent::parse(&raw).unwrap() else {
            unreachable!()
        };
        assert_eq!(p.sn, "0");
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.config, vec!["EO"]);
        assert_eq!(p.anchors.len(), 1);
        assert_eq!(p.said.span.len(), 44);
        assert_eq!(
            &raw[p.said.span.clone()],
            p.said.value.as_bytes(),
            "span must address the value bytes in raw"
        );
        assert_eq!(&raw[p.prefix.span.clone()], p.prefix.value.as_bytes());
    }

    #[test]
    fn parse_inception_reads_all_icp_fields() {
        let raw = probe_icp_bytes();
        let p = ParsedIcp::parse(&raw).unwrap();
        assert!(matches!(p.threshold, ParsedTholder::Hex("1")));
        assert!(matches!(p.next_threshold, ParsedTholder::Hex("1")));
        assert_eq!(p.next_keys.len(), 1);
        assert!(matches!(p.witness_threshold, ParsedCount::Hex("1")));
        assert_eq!(p.witnesses.len(), 1);
    }

    #[test]
    fn parse_rotation_reads_all_rot_fields() {
        let raw = probe_rot_bytes();
        let p = ParsedRot::parse(&raw).unwrap();
        assert_eq!(p.sn, "2");
        assert_eq!(&raw[p.said.span.clone()], p.said.value.as_bytes());
        assert!(!p.prefix.is_empty());
        assert!(!p.prior.is_empty());
        assert!(matches!(p.threshold, ParsedTholder::Hex("1")));
        assert_eq!(p.keys.len(), 1);
        assert!(matches!(p.next_threshold, ParsedTholder::Hex("1")));
        assert_eq!(p.next_keys.len(), 1);
        assert!(matches!(p.witness_threshold, ParsedCount::Hex("1")));
        assert_eq!(p.witness_removals.len(), 1);
        assert_eq!(p.witness_additions.len(), 1);
        assert_eq!(p.anchors.len(), 1);
    }

    #[test]
    fn parse_interaction_reads_all_ixn_fields() {
        let raw = probe_ixn_bytes();
        let p = ParsedIxn::parse(&raw).unwrap();
        assert_eq!(p.sn, "3");
        assert_eq!(&raw[p.said.span.clone()], p.said.value.as_bytes());
        assert!(!p.prefix.is_empty());
        assert!(!p.prior.is_empty());
        assert!(p.anchors.is_empty());
    }

    #[test]
    fn parse_delegated_inception_reads_icp_and_delegator() {
        let raw = probe_dip_bytes();
        let p = ParsedDip::parse(&raw).unwrap();
        assert_eq!(p.icp.sn, "0");
        assert!(!p.delegator.is_empty());
    }

    #[test]
    fn parse_delegated_rotation_reads_rot_fields() {
        let raw = probe_drt_bytes();
        let p = ParsedRot::parse_delegated(&raw).unwrap();
        assert_eq!(p.sn, "2");
    }

    #[test]
    fn parse_event_dispatches_every_ilk_variant() {
        match ParsedEvent::parse(&probe_icp_bytes()).unwrap() {
            ParsedEvent::Inception(p) => assert_eq!(p.sn, "0"),
            other => unreachable!("expected Inception, got {other:?}"),
        }
        match ParsedEvent::parse(&probe_rot_bytes()).unwrap() {
            ParsedEvent::Rotation(p) => assert_eq!(p.sn, "2"),
            other => unreachable!("expected Rotation, got {other:?}"),
        }
        match ParsedEvent::parse(&probe_ixn_bytes()).unwrap() {
            ParsedEvent::Interaction(p) => assert_eq!(p.sn, "3"),
            other => unreachable!("expected Interaction, got {other:?}"),
        }
        match ParsedEvent::parse(&probe_dip_bytes()).unwrap() {
            ParsedEvent::DelegatedInception(p) => assert_eq!(p.icp.sn, "0"),
            other => unreachable!("expected DelegatedInception, got {other:?}"),
        }
        match ParsedEvent::parse(&probe_drt_bytes()).unwrap() {
            ParsedEvent::DelegatedRotation(p) => assert_eq!(p.sn, "2"),
            other => unreachable!("expected DelegatedRotation, got {other:?}"),
        }
    }

    #[test]
    fn per_ilk_entry_rejects_wrong_ilk() {
        let raw = probe_ixn_bytes();
        assert!(matches!(
            ParsedRot::parse(&raw),
            Err(SerderError::NonCanonical {
                expected: "rot",
                ..
            })
        ));
    }

    #[test]
    fn unknown_ilk_is_typed() {
        let mut raw = probe_ixn_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"ixn\"").unwrap();
        raw[pos + 1..pos + 4].copy_from_slice(b"xxx");
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::UnknownIlk(ref s)) if s == "xxx"
        ));
    }

    #[test]
    fn whitespace_with_consistent_size_is_non_canonical() {
        // Insert one space after the first comma AND fix the version size so
        // the length check passes — the grammar itself must reject it.
        let raw = probe_ixn_bytes();
        let comma = raw.iter().position(|b| *b == b',').unwrap();
        let mut padded = Vec::with_capacity(raw.len() + 1);
        padded.extend_from_slice(&raw[..=comma]);
        padded.push(b' ');
        padded.extend_from_slice(&raw[comma + 1..]);
        fix_size(&mut padded);
        assert!(matches!(
            ParsedEvent::parse(&padded),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn duplicate_field_is_non_canonical() {
        // Overwrite the `,"i":` key with a second `,"d":` — same length, so
        // the version size stays consistent; the grammar must reject it.
        let mut raw = probe_ixn_bytes();
        let pos = raw.windows(5).position(|w| w == b",\"i\":").unwrap();
        raw[pos..pos + 5].copy_from_slice(b",\"d\":");
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn reordered_fields_are_non_canonical() {
        // Swap the `"s"` and `"p"` key names (same length) in an ixn.
        let mut raw = probe_ixn_bytes();
        let s_pos = raw.windows(5).position(|w| w == b",\"s\":").unwrap();
        let p_pos = raw.windows(5).position(|w| w == b",\"p\":").unwrap();
        raw[s_pos + 2] = b'p';
        raw[p_pos + 2] = b's';
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn escape_in_value_is_non_canonical() {
        // Replace sn value "3" with an escaped form and fix the size field.
        let raw = probe_ixn_bytes();
        let pos = raw.windows(8).position(|w| w == b",\"s\":\"3\"").unwrap();
        let mut mutated = Vec::with_capacity(raw.len() + 5);
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b",\"s\":\"\\u0033\"");
        mutated.extend_from_slice(&raw[pos + 8..]);
        fix_size(&mut mutated);
        assert!(matches!(
            ParsedEvent::parse(&mutated),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_non_canonical() {
        let mut raw = probe_ixn_bytes();
        raw.push(b'X');
        fix_size(&mut raw);
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn length_lie_is_still_invalid_version_string() {
        // Without fixing the size field, a padded input fails the size check
        // first — preserving the #139 defence.
        let mut raw = probe_ixn_bytes();
        raw.push(b'X');
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::InvalidVersionString(_))
        ));
    }

    #[test]
    fn every_strict_prefix_is_rejected_without_panicking() {
        let raw = probe_icp_bytes();
        for cut in 0..raw.len() {
            assert!(
                ParsedEvent::parse(&raw[..cut]).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    #[test]
    fn multibyte_utf8_in_version_window_is_rejected_not_panicking() {
        // 23 bytes: char 'é' straddles the proto/major boundary at offset 4
        // of the version window — previously panicked inside
        // VersionString::parse via non-char-boundary &str slicing.
        assert!(ParsedEvent::parse(b"{\"v\":\"KER\xC3\xA9AJSONAAAAAA_").is_err());
    }

    #[test]
    fn wrong_first_byte_is_non_canonical() {
        assert!(matches!(
            ParsedEvent::parse(b"[\"v\":\"KERI10JSON000017_"),
            Err(SerderError::NonCanonical { offset: 0, .. })
        ));
    }

    #[test]
    fn oversized_ilk_is_rejected() {
        let raw = probe_ixn_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"ixn\"").unwrap();
        let mut mutated = Vec::with_capacity(raw.len() + 1);
        mutated.extend_from_slice(&raw[..pos + 4]);
        mutated.push(b'X');
        mutated.extend_from_slice(&raw[pos + 4..]);
        fix_size(&mut mutated);
        assert!(matches!(
            ParsedEvent::parse(&mutated),
            Err(SerderError::UnknownIlk(ref s)) if s == "ixnX"
        ));
        assert!(matches!(
            ParsedIxn::parse(&mutated),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn delegator_field_on_icp_is_rejected() {
        // icp grammar ends at the anchors; a trailing "di" is non-canonical.
        let mut raw = probe_dip_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"dip\"").unwrap();
        raw[pos + 1..pos + 4].copy_from_slice(b"icp");
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn missing_delegator_on_dip_is_rejected() {
        // ilk says dip but the body is an icp body — fails at `,"di":`.
        let mut raw = probe_icp_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"icp\"").unwrap();
        raw[pos + 1..pos + 4].copy_from_slice(b"dip");
        assert!(matches!(
            ParsedEvent::parse(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn corrupt_version_terminator_seam_is_rejected() {
        let mut raw = probe_ixn_bytes();
        // byte 23 is the closing quote of the version string value
        raw[23] = b'X';
        assert!(ParsedEvent::parse(&raw).is_err());
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// A scanner over untrusted bytes must never panic, whatever the
            /// input — every failure is a typed error.
            #[test]
            fn scanner_never_panics(input in proptest::collection::vec(any::<u8>(), 0..64)) {
                let _ = Scanner::new(&input).string();
                let _ = Scanner::new(&input).integer();
                let mut sc = Scanner::new(&input);
                let _ = sc.expect("{\"v\":\"");
                let _ = sc.finish();
                let _ = Scanner::new(&input).string_array();
                let _ = ParsedTholder::decode(&mut Scanner::new(&input));
                let _ = ParsedCount::decode(&mut Scanner::new(&input));
                let _ = ParsedSeal::decode(&mut Scanner::new(&input));
                let _ = Scanner::new(&input).delimited_list(ParsedSeal::decode);
                let _ = ParsedEvent::parse(&input);
            }

            /// Load-bearing invariant: an accepted string's span addresses
            /// exactly its value bytes in the raw input (SAID verification
            /// overwrites raw[span] later).
            #[test]
            fn accepted_string_span_addresses_value(input in proptest::collection::vec(any::<u8>(), 0..64)) {
                if let Ok(s) = Scanner::new(&input).string() {
                    prop_assert_eq!(&input[s.span.clone()], s.value.as_bytes());
                }
            }
        }
    }
}
#[cfg(test)]
mod write_tests {
    use super::*;
    use crate::event_strategies::{
        IdSpec, build_icp, build_identifier, build_ixn, build_rot, icp_strategy, ixn_strategy,
        prefixer, rot_strategy, saider,
    };
    use crate::serialize::SerializedEvent;
    use crate::traits::{Deserialize, Serialize};
    use cesr::core::matter::code::CesrCode;
    use cesr::core::matter::matter::Matter;
    use keri_events::ConfigTrait;
    use keri_events::KeriEvent;
    use keri_events::Seal;
    use keri_events::SigningThreshold;
    use keri_events::sequence::SequenceNumber;
    use keri_events::threshold_form::ThresholdForm;
    use keri_events::toad::Toad;
    use keri_events::{DelegatedInceptionEvent, DelegatedRotationEvent, Identifier};
    use proptest::prelude::*;
    use serde_json::{Value, json};

    // ------------------------------------------------------------------
    // Structural oracle: an INDEPENDENT rendering of each event as a
    // serde_json::Value tree, built from domain fields in test code. The
    // writer's output must parse (via serde_json — no shared code with the
    // writer) to exactly this tree. The tree construction does reuse the
    // shared value encoders — qb64 (`Matter::to_qb64`/`identifier_qb64`),
    // `SequenceNumber`'s hex `Display`, and
    // `ConfigTrait::code()` — all core/keri-tested elsewhere, none part of
    // this writer. `fraction` deliberately re-states the
    // weight-rendering rule rather than calling `weight_to_string`; that
    // duplication IS the oracle. Byte-level canonical form (field order,
    // framing) is asserted by the fixpoint tests
    // (`back_kind_and_opaque_seals_render_verbatim_and_fixpoint` here, the
    // `*_strict_equals_reference` suite in deserialize.rs) and keripy
    // corpora, which Value equality cannot see.
    // ------------------------------------------------------------------

    fn fraction(num: u64, den: u64) -> String {
        if den != 0 && (num == 0 || num == den) {
            format!("{}", num / den)
        } else {
            format!("{num}/{den}")
        }
    }

    fn hex_tholder(t: &SigningThreshold) -> Value {
        match t {
            SigningThreshold::Simple(n) => Value::String(format!("{n:x}")),
            SigningThreshold::Weighted(w) => {
                let clauses: Vec<Value> = w
                    .clauses()
                    .map(|clause| {
                        Value::Array(
                            clause
                                .iter()
                                .map(|(n, d)| Value::String(fraction(*n, *d)))
                                .collect(),
                        )
                    })
                    .collect();
                match <[Value; 1]>::try_from(clauses) {
                    Ok([single]) => single,
                    Err(multiple) => Value::Array(multiple),
                }
            }
        }
    }

    fn qb64_values<C: CesrCode>(matters: &[Matter<'_, C>]) -> Value {
        Value::Array(matters.iter().map(|m| Value::String(m.to_qb64())).collect())
    }

    fn identifier_qb64(id: &Identifier<'_>) -> String {
        match id {
            Identifier::Basic(p) => p.to_qb64(),
            Identifier::SelfAddressing(s) => s.to_qb64(),
        }
    }

    fn seal_value(seal: &Seal) -> Value {
        match seal {
            Seal::Digest { d } => json!({"d": d.to_qb64()}),
            Seal::Root { rd } => json!({"rd": rd.to_qb64()}),
            Seal::Source { s, d } => json!({"s": s.to_string(), "d": d.to_qb64()}),
            Seal::Event { i, s, d } => {
                json!({"i": i.to_qb64(), "s": s.to_string(), "d": d.to_qb64()})
            }
            Seal::Last { i } => json!({"i": i.to_qb64()}),
            Seal::Back { bi, d } => json!({"bi": bi.to_qb64(), "d": d.to_qb64()}),
            Seal::Kind { t, d } => json!({"t": t.to_qb64(), "d": d.to_qb64()}),
            Seal::Opaque(raw) => serde_json::from_str(raw.as_str())
                .expect("OpaqueSeal payloads are valid JSON by construction"),
        }
    }

    fn seal_values(seals: &[Seal]) -> Value {
        Value::Array(seals.iter().map(seal_value).collect())
    }

    // `v`, `d`, and (for double-SAID events) `i` are backpatched by the
    // orchestration, so they are taken from the output rather than the
    // event; the circularity is closed by the dedicated size assertion in
    // each proptest and SAID verification in the fixpoint tests
    // (`back_kind_and_opaque_seals_render_verbatim_and_fixpoint`, plus the
    // `*_strict_equals_reference` suite in deserialize.rs).
    fn expected_icp_tree(e: &InceptionEvent, out: &SerializedEvent, ilk: &str) -> Value {
        let prefix = match e.prefix() {
            Identifier::SelfAddressing(_) => out.said().to_qb64(),
            Identifier::Basic(p) => p.to_qb64(),
        };
        json!({
            "v": format!("KERI10JSON{:06x}_", out.size()),
            "t": ilk,
            "d": out.said().to_qb64(),
            "i": prefix,
            "s": e.sn().to_string(),
            "kt": hex_tholder(e.threshold()),
            "k": qb64_values(e.keys()),
            "nt": hex_tholder(e.next_threshold()),
            "n": qb64_values(e.next_keys()),
            "bt": format!("{:x}", e.witness_threshold().value()),
            "b": qb64_values(e.witnesses()),
            "c": Value::Array(
                e.config().iter().map(|c| Value::String(c.code().to_owned())).collect()
            ),
            "a": seal_values(e.anchors()),
        })
    }

    fn expected_rot_tree(e: &RotationEvent, out: &SerializedEvent, ilk: &str) -> Value {
        json!({
            "v": format!("KERI10JSON{:06x}_", out.size()),
            "t": ilk,
            "d": out.said().to_qb64(),
            "i": identifier_qb64(e.prefix()),
            "s": e.sn().to_string(),
            "p": e.prior_event_said().to_qb64(),
            "kt": hex_tholder(e.threshold()),
            "k": qb64_values(e.keys()),
            "nt": hex_tholder(e.next_threshold()),
            "n": qb64_values(e.next_keys()),
            "bt": format!("{:x}", e.witness_threshold().value()),
            "br": qb64_values(e.witness_removals()),
            "ba": qb64_values(e.witness_additions()),
            "a": seal_values(e.anchors()),
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn icp_output_matches_independent_tree(spec in icp_strategy()) {
            let event = build_icp(spec);
            let out = event.serialize().unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_icp_tree(&event, &out, "icp"));
        }

        #[test]
        fn rot_output_matches_independent_tree(spec in rot_strategy()) {
            let event = build_rot(spec);
            let out = event.serialize().unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_rot_tree(&event, &out, "rot"));
        }

        #[test]
        fn ixn_output_matches_independent_tree(spec in ixn_strategy()) {
            let event = build_ixn(spec);
            let out = event.serialize().unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            let expected = json!({
                "v": format!("KERI10JSON{:06x}_", out.size()),
                "t": "ixn",
                "d": out.said().to_qb64(),
                "i": identifier_qb64(event.prefix()),
                "s": event.sn().to_string(),
                "p": event.prior_event_said().to_qb64(),
                "a": seal_values(event.anchors()),
            });
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn dip_output_matches_independent_tree(
            spec in icp_strategy(),
            delegator in any::<IdSpec>(),
        ) {
            let dip = DelegatedInceptionEvent::new(build_icp(spec), build_identifier(delegator));
            let out = dip.serialize().unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            let mut expected = expected_icp_tree(dip.inception(), &out, "dip");
            expected.as_object_mut().unwrap().insert(
                "di".to_owned(),
                Value::String(identifier_qb64(dip.delegator())),
            );
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn drt_output_matches_independent_tree(spec in rot_strategy()) {
            let drt = DelegatedRotationEvent::new(build_rot(spec));
            let out = drt.serialize().unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_rot_tree(drt.rotation(), &out, "drt"));
        }

        #[test]
        fn escaper_matches_serde_json_arbitrary_unicode(s in any::<String>()) {
            // any::<String>() reaches control characters and unpaired-surrogate
            // -adjacent code points that the ".*" regex strategy under-samples.
            let mut buf = Vec::new();
            JsonWriter::write_str(&mut buf, &s);
            let expected =
                serde_json::to_string(&serde_json::Value::String(s.clone())).unwrap();
            prop_assert_eq!(core::str::from_utf8(&buf).unwrap(), expected.as_str());
        }

        #[test]
        fn escaper_matches_serde_json(s in ".*") {
            let mut buf = Vec::new();
            JsonWriter::write_str(&mut buf, &s);
            let expected =
                serde_json::to_string(&serde_json::Value::String(s.clone())).unwrap();
            prop_assert_eq!(core::str::from_utf8(&buf).unwrap(), expected.as_str());
        }
    }

    #[test]
    fn escaper_covers_every_escape_class() {
        // One deterministic probe per escape class: quote, backslash, the
        // five short escapes, \u00xx fallbacks (NUL, 0x1F), the unescaped
        // DEL boundary (0x7F), and multi-byte UTF-8 passthrough.
        let s = "q\" b\\ \u{8}\t\n\u{c}\r \u{0}\u{1f}\u{7f} héllo → 日本";
        let mut buf = Vec::new();
        JsonWriter::write_str(&mut buf, s);
        let expected = serde_json::to_string(&serde_json::Value::String(s.to_owned())).unwrap();
        assert_eq!(core::str::from_utf8(&buf).unwrap(), expected);
    }

    #[test]
    fn render_into_prefilled_buffer_reports_absolute_slots() {
        let event = build_ixn(((true, [0; 32]), 1, [1; 32], [2; 32], vec![]));
        let placeholder = "#".repeat(44);
        let mut buf = b"JUNK".to_vec();
        let layout = EventRef::Interaction(&event)
            .render(&placeholder, &mut buf)
            .unwrap();
        assert_eq!(&buf[..4], b"JUNK", "render must append, not overwrite");
        assert_eq!(&buf[layout.size], b"000000");
        assert_eq!(&buf[layout.said], placeholder.as_bytes());
        assert!(layout.prefix.is_none(), "ixn is single-SAID");
    }

    // The read path is now the strict canonical parser (#142); the assertion
    // is unchanged — the writer's output must still SAID-verify through it.
    #[test]
    fn output_verifies_through_unchanged_read_path() {
        let event = InceptionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            SequenceNumber::new(0),
            saider([1; 32]),
            vec![prefixer([2; 32])],
            SigningThreshold::Simple(1),
            vec![saider([3; 32])],
            SigningThreshold::Simple(1),
            vec![prefixer([4; 32])],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: saider([5; 32]) }],
            ThresholdForm::HexString,
        );
        let out = event.serialize().unwrap();
        let parsed = InceptionEvent::deserialize(out.as_bytes()).unwrap();
        assert_eq!(
            parsed.said().to_qb64(),
            out.said().to_qb64(),
            "rendered event must SAID-verify through the strict canonical read path"
        );
    }

    #[test]
    fn back_kind_and_opaque_seals_render_verbatim_and_fixpoint() {
        use crate::traits::Serialize;
        use cesr::core::matter::builder::MatterBuilder;
        use cesr::core::matter::code::VerserCode;
        use keri_events::OpaqueSeal;

        // The reviewer counterexample: a Value round-trip rewrites `1e2` as
        // `100.0` and the `é` escape as a raw `é` — the writer must emit the
        // stored payload untouched, and the strict reader must hand it
        // back byte-identical.
        let payload = "{\"x\":1e2,\"u\":\"\\u00e9\"}";
        let verser = MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<VerserCode>()
            .unwrap()
            .into_static();
        let event = InteractionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            SequenceNumber::new(1),
            saider([1; 32]),
            saider([2; 32]),
            vec![
                Seal::Back {
                    bi: prefixer([3; 32]),
                    d: saider([4; 32]),
                },
                Seal::Kind {
                    t: verser,
                    d: saider([5; 32]),
                },
                Seal::Opaque(OpaqueSeal::new_unchecked(payload.to_owned())),
            ],
        );
        let out = event.serialize().unwrap();
        let text = core::str::from_utf8(out.as_bytes()).unwrap();
        assert!(
            text.contains(payload),
            "opaque payload must be emitted verbatim: {text}"
        );
        let parsed = KeriEvent::deserialize(out.as_bytes()).unwrap();
        let again = parsed.serialize().unwrap();
        assert_eq!(out.as_bytes(), again.as_bytes());
    }
}
