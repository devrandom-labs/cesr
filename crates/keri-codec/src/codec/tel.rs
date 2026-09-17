//! The TEL (Transaction Event Log) wire grammar — both directions in one
//! place.
//!
//! Write form: keripy's registry-event factories at the pin
//! (`src/keri/vdr/eventing.py:37-445`, keripy `de59bc7d`) render six fixed
//! canonical-JSON bodies; [`TelBodyRef::render`] reproduces those bytes
//! exactly, with placeholder slots where the SAID splices in. Read form:
//! strict single-pass scanners in the same field order — any deviation is a
//! typed [`DeserializeError::NonCanonical`].
//!
//! The SAID lifecycle (dummy → size-patch → digest → splice; verify) is NOT
//! here: it is the generic [`SadCodes`](crate::SadCodes) machinery. A TEL
//! body is a plain SAD whose digestive fields are `d` (every ilk) and, for
//! `vcp` only, `i` (the registry identity IS the vcp SAID). Numeric fields
//! (`s`, `bt`, seal `s`) are quoted lowercase-hex — the TEL factories never
//! set `intive`.

use crate::codec::event::{ParsedEvent, ParsedSeal};
use crate::codec::scanner::Scanner;
use crate::codec::threshold::{CountField, ParsedCount};
use crate::codec::{Decode as _, Encode as _, JsonWriter};
use crate::error::{BuilderError, CodecError, DeserializeError, InternalError};
use crate::serialize::EventRef;
use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::Ordinal;
use cesr::core::version::SerializationKind;
use keri_events::MessageType;
use keri_events::TelEvent;
use keri_events::tel::{RegistryInception, RegistryRotation};
use keri_events::threshold_form::ThresholdForm;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// A scanned TEL body — the strict wire-view of one of the six registry
/// ilks. Every field is a borrowed span; lift to domain types happens after
/// SAID verification (the [`Field`](crate::codec::field::Field) pipeline).
#[derive(Debug)]
pub(crate) enum ParsedTel<'a> {
    /// Registry inception (`vcp`).
    RegistryInception(ParsedVcp<'a>),
    /// Registry rotation (`vrt`).
    RegistryRotation(ParsedVrt<'a>),
    /// Credential issue (`iss`).
    Issue(ParsedIss<'a>),
    /// Credential revoke (`rev`).
    Revoke(ParsedRev<'a>),
    /// Backed credential issue (`bis`).
    BackedIssue(ParsedBis<'a>),
    /// Backed credential revoke (`brv`).
    BackedRevoke(ParsedBrv<'a>),
}

/// Scanned `vcp` body — keripy `incept` (`vdr/eventing.py:37-125`).
///
/// Wire fields: `v,t,d,i,ii,s,c,bt,b,n`. Both `d` and `i` are computed
/// SAIDs (the registry identity is the vcp SAID; keripy's makify fills
/// both from one dummied render).
#[derive(Debug)]
pub(crate) struct ParsedVcp<'a> {
    /// The vcp SAID (`d`).
    pub(crate) said: &'a str,
    /// The registry identifier (`i`) — must equal `said` in canonical
    /// output (both digest under the same code over one render).
    pub(crate) registry: &'a str,
    /// The issuing identifier (`ii`).
    pub(crate) issuer: &'a str,
    /// Sequence number (`s`) — the factory pins it to `"0"`.
    pub(crate) sn: &'a str,
    /// Configuration traits (`c`).
    pub(crate) config: Vec<&'a str>,
    /// Backer threshold (`bt`).
    pub(crate) backer_threshold: ParsedCount<'a>,
    /// Backers (`b`).
    pub(crate) backers: Vec<&'a str>,
    /// Registry nonce (`n`) — a CESR `Noncer` qb64.
    pub(crate) nonce: &'a str,
}

/// Scanned `vrt` body — keripy `rotate` (`vdr/eventing.py:128-260`).
///
/// Wire fields: `v,t,d,i,p,s,bt,br,ba`. The registry identifier (`i`) is
/// carried data here, not a SAID slot.
#[derive(Debug)]
pub(crate) struct ParsedVrt<'a> {
    /// The vrt SAID (`d`).
    pub(crate) said: &'a str,
    /// The registry identifier (`i`).
    pub(crate) registry: &'a str,
    /// The prior TEL event's SAID (`p`).
    pub(crate) prior: &'a str,
    /// Sequence number (`s`) — the factory requires sn ≥ 1.
    pub(crate) sn: &'a str,
    /// Backer threshold (`bt`) over the post-rotation backer set.
    pub(crate) backer_threshold: ParsedCount<'a>,
    /// Backer cuts (`br`).
    pub(crate) backer_cuts: Vec<&'a str>,
    /// Backer additions (`ba`).
    pub(crate) backer_additions: Vec<&'a str>,
}

/// Scanned `iss` body — keripy `issue` (`vdr/eventing.py:262-300`).
///
/// Wire fields: `v,t,d,i,s,ri,dt`. The credential SAID (`i`) is carried
/// data; only `d` is digestive.
#[derive(Debug)]
pub(crate) struct ParsedIss<'a> {
    /// The iss SAID (`d`).
    pub(crate) said: &'a str,
    /// The credential's SAID (`i`).
    pub(crate) credential: &'a str,
    /// Sequence number (`s`) — pinned to `"0"`.
    pub(crate) sn: &'a str,
    /// The registry identifier (`ri`).
    pub(crate) registry: &'a str,
    /// Issuance timestamp (`dt`).
    pub(crate) datetime: &'a str,
}

/// Scanned `rev` body — keripy `revoke` (`vdr/eventing.py:302-345`).
///
/// Wire fields: `v,t,d,i,s,ri,p,dt`. Sequence pinned to `"1"`.
#[derive(Debug)]
pub(crate) struct ParsedRev<'a> {
    /// The rev SAID (`d`).
    pub(crate) said: &'a str,
    /// The credential's SAID (`i`).
    pub(crate) credential: &'a str,
    /// Sequence number (`s`) — pinned to `"1"`.
    pub(crate) sn: &'a str,
    /// The registry identifier (`ri`).
    pub(crate) registry: &'a str,
    /// The prior TEL event's SAID (`p`).
    pub(crate) prior: &'a str,
    /// Revocation timestamp (`dt`).
    pub(crate) datetime: &'a str,
}

/// Scanned `bis` body — keripy `backerIssue` (`vdr/eventing.py:347-400`).
///
/// Wire fields: `v,t,d,i,ii,s,ra,dt`. The `ra` anchor is a full event
/// seal — the backed event's coordinate in the registry's own TEL.
#[derive(Debug)]
pub(crate) struct ParsedBis<'a> {
    /// The bis SAID (`d`).
    pub(crate) said: &'a str,
    /// The credential's SAID (`i`).
    pub(crate) credential: &'a str,
    /// The registry identifier (`ii`).
    pub(crate) issuer: &'a str,
    /// Sequence number (`s`) — pinned to `"0"`.
    pub(crate) sn: &'a str,
    /// The `ra` anchor (event-seal shape).
    pub(crate) anchor: ParsedSeal<'a>,
    /// Backing timestamp (`dt`).
    pub(crate) datetime: &'a str,
}

/// Scanned `brv` body — keripy `backerRevoke` (`vdr/eventing.py:402-445`).
///
/// Wire fields: `v,t,d,i,s,p,ra,dt`. Sequence pinned to `"1"`.
#[derive(Debug)]
pub(crate) struct ParsedBrv<'a> {
    /// The brv SAID (`d`).
    pub(crate) said: &'a str,
    /// The credential's SAID (`i`).
    pub(crate) credential: &'a str,
    /// Sequence number (`s`) — pinned to `"1"`.
    pub(crate) sn: &'a str,
    /// The prior TEL event's SAID (`p`).
    pub(crate) prior: &'a str,
    /// The `ra` anchor (event-seal shape).
    pub(crate) anchor: ParsedSeal<'a>,
    /// Backing revocation timestamp (`dt`).
    pub(crate) datetime: &'a str,
}

impl<'a> ParsedTel<'a> {
    /// Parse a strict canonical TEL body, dispatched on the wire `t` field.
    ///
    /// # Errors
    ///
    /// Returns the head-grammar errors of [`ParsedEvent::head`],
    /// [`DeserializeError::UnknownMessageType`] if `t` is not a TEL ilk,
    /// and [`DeserializeError::NonCanonical`] for any deviation from the
    /// ilk's fixed field order.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, CodecError> {
        let (mut sc, message_type) = ParsedEvent::head(raw)?;
        match message_type.value {
            "vcp" => Ok(Self::RegistryInception(Self::vcp(&mut sc)?)),
            "vrt" => Ok(Self::RegistryRotation(Self::vrt(&mut sc)?)),
            "iss" => Ok(Self::Issue(Self::iss(&mut sc)?)),
            "rev" => Ok(Self::Revoke(Self::rev(&mut sc)?)),
            "bis" => Ok(Self::BackedIssue(Self::bis(&mut sc)?)),
            "brv" => Ok(Self::BackedRevoke(Self::brv(&mut sc)?)),
            other => Err(DeserializeError::UnknownMessageType(String::from(other)).into()),
        }
    }

    /// The wire `t` of the parsed body.
    pub(crate) const fn message_type(&self) -> MessageType {
        match self {
            Self::RegistryInception(_) => MessageType::Vcp,
            Self::RegistryRotation(_) => MessageType::Vrt,
            Self::Issue(_) => MessageType::Iss,
            Self::Revoke(_) => MessageType::Rev,
            Self::BackedIssue(_) => MessageType::Bis,
            Self::BackedRevoke(_) => MessageType::Brv,
        }
    }

    /// The wire `d` span — the claimed event SAID, pre-verification. The
    /// caller reads its derivation code to configure the generic verify.
    pub(crate) const fn said(&self) -> &'a str {
        match self {
            Self::RegistryInception(p) => p.said,
            Self::RegistryRotation(p) => p.said,
            Self::Issue(p) => p.said,
            Self::Revoke(p) => p.said,
            Self::BackedIssue(p) => p.said,
            Self::BackedRevoke(p) => p.said,
        }
    }

    /// `d,i,ii,s,c,bt,b,n` — the head through `t` is shared; the remainder
    /// is this ilk's fixed field order.
    fn vcp(sc: &mut Scanner<'a>) -> Result<ParsedVcp<'a>, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let registry = sc.string()?.value;
        sc.expect(",\"ii\":")?;
        let issuer = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"c\":")?;
        let config = sc.string_array()?;
        sc.expect(",\"bt\":")?;
        let backer_threshold = ParsedCount::decode(sc)?;
        sc.expect(",\"b\":")?;
        let backers = sc.string_array()?;
        sc.expect(",\"n\":")?;
        let nonce = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedVcp {
            said,
            registry,
            issuer,
            sn,
            config,
            backer_threshold,
            backers,
            nonce,
        })
    }

    /// `d,i,p,s,bt,br,ba`.
    fn vrt(sc: &mut Scanner<'a>) -> Result<ParsedVrt<'a>, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let registry = sc.string()?.value;
        sc.expect(",\"p\":")?;
        let prior = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"bt\":")?;
        let backer_threshold = ParsedCount::decode(sc)?;
        sc.expect(",\"br\":")?;
        let backer_cuts = sc.string_array()?;
        sc.expect(",\"ba\":")?;
        let backer_additions = sc.string_array()?;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedVrt {
            said,
            registry,
            prior,
            sn,
            backer_threshold,
            backer_cuts,
            backer_additions,
        })
    }

    /// `d,i,s,ri,dt`.
    fn iss(sc: &mut Scanner<'a>) -> Result<ParsedIss<'a>, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let credential = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"ri\":")?;
        let registry = sc.string()?.value;
        sc.expect(",\"dt\":")?;
        let datetime = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedIss {
            said,
            credential,
            sn,
            registry,
            datetime,
        })
    }

    /// `d,i,s,ri,p,dt`.
    fn rev(sc: &mut Scanner<'a>) -> Result<ParsedRev<'a>, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let credential = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"ri\":")?;
        let registry = sc.string()?.value;
        sc.expect(",\"p\":")?;
        let prior = sc.string()?.value;
        sc.expect(",\"dt\":")?;
        let datetime = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedRev {
            said,
            credential,
            sn,
            registry,
            prior,
            datetime,
        })
    }

    /// `d,i,ii,s,ra,dt`.
    fn bis(sc: &mut Scanner<'a>) -> Result<ParsedBis<'a>, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let credential = sc.string()?.value;
        sc.expect(",\"ii\":")?;
        let issuer = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"ra\":")?;
        let anchor = ParsedSeal::decode(sc)?;
        sc.expect(",\"dt\":")?;
        let datetime = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedBis {
            said,
            credential,
            issuer,
            sn,
            anchor,
            datetime,
        })
    }

    /// `d,i,s,p,ra,dt`.
    fn brv(sc: &mut Scanner<'a>) -> Result<ParsedBrv<'a>, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let credential = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect(",\"p\":")?;
        let prior = sc.string()?.value;
        sc.expect(",\"ra\":")?;
        let anchor = ParsedSeal::decode(sc)?;
        sc.expect(",\"dt\":")?;
        let datetime = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(ParsedBrv {
            said,
            credential,
            sn,
            prior,
            anchor,
            datetime,
        })
    }
}

/// The write-side view of a TEL body: render one ilk's canonical JSON.
///
/// `bt` and seal `s` render as quoted lowercase-hex strings — keripy's
/// `"{:x}".format` spelling, always, because the TEL factories never set
/// `intive`. The vstring carries a zero size (`KERI10JSON000000_`); the
/// generic SAID orchestration backpatches it before digesting.
pub(crate) enum TelBodyRef<'a> {
    /// Registry inception (`vcp`).
    RegistryInception(&'a keri_events::RegistryInception<'a>),
    /// Registry rotation (`vrt`).
    RegistryRotation(&'a keri_events::RegistryRotation<'a>),
    /// Credential issue (`iss`).
    Issue(&'a keri_events::Issue<'a>),
    /// Credential revoke (`rev`).
    Revoke(&'a keri_events::Revoke<'a>),
    /// Backed credential issue (`bis`).
    BackedIssue(&'a keri_events::BackedIssue<'a>),
    /// Backed credential revoke (`brv`).
    BackedRevoke(&'a keri_events::BackedRevoke<'a>),
}

impl TelBodyRef<'_> {
    /// The wire `t` of the body being rendered.
    pub(crate) const fn message_type(&self) -> MessageType {
        match self {
            Self::RegistryInception(_) => MessageType::Vcp,
            Self::RegistryRotation(_) => MessageType::Vrt,
            Self::Issue(_) => MessageType::Iss,
            Self::Revoke(_) => MessageType::Rev,
            Self::BackedIssue(_) => MessageType::Bis,
            Self::BackedRevoke(_) => MessageType::Brv,
        }
    }

    /// The digest code of the event's `d` field — the derivation code for
    /// every digestive span of this ilk (`d`, and `i` for `vcp`). Builders
    /// pin keripy's default ([`DigestCode::Blake3_256`], the `Saider
    /// .saidify` default the registry factories use); parsed events carry
    /// their wire code, so re-serialization preserves the algorithm.
    pub(crate) const fn said_code(&self) -> DigestCode {
        match self {
            Self::RegistryInception(e) => *e.said().as_matter().code(),
            Self::RegistryRotation(e) => *e.said().as_matter().code(),
            Self::Issue(e) => *e.said().as_matter().code(),
            Self::Revoke(e) => *e.said().as_matter().code(),
            Self::BackedIssue(e) => *e.said().as_matter().code(),
            Self::BackedRevoke(e) => *e.said().as_matter().code(),
        }
    }

    /// Render the body into `buf` (appending): the shared
    /// `{"v":"<zero-size>","t":"<ilk>","d":"<placeholder>` head, then the
    /// ilk's fixed field order. For `vcp`, `i` carries the same placeholder
    /// as `d` — both digest under the same code over one render.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::NonEventBackerAnchor`](crate::error::BuilderError)
    /// if a backed event's `ra` anchor is not the event-seal shape (the
    /// only form keripy's `SealEvent` anchor renders), or the head-writer's
    /// version-grammar errors.
    pub(crate) fn render(
        &self,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        // The head's size and `d` slots are backpatched by the generic
        // SadCodes saidify, which re-scans `v` and splices by label —
        // nothing to report back to the caller.
        EventRef::write_head(
            buf,
            self.message_type(),
            said_placeholder,
            SerializationKind::Json,
        )?;

        match self {
            Self::RegistryInception(e) => Self::render_vcp(e, said_placeholder, buf),
            Self::RegistryRotation(e) => Self::render_vrt(e, buf),
            Self::Issue(e) => {
                buf.extend_from_slice(b",\"i\":");
                e.credential_said().encode(buf);
                buf.extend_from_slice(b",\"s\":");
                JsonWriter::write_str(buf, &e.sn().numh().to_string());
                buf.extend_from_slice(b",\"ri\":");
                e.registry_said().encode(buf);
                buf.extend_from_slice(b",\"dt\":");
                JsonWriter::write_str(buf, e.datetime());
            }
            Self::Revoke(e) => {
                buf.extend_from_slice(b",\"i\":");
                e.credential_said().encode(buf);
                buf.extend_from_slice(b",\"s\":");
                JsonWriter::write_str(buf, &e.sn().numh().to_string());
                buf.extend_from_slice(b",\"ri\":");
                e.registry_said().encode(buf);
                buf.extend_from_slice(b",\"p\":");
                e.prior().encode(buf);
                buf.extend_from_slice(b",\"dt\":");
                JsonWriter::write_str(buf, e.datetime());
            }
            Self::BackedIssue(e) => {
                buf.extend_from_slice(b",\"i\":");
                e.credential_said().encode(buf);
                buf.extend_from_slice(b",\"ii\":");
                e.registry_said().encode(buf);
                buf.extend_from_slice(b",\"s\":");
                JsonWriter::write_str(buf, &e.sn().numh().to_string());
                buf.extend_from_slice(b",\"ra\":");
                e.anchor().event_seal()?.encode(buf);
                buf.extend_from_slice(b",\"dt\":");
                JsonWriter::write_str(buf, e.datetime());
            }
            Self::BackedRevoke(e) => {
                buf.extend_from_slice(b",\"i\":");
                e.credential_said().encode(buf);
                buf.extend_from_slice(b",\"s\":");
                JsonWriter::write_str(buf, &e.sn().numh().to_string());
                buf.extend_from_slice(b",\"p\":");
                e.prior().encode(buf);
                buf.extend_from_slice(b",\"ra\":");
                e.anchor().event_seal()?.encode(buf);
                buf.extend_from_slice(b",\"dt\":");
                JsonWriter::write_str(buf, e.datetime());
            }
        }
        buf.push(b'}');
        Ok(())
    }

    /// The `vcp` field body (after the head): `i` carries the SAID
    /// placeholder — the registry identity digests under the same code over
    /// one render.
    fn render_vcp(e: &RegistryInception<'_>, said_placeholder: &str, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b",\"i\":\"");
        buf.extend_from_slice(said_placeholder.as_bytes());
        buf.push(b'"');
        buf.extend_from_slice(b",\"ii\":");
        e.issuer().encode(buf);
        buf.extend_from_slice(b",\"s\":");
        JsonWriter::write_str(buf, &e.sn().numh().to_string());
        buf.extend_from_slice(b",\"c\":");
        e.config().encode(buf);
        buf.extend_from_slice(b",\"bt\":");
        CountField {
            toad: e.backer_threshold(),
            form: ThresholdForm::HexString,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"b\":");
        e.backers().encode(buf);
        buf.extend_from_slice(b",\"n\":");
        e.nonce().encode(buf);
    }

    /// The `vrt` field body (after the head): prior SAID, stored sequence,
    /// from-wire threshold, and the cut/addition backer lists.
    fn render_vrt(e: &RegistryRotation<'_>, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b",\"i\":");
        e.registry().encode(buf);
        buf.extend_from_slice(b",\"p\":");
        e.prior().encode(buf);
        buf.extend_from_slice(b",\"s\":");
        JsonWriter::write_str(buf, &e.sn().numh().to_string());
        buf.extend_from_slice(b",\"bt\":");
        CountField {
            toad: e.backer_threshold(),
            form: ThresholdForm::HexString,
        }
        .encode(buf);
        buf.extend_from_slice(b",\"br\":");
        e.backer_cuts().encode(buf);
        buf.extend_from_slice(b",\"ba\":");
        e.backer_additions().encode(buf);
    }
}

/// The backer anchor of a backed event (`ra`) must be the event-seal shape
/// — the only form keripy's `SealEvent` anchor renders. A method on the
/// seal (not a free fn): the fn-ratchet budget is spent.
pub(crate) trait EventSealRef {
    /// The seal as the event-seal variant, or a typed builder error.
    fn event_seal(&self) -> Result<&Self, CodecError>;
}

impl EventSealRef for keri_events::Seal<'_> {
    fn event_seal(&self) -> Result<&Self, CodecError> {
        match self {
            Self::Event { .. } => Ok(self),
            _ => Err(BuilderError::NonEventBackerAnchor.into()),
        }
    }
}

impl<'a> From<&'a TelEvent<'a>> for TelBodyRef<'a> {
    fn from(event: &'a TelEvent<'a>) -> Self {
        match event {
            TelEvent::RegistryInception(e) => Self::RegistryInception(e),
            TelEvent::RegistryRotation(e) => Self::RegistryRotation(e),
            TelEvent::Issue(e) => Self::Issue(e),
            TelEvent::Revoke(e) => Self::Revoke(e),
            TelEvent::BackedIssue(e) => Self::BackedIssue(e),
            TelEvent::BackedRevoke(e) => Self::BackedRevoke(e),
        }
    }
}

/// The generic SAID configuration of a TEL ilk: `d` for every ilk, plus `i`
/// for `vcp` — the registry identity digests alongside `d` under the same
/// code over one render (keripy's `makify` computes both from a single
/// dummied body). A trait on `MessageType`, not a free fn: the fn-ratchet
/// budget is spent, and the TEL grammar module owns the wire law.
pub(crate) trait TelSadConfig {
    /// The digestive-field configuration for this ilk under one derivation
    /// code, or an error for a non-TEL ilk.
    ///
    /// # Errors
    ///
    /// Returns [`InternalError::EventLayout`] for a non-TEL message type —
    /// the static grammar cannot configure digestive fields for it.
    fn tel_sad_config(&self, code: DigestCode) -> Result<crate::SadCodes, CodecError>;
}

impl TelSadConfig for MessageType {
    fn tel_sad_config(&self, code: DigestCode) -> Result<crate::SadCodes, CodecError> {
        // Static shape: labels are never the reserved `v`, and the pair
        // count is within `SadCodes` capacity — a rejection would be a
        // broken invariant, not wire input, so the source is reported as
        // the layout error it would be.
        let pairs: &[(&'static str, DigestCode)] = match self {
            Self::Vcp => &[("d", code), ("i", code)],
            Self::Vrt | Self::Iss | Self::Rev | Self::Bis | Self::Brv => &[("d", code)],
            _ => {
                return Err(InternalError::EventLayout(
                    "non-TEL ilk has no TEL SAID configuration",
                )
                .into());
            }
        };
        crate::SadCodes::from_pairs(pairs).map_err(|_| {
            InternalError::EventLayout("static TEL SAID configuration rejected").into()
        })
    }
}
