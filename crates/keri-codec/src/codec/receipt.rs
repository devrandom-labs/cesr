//! The receipt (`rct`) canonical grammar — both wire directions.
//!
//! A receipt body is the four-field message keripy's `receipt()` emits
//! (`eventing.py:957` at the pin): `v, t, d, i, s`, where `d` is the SAID
//! of the *receipted* event — plain data, not a self-SAID. There is
//! therefore no SAID placeholder, no splice, and no verification pass: the
//! writer renders every value verbatim and backpatches only the version
//! string's size field; the reader lifts the fields as they stand.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::ToString, vec, vec::Vec};

use crate::codec::event::ParsedEvent;
use crate::codec::scanner::Scanner;
use crate::codec::{Encode as _, JsonWriter};
use crate::error::{CodecError, InternalError, VersionGrammarError};
use crate::serialize::{EventRef, SerializedReceipt};
use cesr::core::primitives::Ordinal;
use cesr::core::version::{SerializationKind, VERSION_SIZE_MAX, VersionError};
use keri_events::{MessageType, Receipt};

/// A parsed receipt (`rct`) body: borrowed field views.
///
/// No spans are recorded: a receipt's `d` is the receipted event's SAID,
/// carried as data — there is nothing to dummy and re-hash.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedRct<'a> {
    /// The `d` field: SAID of the receipted event, qb64.
    pub(crate) said: &'a str,
    /// The `i` field: identifier prefix of the receipted KEL, qb64.
    pub(crate) prefix: &'a str,
    /// The `s` field: sequence number of the receipted event, hex.
    pub(crate) sn: &'a str,
}

impl<'a> ParsedRct<'a> {
    /// Parse a strict canonical `rct` body.
    ///
    /// # Errors
    ///
    /// See [`ParsedEvent::parse`]. Additionally returns
    /// [`DeserializeError::NonCanonical`](crate::error::DeserializeError::NonCanonical)
    /// if the wire `t` field is not `"rct"`.
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, CodecError> {
        let (sc, message_type) = ParsedEvent::head(raw)?;
        ParsedEvent::require_message_type(&sc, &message_type, "rct")?;
        Self::body(sc)
    }

    fn body(mut sc: Scanner<'a>) -> Result<Self, CodecError> {
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"i\":")?;
        let prefix = sc.string()?.value;
        sc.expect(",\"s\":")?;
        let sn = sc.string()?.value;
        sc.expect("}")?;
        sc.finish()?;
        Ok(Self { said, prefix, sn })
    }
}

impl SerializedReceipt {
    /// Render a receipt's canonical JSON — field order `v, t, d, i, s`
    /// (keripy `receipt()`, `eventing.py:957` at the pin) — and backpatch
    /// the version string's size field.
    ///
    /// The head writer's `d` "placeholder" is the actual SAID qb64: the
    /// value is data, so writing it up front leaves nothing to splice.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the version string cannot be built or the
    /// rendered body exceeds the version string's size capacity.
    pub(crate) fn build(receipt: &Receipt<'_>) -> Result<Self, CodecError> {
        let mut buf = Vec::new();
        let said_qb64 = receipt.said().to_qb64();
        let (size_slot, _) =
            EventRef::write_head(&mut buf, MessageType::Rct, &said_qb64, SerializationKind::Json)?;
        buf.extend_from_slice(b",\"i\":");
        receipt.prefix().encode(&mut buf);
        buf.extend_from_slice(b",\"s\":");
        JsonWriter::write_str(&mut buf, &receipt.sn().numh().to_string());
        buf.push(b'}');

        let size = buf.len();
        let size_u32 = u32::try_from(size)
            .ok()
            .filter(|s| *s <= VERSION_SIZE_MAX)
            .ok_or(VersionGrammarError::Version(VersionError::FieldOverflow {
                field: "size",
                max: VERSION_SIZE_MAX,
            }))?;
        let hex = format!("{size_u32:06x}");
        let dst = buf
            .get_mut(size_slot)
            .ok_or(InternalError::EventLayout("size slot out of bounds"))?;
        if dst.len() != hex.len() {
            return Err(InternalError::EventLayout("size slot width does not match").into());
        }
        dst.copy_from_slice(hex.as_bytes());
        Ok(Self { raw: buf, size })
    }
}
