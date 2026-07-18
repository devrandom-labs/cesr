//! The internal codec vocabulary: symmetric [`Encode`]/[`Decode`] traits over
//! the canonical JSON wire form, plus [`JsonWriter`], the shared JSON string
//! escaper. der-precedent (#193): one type owns both wire directions, stated
//! once, co-located per type in `codec::*` submodules — [`scanner`] (the
//! strict Reader), [`seal`], [`threshold`], and [`event`] (the five event
//! grammars, writer and parser together).
//!
//! Crate-internal by design: the wire-grammar traits are a narrower,
//! non-SAID contract than the public [`Serialize`](crate::Serialize)/
//! [`Deserialize`](crate::Deserialize) surface, which adds SAID
//! computation/verification and version-size backpatching on top.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::codec::scanner::Scanner;
use crate::error::SerderError;
use cesr::core::matter::code::CesrCode;
use cesr::core::matter::matter::Matter;
use keri_events::{ConfigTrait, Identifier};

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) mod event;
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) mod field;
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) mod scanner;
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) mod seal;
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) mod threshold;

/// Append `self`'s canonical JSON wire form to `out`.
///
/// Infallible: encoding a well-formed in-memory value cannot fail (the
/// canonical form has no length prefixes to precompute — unlike der's TLV).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) trait Encode {
    /// Append this value's canonical JSON bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

/// Parse one value from the scanner, advancing its cursor past the value.
///
/// Decodes to the borrowed scan-stage view (der's `*Ref` analogue), not the
/// qb64-lifted type: the pipeline is scan → SAID-verify → lift, and lifting
/// belongs after verification.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) trait Decode<'a>: Sized {
    /// Parse one value at the scanner's cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] when the input at the cursor is not this
    /// type's canonical wire form.
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, SerderError>;
}

impl<C: CesrCode> Encode for Matter<'_, C> {
    /// A qb64 string, quoted.
    fn encode(&self, out: &mut Vec<u8>) {
        JsonWriter::write_str(out, &self.to_qb64());
    }
}

impl Encode for Identifier<'_> {
    /// Dispatches to the inner `Prefixer`/`Saider`'s qb64 form.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Identifier::Basic(p) => p.encode(out),
            Identifier::SelfAddressing(s) => s.encode(out),
        }
    }
}

impl<C: CesrCode> Encode for [Matter<'_, C>] {
    /// A JSON array of qb64 strings — one per primitive, compact.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(b'[');
        for (idx, m) in self.iter().enumerate() {
            if idx > 0 {
                out.push(b',');
            }
            m.encode(out);
        }
        out.push(b']');
    }
}

impl Encode for [ConfigTrait] {
    /// A JSON array of configuration-trait codes, compact.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(b'[');
        for (idx, c) in self.iter().enumerate() {
            if idx > 0 {
                out.push(b',');
            }
            JsonWriter::write_str(out, c.code());
        }
        out.push(b']');
    }
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// The canonical JSON byte writer (a namespace type — methods, not free
/// fns, so the `cesr-fn-ratchet` count is untouched).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct JsonWriter;

impl JsonWriter {
    /// Write `s` as a JSON string with RFC 8259 escaping, byte-identical to
    /// `serde_json`'s escaper: `"`, `\`, and control characters below 0x20
    /// are escaped (short forms where they exist, `\u00xx` otherwise);
    /// everything else — including multi-byte UTF-8 — passes through raw.
    pub(crate) fn write_str(buf: &mut Vec<u8>, s: &str) {
        buf.push(b'"');
        for &byte in s.as_bytes() {
            match byte {
                b'"' => buf.extend_from_slice(b"\\\""),
                b'\\' => buf.extend_from_slice(b"\\\\"),
                0x08 => buf.extend_from_slice(b"\\b"),
                0x09 => buf.extend_from_slice(b"\\t"),
                0x0A => buf.extend_from_slice(b"\\n"),
                0x0C => buf.extend_from_slice(b"\\f"),
                0x0D => buf.extend_from_slice(b"\\r"),
                b if b < 0x20 => {
                    buf.extend_from_slice(b"\\u00");
                    buf.push(HEX[usize::from(b >> 4)]);
                    buf.push(HEX[usize::from(b & 0x0F)]);
                }
                b => buf.push(b),
            }
        }
        buf.push(b'"');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use alloc::format;
    use alloc::vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};

    // Migrated from the dissolved `primitives.rs`: `to_qb64_string`/
    // `identifier_to_qb64_string` were exactly `matter.to_qb64()` /
    // a variant-dispatch to the inner matter's `to_qb64()`; these assert the
    // `Encode` impls reproduce that qb64 wrapped in JSON quotes, byte-exact.

    #[test]
    fn matter_encode_writes_quoted_qb64() {
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .expect("raw should be accepted")
            .build()
            .expect("build should succeed");

        let mut out = Vec::new();
        verfer.encode(&mut out);
        assert_eq!(out, format!("\"{}\"", verfer.to_qb64()).into_bytes());
        assert_eq!(verfer.to_qb64().len(), 44);
        assert!(
            verfer.to_qb64().starts_with('D'),
            "Ed25519 verfer qb64 should start with 'D'"
        );
    }

    #[test]
    fn saider_encode_writes_quoted_qb64() {
        let saider = MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .expect("raw should be accepted")
            .build()
            .expect("build should succeed");

        let mut out = Vec::new();
        saider.encode(&mut out);
        assert_eq!(out, format!("\"{}\"", saider.to_qb64()).into_bytes());
        assert_eq!(saider.to_qb64().len(), 44);
        assert!(
            saider.to_qb64().starts_with('E'),
            "Blake3_256 saider qb64 should start with 'E'"
        );
    }

    #[test]
    fn identifier_encode_basic_dispatches_to_inner_matter() {
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let id = Identifier::Basic(verfer.clone());

        let mut expected = Vec::new();
        verfer.encode(&mut expected);
        let mut got = Vec::new();
        id.encode(&mut got);
        assert_eq!(got, expected);
    }

    #[test]
    fn identifier_encode_self_addressing_dispatches_to_inner_matter() {
        let saider = MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let id = Identifier::SelfAddressing(saider.clone());

        let mut expected = Vec::new();
        saider.encode(&mut expected);
        let mut got = Vec::new();
        id.encode(&mut got);
        assert_eq!(got, expected);
    }

    #[test]
    fn matter_slice_encode_reuses_single_value_encode() {
        let a = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![3u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let b = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![4u8; 32]))
            .unwrap()
            .build()
            .unwrap();

        let mut expected = Vec::new();
        expected.push(b'[');
        a.encode(&mut expected);
        expected.push(b',');
        b.encode(&mut expected);
        expected.push(b']');

        let arr = [a, b];
        let mut got = Vec::new();
        arr.encode(&mut got);
        assert_eq!(got, expected);
    }
}
