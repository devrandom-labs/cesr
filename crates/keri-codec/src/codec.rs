//! The internal codec vocabulary: symmetric [`Encode`]/[`Decode`] traits over
//! the canonical JSON wire form, plus [`JsonWriter`], the shared JSON string
//! escaper. der-precedent (#193 step 2): one type owns both wire directions,
//! stated once, co-located per type in `codec::*` submodules.
//!
//! Crate-internal by design: step 2 changes no public surface. Public
//! promotion (and the `KeriSerialize`/`KeriDeserialize` rename decision) is
//! step 3, which also dissolves the legacy per-file writers/readers
//! (`serialize/json.rs`, the per-type grammar in `deserialize/canonical.rs`)
//! into `codec::*` impls.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub(crate) mod seal;

/// Append `self`'s canonical JSON wire form to `out`.
///
/// Infallible: encoding a well-formed in-memory value cannot fail (the
/// canonical form has no length prefixes to precompute — unlike der's TLV).
pub(crate) trait Encode {
    /// Append this value's canonical JSON bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// The canonical JSON byte writer (a namespace type — methods, not free
/// fns, so the `cesr-fn-ratchet` count is untouched).
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
