use crate::core::primitives::{Prefixer, Saider, Verser};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{string::String, vec, vec::Vec};
use core::ops::RangeInclusive;
use core::str::from_utf8;

use thiserror::Error;

use crate::keri::sequence::SequenceNumber;

/// Anchoring seals that bind events to external data.
pub enum Seal {
    /// Digest seal — anchors a single hash.
    Digest {
        /// The digest value.
        d: Saider<'static>,
    },
    /// Root seal — anchors a Merkle tree root.
    Root {
        /// The root digest.
        rd: Saider<'static>,
    },
    /// Source seal — references a prior event by sequence number and digest.
    Source {
        /// Sequence number of the source event.
        s: SequenceNumber,
        /// Digest of the source event.
        d: Saider<'static>,
    },
    /// Event seal — fully identifies an event by prefix, sequence number, and digest.
    Event {
        /// Prefix of the identifier.
        i: Prefixer<'static>,
        /// Sequence number of the event.
        s: SequenceNumber,
        /// Digest of the event.
        d: Saider<'static>,
    },
    /// Last-event seal — references the latest event for a given prefix.
    Last {
        /// Prefix of the identifier.
        i: Prefixer<'static>,
    },
    /// Registrar-backer seal — nontransferable backer prefix plus a digest
    /// of the anchored backer metadata (keripy `SealBack`).
    Back {
        /// Backer identifier prefix.
        bi: Prefixer<'static>,
        /// Digest of the anchored backer metadata.
        d: Saider<'static>,
    },
    /// Typed digest seal — a version/type tag plus a SAID (keripy `SealKind`).
    Kind {
        /// Type of the digest.
        t: Verser<'static>,
        /// The digest value.
        d: Saider<'static>,
    },
    /// A non-codex anchor preserved verbatim.
    Opaque(OpaqueSeal),
}

/// A non-codex anchor: an arbitrary compact-JSON object preserved verbatim.
///
/// keripy validates event anchors (`data`) only as being a list — the dicts
/// inside are arbitrary. This type carries such an anchor through cesr
/// unmodified: the JSON writer re-emits the stored text byte-for-byte, so
/// decode → encode round-trips keripy events exactly.
///
/// The payload must be one well-formed *compact* JSON object (no whitespace
/// between tokens — the form keripy's canonical
/// `json.dumps(..., separators=(",", ":"))` emits), enforced at construction.
#[derive(Debug)]
pub struct OpaqueSeal(String);

impl OpaqueSeal {
    /// Validate and wrap a compact-JSON object payload.
    ///
    /// # Errors
    ///
    /// Returns [`OpaqueSealError`] when `raw` is not exactly one well-formed
    /// compact JSON object.
    pub fn new(raw: String) -> Result<Self, OpaqueSealError> {
        let len = scan_object(raw.as_bytes())?;
        if len != raw.len() {
            return Err(OpaqueSealError::TrailingBytes { offset: len });
        }
        Ok(Self(raw))
    }

    /// The verbatim JSON object text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Rejections from [`OpaqueSeal::new`]'s compact-JSON object validation.
#[derive(Debug, Error)]
pub enum OpaqueSealError {
    /// The payload does not start with `{`.
    #[error("opaque seal payload must be a JSON object")]
    NotAnObject,
    /// A byte that no compact-JSON production allows at its position
    /// (this includes any whitespace between tokens).
    #[error("unexpected byte at offset {offset} in opaque seal payload")]
    UnexpectedByte {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// Input ended before the object closed.
    #[error("opaque seal payload is truncated")]
    Truncated,
    /// An unescaped control character inside a string.
    #[error("control character at offset {offset} in opaque seal string")]
    ControlCharacter {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// A malformed `\` escape inside a string.
    #[error("invalid escape sequence at offset {offset} in opaque seal string")]
    InvalidEscape {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// Bytes remain after the object closed.
    #[error("trailing bytes after opaque seal object at offset {offset}")]
    TrailingBytes {
        /// Byte offset of the first trailing byte.
        offset: usize,
    },
    /// A number whose magnitude does not fit in an IEEE-754 double.
    /// `serde_json` rejects such payloads when materializing a `Value`
    /// (`number out of range`), so the scanner rejects them too — readers
    /// and tooling can then reparse any accepted payload into a `Value`.
    /// (The write path is unaffected either way: the JSON writer emits the
    /// stored text verbatim.)
    #[error("number out of range at offset {offset} in opaque seal payload")]
    NumberOutOfRange {
        /// Byte offset of the number's first byte.
        offset: usize,
    },
    /// A position computation overflowed `usize`.
    #[error("offset overflow while scanning opaque seal payload")]
    OffsetOverflow,
}

fn bump(pos: usize) -> Result<usize, OpaqueSealError> {
    pos.checked_add(1).ok_or(OpaqueSealError::OffsetOverflow)
}

enum ScanState {
    /// Just after `{`: a key string or `}`.
    FirstKey,
    /// Just after `,` inside an object: a key string.
    NextKey,
    /// Start of any JSON value.
    Value,
    /// Just after `[`: a value or `]`.
    FirstValue,
    /// Just after a complete value: `,` or the container's closer.
    AfterValue,
}

/// Byte length of one complete compact-JSON object at the start of `input`.
///
/// Iterative — nesting depth costs heap (one container-kind entry per open
/// bracket, bounded by input length), never call stack, so adversarially
/// deep anchors cannot overflow the stack. Used by [`OpaqueSeal::new`] and
/// by the strict event reader's opaque-anchor fallback.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — callable from serder's strict reader but not part of the public API"
)]
pub(crate) fn scan_object(input: &[u8]) -> Result<usize, OpaqueSealError> {
    if input.first() != Some(&b'{') {
        return Err(OpaqueSealError::NotAnObject);
    }
    // `true` = object, `false` = array.
    let mut containers = vec![true];
    let mut pos = 1_usize;
    let mut state = ScanState::FirstKey;
    loop {
        match state {
            ScanState::FirstKey | ScanState::NextKey => {
                match input.get(pos).ok_or(OpaqueSealError::Truncated)? {
                    b'}' if matches!(state, ScanState::FirstKey) => {
                        pos = bump(pos)?;
                        containers.pop();
                        if containers.is_empty() {
                            return Ok(pos);
                        }
                        state = ScanState::AfterValue;
                    }
                    b'"' => {
                        pos = scan_string(input, pos)?;
                        if input.get(pos) != Some(&b':') {
                            return Err(OpaqueSealError::UnexpectedByte { offset: pos });
                        }
                        pos = bump(pos)?;
                        state = ScanState::Value;
                    }
                    _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
                }
            }
            ScanState::Value => {
                (pos, state) = scan_value_start(input, pos, &mut containers)?;
            }
            ScanState::FirstValue => {
                if input.get(pos).ok_or(OpaqueSealError::Truncated)? == &b']' {
                    pos = bump(pos)?;
                    containers.pop();
                    if containers.is_empty() {
                        return Ok(pos);
                    }
                    state = ScanState::AfterValue;
                } else {
                    state = ScanState::Value;
                }
            }
            ScanState::AfterValue => {
                let byte = *input.get(pos).ok_or(OpaqueSealError::Truncated)?;
                // Invariant: the loop returns the moment `containers` empties,
                // so a container is always open here; `Truncated` is a
                // defensive mapping, not a reachable state.
                let in_object = *containers.last().ok_or(OpaqueSealError::Truncated)?;
                match (byte, in_object) {
                    (b',', true) => {
                        pos = bump(pos)?;
                        state = ScanState::NextKey;
                    }
                    (b',', false) => {
                        pos = bump(pos)?;
                        state = ScanState::Value;
                    }
                    (b'}', true) | (b']', false) => {
                        pos = bump(pos)?;
                        containers.pop();
                        if containers.is_empty() {
                            return Ok(pos);
                        }
                    }
                    _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
                }
            }
        }
    }
}

/// Dispatch on a value's first byte (cursor at the start of a JSON value):
/// descend into a container (recording its kind) or scan a complete scalar.
/// Returns the next cursor position and scanner state.
fn scan_value_start(
    input: &[u8],
    pos: usize,
    containers: &mut Vec<bool>,
) -> Result<(usize, ScanState), OpaqueSealError> {
    match input.get(pos).ok_or(OpaqueSealError::Truncated)? {
        b'{' => {
            containers.push(true);
            Ok((bump(pos)?, ScanState::FirstKey))
        }
        b'[' => {
            containers.push(false);
            Ok((bump(pos)?, ScanState::FirstValue))
        }
        b'"' => Ok((scan_string(input, pos)?, ScanState::AfterValue)),
        b'-' | b'0'..=b'9' => Ok((scan_number(input, pos)?, ScanState::AfterValue)),
        b't' => Ok((scan_lit(input, pos, b"true")?, ScanState::AfterValue)),
        b'f' => Ok((scan_lit(input, pos, b"false")?, ScanState::AfterValue)),
        b'n' => Ok((scan_lit(input, pos, b"null")?, ScanState::AfterValue)),
        _ => Err(OpaqueSealError::UnexpectedByte { offset: pos }),
    }
}

/// Advance past one JSON string (cursor on the opening `"`); returns the
/// position after the closing `"`. Escapes are validated, not decoded.
fn scan_string(input: &[u8], start: usize) -> Result<usize, OpaqueSealError> {
    let mut pos = bump(start)?;
    loop {
        let byte = *input.get(pos).ok_or(OpaqueSealError::Truncated)?;
        match byte {
            b'"' => return bump(pos),
            b'\\' => {
                let esc_at = bump(pos)?;
                let esc = *input.get(esc_at).ok_or(OpaqueSealError::Truncated)?;
                pos = match esc {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => bump(esc_at)?,
                    b'u' => scan_unicode_escape(input, esc_at)?,
                    _ => return Err(OpaqueSealError::InvalidEscape { offset: esc_at }),
                };
            }
            b if b < 0x20 => return Err(OpaqueSealError::ControlCharacter { offset: pos }),
            _ => pos = bump(pos)?,
        }
    }
}

/// First UTF-16 code unit of a surrogate pair.
const HIGH_SURROGATES: RangeInclusive<u32> = 0xD800..=0xDBFF;
/// Second UTF-16 code unit of a surrogate pair.
const LOW_SURROGATES: RangeInclusive<u32> = 0xDC00..=0xDFFF;

/// Validate a `\u` escape (cursor on the `u`), including UTF-16 surrogate
/// pairing per RFC 8259 section 7: a high surrogate must be immediately
/// followed by a `\u` low surrogate, and a lone low surrogate is invalid —
/// aligned with `serde_json`'s string parsing so every accepted payload
/// reparses. Returns the position after the complete escape.
fn scan_unicode_escape(input: &[u8], u_at: usize) -> Result<usize, OpaqueSealError> {
    let (after_high, unit) = scan_hex4(input, bump(u_at)?)?;
    if LOW_SURROGATES.contains(&unit) {
        return Err(OpaqueSealError::InvalidEscape { offset: u_at });
    }
    if !HIGH_SURROGATES.contains(&unit) {
        return Ok(after_high);
    }
    if input.get(after_high) != Some(&b'\\') {
        return Err(OpaqueSealError::InvalidEscape { offset: after_high });
    }
    let low_u_at = bump(after_high)?;
    if input.get(low_u_at) != Some(&b'u') {
        return Err(OpaqueSealError::InvalidEscape { offset: low_u_at });
    }
    let (after_low, low_unit) = scan_hex4(input, bump(low_u_at)?)?;
    if LOW_SURROGATES.contains(&low_unit) {
        Ok(after_low)
    } else {
        Err(OpaqueSealError::InvalidEscape { offset: low_u_at })
    }
}

/// Read four hex digits (cursor on the first digit); returns the position
/// after them and the decoded UTF-16 code unit.
fn scan_hex4(input: &[u8], start: usize) -> Result<(usize, u32), OpaqueSealError> {
    let mut unit = 0_u32;
    let mut pos = start;
    for _ in 0_u8..4 {
        let byte = *input.get(pos).ok_or(OpaqueSealError::Truncated)?;
        let digit = char::from(byte)
            .to_digit(16)
            .ok_or(OpaqueSealError::InvalidEscape { offset: pos })?;
        unit = (unit << 4) | digit;
        pos = bump(pos)?;
    }
    Ok((pos, unit))
}

/// Advance past one JSON number (cursor on `-` or a digit); returns the
/// position after its last byte. Numbers whose magnitude overflows an
/// IEEE-754 double are rejected, matching `serde_json`'s `number out of
/// range` so every accepted payload reparses.
fn scan_number(input: &[u8], start: usize) -> Result<usize, OpaqueSealError> {
    let mut pos = start;
    if input.get(pos) == Some(&b'-') {
        pos = bump(pos)?;
    }
    match input.get(pos) {
        Some(b'0') => pos = bump(pos)?,
        Some(b'1'..=b'9') => {
            pos = bump(pos)?;
            while matches!(input.get(pos), Some(b'0'..=b'9')) {
                pos = bump(pos)?;
            }
        }
        _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
    }
    if input.get(pos) == Some(&b'.') {
        pos = bump(pos)?;
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(OpaqueSealError::UnexpectedByte { offset: pos });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos = bump(pos)?;
        }
    }
    if matches!(input.get(pos), Some(b'e' | b'E')) {
        pos = bump(pos)?;
        if matches!(input.get(pos), Some(b'+' | b'-')) {
            pos = bump(pos)?;
        }
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(OpaqueSealError::UnexpectedByte { offset: pos });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos = bump(pos)?;
        }
    }
    let bytes = input.get(start..pos).ok_or(OpaqueSealError::Truncated)?;
    // The scanned bytes are ASCII sign/digit/dot/exponent by construction and
    // JSON's number grammar is a subset of Rust's f64 grammar, so both `else`
    // branches are defensive mappings, not reachable states.
    let Ok(text) = from_utf8(bytes) else {
        return Err(OpaqueSealError::UnexpectedByte { offset: start });
    };
    let Ok(value) = text.parse::<f64>() else {
        return Err(OpaqueSealError::NumberOutOfRange { offset: start });
    };
    if value.is_finite() {
        Ok(pos)
    } else {
        Err(OpaqueSealError::NumberOutOfRange { offset: start })
    }
}

/// Expect the exact literal at `pos`; returns the position after it.
fn scan_lit(input: &[u8], pos: usize, lit: &'static [u8]) -> Result<usize, OpaqueSealError> {
    let end = pos
        .checked_add(lit.len())
        .ok_or(OpaqueSealError::OffsetOverflow)?;
    match input.get(pos..end) {
        Some(bytes) if bytes == lit => Ok(end),
        Some(_) => Err(OpaqueSealError::UnexpectedByte { offset: pos }),
        None => Err(OpaqueSealError::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode, VerserCode};
    use alloc::borrow::Cow;
    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::string::String;

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verser() -> Verser<'static> {
        MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<VerserCode>()
            .unwrap()
            .into_static()
    }

    #[test]
    fn seal_digest() {
        let Seal::Digest { d } = (Seal::Digest { d: make_saider() }) else {
            unreachable!()
        };
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_root() {
        let Seal::Root { rd } = (Seal::Root { rd: make_saider() }) else {
            unreachable!()
        };
        assert_eq!(*rd.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_source() {
        let Seal::Source { s, d } = (Seal::Source {
            s: SequenceNumber::new(0),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(s.value(), 0);
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_event() {
        let Seal::Event { i, s, d } = (Seal::Event {
            i: make_prefixer(),
            s: SequenceNumber::new(1),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*i.code(), VerKeyCode::Ed25519);
        assert_eq!(s.value(), 1);
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_last() {
        let Seal::Last { i } = (Seal::Last { i: make_prefixer() }) else {
            unreachable!()
        };
        assert_eq!(*i.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn seal_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Seal>();
    }

    #[test]
    #[allow(clippy::panic, reason = "panics are expected in test assertions")]
    fn opaque_accepts_compact_objects() {
        for raw in [
            "{}",
            "{\"x\":1}",
            "{\"a\":\"b\",\"c\":[1,-2.5e+10,true,false,null],\"d\":{\"e\":[]}}",
            "{\"q\":\"say \\\"hi\\\"\\n\",\"u\":\"\\u00e9\"}",
            "{\"\":\"\"}",
            "{\"n\":-0}",
            "{\"t\":\"\\t\"}",
            "{\"a\":\"\u{1F600}\"}",
            "{\"a\":\"\\ud83d\\ude00\"}",
            "{\"e\":1e308}",
            "{\"z\":1e-1000}",
        ] {
            let seal = OpaqueSeal::new(raw.to_owned()).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(seal.as_str(), raw);
        }
    }

    type RejectCase = (&'static str, fn(&OpaqueSealError) -> bool);

    #[test]
    fn opaque_rejects_malformed_payloads() {
        use crate::keri::seal::OpaqueSealError as E;
        let cases: &[RejectCase] = &[
            ("", |e| matches!(e, E::NotAnObject)),
            ("[1]", |e| matches!(e, E::NotAnObject)),
            ("\"str\"", |e| matches!(e, E::NotAnObject)),
            ("{", |e| matches!(e, E::Truncated)),
            ("{\"a\":1", |e| matches!(e, E::Truncated)),
            ("{\"a\":\"unterminated", |e| matches!(e, E::Truncated)),
            ("{\"a\":1}x", |e| matches!(e, E::TrailingBytes { .. })),
            ("{\"a\":01}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\" :1}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":1,}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":\"\\x\"}", |e| matches!(e, E::InvalidEscape { .. })),
            ("{\"a\":\"\\u12g4\"}", |e| {
                matches!(e, E::InvalidEscape { .. })
            }),
            ("{\"a\":\u{0009}1}", |e| {
                matches!(e, E::UnexpectedByte { .. })
            }),
            ("{\"a\":1]", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":[1}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\"::1}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{,}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":\"\\ud800\"}", |e| {
                matches!(e, E::InvalidEscape { .. })
            }),
            ("{\"a\":\"\\udc00\"}", |e| {
                matches!(e, E::InvalidEscape { .. })
            }),
            ("{\"a\":\"\\ud83dx\"}", |e| {
                matches!(e, E::InvalidEscape { .. })
            }),
            ("{\"a\":-2.5e+1001}", |e| {
                matches!(e, E::NumberOutOfRange { .. })
            }),
            ("{\"a\":1e309}", |e| matches!(e, E::NumberOutOfRange { .. })),
        ];
        for (raw, is_expected) in cases {
            let err =
                OpaqueSeal::new((*raw).to_owned()).expect_err(&format!("{raw} must be rejected"));
            assert!(is_expected(&err), "{raw}: wrong error {err}");
        }
    }

    #[test]
    fn opaque_deep_nesting_is_iterative_not_recursive() {
        let depth = 20_000;
        let mut raw = String::from("{\"a\":");
        for _ in 0..depth {
            raw.push('[');
        }
        for _ in 0..depth {
            raw.push(']');
        }
        raw.push('}');
        let seal = OpaqueSeal::new(raw.clone()).unwrap();
        assert_eq!(seal.as_str(), raw);
    }

    #[test]
    fn seal_back_and_kind_carry_typed_fields() {
        let Seal::Back { bi, d } = (Seal::Back {
            bi: make_prefixer(),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*bi.code(), VerKeyCode::Ed25519);
        assert_eq!(*d.code(), DigestCode::Blake3_256);

        let Seal::Kind { t, d: kind_digest } = (Seal::Kind {
            t: make_verser(),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*t.code(), VerserCode::Tag7);
        assert_eq!(*kind_digest.code(), DigestCode::Blake3_256);
    }
}
