//! Codec-local compact-JSON object scanner.
//!
//! A byte-exact copy of the iterative object scanner (`#193` P3): a
//! codec-local [`OpaqueScan`] measures one complete compact-JSON object at
//! the start of a byte slice without materializing a `serde_json::Value`.
//! Depth costs heap (one container-kind entry per open bracket, bounded by
//! input length), never call stack, so adversarially deep anchors cannot
//! overflow the stack.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use core::ops::RangeInclusive;
use core::str::from_utf8;

use thiserror::Error;

/// Rejections from [`OpaqueScan::object_len`]'s compact-JSON object validation.
#[derive(Debug, Error)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum OpaqueScanError {
    /// The payload does not start with `{`.
    #[error("opaque anchor payload must be a JSON object")]
    NotAnObject,
    /// A byte that no compact-JSON production allows at its position
    /// (this includes any whitespace between tokens).
    #[error("unexpected byte at offset {offset} in opaque anchor payload")]
    UnexpectedByte {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// Input ended before the object closed.
    #[error("opaque anchor payload is truncated")]
    Truncated,
    /// An unescaped control character inside a string.
    #[error("control character at offset {offset} in opaque anchor string")]
    ControlCharacter {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// A malformed `\` escape inside a string.
    #[error("invalid escape sequence at offset {offset} in opaque anchor string")]
    InvalidEscape {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// Bytes remain after the object closed.
    #[error("trailing bytes after opaque anchor object at offset {offset}")]
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
    #[error("number out of range at offset {offset} in opaque anchor payload")]
    NumberOutOfRange {
        /// Byte offset of the number's first byte.
        offset: usize,
    },
    /// A position computation overflowed `usize`.
    #[error("offset overflow while scanning opaque anchor payload")]
    OffsetOverflow,
}

/// Codec-local scanner for one complete compact-JSON object.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct OpaqueScan;

impl OpaqueScan {
    /// Byte length of one complete compact-JSON object at the start of `input`.
    ///
    /// Iterative — nesting depth costs heap (one container-kind entry per open
    /// bracket, bounded by input length), never call stack, so adversarially
    /// deep anchors cannot overflow the stack.
    ///
    /// # Errors
    ///
    /// Returns [`OpaqueScanError`] if `input` does not begin with a complete,
    /// well-formed compact-JSON object.
    pub(crate) fn object_len(input: &[u8]) -> Result<usize, OpaqueScanError> {
        if input.first() != Some(&b'{') {
            return Err(OpaqueScanError::NotAnObject);
        }
        // `true` = object, `false` = array.
        let mut containers = vec![true];
        let mut pos = 1_usize;
        let mut state = ScanState::FirstKey;
        loop {
            match state {
                ScanState::FirstKey | ScanState::NextKey => {
                    match input.get(pos).ok_or(OpaqueScanError::Truncated)? {
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
                                return Err(OpaqueScanError::UnexpectedByte { offset: pos });
                            }
                            pos = bump(pos)?;
                            state = ScanState::Value;
                        }
                        _ => return Err(OpaqueScanError::UnexpectedByte { offset: pos }),
                    }
                }
                ScanState::Value => {
                    (pos, state) = scan_value_start(input, pos, &mut containers)?;
                }
                ScanState::FirstValue => {
                    if input.get(pos).ok_or(OpaqueScanError::Truncated)? == &b']' {
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
                    let byte = *input.get(pos).ok_or(OpaqueScanError::Truncated)?;
                    // Invariant: the loop returns the moment `containers` empties,
                    // so a container is always open here; `Truncated` is a
                    // defensive mapping, not a reachable state.
                    let in_object = *containers.last().ok_or(OpaqueScanError::Truncated)?;
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
                        _ => return Err(OpaqueScanError::UnexpectedByte { offset: pos }),
                    }
                }
            }
        }
    }
}

fn bump(pos: usize) -> Result<usize, OpaqueScanError> {
    pos.checked_add(1).ok_or(OpaqueScanError::OffsetOverflow)
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

/// Dispatch on a value's first byte (cursor at the start of a JSON value):
/// descend into a container (recording its kind) or scan a complete scalar.
/// Returns the next cursor position and scanner state.
fn scan_value_start(
    input: &[u8],
    pos: usize,
    containers: &mut Vec<bool>,
) -> Result<(usize, ScanState), OpaqueScanError> {
    match input.get(pos).ok_or(OpaqueScanError::Truncated)? {
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
        _ => Err(OpaqueScanError::UnexpectedByte { offset: pos }),
    }
}

/// Advance past one JSON string (cursor on the opening `"`); returns the
/// position after the closing `"`. Escapes are validated, not decoded.
fn scan_string(input: &[u8], start: usize) -> Result<usize, OpaqueScanError> {
    let mut pos = bump(start)?;
    loop {
        let byte = *input.get(pos).ok_or(OpaqueScanError::Truncated)?;
        match byte {
            b'"' => return bump(pos),
            b'\\' => {
                let esc_at = bump(pos)?;
                let esc = *input.get(esc_at).ok_or(OpaqueScanError::Truncated)?;
                pos = match esc {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => bump(esc_at)?,
                    b'u' => scan_unicode_escape(input, esc_at)?,
                    _ => return Err(OpaqueScanError::InvalidEscape { offset: esc_at }),
                };
            }
            b if b < 0x20 => return Err(OpaqueScanError::ControlCharacter { offset: pos }),
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
fn scan_unicode_escape(input: &[u8], u_at: usize) -> Result<usize, OpaqueScanError> {
    let (after_high, unit) = scan_hex4(input, bump(u_at)?)?;
    if LOW_SURROGATES.contains(&unit) {
        return Err(OpaqueScanError::InvalidEscape { offset: u_at });
    }
    if !HIGH_SURROGATES.contains(&unit) {
        return Ok(after_high);
    }
    if input.get(after_high) != Some(&b'\\') {
        return Err(OpaqueScanError::InvalidEscape { offset: after_high });
    }
    let low_u_at = bump(after_high)?;
    if input.get(low_u_at) != Some(&b'u') {
        return Err(OpaqueScanError::InvalidEscape { offset: low_u_at });
    }
    let (after_low, low_unit) = scan_hex4(input, bump(low_u_at)?)?;
    if LOW_SURROGATES.contains(&low_unit) {
        Ok(after_low)
    } else {
        Err(OpaqueScanError::InvalidEscape { offset: low_u_at })
    }
}

/// Read four hex digits (cursor on the first digit); returns the position
/// after them and the decoded UTF-16 code unit.
fn scan_hex4(input: &[u8], start: usize) -> Result<(usize, u32), OpaqueScanError> {
    let mut unit = 0_u32;
    let mut pos = start;
    for _ in 0_u8..4 {
        let byte = *input.get(pos).ok_or(OpaqueScanError::Truncated)?;
        let digit = char::from(byte)
            .to_digit(16)
            .ok_or(OpaqueScanError::InvalidEscape { offset: pos })?;
        unit = (unit << 4) | digit;
        pos = bump(pos)?;
    }
    Ok((pos, unit))
}

/// Advance past one JSON number (cursor on `-` or a digit); returns the
/// position after its last byte. Numbers whose magnitude overflows an
/// IEEE-754 double are rejected, matching `serde_json`'s `number out of
/// range` so every accepted payload reparses.
fn scan_number(input: &[u8], start: usize) -> Result<usize, OpaqueScanError> {
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
        _ => return Err(OpaqueScanError::UnexpectedByte { offset: pos }),
    }
    if input.get(pos) == Some(&b'.') {
        pos = bump(pos)?;
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(OpaqueScanError::UnexpectedByte { offset: pos });
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
            return Err(OpaqueScanError::UnexpectedByte { offset: pos });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos = bump(pos)?;
        }
    }
    let bytes = input.get(start..pos).ok_or(OpaqueScanError::Truncated)?;
    // The scanned bytes are ASCII sign/digit/dot/exponent by construction and
    // JSON's number grammar is a subset of Rust's f64 grammar, so both `else`
    // branches are defensive mappings, not reachable states.
    let Ok(text) = from_utf8(bytes) else {
        return Err(OpaqueScanError::UnexpectedByte { offset: start });
    };
    let Ok(value) = text.parse::<f64>() else {
        return Err(OpaqueScanError::NumberOutOfRange { offset: start });
    };
    if value.is_finite() {
        Ok(pos)
    } else {
        Err(OpaqueScanError::NumberOutOfRange { offset: start })
    }
}

/// Expect the exact literal at `pos`; returns the position after it.
fn scan_lit(input: &[u8], pos: usize, lit: &'static [u8]) -> Result<usize, OpaqueScanError> {
    let end = pos
        .checked_add(lit.len())
        .ok_or(OpaqueScanError::OffsetOverflow)?;
    match input.get(pos..end) {
        Some(bytes) if bytes == lit => Ok(end),
        Some(_) => Err(OpaqueScanError::UnexpectedByte { offset: pos }),
        None => Err(OpaqueScanError::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    #[test]
    fn rejects_malformed_payloads() {
        // The full set of malformed-object cases from the keri-events
        // `opaque_rejects_malformed_payloads` test, minus `{"a":1}x`: that
        // input is a *well-formed* object with a trailing byte, which the
        // scanner measures rather than rejects (the `TrailingBytes` check is
        // the caller's, via `len != input.len()`). It is covered by
        // `measures_first_object_and_leaves_trailing_bytes` below. Each case
        // asserts its exact rejection variant, mirroring the original.
        type RejectCase = (&'static [u8], fn(&OpaqueScanError) -> bool);
        let cases: &[RejectCase] = &[
            (b"", |e| matches!(e, OpaqueScanError::NotAnObject)),
            (b"[1]", |e| matches!(e, OpaqueScanError::NotAnObject)),
            (b"\"str\"", |e| matches!(e, OpaqueScanError::NotAnObject)),
            (b"{", |e| matches!(e, OpaqueScanError::Truncated)),
            (b"{\"a\":1", |e| matches!(e, OpaqueScanError::Truncated)),
            (b"{\"a\":\"unterminated", |e| {
                matches!(e, OpaqueScanError::Truncated)
            }),
            (b"{\"a\":01}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\" :1}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\":1,}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\":\"\\x\"}", |e| {
                matches!(e, OpaqueScanError::InvalidEscape { .. })
            }),
            (b"{\"a\":\"\\u12g4\"}", |e| {
                matches!(e, OpaqueScanError::InvalidEscape { .. })
            }),
            (b"{\"a\":\t1}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\":1]", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\":[1}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\":}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\"::1}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{,}", |e| {
                matches!(e, OpaqueScanError::UnexpectedByte { .. })
            }),
            (b"{\"a\":\"\\ud800\"}", |e| {
                matches!(e, OpaqueScanError::InvalidEscape { .. })
            }),
            (b"{\"a\":\"\\udc00\"}", |e| {
                matches!(e, OpaqueScanError::InvalidEscape { .. })
            }),
            (b"{\"a\":\"\\ud83dx\"}", |e| {
                matches!(e, OpaqueScanError::InvalidEscape { .. })
            }),
            (b"{\"a\":-2.5e+1001}", |e| {
                matches!(e, OpaqueScanError::NumberOutOfRange { .. })
            }),
            (b"{\"a\":1e309}", |e| {
                matches!(e, OpaqueScanError::NumberOutOfRange { .. })
            }),
        ];
        for (bad, is_expected) in cases {
            let err =
                OpaqueScan::object_len(bad).expect_err(&format!("{bad:?} must be rejected"));
            assert!(is_expected(&err), "{bad:?}: wrong error {err}");
        }
    }

    #[test]
    fn accepts_and_measures_compact_objects() {
        // Positive-path boundary coverage mirroring the keri-events
        // `opaque_accepts_compact_objects` test: empty object, empty string,
        // negative zero, both `\u` escape arms, and `1e308` (the accepted
        // side of the finite/infinite f64 boundary whose rejected side
        // `1e309` is exercised above).
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
            assert_eq!(
                OpaqueScan::object_len(raw.as_bytes()).unwrap(),
                raw.len(),
                "{raw} must be accepted and fully measured",
            );
        }
    }

    #[test]
    fn measures_first_object_and_leaves_trailing_bytes() {
        // `{"a":1}x`: one complete object (7 bytes) followed by a stray byte.
        // `object_len` reports the object's length; detecting the trailing
        // byte is the caller's job (`len != input.len()`).
        let with_trailing = b"{\"a\":1}x";
        let len = OpaqueScan::object_len(with_trailing).unwrap();
        assert_eq!(len, 7);
        assert!(len < with_trailing.len());
    }

    #[test]
    fn deep_nesting_is_iterative_not_recursive() {
        let depth = 20_000;
        let mut raw = String::from("{\"a\":");
        for _ in 0..depth {
            raw.push('[');
        }
        for _ in 0..depth {
            raw.push(']');
        }
        raw.push('}');
        assert_eq!(OpaqueScan::object_len(raw.as_bytes()).unwrap(), raw.len());
    }
}
