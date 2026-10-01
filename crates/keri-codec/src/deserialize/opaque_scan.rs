//! Codec-local compact-JSON object scanner.
//!
//! Moved from `keri-events` (#193 P3) so JSON validation lives in the crate
//! that owns JSON: [`OpaqueScan`] measures one complete compact-JSON object
//! at the start of a byte slice without materializing a `serde_json::Value`.
//! Depth costs heap (one container-kind entry per open bracket, bounded by
//! input length), never call stack, so adversarially deep anchors cannot
//! overflow the stack.

#[cfg(feature = "alloc")]
use alloc::{collections::BTreeSet, string::String, vec, vec::Vec};
use core::ops::RangeInclusive;
use core::str::from_utf8;

use crate::codec::scanner::JsonBudget;
use crate::error::OpaqueScanError;

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
    pub(crate) fn object_len(
        input: &[u8],
        budget: &mut JsonBudget,
    ) -> Result<usize, OpaqueScanError> {
        if input.first() != Some(&b'{') {
            return Err(OpaqueScanError::NotAnObject);
        }
        if !budget.enter() {
            return Err(OpaqueScanError::DepthLimit {
                offset: 0,
                limit: budget.max_depth,
            });
        }
        // `true` = object, `false` = array.
        let mut containers = vec![true];
        let mut keys = vec![BTreeSet::new()];
        let mut pos = 1_usize;
        let mut state = ScanState::FirstKey;
        loop {
            match state {
                ScanState::FirstKey | ScanState::NextKey => {
                    match input.get(pos).ok_or(OpaqueScanError::Truncated)? {
                        b'}' if matches!(state, ScanState::FirstKey) => {
                            pos = bump(pos)?;
                            containers.pop();
                            keys.pop();
                            budget.leave();
                            if containers.is_empty() {
                                return Ok(pos);
                            }
                            state = ScanState::AfterValue;
                        }
                        b'"' => {
                            pos = scan_member_key(input, pos, &mut keys, budget)?;
                            state = ScanState::Value;
                        }
                        _ => return Err(OpaqueScanError::UnexpectedByte { offset: pos }),
                    }
                }
                ScanState::Value => {
                    (pos, state) =
                        scan_value_start(input, pos, &mut containers, &mut keys, budget)?;
                }
                ScanState::FirstValue => {
                    if input.get(pos).ok_or(OpaqueScanError::Truncated)? == &b']' {
                        pos = bump(pos)?;
                        containers.pop();
                        keys.pop();
                        budget.leave();
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
                            keys.pop();
                            budget.leave();
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

fn scan_member_key(
    input: &[u8],
    pos: usize,
    keys: &mut [BTreeSet<String>],
    budget: &mut JsonBudget,
) -> Result<usize, OpaqueScanError> {
    if !budget.field() {
        return Err(OpaqueScanError::FieldLimit {
            offset: pos,
            limit: budget.max_fields,
        });
    }
    let after_key = scan_string(input, pos)?;
    let key = decode_key(input, pos, after_key)?;
    let seen = keys.last_mut().ok_or(OpaqueScanError::Truncated)?;
    if !seen.insert(key) {
        return Err(OpaqueScanError::DuplicateKey { offset: pos });
    }
    if input.get(after_key) != Some(&b':') {
        return Err(OpaqueScanError::UnexpectedByte { offset: after_key });
    }
    bump(after_key)
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
    keys: &mut Vec<BTreeSet<String>>,
    budget: &mut JsonBudget,
) -> Result<(usize, ScanState), OpaqueScanError> {
    match input.get(pos).ok_or(OpaqueScanError::Truncated)? {
        b'{' => {
            if !budget.enter() {
                return Err(OpaqueScanError::DepthLimit {
                    offset: pos,
                    limit: budget.max_depth,
                });
            }
            containers.push(true);
            keys.push(BTreeSet::new());
            Ok((bump(pos)?, ScanState::FirstKey))
        }
        b'[' => {
            if !budget.enter() {
                return Err(OpaqueScanError::DepthLimit {
                    offset: pos,
                    limit: budget.max_depth,
                });
            }
            containers.push(false);
            keys.push(BTreeSet::new());
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

/// Decode a validated JSON object key solely for uniqueness checking. The
/// opaque payload itself remains byte-for-byte untouched and may use any RFC
/// 8259 escape spelling, including surrogate pairs. Equal decoded names must
/// not be interpreted differently by two downstream JSON consumers.
fn decode_key(input: &[u8], start: usize, end: usize) -> Result<String, OpaqueScanError> {
    let content_start = bump(start)?;
    let content_end = end.checked_sub(1).ok_or(OpaqueScanError::Truncated)?;
    let mut result = String::new();
    let mut chunk_start = content_start;
    let mut pos = content_start;
    while pos < content_end {
        if input.get(pos) != Some(&b'\\') {
            pos = bump(pos)?;
            continue;
        }
        let chunk = input
            .get(chunk_start..pos)
            .ok_or(OpaqueScanError::Truncated)?;
        result.push_str(
            from_utf8(chunk).map_err(|_| OpaqueScanError::UnexpectedByte {
                offset: chunk_start,
            })?,
        );
        let esc_at = bump(pos)?;
        let esc = *input.get(esc_at).ok_or(OpaqueScanError::Truncated)?;
        let (decoded, after) = match esc {
            b'"' => ('"', bump(esc_at)?),
            b'\\' => ('\\', bump(esc_at)?),
            b'/' => ('/', bump(esc_at)?),
            b'b' => ('\u{0008}', bump(esc_at)?),
            b'f' => ('\u{000c}', bump(esc_at)?),
            b'n' => ('\n', bump(esc_at)?),
            b'r' => ('\r', bump(esc_at)?),
            b't' => ('\t', bump(esc_at)?),
            b'u' => {
                let (after_high, high) = scan_hex4(input, bump(esc_at)?)?;
                let (code_point, after) = if HIGH_SURROGATES.contains(&high) {
                    let low_start = after_high
                        .checked_add(2)
                        .ok_or(OpaqueScanError::OffsetOverflow)?;
                    let (after_low, low) = scan_hex4(input, low_start)?;
                    if !LOW_SURROGATES.contains(&low) {
                        return Err(OpaqueScanError::InvalidEscape { offset: esc_at });
                    }
                    (
                        0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00),
                        after_low,
                    )
                } else {
                    (high, after_high)
                };
                let scalar = char::from_u32(code_point)
                    .ok_or(OpaqueScanError::InvalidEscape { offset: esc_at })?;
                (scalar, after)
            }
            _ => return Err(OpaqueScanError::InvalidEscape { offset: esc_at }),
        };
        result.push(decoded);
        pos = after;
        chunk_start = after;
    }
    let chunk = input
        .get(chunk_start..content_end)
        .ok_or(OpaqueScanError::Truncated)?;
    result.push_str(
        from_utf8(chunk).map_err(|_| OpaqueScanError::UnexpectedByte {
            offset: chunk_start,
        })?,
    );
    Ok(result)
}

/// Advance past one JSON string (cursor on the opening `"`); returns the
/// position after the closing `"`. Escapes are validated, not decoded.
fn scan_string(input: &[u8], start: usize) -> Result<usize, OpaqueScanError> {
    let mut pos = bump(start)?;
    loop {
        let byte = *input.get(pos).ok_or(OpaqueScanError::Truncated)?;
        match byte {
            b'"' => {
                let content_start = bump(start)?;
                let content = input
                    .get(content_start..pos)
                    .ok_or(OpaqueScanError::Truncated)?;
                from_utf8(content).map_err(|error| OpaqueScanError::UnexpectedByte {
                    offset: content_start.saturating_add(error.valid_up_to()),
                })?;
                return bump(pos);
            }
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

/// Advance past one RFC 8259 JSON number (cursor on `-` or a digit); returns
/// the position after its last byte. The anchor is opaque signed data, so
/// imposing an `f64` magnitude limit would reject valid exact integers that
/// the pinned reference can emit.
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
    Ok(pos)
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

    #[test]
    fn work_budget_rejects_many_keys_before_scanning_values() {
        let mut budget = JsonBudget::new(2, 3);
        let err = OpaqueScan::object_len(br#"{"a":0,"b":1,"c":2}"#, &mut budget)
            .expect_err("third object field exceeds the budget");
        assert!(matches!(err, OpaqueScanError::FieldLimit { limit: 2, .. }));
    }

    #[test]
    fn work_budget_rejects_deep_values_before_stack_growth() {
        let mut budget = JsonBudget::new(8, 2);
        let err = OpaqueScan::object_len(br#"{"a":[[0]]}"#, &mut budget)
            .expect_err("third container exceeds the budget");
        assert!(matches!(err, OpaqueScanError::DepthLimit { limit: 2, .. }));
    }
    use alloc::format;
    use alloc::string::String;

    #[test]
    fn rejects_malformed_payloads() {
        // The full set of malformed-object cases from the former keri-events
        // `opaque_rejects_malformed_payloads` test, minus `{"a":1}x`: that
        // input is a *well-formed* object with a trailing byte, which the
        // scanner measures rather than rejects (whole-input callers check
        // `len == input.len()` themselves). It is covered by
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
        ];
        for (bad, is_expected) in cases {
            let err = OpaqueScan::object_len(bad, &mut JsonBudget::unlimited())
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(is_expected(&err), "{bad:?}: wrong error {err}");
        }
    }

    #[test]
    fn accepts_and_measures_compact_objects() {
        // Positive-path boundary coverage mirroring the keri-events
        // `opaque_accepts_compact_objects` test: empty object, empty string,
        // negative zero, both `\u` escape arms, and numbers beyond the f64
        // range (they remain exact opaque signed bytes).
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
            "{\"z\":1e309}",
            "{\"z\":-2.5e+1001}",
        ] {
            assert_eq!(
                OpaqueScan::object_len(raw.as_bytes(), &mut JsonBudget::unlimited()).unwrap(),
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
        let len = OpaqueScan::object_len(with_trailing, &mut JsonBudget::unlimited()).unwrap();
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
        assert_eq!(
            OpaqueScan::object_len(raw.as_bytes(), &mut JsonBudget::unlimited()).unwrap(),
            raw.len()
        );
    }

    #[test]
    fn rejects_duplicate_keys_including_escaped_aliases() {
        for raw in [
            r#"{"x":1,"x":2}"#,
            r#"{"x":1,"\u0078":2}"#,
            r#"{"child":{"x":1,"x":2}}"#,
        ] {
            assert!(
                matches!(
                    OpaqueScan::object_len(raw.as_bytes(), &mut JsonBudget::unlimited()),
                    Err(OpaqueScanError::DuplicateKey { .. })
                ),
                "{raw} must reject ambiguous keys"
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8_in_opaque_values() {
        assert!(matches!(
            OpaqueScan::object_len(b"{\"x\":\"\xff\"}", &mut JsonBudget::unlimited()),
            Err(OpaqueScanError::UnexpectedByte { .. })
        ));
    }
}
