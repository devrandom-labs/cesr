//! The strict canonical-JSON reader: a single-pass cursor over the raw
//! event bytes (the der `Reader` analogue). Accepts exactly the canonical
//! language — compact, fixed tokens kept distinct from payload JSON — and reports
//! every rejection as a typed, offset-carrying [`DeserializeError`].

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::Cow, collections::BTreeSet, string::String, vec, vec::Vec};
use core::ops::Range;
use core::str;

use crate::error::{CodecError, DeserializeError, InternalError};
use crate::traits::JsonLimits;

/// A borrowed string value plus its byte span in the raw input.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct Spanned<'a> {
    pub(crate) value: &'a str,
    pub(crate) span: Range<usize>,
}

/// Iterative-descent states for [`Scanner::canonical_value`]: where the
/// cursor sits inside the value being validated-and-skipped. Mirrors the
/// opaque-anchor scanner's state machine, with the strict canonical scalar
/// grammar ([`Scanner::string`], [`Scanner::integer`]) in place of the
/// permissive compact-JSON scans.
enum ValueScanState {
    /// Just after `{`: a key string or `}`.
    FirstMember,
    /// Just after `,` inside an object: a key string.
    NextMember,
    /// Start of any value.
    Value,
    /// Just after `[`: a value or `]`.
    FirstItem,
    /// Just after a complete value: `,` or the container's closer.
    AfterValue,
}

/// Cumulative JSON work charged by the existing strict and opaque scanners.
/// A field is charged before its key is decoded and a container before its
/// stack entry is allocated. One budget follows a whole typed body.
#[derive(Clone, Copy)]
pub(crate) struct JsonBudget {
    pub(crate) max_fields: usize,
    pub(crate) max_depth: usize,
    fields: usize,
    depth: usize,
}

impl JsonBudget {
    pub(crate) const fn new(max_fields: usize, max_depth: usize) -> Self {
        Self {
            max_fields,
            max_depth,
            fields: 0,
            depth: 0,
        }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX)
    }

    pub(crate) const fn field(&mut self) -> bool {
        if self.fields >= self.max_fields {
            return false;
        }
        self.fields += 1;
        true
    }

    pub(crate) const fn enter(&mut self) -> bool {
        if self.depth >= self.max_depth {
            return false;
        }
        self.depth += 1;
        true
    }

    pub(crate) const fn leave(&mut self) {
        self.depth -= 1;
    }
}

impl From<JsonLimits> for JsonBudget {
    fn from(limits: JsonLimits) -> Self {
        Self::new(limits.max_fields, limits.max_depth)
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct Scanner<'a> {
    pub(crate) input: &'a [u8],
    pub(crate) pos: usize,
    pub(crate) budget: JsonBudget,
}

impl<'a> Scanner<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self::with_budget(input, JsonBudget::unlimited())
    }

    pub(crate) const fn with_budget(input: &'a [u8], budget: JsonBudget) -> Self {
        Self {
            input,
            pos: 0,
            budget,
        }
    }

    pub(crate) fn err_at(&self, offset: usize, expected: &'static str) -> DeserializeError {
        DeserializeError::NonCanonical {
            offset,
            expected,
            found: self.input.get(offset).copied(),
        }
    }

    pub(crate) fn err(&self, expected: &'static str) -> DeserializeError {
        self.err_at(self.pos, expected)
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Consume `lit` if it is next; charge its fixed JSON field and container
    /// tokens before advancing. These literals are part of the typed grammar,
    /// so no input is rescanned to enforce the budget.
    pub(crate) fn take_lit(&mut self, lit: &'static str) -> Result<bool, DeserializeError> {
        let Some(end) = self.pos.checked_add(lit.len()) else {
            return Ok(false);
        };
        if self.input.get(self.pos..end) == Some(lit.as_bytes()) {
            self.charge_literal(lit)?;
            self.pos = end;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn charge_literal(&mut self, lit: &'static str) -> Result<(), DeserializeError> {
        let bytes = lit.as_bytes();
        for (index, byte) in bytes.iter().copied().enumerate() {
            let offset = self.pos.saturating_add(index);
            match byte {
                b'{' | b'[' if !self.budget.enter() => {
                    return Err(DeserializeError::JsonDepthLimit {
                        offset,
                        limit: self.budget.max_depth,
                    });
                }
                b'}' | b']' if self.budget.depth == 0 => {
                    return Err(self.err_at(offset, "balanced JSON container"));
                }
                b'}' | b']' => self.budget.leave(),
                b'"' if bytes.get(index + 1) == Some(&b':') && !self.budget.field() => {
                    return Err(DeserializeError::JsonFieldLimit {
                        offset,
                        limit: self.budget.max_fields,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// On mismatch the error reports the literal's START offset with the byte
    /// found there; the `expected` field carries the whole literal.
    pub(crate) fn expect(&mut self, lit: &'static str) -> Result<(), DeserializeError> {
        if self.take_lit(lit)? {
            Ok(())
        } else {
            Err(self.err(lit))
        }
    }

    /// Validates and captures the span of one canonical JSON *object* value.
    ///
    /// The cursor must sit at the value's `{`; on success it sits just past
    /// the matching `}`. Used for verbatim SAD blocks (ACDC sections, the exn
    /// embeds map), whose payloads are preserved byte-for-byte — the walk
    /// enforces canonicality without re-serializing.
    pub(crate) fn object_value_span(&mut self) -> Result<Range<usize>, CodecError> {
        if self.peek() != Some(b'{') {
            return Err(self.err("JSON object").into());
        }
        let start = self.pos;
        let mut containers = Vec::new();
        self.canonical_value(&mut containers)?;
        Ok(start..self.pos)
    }

    /// Capture any canonical JSON value without materializing a value tree.
    /// Used by selected routed payload readers to skip unrelated state fields.
    pub(crate) fn value_span(&mut self) -> Result<Range<usize>, CodecError> {
        let start = self.pos;
        let mut containers = Vec::new();
        self.canonical_value(&mut containers)?;
        Ok(start..self.pos)
    }

    fn advance(&mut self, by: usize, expected: &'static str) -> Result<(), DeserializeError> {
        self.pos = self.pos.checked_add(by).ok_or_else(|| self.err(expected))?;
        Ok(())
    }

    /// A canonical JSON string: no escapes, no control characters, UTF-8.
    ///
    /// Returns [`CodecError`] because the span guards below are internal
    /// invariants ([`InternalError::EventLayout`]), a distinct domain from the
    /// [`DeserializeError`] grammar rejections; `?` unifies both under the
    /// codec-boundary union.
    pub(crate) fn string(&mut self) -> Result<Spanned<'a>, CodecError> {
        self.expect("\"")?;
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') => {
                    return Err(self
                        .err("unescaped string byte (canonical values never require escaping)")
                        .into());
                }
                Some(b) if b < 0x20 => {
                    return Err(self
                        .err("unescaped string byte (no control characters)")
                        .into());
                }
                Some(_) => self.advance(1, "string byte")?,
                None => return Err(self.err("closing '\"'").into()),
            }
        }
        let span = start..self.pos;
        let bytes = self
            .input
            .get(span.clone())
            .ok_or(InternalError::EventLayout("string span out of bounds"))?;
        let value = str::from_utf8(bytes).map_err(|e| -> CodecError {
            start.checked_add(e.valid_up_to()).map_or_else(
                || InternalError::EventLayout("UTF-8 error offset overflow").into(),
                |offset| self.err_at(offset, "UTF-8 string value").into(),
            )
        })?;
        self.expect("\"")?;
        Ok(Spanned { value, span })
    }

    /// Read a generic JSON string in the pinned V1 writer's compact form.
    /// The returned span and value are the original *encoded* bytes between
    /// quotes. Fixed CESR fields deliberately keep using [`Self::string`].
    /// The writer emits raw UTF-8 and only escapes quotes, backslashes and
    /// controls. Escaped `/`, printable Unicode, surrogate pairs, and long
    /// forms for controls with short escapes are valid JSON but not that
    /// writer's canonical byte spelling.
    pub(crate) fn json_string(&mut self) -> Result<Spanned<'a>, CodecError> {
        self.expect("\"")?;
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') => {
                    self.advance(1, "JSON escape")?;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.advance(1, "JSON escape")?;
                        }
                        Some(b'u') => {
                            self.advance(1, "JSON control escape")?;
                            self.expect("00")?;
                            let high = self.hex_digit()?;
                            let low = self.hex_digit()?;
                            let control = (high << 4) | low;
                            if control >= 0x20
                                || matches!(control, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d)
                            {
                                return Err(self
                                    .err_at(
                                        self.pos.saturating_sub(4),
                                        "writer-form JSON control escape",
                                    )
                                    .into());
                            }
                        }
                        _ => return Err(self.err("writer-form JSON escape").into()),
                    }
                }
                Some(b) if b < 0x20 => return Err(self.err("escaped JSON control").into()),
                Some(_) => self.advance(1, "JSON string byte")?,
                None => return Err(self.err("closing '\"'").into()),
            }
        }
        let span = start..self.pos;
        let bytes = self
            .input
            .get(span.clone())
            .ok_or(InternalError::EventLayout("JSON string span out of bounds"))?;
        let value = str::from_utf8(bytes)
            .map_err(|e| self.err_at(start.saturating_add(e.valid_up_to()), "UTF-8 JSON string"))?;
        self.expect("\"")?;
        Ok(Spanned { value, span })
    }

    /// Decode a human JSON string after validating its exact wire spelling.
    /// Unescaped text borrows from the signed body; escaped text owns only the
    /// decoded value. The signed body and SAID spans are never rewritten.
    pub(crate) fn json_text(&mut self) -> Result<Cow<'a, str>, CodecError> {
        let encoded = self.json_string()?.value;
        if !encoded.as_bytes().contains(&b'\\') {
            return Ok(Cow::Borrowed(encoded));
        }
        let mut decoded = String::with_capacity(encoded.len());
        let mut tail = encoded;
        while let Some(at) = tail.as_bytes().iter().position(|byte| *byte == b'\\') {
            decoded.push_str(&tail[..at]);
            let escape = tail
                .as_bytes()
                .get(at + 1)
                .copied()
                .ok_or(InternalError::EventLayout(
                    "validated JSON escape was truncated",
                ))?;
            let (value, width) = match escape {
                b'"' => ('"', 2),
                b'\\' => ('\\', 2),
                b'b' => ('\u{0008}', 2),
                b'f' => ('\u{000c}', 2),
                b'n' => ('\n', 2),
                b'r' => ('\r', 2),
                b't' => ('\t', 2),
                b'u' => {
                    let hex =
                        tail.as_bytes()
                            .get(at + 4..at + 6)
                            .ok_or(InternalError::EventLayout(
                                "validated control escape was truncated",
                            ))?;
                    let high = Self::hex_value(hex[0]).ok_or(InternalError::EventLayout(
                        "validated control escape has invalid hex",
                    ))?;
                    let low = Self::hex_value(hex[1]).ok_or(InternalError::EventLayout(
                        "validated control escape has invalid hex",
                    ))?;
                    (char::from((high << 4) | low), 6)
                }
                _ => return Err(InternalError::EventLayout("invalid validated JSON escape").into()),
            };
            decoded.push(value);
            tail = tail.get(at + width..).ok_or(InternalError::EventLayout(
                "validated JSON escape width exceeds string",
            ))?;
        }
        decoded.push_str(tail);
        Ok(Cow::Owned(decoded))
    }

    const fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    fn hex_digit(&mut self) -> Result<u8, DeserializeError> {
        let value = self
            .peek()
            .and_then(Self::hex_value)
            .ok_or_else(|| self.err("lowercase JSON hex digit"))?;
        self.advance(1, "JSON hex digit")?;
        Ok(value)
    }

    /// RFC 8259 number syntax for arbitrary JSON payloads. No floating-point
    /// conversion: large exact integers are valid payload bytes. Fixed KERI
    /// count/threshold fields continue to use [`Self::integer`].
    pub(crate) fn json_number(&mut self) -> Result<&'a str, CodecError> {
        let start = self.pos;
        if self.take_lit("-")? && self.peek().is_none() {
            return Err(self.err("JSON number digit").into());
        }
        match self.peek() {
            Some(b'0') => {
                self.advance(1, "JSON number digit")?;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.err("no leading zero in JSON number").into());
                }
            }
            Some(b'1'..=b'9') => {
                self.advance(1, "JSON number digit")?;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.advance(1, "JSON number digit")?;
                }
            }
            _ => return Err(self.err("JSON number digit").into()),
        }
        if self.take_lit(".")? {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("fraction digit").into());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.advance(1, "fraction digit")?;
            }
        }
        if self.take_lit("e")? || self.take_lit("E")? {
            if !self.take_lit("+")? {
                self.take_lit("-")?;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("exponent digit").into());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.advance(1, "exponent digit")?;
            }
        }
        let bytes = self
            .input
            .get(start..self.pos)
            .ok_or(InternalError::EventLayout("JSON number span out of bounds"))?;
        str::from_utf8(bytes).map_err(|_| self.err_at(start, "ASCII JSON number").into())
    }

    /// A canonical JSON integer: `0` or `[1-9][0-9]*`. No sign, no leading
    /// zeros, no fraction or exponent.
    ///
    /// Returns [`CodecError`] for the same reason as [`Scanner::string`]: the
    /// span guard is an internal invariant, not a grammar rejection.
    pub(crate) fn integer(&mut self) -> Result<&'a str, CodecError> {
        let start = self.pos;
        match self.peek() {
            Some(b'0') => {
                self.advance(1, "digit")?;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.err("no leading zeros in canonical integer").into());
                }
            }
            Some(b'1'..=b'9') => {
                self.advance(1, "digit")?;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.advance(1, "digit")?;
                }
            }
            _ => return Err(self.err("digit").into()),
        }
        let bytes = self
            .input
            .get(start..self.pos)
            .ok_or(InternalError::EventLayout("integer span out of bounds"))?;
        // Defensively unreachable: every scanned byte is 0x30–0x39 by construction.
        str::from_utf8(bytes).map_err(|_| self.err_at(start, "ASCII integer").into())
    }

    /// The input must be fully consumed.
    pub(crate) fn finish(&self) -> Result<(), DeserializeError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(self.err("end of input"))
        }
    }

    /// Validate-and-skip one canonical JSON value of any type: scalar,
    /// object, or array. The container walk is iterative — one
    /// container-kind entry per open bracket on `containers`, bounded by
    /// input length, never call stack — so adversarially deep SADs cannot
    /// overflow the stack. Scalars use the generic JSON grammar (including
    /// writer-form escapes and RFC numbers); fixed CESR fields have their
    /// separate strict scans. Object keys are unique at every depth. No
    /// whitespace is accepted.
    ///
    /// `containers` is caller-owned scratch, reusable across calls. The walk
    /// consumes exactly one complete value and stops, leaving the cursor at
    /// the first byte after it.
    ///
    /// Returns [`CodecError`] for the same reason as [`Scanner::string`]:
    /// the container-stack guard is an internal invariant, not a grammar
    /// rejection.
    pub(crate) fn canonical_value(&mut self, containers: &mut Vec<bool>) -> Result<(), CodecError> {
        let base = containers.len();
        let mut keys: Vec<BTreeSet<&'a str>> = Vec::new();
        let mut state = ValueScanState::Value;
        loop {
            state = match state {
                ValueScanState::Value => self.canonical_value_start(containers, &mut keys)?,
                ValueScanState::FirstMember => match self.peek() {
                    Some(b'}') => {
                        self.expect("}")?;
                        Self::pop_container(containers, &mut keys);
                        if containers.len() == base {
                            return Ok(());
                        }
                        ValueScanState::AfterValue
                    }
                    Some(b'"') => {
                        self.json_key(&mut keys)?;
                        self.expect(":")?;
                        ValueScanState::Value
                    }
                    _ => return Err(self.err("key string").into()),
                },
                ValueScanState::NextMember => match self.peek() {
                    Some(b'"') => {
                        self.json_key(&mut keys)?;
                        self.expect(":")?;
                        ValueScanState::Value
                    }
                    _ => return Err(self.err("key string").into()),
                },
                ValueScanState::FirstItem => match self.peek() {
                    Some(b']') => {
                        self.expect("]")?;
                        Self::pop_container(containers, &mut keys);
                        if containers.len() == base {
                            return Ok(());
                        }
                        ValueScanState::AfterValue
                    }
                    _ => ValueScanState::Value,
                },
                ValueScanState::AfterValue => {
                    if containers.len() == base {
                        // The value was a scalar (no frame pushed): nothing
                        // past it belongs to this walk.
                        return Ok(());
                    }
                    match self.peek() {
                        Some(b',') => {
                            self.expect(",")?;
                            match containers.last() {
                                Some(true) => ValueScanState::NextMember,
                                Some(false) => ValueScanState::Value,
                                None => {
                                    return Err(InternalError::EventLayout(
                                        "container stack underflow",
                                    )
                                    .into());
                                }
                            }
                        }
                        Some(b'}') if containers.last() == Some(&true) => {
                            self.expect("}")?;
                            Self::pop_container(containers, &mut keys);
                            if containers.len() == base {
                                return Ok(());
                            }
                            ValueScanState::AfterValue
                        }
                        Some(b']') if containers.last() == Some(&false) => {
                            self.expect("]")?;
                            Self::pop_container(containers, &mut keys);
                            if containers.len() == base {
                                return Ok(());
                            }
                            ValueScanState::AfterValue
                        }
                        _ => return Err(self.err("',' or the container's closer").into()),
                    }
                }
            };
        }
    }

    /// Dispatch on a value's first byte: push a container kind or consume a
    /// complete canonical scalar. The bare literals are matched by
    /// [`Scanner::take_lit`] so a prefix like `tru` falls through to the
    /// rejection.
    fn canonical_value_start(
        &mut self,
        containers: &mut Vec<bool>,
        keys: &mut Vec<BTreeSet<&'a str>>,
    ) -> Result<ValueScanState, CodecError> {
        match self.peek() {
            Some(b'"') => {
                self.json_string()?;
                Ok(ValueScanState::AfterValue)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.json_number()?;
                Ok(ValueScanState::AfterValue)
            }
            Some(b'{') => {
                self.expect("{")?;
                containers.push(true);
                keys.push(BTreeSet::new());
                Ok(ValueScanState::FirstMember)
            }
            Some(b'[') => {
                self.expect("[")?;
                containers.push(false);
                keys.push(BTreeSet::new());
                Ok(ValueScanState::FirstItem)
            }
            _ => {
                if self.take_lit("true")? || self.take_lit("false")? || self.take_lit("null")? {
                    return Ok(ValueScanState::AfterValue);
                }
                Err(self.err("a canonical JSON value").into())
            }
        }
    }

    fn json_key(&mut self, keys: &mut [BTreeSet<&'a str>]) -> Result<(), CodecError> {
        if !self.budget.field() {
            return Err(DeserializeError::JsonFieldLimit {
                offset: self.pos,
                limit: self.budget.max_fields,
            }
            .into());
        }
        let key = self.json_string()?;
        let current = keys.last_mut().ok_or(InternalError::EventLayout(
            "JSON object key without container",
        ))?;
        if !current.insert(key.value) {
            return Err(self.err_at(key.span.start, "unique JSON key").into());
        }
        Ok(())
    }

    fn pop_container(containers: &mut Vec<bool>, keys: &mut Vec<BTreeSet<&'a str>>) {
        containers.pop();
        keys.pop();
    }

    /// Items of a canonical JSON array after the opening `[` and the
    /// empty-array check (`]`) have already been consumed — i.e. the cursor
    /// is positioned at the first item.
    ///
    /// Generic over the item error `E` (only bound: it lifts a
    /// [`DeserializeError`], which the `,`/`]` framing produces) so a closure
    /// scanning internal-fallible items (e.g. [`Scanner::string`], which yields
    /// [`CodecError`]) composes without forcing every list to that union.
    pub(crate) fn tail_list<T, E: From<DeserializeError>>(
        &mut self,
        mut item: impl FnMut(&mut Self) -> Result<T, E>,
    ) -> Result<Vec<T>, E> {
        let mut items = vec![item(self)?];
        loop {
            if self.take_lit("]")? {
                return Ok(items);
            }
            self.expect(",")?;
            items.push(item(self)?);
        }
    }

    /// A canonical JSON array `[item,item,...]` — no whitespace, no trailing
    /// comma; empty `[]` allowed. Generic over the item error `E` like
    /// [`Scanner::tail_list`].
    pub(crate) fn delimited_list<T, E: From<DeserializeError>>(
        &mut self,
        item: impl FnMut(&mut Self) -> Result<T, E>,
    ) -> Result<Vec<T>, E> {
        self.expect("[")?;
        if self.take_lit("]")? {
            return Ok(Vec::new());
        }
        self.tail_list(item)
    }

    /// A canonical JSON array of plain strings.
    pub(crate) fn string_array(&mut self) -> Result<Vec<&'a str>, CodecError> {
        self.delimited_list(|s| s.string().map(|sp| sp.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_value_charges_nested_fields_and_depth() {
        let raw = br#"{"a":{"b":0},"c":1}"#;
        let mut fields = Scanner::with_budget(raw, JsonBudget::new(2, 3));
        assert!(matches!(
            fields.object_value_span(),
            Err(CodecError::Deserialize(DeserializeError::JsonFieldLimit {
                limit: 2,
                ..
            }))
        ));

        let mut depth = Scanner::with_budget(raw, JsonBudget::new(3, 1));
        assert!(matches!(
            depth.object_value_span(),
            Err(CodecError::Deserialize(DeserializeError::JsonDepthLimit {
                limit: 1,
                ..
            }))
        ));
    }

    #[test]
    fn fixed_field_literals_charge_the_same_budget() {
        let mut sc = Scanner::with_budget(br#"{"v":0,"t":1}"#, JsonBudget::new(1, 1));
        sc.expect("{\"v\":").unwrap();
        sc.expect("0").unwrap();
        assert!(matches!(
            sc.expect(",\"t\":"),
            Err(DeserializeError::JsonFieldLimit { limit: 1, .. })
        ));

        let mut depth = Scanner::with_budget(br#"{"v":[]}"#, JsonBudget::new(1, 1));
        depth.expect("{\"v\":").unwrap();
        assert!(matches!(
            depth.expect("["),
            Err(DeserializeError::JsonDepthLimit { limit: 1, .. })
        ));
    }

    fn non_canonical_at(e: &CodecError) -> Option<(usize, &'static str)> {
        if let CodecError::Deserialize(DeserializeError::NonCanonical {
            offset, expected, ..
        }) = e
        {
            Some((*offset, expected))
        } else {
            None
        }
    }

    #[test]
    fn scanner_string_reads_value_and_span() {
        let mut sc = Scanner::new(b"\"abc\"rest");
        let s = sc.string().unwrap();
        assert_eq!(s.value, "abc");
        assert_eq!(s.span, 1..4);
        assert_eq!(sc.pos, 5);
    }

    #[test]
    fn scanner_string_rejects_escape() {
        let mut sc = Scanner::new(b"\"a\\u0030\"");
        let err = sc.string().unwrap_err();
        let (offset, _) = non_canonical_at(&err).expect("NonCanonical");
        assert_eq!(offset, 2, "the backslash byte is the violation");
    }

    #[test]
    fn scanner_string_rejects_control_char() {
        let mut sc = Scanner::new(b"\"a\x01b\"");
        assert!(matches!(
            sc.string(),
            Err(CodecError::Deserialize(DeserializeError::NonCanonical {
                offset: 2,
                ..
            }))
        ));
    }

    #[test]
    fn scanner_string_rejects_unterminated() {
        let mut sc = Scanner::new(b"\"abc");
        assert!(matches!(
            sc.string(),
            Err(CodecError::Deserialize(DeserializeError::NonCanonical {
                offset: 4,
                found: None,
                ..
            }))
        ));
    }

    #[test]
    fn scanner_string_rejects_non_utf8() {
        let mut sc = Scanner::new(b"\"\xFF\xFE\"");
        assert!(matches!(
            sc.string(),
            Err(CodecError::Deserialize(DeserializeError::NonCanonical {
                offset: 1,
                ..
            }))
        ));
    }

    #[test]
    fn scanner_string_utf8_error_reports_violating_byte() {
        let mut sc = Scanner::new(b"\"ab\xFF\"");
        assert!(matches!(
            sc.string(),
            Err(CodecError::Deserialize(DeserializeError::NonCanonical {
                offset: 3,
                found: Some(0xFF),
                ..
            }))
        ));
    }

    #[test]
    fn scanner_string_accepts_multibyte_utf8() {
        let input = "\"héllo\"".as_bytes();
        let mut sc = Scanner::new(input);
        let s = sc.string().unwrap();
        assert_eq!(s.value, "héllo");
        assert_eq!(s.span, 1..7);
        assert_eq!(&input[s.span.clone()], s.value.as_bytes());
    }

    #[test]
    fn scanner_string_empty_input_and_empty_value() {
        let mut sc = Scanner::new(b"");
        assert!(matches!(
            sc.string(),
            Err(CodecError::Deserialize(DeserializeError::NonCanonical {
                offset: 0,
                found: None,
                ..
            }))
        ));
        let mut sc2 = Scanner::new(b"\"\"");
        let s = sc2.string().unwrap();
        assert_eq!(s.value, "");
        assert_eq!(s.span, 1..1);
        sc2.finish().unwrap();
    }

    #[test]
    fn scanner_integer_grammar() {
        assert_eq!(Scanner::new(b"0,").integer().unwrap(), "0");
        assert_eq!(Scanner::new(b"10}").integer().unwrap(), "10");
        assert!(Scanner::new(b"01").integer().is_err(), "leading zero");
        assert!(Scanner::new(b"-1").integer().is_err(), "sign");
        assert!(Scanner::new(b"x").integer().is_err(), "non-digit");
    }

    #[test]
    fn scanner_integer_boundaries() {
        let mut empty = Scanner::new(b"");
        assert!(matches!(
            empty.integer(),
            Err(CodecError::Deserialize(DeserializeError::NonCanonical {
                offset: 0,
                found: None,
                ..
            }))
        ));
        let mut eof_terminated = Scanner::new(b"907");
        assert_eq!(eof_terminated.integer().unwrap(), "907");
        eof_terminated.finish().unwrap();
    }

    #[test]
    fn scanner_expect_reports_offset_and_found() {
        let mut sc = Scanner::new(b"abc");
        let err = sc.expect("abX").unwrap_err();
        assert!(matches!(
            err,
            DeserializeError::NonCanonical {
                offset: 0,
                found: Some(b'a'),
                ..
            }
        ));
    }

    #[test]
    fn scanner_finish_rejects_trailing() {
        let mut sc = Scanner::new(b"ab");
        sc.expect("ab").unwrap();
        sc.finish().unwrap();
        let mut sc2 = Scanner::new(b"abX");
        sc2.expect("ab").unwrap();
        assert!(matches!(
            sc2.finish(),
            Err(DeserializeError::NonCanonical {
                offset: 2,
                found: Some(b'X'),
                ..
            })
        ));
    }

    #[test]
    fn string_array_shapes() {
        assert!(Scanner::new(b"[]").string_array().unwrap().is_empty());
        assert_eq!(
            Scanner::new(b"[\"a\",\"b\"]").string_array().unwrap(),
            vec!["a", "b"]
        );
        assert!(
            Scanner::new(b"[\"a\",]").string_array().is_err(),
            "trailing comma"
        );
        assert!(
            Scanner::new(b"[ \"a\"]").string_array().is_err(),
            "whitespace"
        );
    }

    #[test]
    fn generic_payload_depth_is_iterative_and_bounded_by_input_length() {
        let depth = 20_000;
        let mut raw = String::from("{\"a\":");
        for _ in 0..depth {
            raw.push('[');
        }
        raw.push('0');
        for _ in 0..depth {
            raw.push(']');
        }
        raw.push('}');
        let mut scanner = Scanner::new(raw.as_bytes());
        assert_eq!(scanner.object_value_span().unwrap(), 0..raw.len());
        scanner.finish().unwrap();
    }
}
