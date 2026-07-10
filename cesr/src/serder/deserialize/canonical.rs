//! Strict single-pass parser for the five fixed canonical KERI event
//! grammars (`icp`, `rot`, `ixn`, `dip`, `drt`).
//!
//! Canonical event JSON is byte-deterministic: compact (no whitespace),
//! spec field order, and values that never require string escaping (qb64,
//! hex, ASCII constants — design §2.3 of the #79 write-up). This parser
//! accepts exactly that language, plus JSON integers for `kt`/`nt`/`bt`
//! (keripy `intive=True` emits them; their SAIDs are computed over the
//! integer form, so rejecting them would be a conformance gap).
//!
//! Every field is returned as a borrowed `&str`; the `d` (and `i` for
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

use crate::serder::error::SerderError;

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

/// A `kt`/`nt` threshold value as it appears on the wire.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedTholder<'a> {
    /// Hex string form, e.g. `"1"`, `"a"`.
    Hex(&'a str),
    /// keripy `intive=True` integer form, e.g. `1`.
    Number(&'a str),
    /// Weighted clauses; a flat array is normalized to a single clause.
    Weighted(Vec<Vec<&'a str>>),
}

/// A `bt` witness-threshold value as it appears on the wire.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedCount<'a> {
    /// Hex string form.
    Hex(&'a str),
    /// keripy `intive=True` integer form.
    Number(&'a str),
}

/// A seal object, one of the five fixed shapes.
#[derive(Debug)]
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
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct Scanner<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn err_at(&self, offset: usize, expected: &'static str) -> SerderError {
        SerderError::NonCanonical {
            offset,
            expected,
            found: self.input.get(offset).copied(),
        }
    }

    fn err(&self, expected: &'static str) -> SerderError {
        self.err_at(self.pos, expected)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Consume `lit` if it is next; report whether it was.
    fn take_lit(&mut self, lit: &'static str) -> bool {
        let Some(end) = self.pos.checked_add(lit.len()) else {
            return false;
        };
        if self.input.get(self.pos..end) == Some(lit.as_bytes()) {
            self.pos = end;
            true
        } else {
            false
        }
    }

    /// On mismatch the error reports the literal's START offset with the byte
    /// found there; the `expected` field carries the whole literal.
    pub(crate) fn expect(&mut self, lit: &'static str) -> Result<(), SerderError> {
        if self.take_lit(lit) {
            Ok(())
        } else {
            Err(self.err(lit))
        }
    }

    fn advance(&mut self, by: usize, expected: &'static str) -> Result<(), SerderError> {
        self.pos = self.pos.checked_add(by).ok_or_else(|| self.err(expected))?;
        Ok(())
    }

    /// A canonical JSON string: no escapes, no control characters, UTF-8.
    pub(crate) fn string(&mut self) -> Result<Spanned<'a>, SerderError> {
        self.expect("\"")?;
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') => {
                    return Err(
                        self.err("unescaped string byte (canonical values never require escaping)")
                    );
                }
                Some(b) if b < 0x20 => {
                    return Err(self.err("unescaped string byte (no control characters)"));
                }
                Some(_) => self.advance(1, "string byte")?,
                None => return Err(self.err("closing '\"'")),
            }
        }
        let span = start..self.pos;
        let bytes = self
            .input
            .get(span.clone())
            .ok_or(SerderError::InvalidEventLayout("string span out of bounds"))?;
        let value = str::from_utf8(bytes).map_err(|e| {
            start.checked_add(e.valid_up_to()).map_or_else(
                || SerderError::InvalidEventLayout("UTF-8 error offset overflow"),
                |offset| self.err_at(offset, "UTF-8 string value"),
            )
        })?;
        self.expect("\"")?;
        Ok(Spanned { value, span })
    }

    /// A canonical JSON integer: `0` or `[1-9][0-9]*`. No sign, no leading
    /// zeros, no fraction or exponent.
    pub(crate) fn integer(&mut self) -> Result<&'a str, SerderError> {
        let start = self.pos;
        match self.peek() {
            Some(b'0') => {
                self.advance(1, "digit")?;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.err("no leading zeros in canonical integer"));
                }
            }
            Some(b'1'..=b'9') => {
                self.advance(1, "digit")?;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.advance(1, "digit")?;
                }
            }
            _ => return Err(self.err("digit")),
        }
        let bytes = self
            .input
            .get(start..self.pos)
            .ok_or(SerderError::InvalidEventLayout(
                "integer span out of bounds",
            ))?;
        // Defensively unreachable: every scanned byte is 0x30–0x39 by construction.
        str::from_utf8(bytes).map_err(|_| self.err_at(start, "ASCII integer"))
    }

    /// The input must be fully consumed.
    pub(crate) fn finish(&self) -> Result<(), SerderError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(self.err("end of input"))
        }
    }
}

fn string_array<'a>(sc: &mut Scanner<'a>) -> Result<Vec<&'a str>, SerderError> {
    sc.expect("[")?;
    let mut items = Vec::new();
    if sc.take_lit("]") {
        return Ok(items);
    }
    loop {
        items.push(sc.string()?.value);
        if sc.take_lit("]") {
            return Ok(items);
        }
        sc.expect(",")?;
    }
}

fn tholder<'a>(sc: &mut Scanner<'a>) -> Result<ParsedTholder<'a>, SerderError> {
    match sc.peek() {
        Some(b'"') => Ok(ParsedTholder::Hex(sc.string()?.value)),
        Some(b'0'..=b'9') => Ok(ParsedTholder::Number(sc.integer()?)),
        Some(b'[') => weighted(sc),
        _ => Err(sc.err("threshold (hex string, integer, or weighted array)")),
    }
}

fn weighted<'a>(sc: &mut Scanner<'a>) -> Result<ParsedTholder<'a>, SerderError> {
    sc.expect("[")?;
    if sc.take_lit("]") {
        return Ok(ParsedTholder::Weighted(Vec::new()));
    }
    match sc.peek() {
        Some(b'"') => {
            let mut clause = Vec::new();
            loop {
                clause.push(sc.string()?.value);
                if sc.take_lit("]") {
                    return Ok(ParsedTholder::Weighted(vec![clause]));
                }
                sc.expect(",")?;
            }
        }
        Some(b'[') => {
            let mut clauses = Vec::new();
            loop {
                clauses.push(string_array(sc)?);
                if sc.take_lit("]") {
                    return Ok(ParsedTholder::Weighted(clauses));
                }
                sc.expect(",")?;
            }
        }
        _ => Err(sc.err("weight fraction string or clause array")),
    }
}

fn count<'a>(sc: &mut Scanner<'a>) -> Result<ParsedCount<'a>, SerderError> {
    match sc.peek() {
        Some(b'"') => Ok(ParsedCount::Hex(sc.string()?.value)),
        Some(b'0'..=b'9') => Ok(ParsedCount::Number(sc.integer()?)),
        _ => Err(sc.err("count (hex string or integer)")),
    }
}

/// One seal object. Field order per variant is fixed (matches the writer
/// and keripy's namedtuple serialization order).
fn seal<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    sc.expect("{")?;
    if sc.take_lit("\"d\":") {
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Digest { d });
    }
    if sc.take_lit("\"rd\":") {
        let rd = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Root { rd });
    }
    if sc.take_lit("\"s\":") {
        let s = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Source { s, d });
    }
    if sc.take_lit("\"i\":") {
        let i = sc.string()?.value;
        if sc.take_lit("}") {
            return Ok(ParsedSeal::Last { i });
        }
        sc.expect(",\"s\":")?;
        let s = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Event { i, s, d });
    }
    Err(sc.err("seal object key (\"d\", \"rd\", \"s\", or \"i\")"))
}

fn seal_array<'a>(sc: &mut Scanner<'a>) -> Result<Vec<ParsedSeal<'a>>, SerderError> {
    sc.expect("[")?;
    let mut items = Vec::new();
    if sc.take_lit("]") {
        return Ok(items);
    }
    loop {
        items.push(seal(sc)?);
        if sc.take_lit("]") {
            return Ok(items);
        }
        sc.expect(",")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_canonical_at(e: &SerderError) -> Option<(usize, &'static str)> {
        if let SerderError::NonCanonical {
            offset, expected, ..
        } = e
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
            Err(SerderError::NonCanonical { offset: 2, .. })
        ));
    }

    #[test]
    fn scanner_string_rejects_unterminated() {
        let mut sc = Scanner::new(b"\"abc");
        assert!(matches!(
            sc.string(),
            Err(SerderError::NonCanonical {
                offset: 4,
                found: None,
                ..
            })
        ));
    }

    #[test]
    fn scanner_string_rejects_non_utf8() {
        let mut sc = Scanner::new(b"\"\xFF\xFE\"");
        assert!(matches!(
            sc.string(),
            Err(SerderError::NonCanonical { offset: 1, .. })
        ));
    }

    #[test]
    fn scanner_string_utf8_error_reports_violating_byte() {
        let mut sc = Scanner::new(b"\"ab\xFF\"");
        assert!(matches!(
            sc.string(),
            Err(SerderError::NonCanonical {
                offset: 3,
                found: Some(0xFF),
                ..
            })
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
            Err(SerderError::NonCanonical {
                offset: 0,
                found: None,
                ..
            })
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
            Err(SerderError::NonCanonical {
                offset: 0,
                found: None,
                ..
            })
        ));
        let mut eof_terminated = Scanner::new(b"907");
        assert_eq!(eof_terminated.integer().unwrap(), "907");
        eof_terminated.finish().unwrap();
    }

    #[test]
    fn scanner_expect_reports_offset_and_found() {
        let mut sc = Scanner::new(b"abc");
        let err = sc.expect("abd").unwrap_err();
        assert!(matches!(
            err,
            SerderError::NonCanonical {
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
            Err(SerderError::NonCanonical {
                offset: 2,
                found: Some(b'X'),
                ..
            })
        ));
    }

    #[test]
    fn string_array_shapes() {
        assert!(string_array(&mut Scanner::new(b"[]")).unwrap().is_empty());
        assert_eq!(
            string_array(&mut Scanner::new(b"[\"a\",\"b\"]")).unwrap(),
            vec!["a", "b"]
        );
        assert!(
            string_array(&mut Scanner::new(b"[\"a\",]")).is_err(),
            "trailing comma"
        );
        assert!(
            string_array(&mut Scanner::new(b"[ \"a\"]")).is_err(),
            "whitespace"
        );
    }

    #[test]
    fn tholder_shapes() {
        assert!(matches!(
            tholder(&mut Scanner::new(b"\"a\"")).unwrap(),
            ParsedTholder::Hex("a")
        ));
        assert!(matches!(
            tholder(&mut Scanner::new(b"2,")).unwrap(),
            ParsedTholder::Number("2")
        ));
        let ParsedTholder::Weighted(flat) =
            tholder(&mut Scanner::new(b"[\"1/2\",\"1/2\"]")).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(flat, vec![vec!["1/2", "1/2"]]);
        let ParsedTholder::Weighted(nested) =
            tholder(&mut Scanner::new(b"[[\"1/2\",\"1/2\"],[\"1\"]]")).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(nested, vec![vec!["1/2", "1/2"], vec!["1"]]);
        let ParsedTholder::Weighted(empty) = tholder(&mut Scanner::new(b"[]")).unwrap() else {
            unreachable!()
        };
        assert!(empty.is_empty());
        assert!(tholder(&mut Scanner::new(b"true")).is_err());
    }

    #[test]
    fn count_shapes() {
        assert!(matches!(
            count(&mut Scanner::new(b"\"0\"")).unwrap(),
            ParsedCount::Hex("0")
        ));
        assert!(matches!(
            count(&mut Scanner::new(b"3,")).unwrap(),
            ParsedCount::Number("3")
        ));
        assert!(count(&mut Scanner::new(b"[]")).is_err());
    }

    #[test]
    fn seal_shapes() {
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Digest { d: "X" }
        ));
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"rd\":\"X\"}")).unwrap(),
            ParsedSeal::Root { rd: "X" }
        ));
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"s\":\"1\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Source { s: "1", d: "X" }
        ));
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"i\":\"I\",\"s\":\"1\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Event {
                i: "I",
                s: "1",
                d: "X"
            }
        ));
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"i\":\"I\"}")).unwrap(),
            ParsedSeal::Last { i: "I" }
        ));
        assert!(
            seal(&mut Scanner::new(b"{\"d\":\"X\",\"s\":\"1\"}")).is_err(),
            "out-of-order seal fields are non-canonical"
        );
        assert!(
            seal(&mut Scanner::new(b"{\"x\":\"X\"}")).is_err(),
            "unknown seal key"
        );
    }

    #[test]
    fn seal_array_shapes() {
        assert!(seal_array(&mut Scanner::new(b"[]")).unwrap().is_empty());
        let seals = seal_array(&mut Scanner::new(b"[{\"d\":\"X\"},{\"i\":\"I\"}]")).unwrap();
        assert_eq!(seals.len(), 2);
        assert!(matches!(seals[0], ParsedSeal::Digest { d: "X" }));
        assert!(matches!(seals[1], ParsedSeal::Last { i: "I" }));
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
                let _ = string_array(&mut Scanner::new(&input));
                let _ = tholder(&mut Scanner::new(&input));
                let _ = count(&mut Scanner::new(&input));
                let _ = seal(&mut Scanner::new(&input));
                let _ = seal_array(&mut Scanner::new(&input));
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
