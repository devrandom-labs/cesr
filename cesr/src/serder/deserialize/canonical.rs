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
        let value = str::from_utf8(bytes).map_err(|_| self.err_at(start, "UTF-8 string value"))?;
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
    fn scanner_string_accepts_multibyte_utf8() {
        let mut sc = Scanner::new("\"héllo\"".as_bytes());
        assert_eq!(sc.string().unwrap().value, "héllo");
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
}
