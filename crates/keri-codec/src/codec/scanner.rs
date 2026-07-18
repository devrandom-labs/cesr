//! The strict canonical-JSON reader: a single-pass cursor over the raw
//! event bytes (the der `Reader` analogue). Accepts exactly the canonical
//! language — compact, no escapes in values, no leading zeros — and reports
//! every rejection as a typed, offset-carrying [`SerderError`].

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use core::ops::Range;
use core::str;

use crate::error::SerderError;

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
    pub(crate) input: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Scanner<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    pub(crate) fn err_at(&self, offset: usize, expected: &'static str) -> SerderError {
        SerderError::NonCanonical {
            offset,
            expected,
            found: self.input.get(offset).copied(),
        }
    }

    pub(crate) fn err(&self, expected: &'static str) -> SerderError {
        self.err_at(self.pos, expected)
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Consume `lit` if it is next; report whether it was.
    pub(crate) fn take_lit(&mut self, lit: &'static str) -> bool {
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

    /// Items of a canonical JSON array after the opening `[` and the
    /// empty-array check (`]`) have already been consumed — i.e. the cursor
    /// is positioned at the first item.
    pub(crate) fn tail_list<T>(
        &mut self,
        mut item: impl FnMut(&mut Self) -> Result<T, SerderError>,
    ) -> Result<Vec<T>, SerderError> {
        let mut items = vec![item(self)?];
        loop {
            if self.take_lit("]") {
                return Ok(items);
            }
            self.expect(",")?;
            items.push(item(self)?);
        }
    }

    /// A canonical JSON array `[item,item,...]` — no whitespace, no trailing
    /// comma; empty `[]` allowed.
    pub(crate) fn delimited_list<T>(
        &mut self,
        item: impl FnMut(&mut Self) -> Result<T, SerderError>,
    ) -> Result<Vec<T>, SerderError> {
        self.expect("[")?;
        if self.take_lit("]") {
            return Ok(Vec::new());
        }
        self.tail_list(item)
    }

    /// A canonical JSON array of plain strings.
    pub(crate) fn string_array(&mut self) -> Result<Vec<&'a str>, SerderError> {
        self.delimited_list(|s| s.string().map(|sp| sp.value))
    }
}
