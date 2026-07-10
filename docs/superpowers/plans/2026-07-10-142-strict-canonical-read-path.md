# #142 · Strict Canonical Read-Path Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the tolerant `serde_json` deserialize path in `serder` with a strict single-pass canonical parser for the five fixed KERI event grammars, with offset-based SAID verification (copy-once + slot-fill + hash, no re-render).

**Architecture:** A new `pub(crate)` module `serder::deserialize::canonical` holds a byte `Scanner` and per-ilk grammar functions that return borrowed (`&'a str`) field views plus the byte spans of the `d`/`i` SAID slots (the read-path mirror of `EventLayout`). `said.rs` gains `verify_said_spans` (scratch-copy, fill spans with `#`, hash, compare). The public `deserialize_*` entry points re-wire onto the strict parser; the old `serde_json::Value` path moves to `#[cfg(test)]` module `reference` and survives only as the differential oracle. Public `said::verify_said` is re-implemented strict and changes signature to `Result<(), SerderError>`.

**Tech Stack:** Rust 2024 (stable 1.95.0), no new dependencies. `thiserror` error variant, `proptest` differentials, bolero + afl.rs fuzz targets, criterion/CodSpeed bench, counting-allocator pin. Gate: `nix flake check`.

**Breaking changes (MINOR under 0.x, PR title `feat(serder)!:`):**
1. New `SerderError::NonCanonical { offset, expected, found }` variant; read-path errors change variant for non-canonical inputs.
2. `said::verify_said` becomes `Result<(), SerderError>` (was `Result<bool, _>`), strict.
3. Per-ilk deserializers now require their exact ilk (`deserialize_rotation` no longer accepts `drt` bytes; `deserialize_inception` no longer silently accepts `dip` bytes and drops the delegator).
4. Whitespace, duplicate keys, reordered fields, escapes, and trailing bytes are rejected by construction.

**Conformance decisions (locked):**
- JSON **integers** remain accepted for `kt`/`nt`/`bt` (keripy `intive=True` parity — the current tolerant path accepts them and has behavior-pin tests). Grammar: `0|[1-9][0-9]*`, no leading zeros, no sign, no float/exponent.
- All other scalar values are strings; `\` (any escape), control chars < 0x20, and non-UTF-8 bytes inside strings are non-canonical. Rationale: every value class in the five grammars is qb64 / hex / ASCII constant — no canonical event ever requires escaping (design §2.3).
- keripy corpus differential is covered by `keri/tests/differential.rs`, which drives the corpus through the public `deserialize_event` (now strict) under `nix flake check`. No corpus duplication into cesr (respects #133 fixture-dedup).

---

## Preflight

- [ ] **Step 0.1: Create branch off up-to-date main** (use superpowers:using-git-worktrees if isolating)

```bash
cd /Users/joel/Code/devrandom/cesr
git fetch origin && git checkout -b feat/142-strict-read-path origin/main
```

- [ ] **Step 0.2: Confirm no external callers of the internals being moved**

Run: `rg -n "verify_said|validate_version_string|tholder_from_json|seal_from_json" --glob '!cesr/src/serder/**' cesr/ keri/ fuzz*/`
Expected: only hits inside `cesr/src/serder/` (deserialize.rs, said.rs). If `cesr/tests/frozen_surface.rs` pins `verify_said`, note it — Task 8 updates it.

---

### Task 1: `NonCanonical` error variant

**Files:**
- Modify: `cesr/src/serder/error.rs`

- [ ] **Step 1.1: Add the variant** (after `UnparseablePrimitive`, before `VersionStringOverflow`)

```rust
    /// Input deviates from the fixed canonical event grammar at a specific
    /// byte: whitespace, reordered/duplicate/unknown fields, string escapes,
    /// or malformed framing. Canonical KERI event JSON is byte-deterministic,
    /// so any deviation is rejected by construction.
    #[error("non-canonical event JSON at byte {offset}: expected {expected}, found {found:?}")]
    NonCanonical {
        /// Byte offset in the raw input where the grammar was violated.
        offset: usize,
        /// What the grammar required at that offset.
        expected: &'static str,
        /// The byte actually found, or `None` at end of input.
        found: Option<u8>,
    },
```

- [ ] **Step 1.2: Widen the `InvalidEventLayout` doc comment** (the read path reuses it for parser-reported slot inconsistencies)

```rust
    /// A serialization backend or the canonical parser reported a slot layout
    /// inconsistent with the bytes it rendered or parsed — an internal bug,
    /// surfaced as a typed error so a corrupt frame can never escape.
    #[error("invalid event layout: {0}")]
    InvalidEventLayout(&'static str),
```

- [ ] **Step 1.3: Build check**

Run: `nix develop --command cargo build -p cesr-rs --features serder`
Expected: compiles (variant unused yet is fine — no dead-code lint on pub enum variants).

- [ ] **Step 1.4: Commit**

```bash
git add cesr/src/serder/error.rs
git commit -m "feat(serder): NonCanonical error variant for the strict read path (#142)"
```

---

### Task 2: Scanner core

**Files:**
- Create: `cesr/src/serder/deserialize/canonical.rs`
- Modify: `cesr/src/serder/deserialize.rs` (add module decl)

- [ ] **Step 2.1: Declare the submodule.** In `deserialize.rs`, after the existing `use` block:

```rust
pub(crate) mod canonical;
```

- [ ] **Step 2.2: Write failing scanner tests.** Create `canonical.rs` with module doc, `Spanned`, `Scanner`, and tests first:

```rust
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
use alloc::{borrow::ToOwned, format, string::String, vec, vec::Vec};
use core::ops::Range;
use core::str;

use crate::serder::error::SerderError;
use crate::serder::version::{SerKind, VERSION_STRING_LEN, VersionString};

/// A borrowed string value plus its byte span in the raw input.
pub(crate) struct Spanned<'a> {
    pub(crate) value: &'a str,
    pub(crate) span: Range<usize>,
}

pub(crate) struct Scanner<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    const fn new(input: &'a [u8]) -> Self {
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

    fn expect(&mut self, lit: &'static str) -> Result<(), SerderError> {
        if self.take_lit(lit) {
            Ok(())
        } else {
            Err(self.err(lit))
        }
    }

    fn advance(&mut self, by: usize, expected: &'static str) -> Result<(), SerderError> {
        self.pos = self
            .pos
            .checked_add(by)
            .ok_or_else(|| self.err(expected))?;
        Ok(())
    }

    /// A canonical JSON string: no escapes, no control characters, UTF-8.
    fn string(&mut self) -> Result<Spanned<'a>, SerderError> {
        self.expect("\"")?;
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') => {
                    return Err(self.err(
                        "unescaped string byte (canonical values never require escaping)",
                    ));
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
        let value =
            str::from_utf8(bytes).map_err(|_| self.err_at(start, "UTF-8 string value"))?;
        self.expect("\"")?;
        Ok(Spanned { value, span })
    }

    /// A canonical JSON integer: `0` or `[1-9][0-9]*`. No sign, no leading
    /// zeros, no fraction or exponent.
    fn integer(&mut self) -> Result<&'a str, SerderError> {
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
            .ok_or(SerderError::InvalidEventLayout("integer span out of bounds"))?;
        str::from_utf8(bytes).map_err(|_| self.err_at(start, "ASCII integer"))
    }

    /// The input must be fully consumed.
    fn finish(&self) -> Result<(), SerderError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(self.err("end of input"))
        }
    }
}
```

And the first test block at the bottom of `canonical.rs`:

```rust
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
```

- [ ] **Step 2.3: Run the tests, verify green** (they were written against the impl in the same step; verify they compile and pass — the failure mode to catch is a grammar off-by-one)

Run: `nix develop --command cargo nextest run -p cesr-rs canonical::`
Expected: all `scanner_*` tests PASS.

- [ ] **Step 2.4: Commit**

```bash
git add cesr/src/serder/deserialize.rs cesr/src/serder/deserialize/canonical.rs
git commit -m "feat(serder): strict canonical scanner core (#142)"
```

---

### Task 3: Value grammars — arrays, thresholds, counts, seals

**Files:**
- Modify: `cesr/src/serder/deserialize/canonical.rs`

- [ ] **Step 3.1: Add parsed-value types** (below `Spanned`)

```rust
/// A `kt`/`nt` threshold value as it appears on the wire.
pub(crate) enum ParsedTholder<'a> {
    /// Hex string form, e.g. `"1"`, `"a"`.
    Hex(&'a str),
    /// keripy `intive=True` integer form, e.g. `1`.
    Number(&'a str),
    /// Weighted clauses; a flat array is normalized to a single clause.
    Weighted(Vec<Vec<&'a str>>),
}

/// A `bt` witness-threshold value as it appears on the wire.
pub(crate) enum ParsedCount<'a> {
    /// Hex string form.
    Hex(&'a str),
    /// keripy `intive=True` integer form.
    Number(&'a str),
}

/// A seal object, one of the five fixed shapes.
pub(crate) enum ParsedSeal<'a> {
    Digest { d: &'a str },
    Root { rd: &'a str },
    Source { s: &'a str, d: &'a str },
    Event { i: &'a str, s: &'a str, d: &'a str },
    Last { i: &'a str },
}
```

- [ ] **Step 3.2: Add composite grammar functions**

```rust
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
    Err(sc.err("seal key (\"d\", \"rd\", \"s\", or \"i\")"))
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
```

- [ ] **Step 3.3: Add grammar tests** (inside the existing `mod tests`)

```rust
    #[test]
    fn string_array_shapes() {
        assert!(string_array(&mut Scanner::new(b"[]")).unwrap().is_empty());
        assert_eq!(
            string_array(&mut Scanner::new(b"[\"a\",\"b\"]")).unwrap(),
            vec!["a", "b"]
        );
        assert!(string_array(&mut Scanner::new(b"[\"a\",]")).is_err(), "trailing comma");
        assert!(string_array(&mut Scanner::new(b"[ \"a\"]")).is_err(), "whitespace");
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
            ParsedSeal::Event { i: "I", s: "1", d: "X" }
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
```

- [ ] **Step 3.4: Run tests**

Run: `nix develop --command cargo nextest run -p cesr-rs canonical::`
Expected: PASS.

- [ ] **Step 3.5: Commit**

```bash
git add cesr/src/serder/deserialize/canonical.rs
git commit -m "feat(serder): canonical value grammars — arrays, tholder, count, seal (#142)"
```

---

### Task 4: Head validation, per-ilk grammars, entry points

**Files:**
- Modify: `cesr/src/serder/deserialize/canonical.rs`

- [ ] **Step 4.1: Add parsed-event types**

```rust
/// A parsed inception (`icp`) body: borrowed field views plus SAID spans.
pub(crate) struct ParsedIcp<'a> {
    pub(crate) said: Spanned<'a>,
    pub(crate) prefix: Spanned<'a>,
    pub(crate) sn: &'a str,
    pub(crate) threshold: ParsedTholder<'a>,
    pub(crate) keys: Vec<&'a str>,
    pub(crate) next_threshold: ParsedTholder<'a>,
    pub(crate) next_keys: Vec<&'a str>,
    pub(crate) witness_threshold: ParsedCount<'a>,
    pub(crate) witnesses: Vec<&'a str>,
    pub(crate) config: Vec<&'a str>,
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// A parsed delegated inception (`dip`): an inception plus the delegator.
pub(crate) struct ParsedDip<'a> {
    pub(crate) icp: ParsedIcp<'a>,
    pub(crate) delegator: &'a str,
}

/// A parsed rotation (`rot`) or delegated rotation (`drt`) body.
pub(crate) struct ParsedRot<'a> {
    pub(crate) said: Spanned<'a>,
    pub(crate) prefix: &'a str,
    pub(crate) sn: &'a str,
    pub(crate) prior: &'a str,
    pub(crate) threshold: ParsedTholder<'a>,
    pub(crate) keys: Vec<&'a str>,
    pub(crate) next_threshold: ParsedTholder<'a>,
    pub(crate) next_keys: Vec<&'a str>,
    pub(crate) witness_threshold: ParsedCount<'a>,
    pub(crate) witness_removals: Vec<&'a str>,
    pub(crate) witness_additions: Vec<&'a str>,
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// A parsed interaction (`ixn`) body.
pub(crate) struct ParsedIxn<'a> {
    pub(crate) said: Spanned<'a>,
    pub(crate) prefix: &'a str,
    pub(crate) sn: &'a str,
    pub(crate) prior: &'a str,
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// Any parsed event, dispatched on the wire ilk.
pub(crate) enum ParsedEvent<'a> {
    Inception(ParsedIcp<'a>),
    Rotation(ParsedRot<'a>),
    Interaction(ParsedIxn<'a>),
    DelegatedInception(ParsedDip<'a>),
    DelegatedRotation(ParsedRot<'a>),
}
```

- [ ] **Step 4.2: Head parsing.** Validates the version string at its fixed offset — kind, widths, and `size == raw.len()` — with **zero** JSON parsing (replaces `validate_version_string`'s full `serde_json::from_slice`):

```rust
/// Parse and validate the fixed head `{"v":"<17-byte version string>","t":`
/// and return the scanner positioned at the ilk value plus the ilk itself.
fn head<'a>(raw: &'a [u8]) -> Result<(Scanner<'a>, Spanned<'a>), SerderError> {
    let mut sc = Scanner::new(raw);
    sc.expect("{\"v\":\"")?;
    let vs_start = sc.pos;
    let vs_end = vs_start
        .checked_add(VERSION_STRING_LEN)
        .ok_or(SerderError::InvalidEventLayout("version span overflow"))?;
    let vs_bytes = raw
        .get(vs_start..vs_end)
        .ok_or_else(|| sc.err("17-byte version string"))?;
    let vs_str = str::from_utf8(vs_bytes).map_err(|_| sc.err("ASCII version string"))?;
    let vs = VersionString::parse(vs_str)?;
    if vs.kind != SerKind::Json {
        return Err(SerderError::InvalidVersionString(format!(
            "expected JSON, got {}",
            vs.kind.as_str()
        )));
    }
    let expected_size = usize::try_from(vs.size)
        .map_err(|e| SerderError::InvalidVersionString(e.to_string()))?;
    if expected_size != raw.len() {
        return Err(SerderError::InvalidVersionString(format!(
            "version string size {} does not match actual size {}",
            expected_size,
            raw.len()
        )));
    }
    sc.pos = vs_end;
    sc.expect("\",\"t\":")?;
    let ilk = sc.string()?;
    Ok((sc, ilk))
}
```

(Add `use alloc::string::ToString;` to the alloc import list for `e.to_string()`.)

- [ ] **Step 4.3: Per-ilk bodies and public (crate) entry points**

```rust
fn icp_fields<'a>(sc: &mut Scanner<'a>) -> Result<ParsedIcp<'a>, SerderError> {
    sc.expect(",\"d\":")?;
    let said = sc.string()?;
    sc.expect(",\"i\":")?;
    let prefix = sc.string()?;
    sc.expect(",\"s\":")?;
    let sn = sc.string()?.value;
    sc.expect(",\"kt\":")?;
    let threshold = tholder(sc)?;
    sc.expect(",\"k\":")?;
    let keys = string_array(sc)?;
    sc.expect(",\"nt\":")?;
    let next_threshold = tholder(sc)?;
    sc.expect(",\"n\":")?;
    let next_keys = string_array(sc)?;
    sc.expect(",\"bt\":")?;
    let witness_threshold = count(sc)?;
    sc.expect(",\"b\":")?;
    let witnesses = string_array(sc)?;
    sc.expect(",\"c\":")?;
    let config = string_array(sc)?;
    sc.expect(",\"a\":")?;
    let anchors = seal_array(sc)?;
    Ok(ParsedIcp {
        said,
        prefix,
        sn,
        threshold,
        keys,
        next_threshold,
        next_keys,
        witness_threshold,
        witnesses,
        config,
        anchors,
    })
}

fn rot_body<'a>(mut sc: Scanner<'a>) -> Result<ParsedRot<'a>, SerderError> {
    sc.expect(",\"d\":")?;
    let said = sc.string()?;
    sc.expect(",\"i\":")?;
    let prefix = sc.string()?.value;
    sc.expect(",\"s\":")?;
    let sn = sc.string()?.value;
    sc.expect(",\"p\":")?;
    let prior = sc.string()?.value;
    sc.expect(",\"kt\":")?;
    let threshold = tholder(&mut sc)?;
    sc.expect(",\"k\":")?;
    let keys = string_array(&mut sc)?;
    sc.expect(",\"nt\":")?;
    let next_threshold = tholder(&mut sc)?;
    sc.expect(",\"n\":")?;
    let next_keys = string_array(&mut sc)?;
    sc.expect(",\"bt\":")?;
    let witness_threshold = count(&mut sc)?;
    sc.expect(",\"br\":")?;
    let witness_removals = string_array(&mut sc)?;
    sc.expect(",\"ba\":")?;
    let witness_additions = string_array(&mut sc)?;
    sc.expect(",\"a\":")?;
    let anchors = seal_array(&mut sc)?;
    sc.expect("}")?;
    sc.finish()?;
    Ok(ParsedRot {
        said,
        prefix,
        sn,
        prior,
        threshold,
        keys,
        next_threshold,
        next_keys,
        witness_threshold,
        witness_removals,
        witness_additions,
        anchors,
    })
}

fn ixn_body<'a>(mut sc: Scanner<'a>) -> Result<ParsedIxn<'a>, SerderError> {
    sc.expect(",\"d\":")?;
    let said = sc.string()?;
    sc.expect(",\"i\":")?;
    let prefix = sc.string()?.value;
    sc.expect(",\"s\":")?;
    let sn = sc.string()?.value;
    sc.expect(",\"p\":")?;
    let prior = sc.string()?.value;
    sc.expect(",\"a\":")?;
    let anchors = seal_array(&mut sc)?;
    sc.expect("}")?;
    sc.finish()?;
    Ok(ParsedIxn {
        said,
        prefix,
        sn,
        prior,
        anchors,
    })
}

fn icp_body<'a>(mut sc: Scanner<'a>) -> Result<ParsedIcp<'a>, SerderError> {
    let fields = icp_fields(&mut sc)?;
    sc.expect("}")?;
    sc.finish()?;
    Ok(fields)
}

fn dip_body<'a>(mut sc: Scanner<'a>) -> Result<ParsedDip<'a>, SerderError> {
    let icp = icp_fields(&mut sc)?;
    sc.expect(",\"di\":")?;
    let delegator = sc.string()?.value;
    sc.expect("}")?;
    sc.finish()?;
    Ok(ParsedDip { icp, delegator })
}

fn require_ilk(sc: &Scanner<'_>, ilk: &Spanned<'_>, expected: &'static str) -> Result<(), SerderError> {
    if ilk.value == expected {
        Ok(())
    } else {
        Err(sc.err_at(ilk.span.start, expected))
    }
}

pub(crate) fn parse_event(raw: &[u8]) -> Result<ParsedEvent<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    match ilk.value {
        "icp" => Ok(ParsedEvent::Inception(icp_body(sc)?)),
        "rot" => Ok(ParsedEvent::Rotation(rot_body(sc)?)),
        "ixn" => Ok(ParsedEvent::Interaction(ixn_body(sc)?)),
        "dip" => Ok(ParsedEvent::DelegatedInception(dip_body(sc)?)),
        "drt" => Ok(ParsedEvent::DelegatedRotation(rot_body(sc)?)),
        other => Err(SerderError::UnknownIlk(other.to_owned())),
    }
}

pub(crate) fn parse_inception(raw: &[u8]) -> Result<ParsedIcp<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "icp")?;
    icp_body(sc)
}

pub(crate) fn parse_rotation(raw: &[u8]) -> Result<ParsedRot<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "rot")?;
    rot_body(sc)
}

pub(crate) fn parse_interaction(raw: &[u8]) -> Result<ParsedIxn<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "ixn")?;
    ixn_body(sc)
}

pub(crate) fn parse_delegated_inception(raw: &[u8]) -> Result<ParsedDip<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "dip")?;
    dip_body(sc)
}

pub(crate) fn parse_delegated_rotation(raw: &[u8]) -> Result<ParsedRot<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "drt")?;
    rot_body(sc)
}
```

- [ ] **Step 4.4: Grammar tests against real writer output.** Add to `mod tests` (fixtures via the existing serialize path):

```rust
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::{ConfigTrait, InceptionEvent, InteractionEvent, Seal};
    use crate::serder::serialize::{serialize_inception, serialize_interaction};
    use alloc::borrow::Cow;

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verfer() -> Verfer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn probe_icp_bytes() -> Vec<u8> {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_saider()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: make_saider() }],
        );
        serialize_inception(&event).unwrap().as_bytes().to_vec()
    }

    fn probe_ixn_bytes() -> Vec<u8> {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(3),
            make_saider(),
            make_saider(),
            vec![],
        );
        serialize_interaction(&event).unwrap().as_bytes().to_vec()
    }

    #[test]
    fn parse_event_reads_writer_output_icp() {
        let raw = probe_icp_bytes();
        let ParsedEvent::Inception(p) = parse_event(&raw).unwrap() else {
            unreachable!()
        };
        assert_eq!(p.sn, "0");
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.config, vec!["EO"]);
        assert_eq!(p.anchors.len(), 1);
        assert_eq!(p.said.span.len(), 44);
        assert_eq!(
            &raw[p.said.span.clone()],
            p.said.value.as_bytes(),
            "span must address the value bytes in raw"
        );
        assert_eq!(&raw[p.prefix.span.clone()], p.prefix.value.as_bytes());
    }

    #[test]
    fn per_ilk_entry_rejects_wrong_ilk() {
        let raw = probe_ixn_bytes();
        assert!(matches!(
            parse_rotation(&raw),
            Err(SerderError::NonCanonical { expected: "rot", .. })
        ));
    }

    #[test]
    fn unknown_ilk_is_typed() {
        let mut raw = probe_ixn_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"ixn\"").unwrap();
        raw[pos + 1..pos + 4].copy_from_slice(b"xxx");
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::UnknownIlk(ref s)) if s == "xxx"
        ));
    }

    #[test]
    fn whitespace_with_consistent_size_is_non_canonical() {
        // Insert one space after the first comma AND fix the version size so
        // the length check passes — the grammar itself must reject it.
        let raw = probe_ixn_bytes();
        let comma = raw.iter().position(|b| *b == b',').unwrap();
        let mut padded = Vec::with_capacity(raw.len() + 1);
        padded.extend_from_slice(&raw[..=comma]);
        padded.push(b' ');
        padded.extend_from_slice(&raw[comma + 1..]);
        fix_size(&mut padded);
        assert!(matches!(
            parse_event(&padded),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn duplicate_field_is_non_canonical() {
        // Overwrite the `,"i":` key with a second `,"d":` — same length, so
        // the version size stays consistent; the grammar must reject it.
        let mut raw = probe_ixn_bytes();
        let pos = raw.windows(5).position(|w| w == b",\"i\":").unwrap();
        raw[pos..pos + 5].copy_from_slice(b",\"d\":");
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn reordered_fields_are_non_canonical() {
        // Swap the `"s"` and `"p"` key names (same length) in an ixn.
        let mut raw = probe_ixn_bytes();
        let s_pos = raw.windows(5).position(|w| w == b",\"s\":").unwrap();
        let p_pos = raw.windows(5).position(|w| w == b",\"p\":").unwrap();
        raw[s_pos + 2] = b'p';
        raw[p_pos + 2] = b's';
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn escape_in_value_is_non_canonical() {
        // Replace sn value "3" with "3" and fix the size field.
        let raw = probe_ixn_bytes();
        let pos = raw.windows(8).position(|w| w == b",\"s\":\"3\"").unwrap();
        let mut mutated = Vec::with_capacity(raw.len() + 5);
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b",\"s\":\"\\u0033\"");
        mutated.extend_from_slice(&raw[pos + 8..]);
        fix_size(&mut mutated);
        assert!(matches!(
            parse_event(&mutated),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_non_canonical() {
        let mut raw = probe_ixn_bytes();
        raw.push(b'X');
        fix_size(&mut raw);
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn length_lie_is_still_invalid_version_string() {
        // Without fixing the size field, a padded input fails the size check
        // first — preserving the #139 defence.
        let mut raw = probe_ixn_bytes();
        raw.push(b'X');
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::InvalidVersionString(_))
        ));
    }

    #[test]
    fn every_strict_prefix_is_rejected_without_panicking() {
        let raw = probe_icp_bytes();
        for cut in 0..raw.len() {
            assert!(
                parse_event(&raw[..cut]).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    /// Rewrite the six size hex digits (bytes 16..22) to the buffer's actual
    /// length so grammar probes are not masked by the #139 length check.
    fn fix_size(raw: &mut [u8]) {
        let size = raw.len();
        let hex = format!("{size:06x}");
        raw[16..22].copy_from_slice(hex.as_bytes());
    }
```

- [ ] **Step 4.5: Run tests**

Run: `nix develop --command cargo nextest run -p cesr-rs canonical::`
Expected: PASS.

- [ ] **Step 4.6: Commit**

```bash
git add cesr/src/serder/deserialize/canonical.rs
git commit -m "feat(serder): per-ilk strict grammars with fixed-offset version validation (#142)"
```

---

### Task 5: Offset-based SAID verification

**Files:**
- Modify: `cesr/src/serder/said.rs`

- [ ] **Step 5.1: Add `DUMMY_BYTE` and `verify_said_spans`** (below `DUMMY_CHAR`)

```rust
/// Byte form of [`DUMMY_CHAR`] for in-place span filling.
pub(crate) const DUMMY_BYTE: u8 = b'#';
```

```rust
use core::ops::Range;
```

(add to the top-of-file imports), then:

```rust
/// Verify a SAID by span: copy `raw` once into a scratch buffer, overwrite
/// the SAID value span (and the prefix span for double-SAID events) with
/// [`DUMMY_BYTE`], hash, and compare against `said_value`.
///
/// Spans come from the canonical parser and must address the qb64 value
/// bytes exactly (quotes excluded). This replaces the historical
/// parse-mutate-re-render verification with one allocation and one hash.
///
/// # Errors
///
/// Returns [`SerderError::SaidMismatch`] if the computed digest differs,
/// [`SerderError::InvalidEventLayout`] if a span is out of bounds, or
/// [`SerderError::DigestError`] on hash failure.
pub(crate) fn verify_said_spans(
    raw: &[u8],
    said_value: &str,
    said_span: &Range<usize>,
    prefix_span: Option<&Range<usize>>,
    code: DigestCode,
) -> Result<(), SerderError> {
    let mut scratch = raw.to_vec();
    fill_span(&mut scratch, said_span)?;
    if let Some(span) = prefix_span {
        fill_span(&mut scratch, span)?;
    }
    let computed = compute_digest(&scratch, code)?;
    let computed_qb64 = to_qb64_string(&computed);
    if said_value == computed_qb64 {
        Ok(())
    } else {
        Err(SerderError::SaidMismatch {
            expected: said_value.to_owned(),
            computed: computed_qb64,
        })
    }
}

fn fill_span(scratch: &mut [u8], span: &Range<usize>) -> Result<(), SerderError> {
    scratch
        .get_mut(span.clone())
        .ok_or(SerderError::InvalidEventLayout("SAID span out of bounds"))?
        .fill(DUMMY_BYTE);
    Ok(())
}
```

(`alloc::vec::Vec` is already importable; extend the `alloc` import list with `vec::Vec` if missing.)

- [ ] **Step 5.2: Tests** (in `said.rs` `mod tests`) — verify against the writer's own orchestration, which computes SAIDs the same way:

```rust
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::VerKeyCode;
    use crate::core::primitives::{Seqner, Tholder};
    use crate::keri::InteractionEvent;
    use crate::serder::serialize::serialize_interaction;
    use alloc::borrow::Cow;

    fn probe_ixn_raw() -> (alloc::vec::Vec<u8>, String) {
        let prefixer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let saider_fixture = compute_digest(b"seed", DigestCode::Blake3_256).unwrap();
        let event = InteractionEvent::new(
            prefixer.into(),
            Seqner::new(1),
            saider_fixture.clone(),
            saider_fixture,
            vec![],
        );
        let ser = serialize_interaction(&event).unwrap();
        let said = to_qb64_string(ser.said());
        (ser.as_bytes().to_vec(), said)
    }

    #[test]
    fn verify_said_spans_accepts_writer_output() {
        let (raw, said) = probe_ixn_raw();
        let start = raw
            .windows(6)
            .position(|w| w == b"\"d\":\"E")
            .expect("d field present")
            + 5;
        let span = start..start + 44;
        assert_eq!(&raw[span.clone()], said.as_bytes());
        verify_said_spans(&raw, &said, &span, None, DigestCode::Blake3_256)
            .expect("writer output must verify");
    }

    #[test]
    fn verify_said_spans_rejects_tamper() {
        let (mut raw, said) = probe_ixn_raw();
        let start = raw
            .windows(6)
            .position(|w| w == b"\"d\":\"E")
            .unwrap()
            + 5;
        let span = start..start + 44;
        let s_pos = raw.windows(8).position(|w| w == b",\"s\":\"1\"").unwrap();
        raw[s_pos + 6] = b'2';
        assert!(matches!(
            verify_said_spans(&raw, &said, &span, None, DigestCode::Blake3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_spans_rejects_out_of_bounds_span() {
        let (raw, said) = probe_ixn_raw();
        let bogus = raw.len()..raw.len() + 44;
        assert!(matches!(
            verify_said_spans(&raw, &said, &bogus, None, DigestCode::Blake3_256),
            Err(SerderError::InvalidEventLayout(_))
        ));
    }
```

(`SerderError` and `String` need importing in the test module if not present: `use crate::serder::error::SerderError;` and `use alloc::string::String;`.)

- [ ] **Step 5.3: Run tests**

Run: `nix develop --command cargo nextest run -p cesr-rs said::`
Expected: PASS.

- [ ] **Step 5.4: Commit**

```bash
git add cesr/src/serder/said.rs
git commit -m "feat(serder): offset-based SAID verification — copy-once, fill spans, hash (#142)"
```

---

### Task 6: Rewire the public deserializers onto the strict parser

**Files:**
- Create: `cesr/src/serder/deserialize/reference.rs` (old path, `#[cfg(test)]` oracle)
- Modify: `cesr/src/serder/deserialize.rs`

This is the pivotal task. The old `serde_json::Value` implementation moves verbatim into `reference.rs`; the public entry points re-implement over `canonical` + `verify_said_spans`. The qb64/sn/weight converters stay in `deserialize.rs` and are shared by both paths, so conversion behavior is identical by construction.

- [ ] **Step 6.1: Create `reference.rs`** — move these items out of `deserialize.rs` **unchanged** (cut-paste, adjusting only paths to `super::`): `validate_version_string`, `verify_said_single`, `verify_said_double`, `tholder_from_json`, `parse_witness_threshold`, `seal_from_json`, `parse_seal_array`, `parse_config_array`, `parse_qb64_prefixer_array`, `parse_qb64_verfer_array`, `parse_qb64_diger_array`, `get_str`, `get_field`, and the five `deserialize_*` bodies plus `deserialize_event` (renamed inside the module to the same names). Header:

```rust
//! The pre-#142 tolerant read path (`serde_json::Value` + re-render SAID
//! verification), preserved verbatim as the differential-test oracle for
//! the strict canonical parser. Test-only: never compiled into production.

use super::{infer_digest_code, map_qb64_error, parse_qb64_diger, parse_qb64_identifier,
    parse_qb64_prefixer, parse_qb64_saider, parse_qb64_verfer, parse_sn, parse_weight};
use crate::core::matter::code::DigestCode;
use crate::core::matter::error::ValidationError;
use crate::core::primitives::{Diger, Prefixer, Seqner, Tholder, Verfer};
use crate::keri::{
    ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, Ilk,
    InceptionEvent, InteractionEvent, KeriEvent, RotationEvent, Seal,
};
use crate::serder::error::SerderError;
use crate::serder::primitives::to_qb64_string;
use crate::serder::said::{compute_digest, said_placeholder};
use crate::serder::version::{SerKind, VERSION_STRING_LEN, VersionString};
use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};
use serde_json::Value;
```

In `deserialize.rs`, declare it:

```rust
#[cfg(test)]
pub(crate) mod reference;
```

Move the old unit tests that directly exercise Value-based helpers (`tholder_simple_from_json`, `tholder_weighted_from_json`, `tholder_invalid_returns_error`, `seal_*_from_json`, `tholder_from_json_integer`, `parse_witness_threshold_integer`) into a `mod tests` inside `reference.rs` — they pin the oracle's behavior.

- [ ] **Step 6.2: Write the strict conversion layer in `deserialize.rs`** (replacing the moved code; the shared helpers `parse_qb64_*`, `parse_sn`, `parse_weight`, `map_qb64_error`, `infer_digest_code` remain where they are):

```rust
use crate::serder::deserialize::canonical::{
    ParsedCount, ParsedDip, ParsedEvent, ParsedIcp, ParsedIxn, ParsedRot, ParsedSeal,
    ParsedTholder, Spanned,
};
use crate::serder::said::verify_said_spans;
```

```rust
fn tholder_from_parsed(t: &ParsedTholder<'_>) -> Result<Tholder, SerderError> {
    match t {
        ParsedTholder::Hex(s) => {
            let n = u64::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!("invalid hex threshold: {s}")),
            })?;
            Ok(Tholder::Simple(n))
        }
        ParsedTholder::Number(s) => {
            let n = s.parse::<u64>().map_err(|_| SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!("invalid integer threshold: {s}")),
            })?;
            Ok(Tholder::Simple(n))
        }
        ParsedTholder::Weighted(clauses) => {
            let parsed: Result<Vec<Vec<(u64, u64)>>, SerderError> = clauses
                .iter()
                .map(|clause| clause.iter().map(|w| parse_weight(w)).collect())
                .collect();
            Ok(Tholder::Weighted(parsed?))
        }
    }
}

fn witness_threshold_from_parsed(c: &ParsedCount<'_>) -> Result<u32, SerderError> {
    let n = match c {
        ParsedCount::Hex(s) => {
            u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
                field: "bt",
                source: ValidationError::UnknownMatterCode(format!("invalid hex bt: {s}")),
            })?
        }
        ParsedCount::Number(s) => {
            s.parse::<u128>().map_err(|_| SerderError::InvalidPrimitive {
                field: "bt",
                source: ValidationError::UnknownMatterCode(format!("invalid integer bt: {s}")),
            })?
        }
    };
    u32::try_from(n).map_err(|_| SerderError::InvalidPrimitive {
        field: "bt",
        source: ValidationError::UnknownMatterCode(format!(
            "witness threshold {n} exceeds u32::MAX"
        )),
    })
}

fn seal_from_parsed(seal: &ParsedSeal<'_>) -> Result<Seal, SerderError> {
    match seal {
        ParsedSeal::Digest { d } => Ok(Seal::Digest {
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Root { rd } => Ok(Seal::Root {
            rd: parse_qb64_saider(rd, "rd")?,
        }),
        ParsedSeal::Source { s, d } => Ok(Seal::Source {
            s: Seqner::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Event { i, s, d } => Ok(Seal::Event {
            i: parse_qb64_prefixer(i, "i")?,
            s: Seqner::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Last { i } => Ok(Seal::Last {
            i: parse_qb64_prefixer(i, "i")?,
        }),
    }
}

fn config_from_parsed(config: &[&str]) -> Result<Vec<ConfigTrait>, SerderError> {
    config
        .iter()
        .map(|s| ConfigTrait::from_code(s).map_err(|_| SerderError::UnknownIlk((*s).to_owned())))
        .collect()
}

fn verfers_from_parsed(
    items: &[&str],
    field: &'static str,
) -> Result<Vec<Verfer<'static>>, SerderError> {
    items.iter().map(|s| parse_qb64_verfer(s, field)).collect()
}

fn prefixers_from_parsed(
    items: &[&str],
    field: &'static str,
) -> Result<Vec<Prefixer<'static>>, SerderError> {
    items.iter().map(|s| parse_qb64_prefixer(s, field)).collect()
}

fn digers_from_parsed(
    items: &[&str],
    field: &'static str,
) -> Result<Vec<Diger<'static>>, SerderError> {
    items.iter().map(|s| parse_qb64_diger(s, field)).collect()
}

fn anchors_from_parsed(anchors: &[ParsedSeal<'_>]) -> Result<Vec<Seal>, SerderError> {
    anchors.iter().map(seal_from_parsed).collect()
}
```

- [ ] **Step 6.3: SAID verification helpers over parsed spans** (in `deserialize.rs`; preserves today's semantics — double-SAID only when `d == i`):

```rust
fn verify_single_said(raw: &[u8], said: &Spanned<'_>) -> Result<(), SerderError> {
    let code = infer_digest_code(said.value)?;
    verify_said_spans(raw, said.value, &said.span, None, code)
}

fn verify_inception_said(raw: &[u8], parsed: &ParsedIcp<'_>) -> Result<(), SerderError> {
    let code = infer_digest_code(parsed.said.value)?;
    let prefix_span =
        (parsed.said.value == parsed.prefix.value).then_some(&parsed.prefix.span);
    verify_said_spans(raw, parsed.said.value, &parsed.said.span, prefix_span, code)
}
```

- [ ] **Step 6.4: Re-implement the six public entry points** (doc comments stay; update the SAID wording to "verified in place over the raw bytes" and add `SerderError::NonCanonical` to the `# Errors` lists):

```rust
pub fn deserialize_event(raw: &[u8]) -> Result<KeriEvent, SerderError> {
    match canonical::parse_event(raw)? {
        ParsedEvent::Inception(p) => {
            verify_inception_said(raw, &p)?;
            Ok(KeriEvent::Inception(build_inception(&p)?))
        }
        ParsedEvent::Rotation(p) => {
            verify_single_said(raw, &p.said)?;
            Ok(KeriEvent::Rotation(build_rotation(&p)?))
        }
        ParsedEvent::Interaction(p) => {
            verify_single_said(raw, &p.said)?;
            Ok(KeriEvent::Interaction(build_interaction(&p)?))
        }
        ParsedEvent::DelegatedInception(p) => {
            verify_inception_said(raw, &p.icp)?;
            Ok(KeriEvent::DelegatedInception(build_delegated_inception(&p)?))
        }
        ParsedEvent::DelegatedRotation(p) => {
            verify_single_said(raw, &p.said)?;
            Ok(KeriEvent::DelegatedRotation(DelegatedRotationEvent::new(
                build_rotation(&p)?,
            )))
        }
    }
}

pub fn deserialize_inception(raw: &[u8]) -> Result<InceptionEvent, SerderError> {
    let parsed = canonical::parse_inception(raw)?;
    verify_inception_said(raw, &parsed)?;
    build_inception(&parsed)
}

pub fn deserialize_rotation(raw: &[u8]) -> Result<RotationEvent, SerderError> {
    let parsed = canonical::parse_rotation(raw)?;
    verify_single_said(raw, &parsed.said)?;
    build_rotation(&parsed)
}

pub fn deserialize_interaction(raw: &[u8]) -> Result<InteractionEvent, SerderError> {
    let parsed = canonical::parse_interaction(raw)?;
    verify_single_said(raw, &parsed.said)?;
    build_interaction(&parsed)
}

pub fn deserialize_delegated_inception(raw: &[u8]) -> Result<DelegatedInceptionEvent, SerderError> {
    let parsed = canonical::parse_delegated_inception(raw)?;
    verify_inception_said(raw, &parsed.icp)?;
    build_delegated_inception(&parsed)
}

pub fn deserialize_delegated_rotation(raw: &[u8]) -> Result<DelegatedRotationEvent, SerderError> {
    let parsed = canonical::parse_delegated_rotation(raw)?;
    verify_single_said(raw, &parsed.said)?;
    Ok(DelegatedRotationEvent::new(build_rotation(&parsed)?))
}
```

with builders:

```rust
fn build_inception(p: &ParsedIcp<'_>) -> Result<InceptionEvent, SerderError> {
    Ok(InceptionEvent::new(
        parse_qb64_identifier(p.prefix.value, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        verfers_from_parsed(&p.keys, "k")?,
        tholder_from_parsed(&p.threshold)?,
        digers_from_parsed(&p.next_keys, "n")?,
        tholder_from_parsed(&p.next_threshold)?,
        prefixers_from_parsed(&p.witnesses, "b")?,
        witness_threshold_from_parsed(&p.witness_threshold)?,
        config_from_parsed(&p.config)?,
        anchors_from_parsed(&p.anchors)?,
    ))
}

fn build_delegated_inception(p: &ParsedDip<'_>) -> Result<DelegatedInceptionEvent, SerderError> {
    Ok(DelegatedInceptionEvent::new(
        build_inception(&p.icp)?,
        parse_qb64_identifier(p.delegator, "di")?,
    ))
}

fn build_rotation(p: &ParsedRot<'_>) -> Result<RotationEvent, SerderError> {
    Ok(RotationEvent::new(
        parse_qb64_identifier(p.prefix, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        parse_qb64_diger(p.prior, "p")?,
        verfers_from_parsed(&p.keys, "k")?,
        tholder_from_parsed(&p.threshold)?,
        digers_from_parsed(&p.next_keys, "n")?,
        tholder_from_parsed(&p.next_threshold)?,
        prefixers_from_parsed(&p.witness_additions, "ba")?,
        prefixers_from_parsed(&p.witness_removals, "br")?,
        witness_threshold_from_parsed(&p.witness_threshold)?,
        vec![],
        anchors_from_parsed(&p.anchors)?,
    ))
}

fn build_interaction(p: &ParsedIxn<'_>) -> Result<InteractionEvent, SerderError> {
    Ok(InteractionEvent::new(
        parse_qb64_identifier(p.prefix, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        parse_qb64_diger(p.prior, "p")?,
        anchors_from_parsed(&p.anchors)?,
    ))
}
```

Note the `RotationEvent::new` argument order (additions before removals, then threshold, then `config: vec![]` — match the existing call in the old `deserialize_rotation` exactly; rot events carry no `c` field).

Remove `use serde_json::Value;` and the now-unused `said_placeholder` import from `deserialize.rs` production imports.

- [ ] **Step 6.5: Fix knock-on test expectations.**
  - In `deserialize.rs` tests: the whitespace-padding probes (`deserialize_*_rejects_length_mismatched_raw`) still expect `InvalidVersionString` — they stay green (the head size check fires first). Keep them.
  - In `serialize/direct.rs`: update the comment in `direct_output_verifies_through_unchanged_read_path` — the read path is now the strict parser; the assertion itself is unchanged and still valid.
  - Add intive acceptance tests at the public level in `deserialize.rs` tests (replacing the moved Value-level ones), using a re-SAID helper:

```rust
    /// Rewrite the size field and recompute + splice the SAID so a byte-level
    /// surgery on a serialized event stays canonical and verifiable.
    fn resaid(mut raw: Vec<u8>) -> Vec<u8> {
        use crate::serder::said::{compute_digest, said_placeholder};
        let size = raw.len();
        let hex = format!("{size:06x}");
        raw[16..22].copy_from_slice(hex.as_bytes());
        let d_pos = raw.windows(5).position(|w| w == b"\"d\":\"").unwrap() + 5;
        let span = d_pos..d_pos + 44;
        let placeholder = said_placeholder(DigestCode::Blake3_256).unwrap();
        let mut scratch = raw.clone();
        scratch[span.clone()].copy_from_slice(placeholder.as_bytes());
        let computed = compute_digest(&scratch, DigestCode::Blake3_256).unwrap();
        let qb64 = crate::serder::primitives::to_qb64_string(&computed);
        raw[span].copy_from_slice(qb64.as_bytes());
        raw
    }

    #[test]
    fn intive_integer_bt_is_accepted() {
        let raw = serialize_inception(&probe_icp()).unwrap().as_bytes().to_vec();
        let pos = raw.windows(9).position(|w| w == b"\"bt\":\"0\",").unwrap();
        let mut mutated = Vec::with_capacity(raw.len());
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b"\"bt\":0,");
        mutated.extend_from_slice(&raw[pos + 9..]);
        let canonical_intive = resaid(mutated);
        let event = deserialize_inception(&canonical_intive)
            .expect("keripy intive=True integer bt must deserialize");
        assert_eq!(event.witness_threshold(), 0);
    }

    #[test]
    fn intive_integer_kt_is_accepted() {
        let raw = serialize_inception(&probe_icp()).unwrap().as_bytes().to_vec();
        let pos = raw.windows(9).position(|w| w == b"\"kt\":\"1\",").unwrap();
        let mut mutated = Vec::with_capacity(raw.len());
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b"\"kt\":1,");
        mutated.extend_from_slice(&raw[pos + 9..]);
        let canonical_intive = resaid(mutated);
        let event = deserialize_inception(&canonical_intive)
            .expect("keripy intive=True integer kt must deserialize");
        assert_eq!(*event.threshold(), Tholder::Simple(1));
    }
```

  (Note: `resaid` performs single-SAID recomputation, which is only valid for icp probes when `d != i`; `probe_icp()` uses a `make_prefixer()` basic prefix, so `d != i` holds and single-SAID applies.)

  - Behavior-change probes (new):

```rust
    #[test]
    fn deserialize_rotation_rejects_drt_bytes() {
        let drt = DelegatedRotationEvent::new(probe_rot());
        let raw = serialize_delegated_rotation(&drt).unwrap();
        assert!(matches!(
            deserialize_rotation(raw.as_bytes()),
            Err(SerderError::NonCanonical { expected: "rot", .. })
        ));
    }

    #[test]
    fn deserialize_inception_rejects_dip_bytes() {
        let dip = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
        let raw = serialize_delegated_inception(&dip).unwrap();
        assert!(
            deserialize_inception(raw.as_bytes()).is_err(),
            "dip bytes must not silently deserialize as icp (delegator dropped)"
        );
    }
```

- [ ] **Step 6.6: Run the full crate test suite** — the existing round-trip, tamper, and version-string suites are the regression net for the rewire:

Run: `nix develop --command cargo nextest run -p cesr-rs`
Expected: all PASS. Also run doctests: `nix develop --command cargo test -p cesr-rs --doc` — expected PASS.

- [ ] **Step 6.7: Commit**

```bash
git add cesr/src/serder/deserialize.rs cesr/src/serder/deserialize/reference.rs cesr/src/serder/serialize/direct.rs
git commit -m "feat(serder)!: rewire deserializers onto the strict canonical parser (#142)"
```

---

### Task 7: `said::verify_said` — strict, `Result<(), SerderError>`

**Files:**
- Modify: `cesr/src/serder/said.rs`
- Modify (if it pins the old signature): `cesr/tests/frozen_surface.rs`

- [ ] **Step 7.1: Replace the implementation** (keep the name; update docs):

```rust
/// Verify that the `d` field of a serialized canonical event matches a
/// freshly computed SAID.
///
/// Parses the event with the strict canonical parser, fills the `d` (and,
/// for `icp`/`dip` events whose prefix equals their SAID, the `i`) value
/// span with [`DUMMY_CHAR`] in a single scratch copy, hashes, and compares.
///
/// # Errors
///
/// Returns [`SerderError::SaidMismatch`] if the digest differs,
/// [`SerderError::NonCanonical`] / [`SerderError::InvalidVersionString`] if
/// the input is not a canonical event, or [`SerderError::DigestError`] on
/// hash failure.
pub fn verify_said(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    match parse_event(raw)? {
        ParsedEvent::Inception(p) | ParsedEvent::DelegatedInception(ParsedDip { icp: p, .. }) => {
            let prefix_span = (p.said.value == p.prefix.value).then_some(&p.prefix.span);
            verify_said_spans(raw, p.said.value, &p.said.span, prefix_span, code)
        }
        ParsedEvent::Rotation(p) | ParsedEvent::DelegatedRotation(p) => {
            verify_said_spans(raw, p.said.value, &p.said.span, None, code)
        }
        ParsedEvent::Interaction(p) => {
            verify_said_spans(raw, p.said.value, &p.said.span, None, code)
        }
    }
}
```

with the import at the top of `said.rs`:

```rust
use crate::serder::deserialize::canonical::{ParsedDip, ParsedEvent, parse_event};
```

Remove the old body's `serde_json` usage from `said.rs` entirely.

- [ ] **Step 7.2: Update every caller.**

Run: `rg -n "verify_said\(" cesr/ keri/ --glob '!**/canonical.rs'`
For each hit (tests in `said.rs`, possibly `frozen_surface.rs`): change `assert!(verify_said(...)  .unwrap())` forms to `verify_said(...).expect(...)` / `assert!(matches!(verify_said(...), Err(SerderError::SaidMismatch { .. })))`.

- [ ] **Step 7.3: Add/adjust tests in `said.rs`:**

```rust
    #[test]
    fn verify_said_accepts_serialized_event() {
        let (raw, _) = probe_ixn_raw();
        verify_said(&raw, DigestCode::Blake3_256).expect("writer output must verify");
    }

    #[test]
    fn verify_said_rejects_tampered_event() {
        let (mut raw, _) = probe_ixn_raw();
        let s_pos = raw.windows(8).position(|w| w == b",\"s\":\"1\"").unwrap();
        raw[s_pos + 6] = b'2';
        assert!(matches!(
            verify_said(&raw, DigestCode::Blake3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_rejects_non_canonical_input() {
        assert!(matches!(
            verify_said(b"not an event", DigestCode::Blake3_256),
            Err(SerderError::NonCanonical { .. }) | Err(SerderError::InvalidVersionString(_))
        ));
    }
```

- [ ] **Step 7.4: Run tests**

Run: `nix develop --command cargo nextest run -p cesr-rs`
Expected: PASS.

- [ ] **Step 7.5: Commit**

```bash
git add cesr/src/serder/said.rs cesr/tests/frozen_surface.rs
git commit -m "feat(serder)!: verify_said goes strict and returns Result<(), SerderError> (#142)"
```

---

### Task 8: Extract shared proptest event strategies

**Files:**
- Create: `cesr/src/serder/event_strategies.rs`
- Modify: `cesr/src/serder/mod.rs`, `cesr/src/serder/serialize/direct.rs`

- [ ] **Step 8.1: Move the strategy layer.** Cut from `serialize/direct.rs`'s `mod tests` into the new file: `prefixer`, `saider`, the spec type aliases (`IdSpec`, `SealSpec`, `TholderSpec`, `IcpSpec`, `RotSpec`, `IxnSpec`), the `build_*` functions (`build_identifier`, `build_seal`, `build_tholder`, `build_config`, `build_icp`, `build_rot`, `build_ixn`), and the `*_strategy()` functions (`sn_strategy`, `bt_strategy`, `tholder_strategy`, `seal_strategy`, `icp_strategy`, `rot_strategy`, `ixn_strategy`). File header:

```rust
//! Shared proptest strategies over the builder-reachable KERI event space.
//!
//! Single source of truth for cross-backend (write path) and
//! strict-vs-reference (read path) differential property tests.

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{DigestCode, VerKeyCode};
use crate::core::primitives::{Prefixer, Saider, Seqner, Tholder};
use crate::keri::{ConfigTrait, Identifier, InceptionEvent, InteractionEvent, RotationEvent, Seal};
use alloc::borrow::Cow;
use alloc::{vec, vec::Vec};
use proptest::prelude::*;
```

All items become `pub(crate)`. Register in `serder/mod.rs`:

```rust
#[cfg(test)]
pub(crate) mod event_strategies;
```

- [ ] **Step 8.2: Re-point `serialize/direct.rs` tests** at the shared module:

```rust
    use crate::serder::event_strategies::{
        IdSpec, build_icp, build_identifier, build_ixn, build_rot, icp_strategy, ixn_strategy,
        prefixer, rot_strategy, saider,
    };
```

and delete the moved definitions from `direct.rs`. Everything else in the file is untouched.

- [ ] **Step 8.3: Run the write-path differentials to prove the move is behavior-neutral**

Run: `nix develop --command cargo nextest run -p cesr-rs direct::`
Expected: PASS, same test count as before the move.

- [ ] **Step 8.4: Commit**

```bash
git add cesr/src/serder/event_strategies.rs cesr/src/serder/mod.rs cesr/src/serder/serialize/direct.rs
git commit -m "refactor(serder): extract shared event proptest strategies (#142)"
```

---

### Task 9: Read-path differential and mutation properties

**Files:**
- Modify: `cesr/src/serder/deserialize.rs` (tests module)

- [ ] **Step 9.1: Differential property — strict and reference agree over the builder space, and both round-trip byte-identically.** Domain events deliberately have no `PartialEq`, so equality is asserted via re-serialization bytes:

```rust
    mod differential {
        use super::super::reference;
        use super::*;
        use crate::serder::event_strategies::{
            IdSpec, build_icp, build_identifier, build_ixn, build_rot, icp_strategy,
            ixn_strategy, rot_strategy,
        };
        use crate::serder::serialize::{EventRef, SerdeJson, serialize_with};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn icp_strict_equals_reference(spec in icp_strategy()) {
                let event = build_icp(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Inception(&event)).unwrap();
                let strict = deserialize_inception(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_inception(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_inception(&strict).unwrap();
                let oracle_bytes = serialize_inception(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn rot_strict_equals_reference(spec in rot_strategy()) {
                let event = build_rot(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Rotation(&event)).unwrap();
                let strict = deserialize_rotation(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_rotation(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_rotation(&strict).unwrap();
                let oracle_bytes = serialize_rotation(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn ixn_strict_equals_reference(spec in ixn_strategy()) {
                let event = build_ixn(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Interaction(&event)).unwrap();
                let strict = deserialize_interaction(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_interaction(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_interaction(&strict).unwrap();
                let oracle_bytes = serialize_interaction(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn dip_strict_equals_reference(spec in icp_strategy(), delegator in any::<IdSpec>()) {
                let dip = DelegatedInceptionEvent::new(build_icp(spec), build_identifier(delegator));
                let bytes = serialize_with(&SerdeJson, EventRef::DelegatedInception(&dip)).unwrap();
                let strict = deserialize_delegated_inception(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_delegated_inception(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_delegated_inception(&strict).unwrap();
                let oracle_bytes = serialize_delegated_inception(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn drt_strict_equals_reference(spec in rot_strategy()) {
                let drt = DelegatedRotationEvent::new(build_rot(spec));
                let bytes = serialize_with(&SerdeJson, EventRef::DelegatedRotation(&drt)).unwrap();
                let strict = deserialize_delegated_rotation(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_delegated_rotation(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_delegated_rotation(&strict).unwrap();
                let oracle_bytes = serialize_delegated_rotation(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            /// Strict acceptance is a subset of tolerant acceptance: any
            /// single-byte mutation the strict parser accepts, the reference
            /// oracle must also accept — and both must see the same event.
            #[test]
            fn strict_acceptance_is_subset_of_reference(
                spec in ixn_strategy(),
                idx in any::<prop::sample::Index>(),
                byte in any::<u8>(),
            ) {
                let event = build_ixn(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Interaction(&event)).unwrap();
                let mut mutated = bytes.as_bytes().to_vec();
                let i = idx.index(mutated.len());
                mutated[i] = byte;
                if let Ok(strict) = deserialize_interaction(&mutated) {
                    let oracle = reference::deserialize_interaction(&mutated);
                    prop_assert!(
                        oracle.is_ok(),
                        "strict accepted a mutation the tolerant oracle rejects"
                    );
                    let strict_bytes = serialize_interaction(&strict).unwrap();
                    let oracle_bytes = serialize_interaction(&oracle.unwrap()).unwrap();
                    prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                }
            }
        }
    }
```

- [ ] **Step 9.2: Run the differentials**

Run: `nix develop --command cargo nextest run -p cesr-rs differential`
Expected: PASS (any divergence between strict and oracle is a bug in Task 4/6 — debug there, do not weaken the property).

- [ ] **Step 9.3: Commit**

```bash
git add cesr/src/serder/deserialize.rs
git commit -m "test(serder): strict-vs-reference read-path differential and mutation-subset properties (#142)"
```

---

### Task 10: Allocation pin

**Files:**
- Modify: `cesr/tests/serder_allocation.rs`

- [ ] **Step 10.1: Add the deserialize measurement** (uses the existing `measure` + `fixture_icp` helpers in that file):

```rust
use cesr::serder::deserialize_event;

#[test]
fn deserialize_allocation_count_is_pinned() {
    let event = fixture_icp();
    let serialized = serialize_with(&DirectJson, EventRef::Inception(&event)).unwrap();
    let bytes = serialized.as_bytes();

    let _ = deserialize_event(bytes).unwrap();

    let (parsed, allocs) = measure(|| deserialize_event(bytes).unwrap());
    drop(parsed);

    assert_eq!(
        allocs, DESERIALIZE_ALLOCS,
        "deserialize_event allocation count changed — the strict read path \
         must stay at one scratch copy plus domain-type construction; a rise \
         means an intermediate tree or render crept back in"
    );
}
```

- [ ] **Step 10.2: Measure the true count, then pin it.** First run with `const DESERIALIZE_ALLOCS: usize = 0;` — the failure output prints the measured value. Set the constant to that exact value with a comment decomposing it (1 scratch copy + N domain Vec/String allocations for the fixture).

Run: `nix develop --command cargo nextest run -p cesr-rs deserialize_allocation`
Expected: FAIL once (prints real count), then PASS after pinning.

- [ ] **Step 10.3: Commit**

```bash
git add cesr/tests/serder_allocation.rs
git commit -m "test(serder): pin strict read-path allocation count (#142)"
```

---

### Task 11: Deserialize benchmark

**Files:**
- Modify: `cesr/benches/serder.rs`

- [ ] **Step 11.1: Add the bench** (reuses the existing `fixture_icp`; check the file's existing `criterion_group!` and add the new function to it):

```rust
use cesr::serder::deserialize_event;

fn bench_deserialize(c: &mut Criterion) {
    let icp = fixture_icp();
    let serialized = serialize_with(&SerdeJson, EventRef::Inception(&icp)).expect("fixture serializes");
    let bytes = serialized.as_bytes();
    c.bench_function("deserialize_event/icp", |b| {
        b.iter(|| deserialize_event(black_box(bytes)).expect("fixture deserializes"));
    });
}
```

and extend the group at the bottom of the file, e.g. `criterion_group!(benches, bench_serialize, bench_deserialize);` (match the existing group name/members exactly — read the tail of the file first).

- [ ] **Step 11.2: Smoke-run the bench compilation**

Run: `nix develop --command cargo bench -p cesr-rs --bench serder -- --test`
Expected: compiles and runs each bench once, exit 0.

- [ ] **Step 11.3: Commit**

```bash
git add cesr/benches/serder.rs
git commit -m "bench(serder): deserialize_event throughput for CodSpeed (#142)"
```

---

### Task 12: Fuzz targets (bolero + AFL)

**Files:**
- Modify: `fuzz-common/Cargo.toml`, `fuzz-common/src/lib.rs`
- Create: `fuzz/tests/serder.rs`, `fuzz-afl/src/bin/serder_deserialize_event.rs`
- Modify: `fuzz-afl/Cargo.toml`, possibly `fuzz/` Cargo manifest and the deep-fuzz workflow

- [ ] **Step 12.1: fuzz-common** — enable serder and add the harness body:

```toml
cesr = { package = "cesr-rs", path = "../cesr", features = ["stream", "serder"] }
```

```rust
use cesr::serder::{KeriSerialize, deserialize_event};

/// Strict canonical event parse on untrusted bytes. A panic is a finding.
/// If the input parses, it must re-serialize and re-parse cleanly
/// (idempotence); byte-identity is NOT asserted because keripy intive
/// integers legally re-render as hex strings.
pub fn serder_deserialize_event(data: &[u8]) {
    if let Ok(event) = deserialize_event(data) {
        let reser = event
            .serialize()
            .expect("a parsed event must re-serialize");
        deserialize_event(reser.as_bytes())
            .expect("a re-serialized event must re-parse");
    }
}
```

- [ ] **Step 12.2: bolero target** — `fuzz/tests/serder.rs` (mirror `binary.rs`'s shape):

```rust
//! Fuzz target for strict canonical KERI event deserialization.

#[test]
fn serder_deserialize_event() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::serder_deserialize_event(input));
}
```

- [ ] **Step 12.3: AFL target** — `fuzz-afl/src/bin/serder_deserialize_event.rs` (mirror an existing bin, e.g. `matter_from_qb64.rs` — read it first and copy its exact shape), plus the manifest entry:

```toml
[[bin]]
name = "serder_deserialize_event"
path = "src/bin/serder_deserialize_event.rs"
```

(match the `path`/formatting convention of the existing `[[bin]]` entries exactly).

- [ ] **Step 12.4: Wire into CI target lists if enumerated.**

Run: `rg -n "stream_parse_message|matter_from_qb64" .github/workflows/ flake.nix nix/`
If the deep-fuzz workflow or the `cesr-fuzz-replay` check enumerates targets explicitly, add `serder_deserialize_event` in the same style at each site.

- [ ] **Step 12.5: Smoke both engines locally** (bolero runs as a plain test without a fuzzing engine; AFL is CI-only on macOS per project memory — compile-check it only):

```bash
nix develop --command bash -c "cd fuzz && cargo test serder_deserialize_event"
nix develop --command bash -c "cd fuzz-afl && cargo check"
```

Expected: both exit 0.

- [ ] **Step 12.6: Commit**

```bash
git add fuzz-common/ fuzz/tests/serder.rs fuzz-afl/ .github/workflows/ 2>/dev/null
git commit -m "ci(fuzz): strict serder deserialize fuzz target for both engines (#142)"
```

---

### Task 13: Docs, gate, PR

**Files:**
- Modify: `cesr/src/serder/mod.rs`, `cesr/src/serder/deserialize.rs` (module docs), `cesr/CHANGELOG.md` (only if release-plz does not auto-generate — check recent breaking PRs' handling first)

- [ ] **Step 13.1: Update module docs.** `deserialize.rs` header:

```rust
//! KERI event deserialization from canonical JSON with SAID verification.
//!
//! The read path is a strict single-pass canonical parser
//! ([`canonical`]): compact JSON, spec field order, no escapes — any
//! deviation is a typed [`SerderError::NonCanonical`]. SAID verification
//! is offset-based: one scratch copy of the raw bytes, the `d` (and `i`
//! for `icp`/`dip`) spans overwritten with `#`, one hash — no
//! parse-mutate-re-render.
```

and adjust the `serder/mod.rs` crate-module doc's deserialization sentence to say "strict canonical parsing with in-place SAID verification".

- [ ] **Step 13.2: The single gate** (commit everything first — the flake check sees only committed state):

```bash
git status --short   # must be empty
nix flake check
```

Expected: all 36 checks green, including `cesr-wasm`, `cesr-nostd`, `cesr-clippy` (god-level), nextest across the feature matrix, and the keri crate's differential suite (keripy corpus through the now-strict `deserialize_event`).

- [ ] **Step 13.3: Push and open the PR**

```bash
git push -u origin feat/142-strict-read-path
gh pr create --title "feat(serder)!: #142 strict canonical read-path parser — offset-based SAID verification" --body "$(cat <<'EOF'
Closes #142. The read-path half of the #79 seam (design §3.3/§3.5).

## What
- Strict single-pass canonical parser for the five fixed event grammars
  (`serder::deserialize::canonical`): compact JSON, spec field order, no
  escapes/duplicates/whitespace — rejected by construction with the new
  typed `SerderError::NonCanonical { offset, expected, found }`.
- Offset-based SAID verification: one scratch copy + span fill + hash,
  replacing 2–3 `Value` trees and a full re-render per ingested event.
- Borrowed `&str` field views (`ParsedIcp<'a>` …) — the substrate for
  C-a #129's borrow-ified `KeriEvent<'a>`.
- keripy `intive=True` integer `kt`/`nt`/`bt` still accepted (their SAIDs
  are computed over the integer form; rejecting them is a parity gap).

## Breaking (MINOR under 0.x)
- New `SerderError::NonCanonical` variant; non-canonical inputs now fail
  with it instead of assorted `Json`/`MissingField` errors.
- `said::verify_said` is strict and returns `Result<(), SerderError>`
  (was `Result<bool, _>`).
- Per-ilk deserializers require their exact ilk (`deserialize_rotation`
  no longer accepts `drt` bytes; `deserialize_inception` no longer
  silently accepts `dip` bytes and drops the delegator).

## Verification
- Strict-vs-reference differential proptests over the builder-reachable
  event space (all five ilks), byte-identical re-serialization.
- Mutation-subset property: anything strict accepts, the tolerant oracle
  accepts identically.
- Rejection probes: whitespace (size-consistent), duplicate keys,
  reordered fields, escapes, trailing bytes, every-prefix truncation.
- keripy corpus through the strict path via keri/tests/differential.rs.
- Allocation count pinned; CodSpeed deserialize bench added; bolero+AFL
  fuzz target `serder_deserialize_event` (idempotence oracle).
- `nix flake check` green (wasm + no_std included).

The old `serde_json::Value` read path survives only as the `#[cfg(test)]`
differential oracle (`deserialize::reference`). serde demotion to
dev-dependencies is the follow-up card per design §6 staging.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 13.4: Attach the PR/issue to the project board** (org Project #5) and note CodSpeed numbers in the PR once CI reports them.

---

## Self-Review Notes (done at plan time)

- **Spec coverage:** issue acceptance ↔ tasks: strict parser behind EventLayout-style slot vocabulary (Tasks 2–5), byte-range SAID verify without re-render (Task 5), differential vs serde_json read path over builder space (Task 9) + keripy corpus (keri differential suite, Step 13.2), rejection tests for whitespace/duplicates/reordering/escapes (Task 4), no_std+wasm+flake (Step 13.2).
- **Order-of-checks invariant:** head size check (#139 defence) fires before grammar; grammar fires before SAID verify; SAID verify fires before qb64 domain conversion — tests in Tasks 4/6 pin each layer.
- **Type consistency:** `Spanned`/`ParsedIcp`/`ParsedDip`/`ParsedRot`/`ParsedIxn`/`ParsedEvent`/`ParsedTholder`/`ParsedCount`/`ParsedSeal` are defined once in Task 2–4 and used with those exact names in Tasks 6–7; `verify_said_spans(raw, said_value, said_span, prefix_span, code)` signature is identical in Tasks 5, 6, and 7.
- **Known judgment calls an executor must not "fix" silently:** integer acceptance for `kt`/`nt`/`bt` is deliberate (keripy intive parity); `RotationEvent` grammar has **no** `c` field; double-SAID fill only when `d == i` (matches the tolerant path's semantics); fuzz round-trip asserts idempotence, not byte identity (intive re-renders as hex).
