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

use crate::error::SerderError;
use cesr::core::version::{SerializationKind, VERSION_STRING_LEN, VersionString};
use cesr::keri::seal::scan_object;

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

/// A seal object: one of the seven fixed codex shapes, or a verbatim
/// opaque capture of a non-codex anchor.
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
    /// Registrar-backer seal.
    Back {
        /// Backer identifier prefix, qb64.
        bi: &'a str,
        /// Metadata digest, qb64.
        d: &'a str,
    },
    /// Typed digest seal.
    Kind {
        /// Digest type tag, qb64 (Verser).
        t: &'a str,
        /// SAID digest, qb64.
        d: &'a str,
    },
    /// Non-codex anchor: the verbatim compact-JSON object span.
    Opaque {
        /// Raw object text.
        raw: &'a str,
    },
}

/// A parsed inception (`icp`) body: borrowed field views plus SAID spans.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedIcp<'a> {
    /// The `d` field: SAID digest, value and byte span.
    pub(crate) said: Spanned<'a>,
    /// The `i` field: identifier prefix, value and byte span.
    pub(crate) prefix: Spanned<'a>,
    /// The `s` field: sequence number, hex.
    pub(crate) sn: &'a str,
    /// The `kt` field: signing threshold.
    pub(crate) threshold: ParsedTholder<'a>,
    /// The `k` field: signing keys, qb64.
    pub(crate) keys: Vec<&'a str>,
    /// The `nt` field: next signing threshold.
    pub(crate) next_threshold: ParsedTholder<'a>,
    /// The `n` field: next key digests, qb64.
    pub(crate) next_keys: Vec<&'a str>,
    /// The `bt` field: witness threshold.
    pub(crate) witness_threshold: ParsedCount<'a>,
    /// The `b` field: witness identifiers, qb64.
    pub(crate) witnesses: Vec<&'a str>,
    /// The `c` field: configuration traits.
    pub(crate) config: Vec<&'a str>,
    /// The `a` field: anchored seals.
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// A parsed delegated inception (`dip`): an inception plus the delegator.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedDip<'a> {
    /// The inception fields shared with `icp`.
    pub(crate) icp: ParsedIcp<'a>,
    /// The `di` field: delegator identifier, qb64.
    pub(crate) delegator: &'a str,
}

/// A parsed rotation (`rot`) or delegated rotation (`drt`) body.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedRot<'a> {
    /// The `d` field: SAID digest, value and byte span.
    pub(crate) said: Spanned<'a>,
    /// The `i` field: identifier prefix, qb64.
    pub(crate) prefix: &'a str,
    /// The `s` field: sequence number, hex.
    pub(crate) sn: &'a str,
    /// The `p` field: prior event SAID, qb64.
    pub(crate) prior: &'a str,
    /// The `kt` field: signing threshold.
    pub(crate) threshold: ParsedTholder<'a>,
    /// The `k` field: signing keys, qb64.
    pub(crate) keys: Vec<&'a str>,
    /// The `nt` field: next signing threshold.
    pub(crate) next_threshold: ParsedTholder<'a>,
    /// The `n` field: next key digests, qb64.
    pub(crate) next_keys: Vec<&'a str>,
    /// The `bt` field: witness threshold.
    pub(crate) witness_threshold: ParsedCount<'a>,
    /// The `br` field: witness removals, qb64.
    pub(crate) witness_removals: Vec<&'a str>,
    /// The `ba` field: witness additions, qb64.
    pub(crate) witness_additions: Vec<&'a str>,
    /// The `a` field: anchored seals.
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// A parsed interaction (`ixn`) body.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ParsedIxn<'a> {
    /// The `d` field: SAID digest, value and byte span.
    pub(crate) said: Spanned<'a>,
    /// The `i` field: identifier prefix, qb64.
    pub(crate) prefix: &'a str,
    /// The `s` field: sequence number, hex.
    pub(crate) sn: &'a str,
    /// The `p` field: prior event SAID, qb64.
    pub(crate) prior: &'a str,
    /// The `a` field: anchored seals.
    pub(crate) anchors: Vec<ParsedSeal<'a>>,
}

/// Any parsed event, dispatched on the wire ilk.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedEvent<'a> {
    /// `icp`.
    Inception(ParsedIcp<'a>),
    /// `rot`.
    Rotation(ParsedRot<'a>),
    /// `ixn`.
    Interaction(ParsedIxn<'a>),
    /// `dip`.
    DelegatedInception(ParsedDip<'a>),
    /// `drt`.
    DelegatedRotation(ParsedRot<'a>),
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

/// Items of a canonical JSON array after the opening `[` and the empty-array
/// check (`]`) have already been consumed — i.e. the cursor is positioned at
/// the first item.
fn tail_list<'a, T>(
    sc: &mut Scanner<'a>,
    mut item: impl FnMut(&mut Scanner<'a>) -> Result<T, SerderError>,
) -> Result<Vec<T>, SerderError> {
    let mut items = vec![item(sc)?];
    loop {
        if sc.take_lit("]") {
            return Ok(items);
        }
        sc.expect(",")?;
        items.push(item(sc)?);
    }
}

/// A canonical JSON array `[item,item,...]` — no whitespace, no trailing
/// comma; empty `[]` allowed.
fn delimited_list<'a, T>(
    sc: &mut Scanner<'a>,
    item: impl FnMut(&mut Scanner<'a>) -> Result<T, SerderError>,
) -> Result<Vec<T>, SerderError> {
    sc.expect("[")?;
    if sc.take_lit("]") {
        return Ok(Vec::new());
    }
    tail_list(sc, item)
}

fn string_array<'a>(sc: &mut Scanner<'a>) -> Result<Vec<&'a str>, SerderError> {
    delimited_list(sc, |s| s.string().map(|sp| sp.value))
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
            let clause = tail_list(sc, |s| s.string().map(|sp| sp.value))?;
            Ok(ParsedTholder::Weighted(vec![clause]))
        }
        Some(b'[') => {
            let clauses = tail_list(sc, string_array)?;
            Ok(ParsedTholder::Weighted(clauses))
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

/// One codex seal object. Field order per variant is fixed (matches the
/// writer and keripy's namedtuple serialization order).
fn seal_codex<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
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
    if sc.take_lit("\"bi\":") {
        let bi = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Back { bi, d });
    }
    if sc.take_lit("\"t\":") {
        let t = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Kind { t, d });
    }
    Err(sc.err("seal object key (\"d\", \"rd\", \"s\", \"i\", \"bi\", or \"t\")"))
}

/// One seal object: the seven codex shapes parse typed; anything else
/// falls back to a verbatim opaque capture of the whole object. A codex
/// parse failure rewinds — the codex attempt and the opaque scan both
/// start from the object's first byte.
fn seal<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    let start = sc.pos;
    // The codex error is deliberately superseded: the opaque scan is the
    // outermost interpretation and produces its own typed error on failure.
    if let Ok(parsed) = seal_codex(sc) {
        return Ok(parsed);
    }
    sc.pos = start;
    seal_opaque(sc)
}

/// Capture a non-codex anchor object verbatim.
fn seal_opaque<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    let start = sc.pos;
    let rest = sc
        .input
        .get(start..)
        .ok_or(SerderError::InvalidEventLayout("anchor span out of bounds"))?;
    let len = scan_object(rest).map_err(|source| SerderError::InvalidAnchor {
        offset: start,
        source,
    })?;
    let end = start
        .checked_add(len)
        .ok_or(SerderError::InvalidEventLayout("anchor span overflow"))?;
    let bytes = sc
        .input
        .get(start..end)
        .ok_or(SerderError::InvalidEventLayout("anchor span out of bounds"))?;
    let raw = str::from_utf8(bytes).map_err(|e| {
        start.checked_add(e.valid_up_to()).map_or(
            SerderError::InvalidEventLayout("UTF-8 error offset overflow"),
            |offset| sc.err_at(offset, "UTF-8 anchor object"),
        )
    })?;
    sc.pos = end;
    Ok(ParsedSeal::Opaque { raw })
}

fn seal_array<'a>(sc: &mut Scanner<'a>) -> Result<Vec<ParsedSeal<'a>>, SerderError> {
    delimited_list(sc, seal)
}

/// Parse and validate the fixed head `{"v":"<17-byte version string>","t":`
/// and return the scanner positioned after the ilk value, plus the ilk.
fn head(raw: &[u8]) -> Result<(Scanner<'_>, Spanned<'_>), SerderError> {
    let mut sc = Scanner::new(raw);
    sc.expect("{\"v\":\"")?;
    let vs_start = sc.pos;
    let vs_end = vs_start
        .checked_add(VERSION_STRING_LEN)
        .ok_or(SerderError::InvalidEventLayout("version span overflow"))?;
    let vs_bytes = raw
        .get(vs_start..vs_end)
        .ok_or_else(|| sc.err("17-byte version string"))?;
    let (vs, _) = VersionString::parse(vs_bytes)?;
    if vs.kind() != SerializationKind::Json {
        return Err(SerderError::InvalidVersionString(format!(
            "expected JSON, got {}",
            vs.kind().as_str()
        )));
    }
    let expected_size =
        usize::try_from(vs.size()).map_err(|e| SerderError::InvalidVersionString(e.to_string()))?;
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

fn icp_body(mut sc: Scanner<'_>) -> Result<ParsedIcp<'_>, SerderError> {
    let fields = icp_fields(&mut sc)?;
    sc.expect("}")?;
    sc.finish()?;
    Ok(fields)
}

fn dip_body(mut sc: Scanner<'_>) -> Result<ParsedDip<'_>, SerderError> {
    let icp = icp_fields(&mut sc)?;
    sc.expect(",\"di\":")?;
    let delegator = sc.string()?.value;
    sc.expect("}")?;
    sc.finish()?;
    Ok(ParsedDip { icp, delegator })
}

fn rot_body(mut sc: Scanner<'_>) -> Result<ParsedRot<'_>, SerderError> {
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

fn ixn_body(mut sc: Scanner<'_>) -> Result<ParsedIxn<'_>, SerderError> {
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

/// On mismatch the error's offset addresses the ilk value's first byte
/// (inside the quotes) and `expected` carries the bare ilk name — the same
/// start-offset convention as [`Scanner::expect`].
fn require_ilk(
    sc: &Scanner<'_>,
    ilk: &Spanned<'_>,
    expected: &'static str,
) -> Result<(), SerderError> {
    if ilk.value == expected {
        Ok(())
    } else {
        Err(sc.err_at(ilk.span.start, expected))
    }
}

/// Parse any of the five fixed canonical event grammars, dispatched on the
/// wire `t` (ilk) field.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict grammar, [`SerderError::InvalidVersionString`] if the version
/// header is malformed or its size does not match the input length, or
/// [`SerderError::UnknownIlk`] if `t` is not one of `icp`/`rot`/`ixn`/`dip`/`drt`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
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

/// Parse a strict canonical `icp` body.
///
/// # Errors
///
/// See [`parse_event`]. Additionally returns [`SerderError::NonCanonical`]
/// if the wire `t` field is not `"icp"`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_inception(raw: &[u8]) -> Result<ParsedIcp<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "icp")?;
    icp_body(sc)
}

/// Parse a strict canonical `rot` body.
///
/// # Errors
///
/// See [`parse_event`]. Additionally returns [`SerderError::NonCanonical`]
/// if the wire `t` field is not `"rot"`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_rotation(raw: &[u8]) -> Result<ParsedRot<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "rot")?;
    rot_body(sc)
}

/// Parse a strict canonical `ixn` body.
///
/// # Errors
///
/// See [`parse_event`]. Additionally returns [`SerderError::NonCanonical`]
/// if the wire `t` field is not `"ixn"`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_interaction(raw: &[u8]) -> Result<ParsedIxn<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "ixn")?;
    ixn_body(sc)
}

/// Parse a strict canonical `dip` body.
///
/// # Errors
///
/// See [`parse_event`]. Additionally returns [`SerderError::NonCanonical`]
/// if the wire `t` field is not `"dip"`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_delegated_inception(raw: &[u8]) -> Result<ParsedDip<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "dip")?;
    dip_body(sc)
}

/// Parse a strict canonical `drt` body.
///
/// # Errors
///
/// See [`parse_event`]. Additionally returns [`SerderError::NonCanonical`]
/// if the wire `t` field is not `"drt"`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_delegated_rotation(raw: &[u8]) -> Result<ParsedRot<'_>, SerderError> {
    let (sc, ilk) = head(raw)?;
    require_ilk(&sc, &ilk, "drt")?;
    rot_body(sc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::KeriSerialize;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::{Prefixer, Saider, Verfer};
    use cesr::keri::SigningThreshold;
    use cesr::keri::threshold_form::ThresholdForm;
    use cesr::keri::toad::Toad;
    use cesr::keri::{
        ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, InceptionEvent,
        InteractionEvent, OpaqueSealError, RotationEvent, Seal, SequenceNumber,
    };

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
        let err = sc.expect("abX").unwrap_err();
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
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"bi\":\"B\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Back { bi: "B", d: "X" }
        ));
        assert!(matches!(
            seal(&mut Scanner::new(b"{\"t\":\"T\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Kind { t: "T", d: "X" }
        ));
        assert!(
            matches!(
                seal(&mut Scanner::new(b"{\"d\":\"X\",\"s\":\"1\"}")).unwrap(),
                ParsedSeal::Opaque {
                    raw: "{\"d\":\"X\",\"s\":\"1\"}"
                }
            ),
            "out-of-order codex fields fall back to a verbatim opaque capture"
        );
        assert!(
            matches!(
                seal(&mut Scanner::new(b"{\"x\":\"X\"}")).unwrap(),
                ParsedSeal::Opaque {
                    raw: "{\"x\":\"X\"}"
                }
            ),
            "unknown seal keys fall back to a verbatim opaque capture"
        );
        assert!(
            matches!(
                seal(&mut Scanner::new(b"{\"bi\":123}")).unwrap(),
                ParsedSeal::Opaque {
                    raw: "{\"bi\":123}"
                }
            ),
            "a codex key set with a non-string value is a shape mismatch — opaque"
        );
        assert!(
            matches!(
                seal(&mut Scanner::new(b"{\"x\":}")),
                Err(SerderError::InvalidAnchor { offset: 0, .. })
            ),
            "a malformed anchor object is rejected, not captured"
        );
    }

    #[test]
    fn truncated_opaque_anchor_is_invalid_anchor() {
        let mut sc = Scanner::new(b"{\"x\":{\"y\":1");
        let err = seal(&mut sc).expect_err("truncated anchor must be rejected");
        assert!(matches!(
            err,
            SerderError::InvalidAnchor {
                offset: 0,
                source: OpaqueSealError::Truncated,
            }
        ));
    }

    #[test]
    fn weighted_rejects_non_string_non_array_element() {
        let mut sc = Scanner::new(b"[true]");
        assert!(matches!(
            weighted(&mut sc),
            Err(SerderError::NonCanonical { offset: 1, .. })
        ));
    }

    #[test]
    fn seal_array_shapes() {
        assert!(seal_array(&mut Scanner::new(b"[]")).unwrap().is_empty());
        let seals = seal_array(&mut Scanner::new(b"[{\"d\":\"X\"},{\"i\":\"I\"}]")).unwrap();
        assert_eq!(seals.len(), 2);
        assert!(matches!(seals[0], ParsedSeal::Digest { d: "X" }));
        assert!(matches!(seals[1], ParsedSeal::Last { i: "I" }));
    }

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
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: make_saider() }],
            ThresholdForm::HexString,
        );
        event.serialize().unwrap().as_bytes().to_vec()
    }

    fn probe_ixn_bytes() -> Vec<u8> {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(3),
            make_saider(),
            make_saider(),
            vec![],
        );
        event.serialize().unwrap().as_bytes().to_vec()
    }

    fn make_rot() -> RotationEvent<'static> {
        RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(2),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            vec![make_prefixer()],
            Toad::from_wire(1),
            vec![Seal::Digest { d: make_saider() }],
            ThresholdForm::HexString,
        )
    }

    fn probe_rot_bytes() -> Vec<u8> {
        make_rot().serialize().unwrap().as_bytes().to_vec()
    }

    fn probe_dip_bytes() -> Vec<u8> {
        let icp = InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        );
        let delegator: Identifier<'static> = make_prefixer().into();
        let dip = DelegatedInceptionEvent::new(icp, delegator);
        dip.serialize().unwrap().as_bytes().to_vec()
    }

    fn probe_drt_bytes() -> Vec<u8> {
        let drt = DelegatedRotationEvent::new(make_rot());
        drt.serialize().unwrap().as_bytes().to_vec()
    }

    /// Rewrite the six size hex digits (bytes 16..22) to the buffer's actual
    /// length so grammar probes are not masked by the version-size check.
    fn fix_size(raw: &mut [u8]) {
        let size = raw.len();
        let hex = format!("{size:06x}");
        raw[16..22].copy_from_slice(hex.as_bytes());
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
    fn parse_inception_reads_all_icp_fields() {
        let raw = probe_icp_bytes();
        let p = parse_inception(&raw).unwrap();
        assert!(matches!(p.threshold, ParsedTholder::Hex("1")));
        assert!(matches!(p.next_threshold, ParsedTholder::Hex("1")));
        assert_eq!(p.next_keys.len(), 1);
        assert!(matches!(p.witness_threshold, ParsedCount::Hex("1")));
        assert_eq!(p.witnesses.len(), 1);
    }

    #[test]
    fn parse_rotation_reads_all_rot_fields() {
        let raw = probe_rot_bytes();
        let p = parse_rotation(&raw).unwrap();
        assert_eq!(p.sn, "2");
        assert_eq!(&raw[p.said.span.clone()], p.said.value.as_bytes());
        assert!(!p.prefix.is_empty());
        assert!(!p.prior.is_empty());
        assert!(matches!(p.threshold, ParsedTholder::Hex("1")));
        assert_eq!(p.keys.len(), 1);
        assert!(matches!(p.next_threshold, ParsedTholder::Hex("1")));
        assert_eq!(p.next_keys.len(), 1);
        assert!(matches!(p.witness_threshold, ParsedCount::Hex("1")));
        assert_eq!(p.witness_removals.len(), 1);
        assert_eq!(p.witness_additions.len(), 1);
        assert_eq!(p.anchors.len(), 1);
    }

    #[test]
    fn parse_interaction_reads_all_ixn_fields() {
        let raw = probe_ixn_bytes();
        let p = parse_interaction(&raw).unwrap();
        assert_eq!(p.sn, "3");
        assert_eq!(&raw[p.said.span.clone()], p.said.value.as_bytes());
        assert!(!p.prefix.is_empty());
        assert!(!p.prior.is_empty());
        assert!(p.anchors.is_empty());
    }

    #[test]
    fn parse_delegated_inception_reads_icp_and_delegator() {
        let raw = probe_dip_bytes();
        let p = parse_delegated_inception(&raw).unwrap();
        assert_eq!(p.icp.sn, "0");
        assert!(!p.delegator.is_empty());
    }

    #[test]
    fn parse_delegated_rotation_reads_rot_fields() {
        let raw = probe_drt_bytes();
        let p = parse_delegated_rotation(&raw).unwrap();
        assert_eq!(p.sn, "2");
    }

    #[test]
    fn parse_event_dispatches_every_ilk_variant() {
        match parse_event(&probe_icp_bytes()).unwrap() {
            ParsedEvent::Inception(p) => assert_eq!(p.sn, "0"),
            other => unreachable!("expected Inception, got {other:?}"),
        }
        match parse_event(&probe_rot_bytes()).unwrap() {
            ParsedEvent::Rotation(p) => assert_eq!(p.sn, "2"),
            other => unreachable!("expected Rotation, got {other:?}"),
        }
        match parse_event(&probe_ixn_bytes()).unwrap() {
            ParsedEvent::Interaction(p) => assert_eq!(p.sn, "3"),
            other => unreachable!("expected Interaction, got {other:?}"),
        }
        match parse_event(&probe_dip_bytes()).unwrap() {
            ParsedEvent::DelegatedInception(p) => assert_eq!(p.icp.sn, "0"),
            other => unreachable!("expected DelegatedInception, got {other:?}"),
        }
        match parse_event(&probe_drt_bytes()).unwrap() {
            ParsedEvent::DelegatedRotation(p) => assert_eq!(p.sn, "2"),
            other => unreachable!("expected DelegatedRotation, got {other:?}"),
        }
    }

    #[test]
    fn per_ilk_entry_rejects_wrong_ilk() {
        let raw = probe_ixn_bytes();
        assert!(matches!(
            parse_rotation(&raw),
            Err(SerderError::NonCanonical {
                expected: "rot",
                ..
            })
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
        // Replace sn value "3" with an escaped form and fix the size field.
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

    #[test]
    fn multibyte_utf8_in_version_window_is_rejected_not_panicking() {
        // 23 bytes: char 'é' straddles the proto/major boundary at offset 4
        // of the version window — previously panicked inside
        // VersionString::parse via non-char-boundary &str slicing.
        assert!(parse_event(b"{\"v\":\"KER\xC3\xA9AJSONAAAAAA_").is_err());
    }

    #[test]
    fn wrong_first_byte_is_non_canonical() {
        assert!(matches!(
            parse_event(b"[\"v\":\"KERI10JSON000017_"),
            Err(SerderError::NonCanonical { offset: 0, .. })
        ));
    }

    #[test]
    fn oversized_ilk_is_rejected() {
        let raw = probe_ixn_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"ixn\"").unwrap();
        let mut mutated = Vec::with_capacity(raw.len() + 1);
        mutated.extend_from_slice(&raw[..pos + 4]);
        mutated.push(b'X');
        mutated.extend_from_slice(&raw[pos + 4..]);
        fix_size(&mut mutated);
        assert!(matches!(
            parse_event(&mutated),
            Err(SerderError::UnknownIlk(ref s)) if s == "ixnX"
        ));
        assert!(matches!(
            parse_interaction(&mutated),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn delegator_field_on_icp_is_rejected() {
        // icp grammar ends at the anchors; a trailing "di" is non-canonical.
        let mut raw = probe_dip_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"dip\"").unwrap();
        raw[pos + 1..pos + 4].copy_from_slice(b"icp");
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn missing_delegator_on_dip_is_rejected() {
        // ilk says dip but the body is an icp body — fails at `,"di":`.
        let mut raw = probe_icp_bytes();
        let pos = raw.windows(5).position(|w| w == b"\"icp\"").unwrap();
        raw[pos + 1..pos + 4].copy_from_slice(b"dip");
        assert!(matches!(
            parse_event(&raw),
            Err(SerderError::NonCanonical { .. })
        ));
    }

    #[test]
    fn corrupt_version_terminator_seam_is_rejected() {
        let mut raw = probe_ixn_bytes();
        // byte 23 is the closing quote of the version string value
        raw[23] = b'X';
        assert!(parse_event(&raw).is_err());
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
                let _ = parse_event(&input);
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
