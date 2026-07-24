# cesr-stream Typed `ParseError` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete `ParseError::Malformed(String)` from `cesr-stream`, replacing all ~30 construction sites and 7 type-erasing `From` impls with typed, matchable variants that preserve the `source()` chain.

**Architecture:** Additive first, subtractive last. Task 1 adds `SpanKind` and every new `ParseError` variant while `Malformed` still exists, so the tree stays green. Tasks 2–8 migrate call sites file by file, each an independently-compiling commit. Task 9 deletes `Malformed`, updates doc comments, and adds a tripwire test proving the identifier is gone.

**Tech Stack:** Rust 2024 (pinned stable 1.95.0), `thiserror` for all error enums, `cargo nextest` for iteration, `nix flake check` as the only gate.

**Spec:** `docs/superpowers/specs/2026-07-24-cesr-stream-typed-parse-error-design.md`
**Issue:** [#208](https://github.com/devrandom-labs/cesr/issues/208)
**Branch:** `feat/208-typed-parse-error` (already created, spec already committed)

---

## Verification Discipline — read before starting

Two rules from this repo's history, both non-negotiable:

1. **`nix flake check` is the only gate, and it sees only COMMITTED state.** A
   dirty-tree run is vacuous. Run it *after* committing.
2. **Never pipe a gate command.** `nix flake check | tail` masks the exit code;
   `| head` SIGPIPE-kills it. Always redirect and echo the status:

   ```bash
   nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"
   ```

Per-task `cargo nextest` runs shown below are **iteration aids only**. They are
never sufficient to claim a task is done — they skip taplo, audit, deny, wasm,
and no_std. The gate runs at the end of Task 2 and again at the end of Task 9.

## File Structure

| File | Change | Responsibility after change |
|---|---|---|
| `crates/cesr-stream/src/error.rs` | Modify | Owns `SpanKind`, `ParseError`, and every `From` impl. The single place upstream errors become stream errors. |
| `crates/cesr-stream/src/lib.rs` | Modify | Re-export `SpanKind` alongside `ParseError`. |
| `crates/cesr-stream/src/parse.rs` | Modify | `TextStream` cursor + counter reads; 4 sites. |
| `crates/cesr-stream/src/group/mod.rs` | Modify | Group dispatch + span math; 15 sites. |
| `crates/cesr-stream/src/group/kinds.rs` | Modify | Per-kind element grammar; 7 sites. |
| `crates/cesr-stream/src/codec.rs` | Modify | tokio-util `Decoder`/`Encoder`; 2 sites. |
| `crates/cesr-stream/src/qb2.rs` | Modify | qb64↔qb2 conversion; 2 sites. |
| `crates/cesr-stream/src/message.rs` | Modify | `CesrMessage::parse`; 3 sites. |
| `crates/cesr-stream/src/cold.rs` | Modify | Cold-start detection; 1 site. |
| `crates/cesr-stream/src/unwrap.rs` | Modify | Nested group unwrapping; 3 sites. |
| `crates/cesr-stream/src/encode.rs` | Modify | Counter encoding; 5 sites. |
| `crates/cesr-stream/src/version.rs` | Modify | Doc comment only. |
| `crates/keri-codec/src/serialize.rs` | Modify | 2 sites via `FrameError::Encode`. |
| `crates/cesr-stream/CHANGELOG.md` | Modify | Breaking-change entry. |
| `crates/keri-codec/CHANGELOG.md` | Modify | Breaking-change entry. |
| `crates/cesr-stream/Cargo.toml` | Modify | MINOR version bump. |
| `crates/keri-codec/Cargo.toml` | Modify | MINOR version bump. |

No new files. No new free `pub fn` — `free-fn-budget.toml` stays untouched
(`cesr-stream = 2`).

---

### Task 1: Add `SpanKind` and the new `ParseError` variants

`Malformed` stays in place this task. Nothing constructs the new variants yet,
so the tree must stay green.

**Files:**
- Modify: `crates/cesr-stream/src/error.rs`
- Modify: `crates/cesr-stream/src/lib.rs`
- Test: `crates/cesr-stream/src/error.rs` (in-file `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Append to the existing `mod tests` in `crates/cesr-stream/src/error.rs`:

```rust
    #[test]
    fn display_span_kinds_are_distinct_and_named() {
        assert_eq!(
            ParseError::Overflow(SpanKind::GroupSpan).to_string(),
            "span arithmetic failed for group span"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::QuadletCount).to_string(),
            "span arithmetic failed for quadlet count"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::CounterSoftSize).to_string(),
            "span arithmetic failed for counter soft size"
        );
    }

    #[test]
    fn display_structural_variants() {
        assert_eq!(
            ParseError::Misaligned { len: 7, unit: 4 }.to_string(),
            "length 7 is not a multiple of 4"
        );
        assert_eq!(
            ParseError::InvalidUtf8 {
                field: "counter soft field"
            }
            .to_string(),
            "invalid UTF-8 in counter soft field"
        );
        assert_eq!(
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
            .to_string(),
            "count 4096 exceeds counter capacity 4095"
        );
        assert_eq!(
            ParseError::DepthExceeded { max: 8 }.to_string(),
            "max nesting depth 8 exceeded"
        );
        assert_eq!(
            ParseError::UnknownColdStart { byte: 0x7f }.to_string(),
            "unrecognized stream byte: 0x7f"
        );
        assert_eq!(
            ParseError::UnsupportedGenusVersion { major: 3 }.to_string(),
            "unsupported genus version major=3"
        );
        assert_eq!(
            ParseError::MissingVersionString.to_string(),
            "version string not found"
        );
        assert_eq!(
            ParseError::GenusVersionNotAGroup.to_string(),
            "genus version codes are not attachment groups"
        );
    }

    #[test]
    fn display_not_a_counter_with_and_without_byte() {
        assert_eq!(
            ParseError::NotACounter { got: Some(b'A') }.to_string(),
            "expected counter code '-', got 'A'"
        );
        assert_eq!(
            ParseError::NotACounter { got: None }.to_string(),
            "expected counter code '-'"
        );
    }

    #[test]
    fn display_nested_counter_mismatch() {
        assert_eq!(
            ParseError::NestedCounterMismatch {
                outer: "-F",
                expected: "-A",
                got: "-B".to_owned(),
            }
            .to_string(),
            "expected -A counter inside -F group, got -B"
        );
    }

    #[test]
    fn span_kind_is_copy_and_comparable() {
        let a = SpanKind::ElementSpan;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(SpanKind::GroupStart, SpanKind::GroupSpan);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
nix develop --command cargo nextest run -p cesr-stream error:: > /tmp/t1.log 2>&1; echo "exit=$?"
```

Expected: compile failure — `cannot find type SpanKind in this scope`, and
`no variant named Overflow`/`Misaligned`/… on `ParseError`.

- [ ] **Step 3: Add `SpanKind` above `ParseError` in `error.rs`**

```rust
/// Which span computation failed.
///
/// Fieldless on purpose: the diagnostic set is a closed, exhaustively
/// matchable type at zero runtime cost, and two call sites cannot drift to
/// different spellings of the same condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// The start offset of a group within its backing buffer.
    GroupStart,
    /// The total byte span of a group.
    GroupSpan,
    /// The offset of a group's body past its counter.
    GroupOffset,
    /// The quadlet tally of a group payload.
    QuadletCount,
    /// The byte span implied by a quadlet count.
    QuadletSpan,
    /// The byte span of one element within a group.
    ElementSpan,
    /// A `TextStream` cursor position.
    CursorPosition,
    /// The payload size declared by a version string.
    EventSize,
    /// The soft-field width of a counter code.
    CounterSoftSize,
}

impl SpanKind {
    /// The human-readable name used in [`ParseError::Overflow`]'s message.
    const fn as_str(self) -> &'static str {
        match self {
            Self::GroupStart => "group start",
            Self::GroupSpan => "group span",
            Self::GroupOffset => "group offset",
            Self::QuadletCount => "quadlet count",
            Self::QuadletSpan => "quadlet span",
            Self::ElementSpan => "element span",
            Self::CursorPosition => "cursor position",
            Self::EventSize => "event size",
            Self::CounterSoftSize => "counter soft size",
        }
    }
}

impl core::fmt::Display for SpanKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
```

- [ ] **Step 4: Add the new variants to `ParseError`**

Insert these immediately after the existing `Malformed(String)` variant in
`crates/cesr-stream/src/error.rs`. Leave `Malformed` in place — Task 9 removes it.

```rust
    /// A span, offset, or count computation overflowed or underflowed.
    #[error("span arithmetic failed for {0}")]
    Overflow(SpanKind),

    /// The lead byte is not a counter head (`-`).
    #[error("expected counter code '-'{}", match .got {
        Some(b) => alloc::format!(", got '{}'", char::from(*b)),
        None => String::new(),
    })]
    NotACounter {
        /// The offending lead byte, when the layer that rejected it had one.
        got: Option<u8>,
    },

    /// A nested sub-group carried the wrong counter code.
    #[error("expected {expected} counter inside {outer} group, got {got}")]
    NestedCounterMismatch {
        /// Wire letters of the enclosing group.
        outer: &'static str,
        /// The counter code the enclosing group requires.
        expected: &'static str,
        /// The counter code actually found.
        got: String,
    },

    /// A genus-version code appeared where an attachment group was expected.
    #[error("genus version codes are not attachment groups")]
    GenusVersionNotAGroup,

    /// A length was not a whole multiple of its encoding unit.
    #[error("length {len} is not a multiple of {unit}")]
    Misaligned {
        /// The offending length in bytes.
        len: usize,
        /// The required multiple (4 for qb64/quadlets, 3 for qb2).
        unit: usize,
    },

    /// A field that must be UTF-8 text was not.
    #[error("invalid UTF-8 in {field}")]
    InvalidUtf8 {
        /// Name of the offending field.
        field: &'static str,
    },

    /// A count exceeded what its counter's soft field can encode.
    #[error("count {count} exceeds counter capacity {capacity}")]
    CountExceedsCapacity {
        /// The requested count.
        count: u64,
        /// The largest value the counter can carry.
        capacity: u64,
    },

    /// Group nesting exceeded the unwrapping depth limit.
    #[error("max nesting depth {max} exceeded")]
    DepthExceeded {
        /// The configured limit.
        max: usize,
    },

    /// The first byte of the stream starts no known encoding domain.
    #[error("unrecognized stream byte: 0x{byte:02x}")]
    UnknownColdStart {
        /// The offending first byte.
        byte: u8,
    },

    /// The genus version's major number selects no known parsing mode.
    #[error("unsupported genus version major={major}")]
    UnsupportedGenusVersion {
        /// The decoded major version.
        major: u32,
    },

    /// A V2-only group type was encoded with V1 counter codes.
    #[error("{group} cannot be encoded with {version:?} counters")]
    VersionMismatch {
        /// Name of the group type.
        group: &'static str,
        /// The counter version that was attempted.
        version: CesrVersion,
    },

    /// No version string was found within the search range.
    #[error("version string not found")]
    MissingVersionString,

    /// A matter primitive failed to parse.
    #[error(transparent)]
    Matter(ParsingError),

    /// A matter primitive parsed but failed validation.
    #[error(transparent)]
    MatterValidation(ValidationError),

    /// An indexed primitive failed to parse.
    #[error(transparent)]
    Indexer(IndexerParseError),

    /// An indexed primitive parsed but failed validation.
    #[error(transparent)]
    IndexerValidation(IndexerValidationError),

    /// A CESR Base64 operation failed.
    #[error(transparent)]
    Base64(CesrUtilsError),

    /// An I/O failure surfaced through the async `Decoder` bound.
    ///
    /// Stringified because [`std::io::Error`] is not [`PartialEq`], which
    /// [`ParseError`] must remain.
    #[error("io error: {0}")]
    Io(String),
```

Add the `CesrVersion` import to the top of `error.rs`:

```rust
use cesr::core::version::CesrVersion;
```

- [ ] **Step 5: Re-export `SpanKind`**

`crates/cesr-stream/src/lib.rs:63` currently reads `pub use error::ParseError;`.
Replace it with:

```rust
pub use error::{ParseError, SpanKind};
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
nix develop --command cargo nextest run -p cesr-stream error:: > /tmp/t1.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`, all `error::tests::` tests pass including the five new ones.

If clippy objects to the inline `match` inside the `NotACounter` `#[error(...)]`
format expression, replace that attribute with a hand-written arm — do **not**
add an `#[allow]`:

```rust
    #[error("expected counter code '-'{}", got.map_or_else(String::new, |b| alloc::format!(", got '{}'", char::from(b))))]
```

- [ ] **Step 7: Commit**

```bash
git add crates/cesr-stream/src/error.rs crates/cesr-stream/src/lib.rs
git commit -m "feat(cesr-stream): add SpanKind and typed ParseError variants (#208)

Additive only — Malformed(String) still present and still used.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Retype the `From` impls — kill the erasure

**Files:**
- Modify: `crates/cesr-stream/src/error.rs:59-117`
- Test: `crates/cesr-stream/src/error.rs` (in-file `mod tests`)

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `crates/cesr-stream/src/error.rs`:

```rust
    #[test]
    fn parsing_error_keeps_typed_source() {
        let original = ValidationError::MissingRaw {
            code: "A".to_owned(),
        };
        let e: ParseError = original.clone().into();
        assert_eq!(e, ParseError::MatterValidation(original));
    }

    #[test]
    fn indexer_unknown_code_keeps_typed_source() {
        let original = IndexerParseError::UnknownCode("ZZ".to_owned());
        let e: ParseError = original.clone().into();
        assert_eq!(e, ParseError::Indexer(original));
    }

    #[test]
    fn indexer_validation_keeps_typed_source() {
        use cesr::core::indexer::code::IndexedSigCode;

        let original = IndexerValidationError::IndexTooLarge {
            code: IndexedSigCode::Ed25519,
            index: 999,
            max: 63,
        };
        let e: ParseError = original.clone().into();
        assert_eq!(e, ParseError::IndexerValidation(original));
    }

    #[test]
    fn base64_error_keeps_typed_source() {
        let e: ParseError = CesrUtilsError::IntegerOverflow.into();
        assert_eq!(e, ParseError::Base64(CesrUtilsError::IntegerOverflow));
    }

    #[test]
    fn not_a_counter_has_no_byte_at_the_from_boundary() {
        let e: ParseError = CounterCodeError::NotACounter.into();
        assert_eq!(e, ParseError::NotACounter { got: None });
    }

    // The `source()` chain is the whole point of #208: before this change
    // every one of these returned `None` because the error was a String.
    #[cfg(feature = "std")]
    #[test]
    fn typed_variants_expose_their_source() {
        use std::error::Error as StdError;

        let e: ParseError = ValidationError::MissingRaw {
            code: "A".to_owned(),
        }
        .into();
        let src = e.source().expect("MatterValidation must expose a source");
        assert!(src.downcast_ref::<ValidationError>().is_some());
    }

    // Truncation is backpressure, not an error. Every upstream "need more
    // bytes" shape must still land on NeedBytes and never on a typed source
    // variant — this is the streaming invariant the `#[from]` derive would
    // have silently broken.
    #[test]
    fn truncation_still_maps_to_need_bytes() {
        assert_eq!(
            ParseError::from(ParsingError::EmptyStream),
            ParseError::NeedBytes(1)
        );
        assert_eq!(
            ParseError::from(ParsingError::StreamTooShort(MatterPart::Head)),
            ParseError::NeedBytes(1)
        );
        assert_eq!(
            ParseError::from(IndexerParseError::EmptyStream),
            ParseError::NeedBytes(1)
        );
        assert_eq!(
            ParseError::from(IndexerParseError::StreamTooShort { need: 4, got: 2 }),
            ParseError::NeedBytes(4)
        );
        assert_eq!(
            ParseError::from(CounterCodeError::StreamTooShort { need: 3 }),
            ParseError::NeedBytes(3)
        );
        assert_eq!(
            ParseError::from(VersionError::Truncated { needed: 5 }),
            ParseError::NeedBytes(5)
        );
    }
```

Delete these now-superseded tests from the same module — they assert
`Malformed(_)`, which Task 9 removes, and each is replaced above:
`from_validation_error`, `from_counter_code_error_not_a_counter`,
`from_indexer_validation_error`, `from_cesr_utils_error`.

If `ValidationError`, `IndexerParseError`, or `IndexerValidationError` do not
derive `Clone`, drop the `.clone()` calls and construct the expected value a
second time instead — do not add `Clone` to upstream types for a test.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
nix develop --command cargo nextest run -p cesr-stream error:: > /tmp/t2.log 2>&1; echo "exit=$?"
```

Expected: failures asserting `MatterValidation(..)` but receiving
`Malformed("...")`, and `source()` returning `None`.

- [ ] **Step 3: Replace the `From` impls**

Replace `crates/cesr-stream/src/error.rs:59-117` (everything from
`impl From<ParsingError> for ParseError` through the `std::io::Error` impl)
with:

```rust
impl From<ParsingError> for ParseError {
    fn from(e: ParsingError) -> Self {
        match e {
            ParsingError::EmptyStream | ParsingError::StreamTooShort(_) => Self::NeedBytes(1),
            ParsingError::UnknownMatterCode(s) => Self::UnknownMatterCode(s),
            other => Self::Matter(other),
        }
    }
}

impl From<ValidationError> for ParseError {
    fn from(e: ValidationError) -> Self {
        Self::MatterValidation(e)
    }
}

impl From<CounterCodeError> for ParseError {
    fn from(e: CounterCodeError) -> Self {
        match e {
            CounterCodeError::StreamTooShort { need } => Self::NeedBytes(need),
            CounterCodeError::NotACounter => Self::NotACounter { got: None },
            CounterCodeError::UnknownCode(s) => Self::UnknownCounterCode(s),
        }
    }
}

impl From<IndexerParseError> for ParseError {
    fn from(e: IndexerParseError) -> Self {
        match e {
            IndexerParseError::EmptyStream => Self::NeedBytes(1),
            IndexerParseError::StreamTooShort { need, .. } => Self::NeedBytes(need),
            other => Self::Indexer(other),
        }
    }
}

impl From<IndexerValidationError> for ParseError {
    fn from(e: IndexerValidationError) -> Self {
        Self::IndexerValidation(e)
    }
}

impl From<CesrUtilsError> for ParseError {
    fn from(e: CesrUtilsError) -> Self {
        Self::Base64(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
```

The `From<VersionError>` impl above them is unchanged — it was already correct
and is the pattern the three remapping impls follow.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
nix develop --command cargo nextest run -p cesr-stream > /tmp/t2.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`. Other modules' tests may now see typed variants where they
previously saw `Malformed` — if any fail, note which and fix them in the task
that owns that file (Tasks 3–8), not here.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/error.rs
git commit -m "refactor(cesr-stream)!: typed source variants replace Malformed erasure (#208)

BREAKING CHANGE: six From impls no longer stringify their source. The
source() chain now resolves for ParsingError, ValidationError,
IndexerParseError, IndexerValidationError and the b64 error.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Run the real gate for the first time**

```bash
nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`. If not, read `/tmp/gate.log` and fix before proceeding —
do not carry a red tree into the migration tasks.

---

### Task 3: Migrate `parse.rs` (4 sites)

**Files:**
- Modify: `crates/cesr-stream/src/parse.rs:61,123,175,192,640`

- [ ] **Step 1: Update the test to assert the exact variant**

Replace the body of `parse_counter_error_non_counter_input`
(`crates/cesr-stream/src/parse.rs:636-641`):

```rust
    #[test]
    fn parse_counter_error_non_counter_input() {
        let result = TextStream::new(b"AABC").read_counter_v1();
        let err = expect_err(result);
        assert_eq!(err, ParseError::NotACounter { got: Some(b'A') });
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
nix develop --command cargo nextest run -p cesr-stream parse::tests::parse_counter_error_non_counter_input > /tmp/t3.log 2>&1; echo "exit=$?"
```

Expected: FAIL — left is `Malformed("expected counter '-', got 'A'")`.

- [ ] **Step 3: Migrate the four sites**

`parse.rs:59-66` — `map_counter_err`:

```rust
fn map_counter_err(input: &[u8], e: CounterCodeError) -> ParseError {
    match e {
        CounterCodeError::NotACounter => ParseError::NotACounter {
            got: input.first().copied(),
        },
        other => ParseError::from(other),
    }
}
```

Also update its doc comment's last line — "`input` is used only to name the
offending lead byte in the not-a-counter message" becomes "`input` supplies the
offending lead byte that the `From` impl cannot see."

`parse.rs:120-123` — inside `take`:

```rust
        let pos = self
            .pos
            .checked_add(n)
            .ok_or(ParseError::Overflow(SpanKind::CursorPosition))?;
```

`parse.rs:174-175` and `parse.rs:191-192` — both counter soft-field reads
(identical replacement in `read_counter_v1` and `read_counter_v2`):

```rust
        let count_str = core::str::from_utf8(&input[hs..fs]).map_err(|_| {
            ParseError::InvalidUtf8 {
                field: "counter soft field",
            }
        })?;
```

Add `SpanKind` to the `ParseError` import at the top of `parse.rs`.

- [ ] **Step 4: Run to verify it passes**

```bash
nix develop --command cargo nextest run -p cesr-stream parse:: > /tmp/t3.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/parse.rs
git commit -m "refactor(cesr-stream)!: typed errors in parse.rs (#208)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Migrate `group/mod.rs` (15 sites)

**Files:**
- Modify: `crates/cesr-stream/src/group/mod.rs`

- [ ] **Step 1: Update the genus-version test to assert the variant**

Replace `dispatch_v2_genus_version_is_rejected_with_specific_message`
(`crates/cesr-stream/src/group/mod.rs:1964-1977`):

```rust
    // ── V2 special dispatch: KERIACDCGenusVersion is not an attachment group ─
    //
    // Deleting the `KERIACDCGenusVersion` arm in `dispatch_v2_seals` falls
    // through to the generic `_` arm, which returns `UnexpectedCodeType`.
    // Asserting the exact variant distinguishes the two error domains.

    #[test]
    fn dispatch_v2_genus_version_is_rejected_with_its_own_variant() {
        // "-_AAA" + 3 soft chars encoding major=2, minor=0.
        let input = b"-_AAACAA";
        let err = CesrGroup::parse_v2(input).unwrap_err();
        assert_eq!(err, ParseError::GenusVersionNotAGroup);
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
nix develop --command cargo nextest run -p cesr-stream group::tests::dispatch_v2_genus > /tmp/t4.log 2>&1; echo "exit=$?"
```

Expected: FAIL — no variant `GenusVersionNotAGroup` matched; left is
`Malformed(...)`.

- [ ] **Step 3: Migrate all 15 sites**

Add `SpanKind` to the `ParseError` import at the top of `group/mod.rs`.

Span-arithmetic sites — replace `.ok_or_else(|| ParseError::Malformed(...))`
with `.ok_or(ParseError::Overflow(SpanKind::…))` (note `ok_or`, not
`ok_or_else`: the value is now `Copy` and allocation-free):

| Line | Old message | New |
|---|---|---|
| 184 | `"group start out of range"` | `ok_or(ParseError::Overflow(SpanKind::GroupStart))` |
| 189 | `"group span overflows"` | `ok_or(ParseError::Overflow(SpanKind::GroupSpan))` |
| 193 | `"group span overflows"` | `ok_or(ParseError::Overflow(SpanKind::GroupSpan))` |
| 384 | `"quadlet count overflow"` | `ok_or(ParseError::Overflow(SpanKind::QuadletCount))` |
| 388 | `"group start out of range"` | `ok_or(ParseError::Overflow(SpanKind::GroupStart))` |
| 394 | `"quadlet span overflows"` | `ok_or(ParseError::Overflow(SpanKind::QuadletSpan))` |
| 409 | `"quadlet count overflow"` | `ok_or(ParseError::Overflow(SpanKind::QuadletCount))` |
| 413 | `"group start out of range"` | `ok_or(ParseError::Overflow(SpanKind::GroupStart))` |
| 419 | `"quadlet span overflows"` | `ok_or(ParseError::Overflow(SpanKind::QuadletSpan))` |
| 622 | `"group start out of range"` | `ok_or(ParseError::Overflow(SpanKind::GroupStart))` |
| 627 | `"group offset overflows"` | `ok_or(ParseError::Overflow(SpanKind::GroupOffset))` |
| 648 | `"group start out of range"` | `ok_or(ParseError::Overflow(SpanKind::GroupStart))` |
| 653 | `"group offset overflows"` | `ok_or(ParseError::Overflow(SpanKind::GroupOffset))` |
| 1012 | `"too many quadlets"` | `.map_err(\|_\| ParseError::Overflow(SpanKind::QuadletCount))` |

`group/mod.rs:280` (inside an iterator returning `Option<Result<..>>`):

```rust
                    Some(Err(ParseError::Overflow(SpanKind::ElementSpan)))
```

`group/mod.rs:747` and `group/mod.rs:924` — both genus-version arms:

```rust
        CounterCodeV1::KERIACDCGenusVersion => Err(ParseError::GenusVersionNotAGroup),
```

```rust
        CounterCodeV2::KERIACDCGenusVersion => Err(ParseError::GenusVersionNotAGroup),
```

`group/mod.rs:927` — the generic V2 fallthrough:

```rust
        _ => Err(ParseError::UnexpectedCodeType {
            expected: "attachment group counter",
            got: code.as_str().to_owned(),
        }),
```

`group/mod.rs:1006-1009` — inside `frame_quadlet_count`:

```rust
    if !payload.len().is_multiple_of(4) {
        return Err(ParseError::Misaligned {
            len: payload.len(),
            unit: 4,
        });
    }
```

`group/mod.rs:1098-1104` — the V2-only-group encode guard:

```rust
            | Self::TypedMediaQuadruples(_) => Err(ParseError::VersionMismatch {
                group: "V2-only group type",
                version: CesrVersion::V1,
            }),
```

- [ ] **Step 4: Run to verify it passes**

```bash
nix develop --command cargo nextest run -p cesr-stream group:: > /tmp/t4.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/group/mod.rs
git commit -m "refactor(cesr-stream)!: typed errors in group/mod.rs (#208)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Migrate `group/kinds.rs` (7 sites)

**Files:**
- Modify: `crates/cesr-stream/src/group/kinds.rs`

- [ ] **Step 1: Update the two nested-counter tests**

Replace the assertion block at `crates/cesr-stream/src/group/kinds.rs:1327-1332`:

```rust
            assert_eq!(
                err,
                ParseError::NestedCounterMismatch {
                    outer: "-F",
                    expected: "-A",
                    got: "-B".to_owned(),
                }
            );
```

And at `crates/cesr-stream/src/group/kinds.rs:1386-1390`:

```rust
            assert_eq!(
                err,
                ParseError::NestedCounterMismatch {
                    outer: "-H",
                    expected: "-A",
                    got: "-B".to_owned(),
                }
            );
```

- [ ] **Step 2: Run to verify they fail**

```bash
nix develop --command cargo nextest run -p cesr-stream group::kinds > /tmp/t5.log 2>&1; echo "exit=$?"
```

Expected: FAIL — left is `Malformed("expected -A counter inside -F group, got -B")`.

- [ ] **Step 3: Migrate the sites**

Add `SpanKind` to the `ParseError` import at the top of `group/kinds.rs`.

Both mismatch sites live in one function, `skip_nested_controller_sigs`
(`kinds.rs:62-95`). Its sibling `nested_controller_sigs` (`kinds.rs:102`) has
no counter-code check, so only this one signature changes. Tighten the outer
letters to `&'static str` so they can live in the error field:

```rust
fn skip_nested_controller_sigs(
    input: &[u8],
    version: CesrVersion,
    outer_v1: &'static str,
    outer_v2: &'static str,
) -> Result<usize, ParseError> {
```

All call sites already pass string literals (`"-F"`, `"-X"`, `"-H"`), so no
call-site change is needed.

`kinds.rs:73-77`:

```rust
            if code != CounterCodeV1::ControllerIdxSigs {
                return Err(ParseError::NestedCounterMismatch {
                    outer: outer_v1,
                    expected: "-A",
                    got: code.as_str().to_owned(),
                });
            }
```

`kinds.rs:83-87`:

```rust
            if code != CounterCodeV2::ControllerIdxSigs {
                return Err(ParseError::NestedCounterMismatch {
                    outer: outer_v2,
                    expected: "-K",
                    got: code.as_str().to_owned(),
                });
            }
```

Note the V2 arm drops the old message's `" (V2)"` suffix — the `expected: "-K"`
field already identifies the version's code, so the suffix was redundant.

`kinds.rs:125-131` — inside `encode_sigers`. Three shared rules constrain this
one: `as_conversions` is denied, `saturating_*` is banned in size/count paths,
and `unwrap_or(sentinel)` for a failed conversion is banned. So the `usize →
u64` widening gets its own checked arm rather than a fallback value:

```rust
    let len = sigers.len();
    let count = u32::try_from(len).map_err(|_| match u64::try_from(len) {
        Ok(n) => ParseError::CountExceedsCapacity {
            count: n,
            capacity: u64::from(u32::MAX),
        },
        Err(_) => ParseError::Overflow(SpanKind::ElementSpan),
    })?;
```

The second arm is unreachable on every target this crate builds for (`usize` is
32 or 64 bits), but writing it costs nothing and keeps the path free of a
sentinel. `CountExceedsCapacity` keeps `u64` fields — Task 7's `encode.rs`
sites widen from `u32` with the infallible `u64::from`.

`kinds.rs:300`, `:310`, `:361`, `:371` — all four identical:

```rust
            .ok_or(ParseError::Overflow(SpanKind::ElementSpan))?;
```

(the two `skip` variants end the expression without `?`, so drop the `?` there
exactly as the current code does)

- [ ] **Step 4: Run to verify it passes**

```bash
nix develop --command cargo nextest run -p cesr-stream group:: > /tmp/t5.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/group/kinds.rs
git commit -m "refactor(cesr-stream)!: typed errors in group/kinds.rs (#208)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Migrate `codec.rs`, `qb2.rs`, `message.rs`, `cold.rs`, `unwrap.rs` (11 sites)

These five files hold one or two sites each with no shared structure; batching
them keeps the commit count proportional to the work.

**Files:**
- Modify: `crates/cesr-stream/src/codec.rs:176,225`
- Modify: `crates/cesr-stream/src/qb2.rs:26,57`
- Modify: `crates/cesr-stream/src/message.rs:43,73,79,226`
- Modify: `crates/cesr-stream/src/cold.rs:95`
- Modify: `crates/cesr-stream/src/unwrap.rs:59,119,125,383`

- [ ] **Step 1: Update the two tests, and add qb2/cold boundary tests**

`crates/cesr-stream/src/message.rs:221-227`:

```rust
    #[test]
    fn parse_message_without_version_string_is_rejected() {
        let body = br#"{"t":"icp","d":"SAID","x":"no version string here"}"#;
        assert_eq!(
            CesrMessage::parse(body).unwrap_err(),
            ParseError::MissingVersionString
        );
    }
```

`crates/cesr-stream/src/unwrap.rs:381-387`:

```rust
        assert_eq!(
            result.unwrap_err(),
            ParseError::DepthExceeded { max: MAX_DEPTH }
        );
```

(`MAX_DEPTH` is already in scope in that module; if it is not `usize`, convert
with `usize::from`/`usize::try_from` rather than a cast.)

New defensive-boundary tests. Append to `mod tests` in
`crates/cesr-stream/src/qb2.rs`:

```rust
    #[test]
    fn qb64_to_qb2_rejects_misaligned_length() {
        assert_eq!(
            qb64_to_qb2(b"ABC").unwrap_err(),
            ParseError::Misaligned { len: 3, unit: 4 }
        );
    }

    #[test]
    fn qb2_to_qb64_rejects_misaligned_length() {
        assert_eq!(
            qb2_to_qb64(&[0u8, 1]).unwrap_err(),
            ParseError::Misaligned { len: 2, unit: 3 }
        );
    }
```

Append to `mod tests` in `crates/cesr-stream/src/cold.rs`:

```rust
    #[test]
    fn detect_rejects_unknown_lead_byte() {
        // 0x7f: not JSON, not a CBOR/MsgPack head, high bit clear, and not
        // in the CESR text alphabet.
        assert_eq!(
            ColdCode::detect(0x7f).unwrap_err(),
            ParseError::UnknownColdStart { byte: 0x7f }
        );
    }
```

Append to `mod tests` in `crates/cesr-stream/src/unwrap.rs`:

```rust
    #[test]
    fn decode_genus_version_rejects_unsupported_major() {
        // 3 B64 chars encoding major=3, minor=0: 3 << 12 = 12288 = "DAA".
        assert_eq!(
            decode_genus_version(b"DAA").unwrap_err(),
            ParseError::UnsupportedGenusVersion { major: 3 }
        );
    }
```

(If `mod tests` in `qb2.rs` or `cold.rs` does not exist yet, create it with the
same `#[cfg(test)]` + `#[allow(clippy::unwrap_used, clippy::expect_used,
clippy::panic, clippy::as_conversions, reason = "test code: panics and type
conversions acceptable")]` header the other modules in this crate use, and
`use super::*;`.)

- [ ] **Step 2: Run to verify they fail**

```bash
nix develop --command cargo nextest run -p cesr-stream > /tmp/t6.log 2>&1; echo "exit=$?"
```

Expected: the six tests above fail; everything else passes.

- [ ] **Step 3: Migrate the sites**

`codec.rs:173-176` and `codec.rs:222-225` (identical):

```rust
        let inner_bytes = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(4))
            .ok_or(ParseError::Overflow(SpanKind::QuadletCount))?;
```

`qb2.rs:25-29`:

```rust
    if !qb64.len().is_multiple_of(4) {
        return Err(ParseError::Misaligned {
            len: qb64.len(),
            unit: 4,
        });
    }
```

`qb2.rs:56-60`:

```rust
    if !qb2.len().is_multiple_of(3) {
        return Err(ParseError::Misaligned {
            len: qb2.len(),
            unit: 3,
        });
    }
```

`message.rs:40-44`:

```rust
    search_range
        .checked_sub(VERSION_STRING_LEN)
        .and_then(|last| (0..=last).find(|&i| VersionString::parse(&input[i..]).is_ok()))
        .ok_or(ParseError::MissingVersionString)
```

`message.rs:72-73`:

```rust
                let size = usize::try_from(vs.size())
                    .map_err(|_| ParseError::Overflow(SpanKind::EventSize))?;
```

`message.rs:77-79`:

```rust
                    let needed = size
                        .checked_sub(input.len())
                        .ok_or(ParseError::Overflow(SpanKind::EventSize))?;
```

`cold.rs:95-97`:

```rust
            _ => Err(ParseError::UnknownColdStart { byte: first_byte }),
```

`unwrap.rs:58-59`:

```rust
                    if depth >= MAX_DEPTH {
                        return Err(ParseError::DepthExceeded { max: MAX_DEPTH });
                    }
```

`unwrap.rs:118-119`:

```rust
    let soft_str = core::str::from_utf8(soft).map_err(|_| ParseError::InvalidUtf8 {
        field: "genus version",
    })?;
```

`unwrap.rs:125-127`:

```rust
        _ => Err(ParseError::UnsupportedGenusVersion { major }),
```

Add `SpanKind` to the `ParseError` import in `codec.rs` and `message.rs`.
`qb2.rs`, `cold.rs`, and `unwrap.rs` do not need it.

- [ ] **Step 4: Run to verify it passes**

```bash
nix develop --command cargo nextest run -p cesr-stream > /tmp/t6.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/codec.rs crates/cesr-stream/src/qb2.rs \
        crates/cesr-stream/src/message.rs crates/cesr-stream/src/cold.rs \
        crates/cesr-stream/src/unwrap.rs
git commit -m "refactor(cesr-stream)!: typed errors in codec/qb2/message/cold/unwrap (#208)

Adds defensive-boundary tests for qb2 misalignment, unknown cold-start
bytes, and unsupported genus-version majors.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Migrate `encode.rs` (5 sites)

**Files:**
- Modify: `crates/cesr-stream/src/encode.rs:36,42,45,95,117,223,239,247`

- [ ] **Step 1: Update the three over-capacity tests to assert exact values**

`crates/cesr-stream/src/encode.rs:216-224`:

```rust
    #[test]
    fn encode_v1_small_counter_over_capacity_is_rejected() {
        // Without the capacity check the soft field would grow to 3 chars and
        // emit a corrupt 5-byte counter (keripy raises InvalidVarIndexError
        // for the same shape, counting.py:878-880).
        let err = CounterCodeV1::ControllerIdxSigs
            .encode_count(4096)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
        );
    }
```

`crates/cesr-stream/src/encode.rs:235-241`:

```rust
    #[test]
    fn encode_v1_big_counter_over_capacity_is_rejected() {
        let err = CounterCodeV1::BigAttachmentGroup
            .encode_count(1_073_741_824)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 1_073_741_824,
                capacity: 1_073_741_823
            }
        );
    }
```

`crates/cesr-stream/src/encode.rs:243-249`:

```rust
    #[test]
    fn encode_v2_small_counter_over_capacity_is_rejected() {
        let err = CounterCodeV2::ControllerIdxSigs
            .encode_count(4096)
            .unwrap_err();
        assert_eq!(
            err,
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
        );
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
nix develop --command cargo nextest run -p cesr-stream encode:: > /tmp/t7.log 2>&1; echo "exit=$?"
```

Expected: FAIL — left is `Malformed("count 4096 exceeds capacity 4095 …")`.

- [ ] **Step 3: Migrate the sites**

`encode.rs:34-51` — `check_counter_capacity`. Note it loses its `hard`
parameter: the counter code no longer appears in any message, and an unused
parameter would trip `dead_code`. Remove it here and at both call sites.

```rust
/// Validate that `count` fits the `ss`-character soft field (the counter
/// capacity keripy enforces at `counting.py:878-880` — count in
/// `[0, 64^ss - 1]`), returning the soft size as [`NonZeroUsize`].
///
/// Without this check `encode_int` would grow past the soft width and emit
/// a corrupt (over-long) counter.
fn check_counter_capacity(ss: usize, count: u32) -> Result<NonZeroUsize, ParseError> {
    let ss_nz = NonZeroUsize::new(ss).ok_or(ParseError::Overflow(SpanKind::CounterSoftSize))?;
    let capacity = u32::try_from(ss)
        .ok()
        .and_then(|bits| 64_u64.checked_pow(bits))
        .and_then(|full| full.checked_sub(1))
        .ok_or(ParseError::Overflow(SpanKind::CounterSoftSize))?;
    if u64::from(count) > capacity {
        return Err(ParseError::CountExceedsCapacity {
            count: u64::from(count),
            capacity,
        });
    }
    Ok(ss_nz)
}
```

Both `encode_count` impls (`encode.rs:85` for V1, `encode.rs:107` for V2) drop
the argument:

```rust
        let ss_nz = check_counter_capacity(self.soft_size(), count)?;
```

`encode.rs:93-99` (V1) and `encode.rs:115-121` (V2) — the auto-promotion
failure. There is no big variant, so the capacity is the small ceiling:

```rust
    fn encode_count_auto(self, count: u32) -> Result<Vec<u8>, ParseError> {
        if count > 4095 {
            if let Some(big) = self.to_big() {
                return big.encode_count(count);
            }
            return Err(ParseError::CountExceedsCapacity {
                count: u64::from(count),
                capacity: 4095,
            });
        }
        self.encode_count(count)
    }
```

Also delete the now-unused `hard` binding in each `encode_count` if the
compiler flags it — `hard` is still used to build the output string
(`format!("{hard}{soft}")`), so it should remain.

Add `SpanKind` to the `ParseError` import at the top of `encode.rs`.

- [ ] **Step 4: Run to verify it passes**

```bash
nix develop --command cargo nextest run -p cesr-stream encode:: > /tmp/t7.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/encode.rs
git commit -m "refactor(cesr-stream)!: typed errors in encode.rs (#208)

check_counter_capacity drops its now-unused hard-code parameter.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Migrate `keri-codec/src/serialize.rs` (2 sites)

**Files:**
- Modify: `crates/keri-codec/src/serialize.rs:432,438,613`

- [ ] **Step 1: Update the test to assert the exact variant**

The test at `crates/keri-codec/src/serialize.rs:603-614` is
`controller_count_over_v1_counter_capacity_is_an_encode_error` — it builds 4096
sigers, which exceeds the `-A` counter's soft capacity. That path reaches
`encode_count_auto` (migrated in Task 7), so it now yields
`CountExceedsCapacity`, not `Misaligned`.

`FrameError` derives only `Debug` and `thiserror::Error` — **no `PartialEq`** —
so bind the inner error rather than comparing the outer one:

```rust
            let err = event.frame_v1(&sigs, None).unwrap_err();
            let FrameError::Encode(inner) = err else {
                panic!("expected FrameError::Encode, got {err:?}");
            };
            assert_eq!(
                inner,
                ParseError::CountExceedsCapacity {
                    count: 4096,
                    capacity: 4095
                }
            );
```

The two sites being migrated in Step 3 (misaligned attachment region, quadlet
count overflow) have **no test** and get none: the surrounding comment records
that group qb64 is quadlet-aligned by construction, so both are unreachable
defensive guards mirroring keripy's `eventing.py:1687-1689`. Do not invent a
test that fakes a misaligned region through a private field — an unreachable
guard with no honest trigger stays untested and is noted as such.

- [ ] **Step 2: Run to verify it fails**

```bash
nix develop --command cargo nextest run -p keri-codec serialize:: > /tmp/t8.log 2>&1; echo "exit=$?"
```

Expected: FAIL — the `let ... else` binds, then `assert_eq!` reports left as
`Malformed("count 4096 exceeds capacity 4095 of counter code -A")` if Task 7 is
not yet merged into the working tree, or passes immediately if it is. If it
passes at this step, Task 7 already fixed it; verify by checking that the
assertion actually names `CountExceedsCapacity` rather than skipping ahead.

- [ ] **Step 3: Migrate both sites**

`crates/keri-codec/src/serialize.rs:428-442`:

```rust
        // Group qb64 is quadlet-aligned by construction; keripy still
        // checks before counting (`eventing.py:1687-1689`), and so do we —
        // a misaligned region must fail typed, never frame corrupt bytes.
        if !attachment.len().is_multiple_of(4) {
            return Err(FrameError::Encode(ParseError::Misaligned {
                len: attachment.len(),
                unit: 4,
            }));
        }
        let quadlets = u32::try_from(attachment.len() / 4)
            .map_err(|_| FrameError::Encode(ParseError::Overflow(SpanKind::QuadletCount)))?;
```

Add `SpanKind` to the `cesr_stream` import at the top of `serialize.rs`
(alongside the existing `ParseError` import).

- [ ] **Step 4: Run to verify it passes**

```bash
nix develop --command cargo nextest run -p keri-codec > /tmp/t8.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/keri-codec/src/serialize.rs
git commit -m "refactor(keri-codec)!: typed ParseError variants at the frame seam (#208)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Delete `Malformed`, fix docs, add the tripwire, ship

**Files:**
- Modify: `crates/cesr-stream/src/error.rs` (remove the variant and its test)
- Modify: `crates/cesr-stream/src/version.rs:55`
- Modify: `crates/cesr-stream/src/encode.rs:63,76`
- Modify: `crates/cesr-stream/src/qb2.rs:22,54`
- Modify: `crates/cesr-stream/src/message.rs:36`
- Modify: `crates/cesr-stream/src/cold.rs:86`
- Modify: `crates/cesr-stream/src/group/kinds.rs:638,656`
- Modify: `crates/cesr-stream/CHANGELOG.md`, `crates/keri-codec/CHANGELOG.md`
- Modify: `crates/cesr-stream/Cargo.toml`, `crates/keri-codec/Cargo.toml`

- [ ] **Step 1: Write the tripwire test**

Append to `mod tests` in `crates/cesr-stream/src/error.rs`:

```rust
    // Every variant must carry a usable message. This list is maintained by
    // hand; it is not a compile-time exhaustiveness proof, and it does not by
    // itself prevent a stringly-typed variant returning. The guard against
    // that is the `rg` check in the PR checklist plus review.
    #[test]
    fn every_variant_display_is_non_empty() {
        let samples = [
            ParseError::NeedBytes(1),
            ParseError::UnknownMatterCode("A".to_owned()),
            ParseError::UnknownCounterCode("-A".to_owned()),
            ParseError::UnexpectedCodeType {
                expected: "x",
                got: "y".to_owned(),
            },
            ParseError::Version(VersionError::UnknownProtocol { found: *b"XXXX" }),
            ParseError::Overflow(SpanKind::GroupSpan),
            ParseError::NotACounter { got: None },
            ParseError::NestedCounterMismatch {
                outer: "-F",
                expected: "-A",
                got: "-B".to_owned(),
            },
            ParseError::GenusVersionNotAGroup,
            ParseError::Misaligned { len: 1, unit: 4 },
            ParseError::InvalidUtf8 { field: "f" },
            ParseError::CountExceedsCapacity {
                count: 1,
                capacity: 0,
            },
            ParseError::DepthExceeded { max: 1 },
            ParseError::UnknownColdStart { byte: 0 },
            ParseError::UnsupportedGenusVersion { major: 9 },
            ParseError::MissingVersionString,
            ParseError::Io("boom".to_owned()),
        ];
        for e in &samples {
            assert!(!e.to_string().is_empty(), "empty Display for {e:?}");
        }
    }
```

- [ ] **Step 2: Verify no `Malformed` construction sites remain**

```bash
rg -n 'Malformed' crates/cesr-stream/src crates/keri-codec/src > /tmp/malformed.log 2>&1; echo "exit=$?"
cat /tmp/malformed.log
```

Expected: only the variant definition in `error.rs`, its `display_malformed`
test, and doc-comment references. If any *construction* site remains, the
owning task was incomplete — go back and finish it before continuing.

- [ ] **Step 3: Delete the variant and its test**

Remove from `crates/cesr-stream/src/error.rs`:

```rust
    /// Structurally invalid stream data.
    #[error("malformed CESR: {0}")]
    Malformed(String),
```

and the `display_malformed` test:

```rust
    #[test]
    fn display_malformed() {
        let e = ParseError::Malformed("bad data".to_owned());
        assert_eq!(e.to_string(), "malformed CESR: bad data");
    }
```

- [ ] **Step 4: Fix the doc comments**

Each `# Errors` section below names `[ParseError::Malformed]`. Replace with the
concrete variant now returned:

| File:line | Replace with |
|---|---|
| `version.rs:55-56` | "Returns [`ParseError::CountExceedsCapacity`] if the count does not fit in the counter's soft field, or [`ParseError::VersionMismatch`] if a V2-only group is encoded with V1 counters." |
| `encode.rs:63` | "Returns [`ParseError::CountExceedsCapacity`] if the count does not fit in the counter's soft field." |
| `encode.rs:76-78` | "Returns [`ParseError::CountExceedsCapacity`] if count exceeds the small limit and no big variant exists for the code, or if count exceeds the big limit." |
| `qb2.rs:22-23` | "Returns [`ParseError::Misaligned`] if the input length is not a multiple of 4, or [`ParseError::Base64`] if it contains invalid Base64 characters." |
| `qb2.rs:54` | "Returns [`ParseError::Misaligned`] if the input length is not a multiple of 3." |
| `message.rs:36-37` | "Returns [`ParseError::MissingVersionString`] if no version string is found within the search range." |
| `message.rs:60-62` | "Returns [`ParseError::NeedBytes`] if insufficient data, [`ParseError::Version`] for invalid version strings, or [`ParseError::UnknownColdStart`] for unknown formats." |
| `cold.rs:85-86` | "Returns [`ParseError::UnknownColdStart`] if the byte starts no known encoding domain." |
| `kinds.rs:638` | "Returns [`ParseError::CountExceedsCapacity`] if the signature count exceeds the group count range." |
| `kinds.rs:656` | "Returns [`ParseError::CountExceedsCapacity`] if the signature count exceeds the group count range." |

- [ ] **Step 5: Bump versions and write CHANGELOG entries**

Bump the MINOR version in `crates/cesr-stream/Cargo.toml` and
`crates/keri-codec/Cargo.toml` (0.x convention: a breaking change is a MINOR
bump). Read the current values first; do not guess.

`crates/cesr-stream/CHANGELOG.md`, under a new `Unreleased` → `Changed` heading:

```markdown
### Changed

- **BREAKING:** `ParseError::Malformed(String)` is removed (#208). Its ~30
  construction sites are now typed variants: `Overflow(SpanKind)`,
  `Misaligned`, `InvalidUtf8`, `CountExceedsCapacity`, `DepthExceeded`,
  `UnknownColdStart`, `UnsupportedGenusVersion`, `VersionMismatch`,
  `MissingVersionString`, `NotACounter`, `NestedCounterMismatch`, and
  `GenusVersionNotAGroup`.
- **BREAKING:** the `From` impls for `ParsingError`, `ValidationError`,
  `IndexerParseError`, `IndexerValidationError`, and the CESR Base64 error no
  longer stringify their source. They wrap it in `Matter`,
  `MatterValidation`, `Indexer`, `IndexerValidation`, and `Base64`
  respectively, so `Error::source()` now resolves. `std::io::Error` remains
  stringified as `Io(String)` because `ParseError` stays `PartialEq`.
- `SpanKind` is a new public type naming which span computation failed.
- Incomplete-frame remapping to `NeedBytes` is unchanged.
```

`crates/keri-codec/CHANGELOG.md`, under `Unreleased` → `Changed`:

```markdown
### Changed

- **BREAKING:** `FrameError::Encode` now carries the typed `cesr-stream`
  variants `ParseError::Misaligned` and `ParseError::Overflow(SpanKind::QuadletCount)`
  in place of `ParseError::Malformed(String)` (#208).
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(cesr-stream)!: remove ParseError::Malformed(String) (#208)

BREAKING CHANGE: ParseError::Malformed is gone. Callers matching on it
must match the specific typed variant instead; see the CHANGELOG for the
full mapping. Error::source() now resolves for all wrapped upstream errors.

Closes #208

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 7: Run the gate**

```bash
nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"
```

Expected: `exit=0`. This is the only command that can justify claiming the work
is done. It covers clippy, rustfmt, taplo, audit, deny, nextest across feature
combinations, doctests, the wasm and no_std builds, and both spine tripwires
(`cesr-version-owner`, `cesr-fn-ratchet`).

If `cesr-fn-ratchet` fails, the free `pub fn` count moved. It should not have —
no task adds or removes a file-scope `pub fn`. Recount with the documented rule
rather than editing the budget:

```bash
rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/cesr-stream/src -g '*.rs' | wc -l
```

- [ ] **Step 8: Open the PR**

```bash
gh pr create --base main --head feat/208-typed-parse-error \
  --title "refactor(cesr-stream)!: typed ParseError replaces Malformed(String) sink (#208)" \
  --body "$(cat <<'EOF'
Closes #208. Part of #193.

## What

Deletes `ParseError::Malformed(String)` from `cesr-stream`. Its ~30
construction sites and the 7 type-erasing `From` impls become typed,
matchable variants that preserve the `source()` chain.

## Breaking changes

- `ParseError::Malformed(String)` removed. Full variant mapping in
  `crates/cesr-stream/CHANGELOG.md`.
- Six `From` impls stop stringifying their source; `Error::source()` now
  resolves for `ParsingError`, `ValidationError`, `IndexerParseError`,
  `IndexerValidationError`, and the CESR Base64 error.
- New public type `SpanKind`.
- `FrameError::Encode` in `keri-codec` carries the new variants.
- `ParseError` remains `PartialEq + Eq`; `std::io::Error` stays stringified
  as `Io(String)` to preserve that, since it arrives only through the
  `tokio_util::codec::Decoder` trait bound.

## Not in scope

Splitting an `EncodeError` out of `ParseError`. `encode.rs` and the
`Encoder` impl still return `ParseError`. Worth a follow-up issue.

## Verification

`nix flake check` green.

Design: `docs/superpowers/specs/2026-07-24-cesr-stream-typed-parse-error-design.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Then attach the PR's issue to the org board (Project #5) per repo convention,
using the `joeldsouzax` gh account.

---

## Post-merge follow-up

File a new issue for the layering defect this plan deliberately left alone:
`encode.rs` and the `tokio_util` `Encoder` impl return `ParseError`, and
`keri-codec` wraps it as `FrameError::Encode`. Encoding failures are not parse
failures. Reference #193 and this PR.
