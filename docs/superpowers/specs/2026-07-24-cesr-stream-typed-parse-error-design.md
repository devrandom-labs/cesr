# cesr-stream: typed `ParseError` — replacing the `Malformed(String)` sink

**Issue:** [#208](https://github.com/devrandom-labs/cesr/issues/208) (part of #193, `cesr-stream` API redesign)
**Date:** 2026-07-24
**Status:** approved, ready for planning
**Breaking:** yes — MINOR bump for `cesr-stream` and `keri-codec`

## Problem

`ParseError::Malformed(String)` (`crates/cesr-stream/src/error.rs:41`) is a
stringly-typed catch-all. Two distinct failures feed it:

1. **Type erasure at the `From` boundary.** Seven `From` impls funnel typed
   upstream errors into a formatted string, including two blanket
   `_ => Self::Malformed(e.to_string())` arms (`error.rs:64`, `error.rs:95`).
   This discards `ValidationError`, `IndexerValidationError`, the b64 `Error`,
   `io::Error`, most `ParsingError` variants, most `IndexerParseError`
   variants, and `CounterCodeError::NotACounter`. The `#[source]` chain the
   shared error rules mandate is broken; callers cannot match on the real
   failure.

2. **In-crate string construction.** ~30 sites across `group/mod.rs`,
   `group/kinds.rs`, `encode.rs`, `parse.rs`, `qb2.rs`, `codec.rs`,
   `unwrap.rs`, `message.rs`, and `cold.rs` build `Malformed` from a `format!`.
   Conditions with opposite remediation — internal span arithmetic overflow
   versus wire-content rejection — are indistinguishable to a caller.

Two more sites live outside the crate: `keri-codec/src/serialize.rs:432,438`
construct `ParseError::Malformed` through `FrameError::Encode`.

The issue text estimated ~15 sites. The verified count is ~30 construction
sites plus 7 erasing `From` impls plus ~9 doc-comment references.

The one clean piece of the existing design is the `From<VersionError>` impl
(`error.rs:50-57`), which peels `VersionError::Truncated` off to
`ParseError::NeedBytes` before wrapping. That is the pattern the typed source
variants follow.

## Constraints (verified, not assumed)

- **`ParseError` derives `PartialEq, Eq`** and roughly 50 `assert_eq!` sites
  across `cesr-stream` and `keri-codec` depend on it. All six upstream source
  error types (`ParsingError`, `ValidationError`, `IndexerParseError`,
  `IndexerValidationError`, `CounterCodeError`, `cesr::b64::error::Error`)
  derive `PartialEq, Eq`, so typed source variants preserve the derive.
- **`std::io::Error` is not `PartialEq`.** Its `From` impl has zero call
  sites but is *not* dead: `impl Decoder for CesrCodec<V>`
  (`codec.rs:290`, `type Error = ParseError`) requires `Error: From<io::Error>`
  as a `tokio_util::codec::Decoder` trait bound. Therefore `io::Error` keeps a
  stringified payload; everything else gets a typed one.
- **`#[from]` is unusable on `ParsingError`, `CounterCodeError`, and
  `IndexerParseError`.** Their `From` impls remap incomplete-frame cases to
  `NeedBytes`, which is backpressure rather than an error and is load-bearing
  for streaming. `#[from]` would generate a conflicting impl. These stay
  hand-written `From` impls; `?` ergonomics are unaffected.
- **`free-fn-budget.toml` caps `cesr-stream` at 2 free `pub fn`.** The design
  adds none.

## Design

### New public type

```rust
/// Which span computation overflowed.
///
/// Fieldless so the diagnostic set is a closed, exhaustively-matchable type
/// at zero runtime cost: `Copy`, no allocation, and two call sites cannot
/// drift to different spellings of the same condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    GroupStart,
    GroupSpan,
    GroupOffset,
    QuadletCount,
    QuadletSpan,
    ElementSpan,
    CursorPosition,
    EventSize,
    CounterSoftSize,
}
```

`SpanKind` lives in `crates/cesr-stream/src/error.rs` alongside `ParseError`
and is re-exported wherever `ParseError` is.

`Overflow`'s `Display` reads `span arithmetic failed for {0}`, not
"overflows": `message.rs:79` is a defensive `checked_sub` guard, so the variant
covers both directions of failed span arithmetic.

### `ParseError` after the change

```rust
pub enum ParseError {
    // — unchanged —
    NeedBytes(usize),
    UnknownMatterCode(String),
    UnknownCounterCode(String),
    UnexpectedCodeType { expected: &'static str, got: String },
    Version(VersionError),

    // — typed sources; manual `From` impls keep the `NeedBytes` remap —
    Matter(ParsingError),                      // #[error(transparent)]
    MatterValidation(ValidationError),         // #[error(transparent)]
    Indexer(IndexerParseError),                // #[error(transparent)]
    IndexerValidation(IndexerValidationError), // #[error(transparent)]
    Base64(cesr::b64::error::Error),           // #[error(transparent)]
    Io(String),                                // tokio-util Decoder bound only

    // — structural; replaces `Malformed(String)` —
    Overflow(SpanKind),
    NotACounter { got: Option<u8> },
    NestedCounterMismatch { outer: &'static str, expected: &'static str, got: String },
    GenusVersionNotAGroup,
    Misaligned { len: usize, unit: usize },
    InvalidUtf8 { field: &'static str },
    CountExceedsCapacity { count: u64, capacity: u64 },
    DepthExceeded { max: usize },
    UnknownColdStart { byte: u8 },
    UnsupportedGenusVersion { major: u32 },
    VersionMismatch { group: &'static str, version: CesrVersion },
    MissingVersionString,
}
```

`Malformed(String)` is **removed**.

`#[error(transparent)]` on the five typed source variants forwards both
`Display` and `source()` to the wrapped error, matching the existing `Version`
variant's shape.

### Site mapping

Every construction site is accounted for. Seven sites need no new variant —
they duplicate the pre-existing `UnexpectedCodeType` in prose.

| Bucket | Count | Target variant | Sites |
|---|---:|---|---|
| Span arithmetic (`checked_*` → `None`, `try_from` failure) | 21 | `Overflow(SpanKind)` | `group/mod.rs:184,189,193,280,384,388,394,409,413,419,622,627,648,653,1012`; `group/kinds.rs:300,310,361,371`; `codec.rs:176,225`; `parse.rs:123`; `message.rs:73,79` |
| Wrong code kind at a position | 1 | `UnexpectedCodeType` (existing) | `group/mod.rs:927` |
| Nested sub-group counter is the wrong code | 2 | `NestedCounterMismatch { outer, expected, got }` | `group/kinds.rs:74,84` |
| Genus-version code used where a group was expected | 2 | `GenusVersionNotAGroup` | `group/mod.rs:747,924` |
| Lead byte is not a counter head | 1 | `NotACounter { got: Option<u8> }` | `parse.rs:61` |
| Quadlet/triplet alignment | 3 | `Misaligned { len, unit }` | `qb2.rs:26` (unit 4), `qb2.rs:57` (unit 3), `group/mod.rs:1008` (unit 4) |
| Invalid UTF-8 in a text field | 3 | `InvalidUtf8 { field }` | `parse.rs:175,192` (`"counter soft field"`), `unwrap.rs:119` (`"genus version"`) |
| Count exceeds counter capacity | 4 | `CountExceedsCapacity { count, capacity }` | `encode.rs:45,95,117`; `group/kinds.rs:127` |
| Counter code-table defect (zero / out-of-range soft size) | 2 | `Overflow(SpanKind::CounterSoftSize)` | `encode.rs:36,42` |
| Nesting-depth limit | 1 | `DepthExceeded { max }` | `unwrap.rs:59` |
| Unrecognized cold-start byte | 1 | `UnknownColdStart { byte }` | `cold.rs:95` |
| Unsupported genus version major | 1 | `UnsupportedGenusVersion { major }` | `unwrap.rs:125` |
| V2-only group encoded with V1 counters | 1 | `VersionMismatch { group, version }` | `group/mod.rs:1102` |
| Version string absent | 1 | `MissingVersionString` | `message.rs:43` |
| Erasing `From` impls | 7 | typed source variants | `error.rs:64,71,80,93,95,102,108,115` |

Out-of-crate sites in `keri-codec/src/serialize.rs`:

- `:432` (attachment region not whole quadlets) → `Misaligned { len, unit: 4 }`
- `:438` (attachment quadlet count out of range) → `Overflow(SpanKind::QuadletCount)`

`error.rs:80` (`CounterCodeError::NotACounter`) and `parse.rs:61` describe the
same condition at two layers that differ only in whether the offending lead
byte is in hand. `map_counter_err` (`parse.rs:59`) is the sole in-crate
consumer of `CounterCodeError` and intercepts `NotACounter` before delegating,
so it can supply the byte; the public `From<CounterCodeError>` impl cannot.
One variant serves both — `NotACounter { got: Option<u8> }`, with
`map_counter_err` passing `Some(b)` and the `From` impl passing `None`. This
follows the shared rule that unknown values are `Option`, not a sentinel; an
`UnexpectedCodeType { got: String::new() }` would be the sentinel the rule
bans, and two separate variants would invite drift.

`group/kinds.rs:74,84` and `group/mod.rs:747,924,927` do not collapse into a
single `UnexpectedCodeType` either. The nested-counter checks
(`skip_nested_controller_sigs`, `parse_nested_controller_sigs`) name the
*enclosing* group — `"expected -A counter inside -F group, got -B"` — and two
existing tests assert that outer letter. `UnexpectedCodeType`'s two fields
cannot carry it, so those sites get `NestedCounterMismatch { outer, expected,
got }` (the `outer_v1`/`outer_v2` parameters tighten from `&str` to
`&'static str`; all call sites already pass literals). The genus-version
rejections at `group/mod.rs:747,924` are a distinct condition — a valid code
used where no group is permitted, with no "got" to report — and become the unit
variant `GenusVersionNotAGroup`. Only `group/mod.rs:927` is a true
"unexpected code at this position" and reuses `UnexpectedCodeType`.

This also strengthens the existing test at `group/mod.rs:1965`, whose comment
notes it must distinguish the genus-version arm from the generic `_` arm: the
distinction becomes two variants rather than two message strings.

### `From` impl shapes

Three impls keep the truncation peel-off and wrap the remainder:

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

impl From<IndexerParseError> for ParseError {
    fn from(e: IndexerParseError) -> Self {
        match e {
            IndexerParseError::EmptyStream => Self::NeedBytes(1),
            IndexerParseError::StreamTooShort { need, .. } => Self::NeedBytes(need),
            other => Self::Indexer(other),
        }
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
```

`IndexerParseError::UnknownCode` currently becomes a formatted string
(`error.rs:93`); it now falls through to `Self::Indexer(other)`, preserving the
typed source.

The three impls with no truncation case become derived `#[from]`:
`ValidationError`, `IndexerValidationError`, and the b64 `Error`.
`From<std::io::Error>` keeps a hand-written body producing `Io(e.to_string())`.

### Documentation

Roughly nine `# Errors` doc sections reference `[ParseError::Malformed]` and
must name the concrete replacement variant: `version.rs:55`, `encode.rs:63,76`,
`qb2.rs:22,54`, `message.rs:36`, `cold.rs:86`, `group/kinds.rs:638,656`.

## Testing

Categories per `CLAUDE.md` §6.

1. **Variant-exactness (strengthening, not a rename).** Every existing
   `assert!(matches!(e, ParseError::Malformed(_)))` becomes an `assert_eq!`
   against the exact typed variant and payload. The current assertions pass for
   *any* malformed-shaped failure and therefore cannot fail on a wrong-reason
   error; the replacements can.
2. **Source-chain tests.** For each of the five typed source variants, assert
   that `Error::source()` on the `ParseError` downcasts to the original
   upstream error value. These fail against today's code, which has no source.
3. **Truncation-remap regression.** Assert that every upstream truncation
   variant (`ParsingError::EmptyStream`, `ParsingError::StreamTooShort`,
   `IndexerParseError::EmptyStream`, `IndexerParseError::StreamTooShort`,
   `CounterCodeError::StreamTooShort`, `VersionError::Truncated`) still lands
   on `NeedBytes` with the correct byte count, and never on a typed source
   variant. This is the streaming-backpressure invariant.
4. **Defensive boundary.** Feed each newly-typed rejection path its triggering
   input end-to-end — misaligned qb64/qb2 lengths, non-UTF-8 counter soft
   field, over-deep nesting, unknown cold-start byte, unsupported genus major,
   V2 group with V1 counters — and assert the specific variant. No panics.
5. **Round-trip.** Existing encode/decode round-trip coverage must stay green;
   `CountExceedsCapacity` paths get an explicit over-capacity encode test.
6. **Grep guard.** A test (or the existing tripwire style) asserting no
   `Malformed` identifier survives in `crates/*/src`.
7. **Cross-feature.** `nix flake check` already runs nextest across feature
   combinations plus the `wasm` and `no_std` builds; the `async`-gated
   `Decoder` impl must compile with the new `Io(String)` variant.

## Non-goals

- **Splitting an `EncodeError` out of `ParseError`.** `encode.rs` and the
  `tokio_util` `Encoder` impl still return `ParseError`, and `keri-codec`
  still wraps it as `FrameError::Encode`. The layering is wrong and worth a
  follow-up issue, but it is out of scope here.
- Any other `cesr-stream` API redesign under #193.
- Changing upstream `cesr` error types.

## Rollout

Single PR against `main`, branched from `origin/main`.

- Breaking change called out in the PR description and in
  `crates/cesr-stream/CHANGELOG.md` and `crates/keri-codec/CHANGELOG.md`.
- `cesr-stream` and `keri-codec` take a MINOR bump (0.x SemVer convention).
- `free-fn-budget.toml` unchanged — no free `pub fn` added or removed.
- Gate: `nix flake check` only.
