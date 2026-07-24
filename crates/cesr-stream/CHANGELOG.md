# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.1.1...cesr-stream-v0.2.0) - 2026-07-24

### Other

- *(cesr-stream)* [**breaking**] ParseError::UnexpectedCodeType.got is Cow<'static, str> ([#228](https://github.com/devrandom-labs/cesr/pull/228))

### Changed

- **[breaking]** `ParseError::UnexpectedCodeType.got` is now
  `Cow<'static, str>` instead of `String` (#222). The variant is constructed
  from two kinds of site: ones holding a runtime-built name (the
  `Matter::narrow` failures in `parse.rs`, which stringify a `ValidationError`)
  and one already holding a `&'static str` (the counter fallthrough in
  `group/mod.rs`, which had to `to_owned()` a `CounterCodeV2::as_str()` result
  purely to satisfy the field type). `Cow` serves both with no allocation on
  the static path. Measured on a 64-bit target, `Cow<'static, str>` is 24
  bytes — identical to `String` — so `size_of::<ParseError>()` is unchanged at
  56 (`MatterValidation` sets the ceiling); a new `parse_error_size_is_bounded`
  test pins that. `Display` output, `PartialEq`/`Eq`, and the source chain are
  unchanged. Callers matching on `got` must now match a `Cow` (`&*got` or
  `got.as_ref()` yields the previous `&str`).

## [0.1.1](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.1.0...cesr-stream-v0.1.1) - 2026-07-24

### Added

- *(cesr-stream)* Debug for the public parse types ([#221](https://github.com/devrandom-labs/cesr/pull/221)) ([#225](https://github.com/devrandom-labs/cesr/pull/225))

## [0.1.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.0.1...cesr-stream-v0.1.0) - 2026-07-24

### Added

- *(cesr)* [**breaking**] decode-free frame_size primitive; harden indexer/counter size math (#193 P1) ([#199](https://github.com/devrandom-labs/cesr/pull/199))

### Fixed

- *(cesr-stream)* derive counter capacity in encode_count_auto instead of hardcoding 4095 ([#224](https://github.com/devrandom-labs/cesr/pull/224))

### Other

- *(cesr-stream)* [**breaking**] typed ParseError replaces the Malformed(String) sink ([#208](https://github.com/devrandom-labs/cesr/pull/208)) ([#223](https://github.com/devrandom-labs/cesr/pull/223))
- *(stream)* thread group-framing offsets instead of re-slicing ([#217](https://github.com/devrandom-labs/cesr/pull/217))
- move all crates into crates/ directory (#192 follow-up) ([#198](https://github.com/devrandom-labs/cesr/pull/198))

### Fixed

- `EncodeCount::encode_count_auto` no longer hardcodes `4095` as the promotion
  threshold and the reported capacity (#220). `4095` is `64^2 - 1`, correct only
  for codes with `soft_size() == 2`; the genus-version code (ss=3, capacity
  262,143) and the `Big*` codes (ss=5, capacity 1,073,741,823) were rejected for
  any count above 4095 even though `encode_count` accepts those counts, and the
  `CountExceedsCapacity { capacity: 4095 }` they returned understated the real
  ceiling by up to five orders of magnitude. The method now attempts
  `encode_count` first and only consults `to_big()` on a real overflow, so the
  capacity derived in `check_counter_capacity` from `soft_size()` is the sole
  source of truth for every soft size. Promotion of ss=2 codes to their big
  variant is unchanged, as is the error for an ss=2 code with no big variant.
  Not reachable from any in-repo caller (all four reach `encode_count_auto` with
  `soft_size() == 2`); `EncodeCount` is public, so downstream callers could hit
  it.

### Changed

- Group framing threads `(buf, start)` offsets instead of re-slicing the shared buffer per group. `Groups::over` → `CesrGroup::parse_bytes` → dispatch → `Group::parse` previously took an extra `Bytes` slice per group (`buf.slice(cursor..)` in the iterator plus an intermediate `elements` slice inside `parse_bytes`) on top of the unavoidable per-group `raw` span slice. `dispatch_v1`/`_v2`/`_frames`/`_seals`, `parse_kind`, `parse_frame`/`_v2`, `Group::parse`, and `parse_quadlets`/`_v2` now receive an absolute `start` and frame each group directly off the shared buffer; new offset-aware `parse_bytes_at`/`_v2_at` keep the public `parse_bytes`/`_v2` at offset 0 for `codec.rs` and the `QuadletGroup` parser. All span arithmetic uses `checked_add`/`checked_sub` and returns `ParseError::Malformed` on overflow; `NeedBytes` shortfalls are byte-identical. No public API or wire-behavior change (`Group::parse` is `pub(crate)`). Measured (`stream_parse` / `stream_parse_scaling`, `cesr-stream`): ~2% faster on a small multi-group stream (127.3 → 124.5 ns), scaling to ~6% as the group count grows (256-group stream 11.39 → 10.73 µs) — the win tracks the one `Bytes` slice elided per group.
- **BREAKING:** `ParseError::Malformed(String)` is removed (#208). Its ~30
  construction sites are now typed variants: `Overflow(SpanKind)`,
  `Misaligned`, `InvalidUtf8`, `CountExceedsCapacity`, `DepthExceeded`,
  `UnknownColdStart`, `UnsupportedGenusVersion`, `VersionMismatch`,
  `MissingVersionString`, `NotACounter`, `NestedCounterMismatch`, and
  `GenusVersionNotAGroup`.
- **BREAKING:** the `From` impls for `ParsingError`, `ValidationError`,
  `IndexerParseError`, `IndexerValidationError`, and the CESR Base64 error no
  longer stringify their source. They wrap it in `Matter`, `MatterValidation`,
  `Indexer`, `IndexerValidation`, and `Base64` respectively, so
  `Error::source()` now resolves. `std::io::Error` remains stringified as
  `Io(String)` because `ParseError` stays `PartialEq`.
- **BREAKING:** `ParseError::Version` now returns the wrapped `VersionError`
  from `Error::source()` rather than that error's own source. It moved from
  `#[error(transparent)]` to `#[error("{0}")]` + `#[source]` so all wrapped
  variants share one `source()` semantics. `Display` is unchanged.
- `SpanKind` is a new public type naming which span computation failed.
- `ColdCode::detect` is now a `const fn`.
- Incomplete-frame remapping to `NeedBytes` is unchanged.

### Added

- Initial release. Carved from `cesr-rs`'s `stream` module (#192 phase 2) with
  no wire-behavior change: `cesr::stream::X` is now `cesr_stream::X`. CESR stream
  framing — counters, groups, cold-start detection, and text/binary stream
  parsing (`CesrMessage::parse`, `CesrGroup`, the `TextStream` cursor). The
  `async` codec (`CesrCodec`) moves here from `cesr` behind the `async` feature.
  The version starts at 0.1.0 because it is a new crate; the API is under active
  redesign in #193.
