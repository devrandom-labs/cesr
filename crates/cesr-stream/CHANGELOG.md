# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
