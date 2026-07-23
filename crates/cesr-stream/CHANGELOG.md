# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Group framing threads `(buf, start)` offsets instead of re-slicing the shared buffer per group. `Groups::over` → `CesrGroup::parse_bytes` → dispatch → `Group::parse` previously took an extra `Bytes` slice per group (`buf.slice(cursor..)` in the iterator plus an intermediate `elements` slice inside `parse_bytes`) on top of the unavoidable per-group `raw` span slice. `dispatch_v1`/`_v2`/`_frames`/`_seals`, `parse_kind`, `parse_frame`/`_v2`, `Group::parse`, and `parse_quadlets`/`_v2` now receive an absolute `start` and frame each group directly off the shared buffer; new offset-aware `parse_bytes_at`/`_v2_at` keep the public `parse_bytes`/`_v2` at offset 0 for `codec.rs` and the `QuadletGroup` parser. All span arithmetic uses `checked_add`/`checked_sub` and returns `ParseError::Malformed` on overflow; `NeedBytes` shortfalls are byte-identical. No public API or wire-behavior change (`Group::parse` is `pub(crate)`). Measured (`stream_parse` / `stream_parse_scaling`, `cesr-stream`): ~2% faster on a small multi-group stream (127.3 → 124.5 ns), scaling to ~6% as the group count grows (256-group stream 11.39 → 10.73 µs) — the win tracks the one `Bytes` slice elided per group.

### Added

- Initial release. Carved from `cesr-rs`'s `stream` module (#192 phase 2) with
  no wire-behavior change: `cesr::stream::X` is now `cesr_stream::X`. CESR stream
  framing — counters, groups, cold-start detection, and text/binary stream
  parsing (`CesrMessage::parse`, `CesrGroup`, the `TextStream` cursor). The
  `async` codec (`CesrCodec`) moves here from `cesr` behind the `async` feature.
  The version starts at 0.1.0 because it is a new crate; the API is under active
  redesign in #193.
