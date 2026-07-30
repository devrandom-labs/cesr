# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.5.0...cesr-stream-v0.6.0) - 2026-07-30

### Added

- *(keri-codec)* [**breaking**] #82 typed rct receipts — Message sum, endorsement groups, keripy differential ([#264](https://github.com/devrandom-labs/cesr/pull/264))

### Added

- #82 — write-side constructors for the receipt endorsement groups:
  `NonTransReceiptCouples::from_couples` and
  `TransIdxSigGroups::from_groups` (nested `-A` written via the group's V1
  encoding), mirroring `from_indexed_signatures`.
- [**breaking**] #82 — the endorser-prefix element of
  `TransIdxSigGroups` (`-F`), `TransLastIdxSigGroups` (`-H`), and
  `TransReceiptQuadruples` (`-D`) widened from `Prefixer` (verification-key
  codes only) to wide `Matter<MatterCode>` admitting verification-key OR
  digest codes — keripy's `Prefixer`/`PreDex` admits both, and a
  transferable endorser's AID is commonly self-addressing. Any other code
  class fails element typing with `ParseError::UnexpectedCodeType`.

## [0.5.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.4.0...cesr-stream-v0.5.0) - 2026-07-29

### Fixed

- *(cesr-stream)* checked_add the quadlet group span in async codec ([#238](https://github.com/devrandom-labs/cesr/pull/238))

### Other

- [**breaking**] #193 P4+P5 — collapse SequenceNumber onto cesr::Number; relocate qb64↔qb2 into cesr::b64 ([#240](https://github.com/devrandom-labs/cesr/pull/240))

### Changed

- `qb2::{Qb64, Qb2}` now re-export `cesr::b64` (the duplicate whole-blob
  transcoder implementation is removed); their `decode`/`encode` now return
  `Result<_, cesr::b64::Error>` instead of `ParseError`. When converted into a
  `ParseError` (via `?`/`From`), alignment failures surface as
  `ParseError::Misaligned`. (#193 P5)

### Fixed

- (#193) `decode_v1`/`decode_v2` (`codec.rs`) computed the group span
  `counter_size + inner_bytes` with a bare `+`. On a 32-bit target (wasm32) a
  quadlet `count` in the narrow band just under `u32::MAX / 4` passes the
  `checked_mul(4)` guard yet wraps `usize` on the following add, misframing the
  group (undersized `split_to`). Now `checked_add` → `ParseError::Overflow(
  SpanKind::QuadletSpan)`, matching the sibling `parse_quadlets`
  (`group/mod.rs`). Latent (64-bit unaffected); no wire-behaviour change.

## [0.4.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.3.0...cesr-stream-v0.4.0) - 2026-07-25

### Other

- *(cesr-stream)* [**breaking**] resolve #212 low-severity API nits ([#237](https://github.com/devrandom-labs/cesr/pull/237))
- *(cesr-stream)* [**breaking**] API polish — collapse Groups, rename from_sigers/qb2, copy-once docs ([#210](https://github.com/devrandom-labs/cesr/pull/210)) ([#234](https://github.com/devrandom-labs/cesr/pull/234))

### Changed

- **[breaking]** (#210, part of #193) `GroupsV2` removed; `Groups` is now
  `Groups<'a, V: Version = V1>`. Use `Groups::<V2>::over(..)` for V2 streams;
  `Groups::<V1>` or a `Groups<'_>` type annotation selects V1. The `V = V1`
  default only applies in type position — bare `Groups::over(..)` without a
  type-position hint fails to infer `V` (E0283).
- **[breaking]** (#210) `ControllerIdxSigs::from_sigers` and
  `WitnessIdxSigs::from_sigers` renamed to `from_indexed_signatures`.
- **[breaking]** (#210) `qb2_to_qb64` / `qb64_to_qb2` renamed to
  `qb2::to_text` / `qb2::from_text`; the crate-root flat re-export is dropped
  in favour of the module-qualified path.
- (#210) `Groups`'s `Debug` now includes a `version` field, and the group read
  path is documented as copy-once (one shared-`Bytes` copy, then O(1) slices),
  not zero-copy.

## [0.3.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.2.0...cesr-stream-v0.3.0) - 2026-07-24

### Other

- *(keri-codec,cesr-stream)* [**breaking**] demote pub mod, curated re-exports ([#209](https://github.com/devrandom-labs/cesr/pull/209)) ([#232](https://github.com/devrandom-labs/cesr/pull/232))

### Changed

- **[breaking]** `#[doc(hidden)] pub mod parse` is now a private `mod parse`
  (#209, part of #193). Every item inside was already `pub(crate)`, so the
  `pub` granted no reachable surface — `#[doc(hidden)]` was standing in for
  access control. No public item is removed.

## [0.2.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.1.1...cesr-stream-v0.2.0) - 2026-07-24

### Other

- *(cesr-stream)* [**breaking**] carry typed ValidationError in UnexpectedCodeType ([#231](https://github.com/devrandom-labs/cesr/pull/231))
- *(cesr-stream)* [**breaking**] ParseError::UnexpectedCodeType.got is Cow<'static, str> ([#228](https://github.com/devrandom-labs/cesr/pull/228))

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
