# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0](https://github.com/devrandom-labs/cesr/compare/cesr-stream-v0.6.0...cesr-stream-v0.7.0) - 2026-10-02

### Added

- implement corrected CESR V1 protocol foundation

### Fixed

- validate protocol authority and bounded attachments

### Other

- stage coordinated foundation crate versions
- *(foundation)* record sparse witness quorum evidence
- *(stream)* reuse validated V1 signature framing ([#300](https://github.com/devrandom-labs/cesr/pull/300))

### Fixed

- Added `FrameLimits::scan_group_v1` so callers can enforce element and
  signature budgets on a complete nested group before materializing it. It
  includes signatures inside universal enclosures; `keri-codec` uses it for
  pathed EXN material.
- V1 controller and witness signature group parsing reuses the completed
  framing scan when constructing an owned group. It preserves A05's
  per-frame ownership and exact remainder while reducing the parser cost
  introduced by the bounded-copy path; the A30 same-host measurement and
  remaining performance tradeoff are recorded in `docs/TODO.md`.
- [**breaking**] The bounded V1 `MessageFramer` now reports a valid CESR V2
  body version string as `ParseError::UnsupportedVersion { version: V2 }`
  instead of a misleading V1 grammar error. During incremental reads it
  waits for the complete V2 head before rejecting it. Callers matching
  parse errors should handle the new variant.
- Removed the obsolete `concurrent_parse` example. Its copy-once-versus-
  per-group-copy arms described the pre-A05 parser and its run command named
  the removed `stream` feature. Current group-copy scaling is guarded by
  `tests/allocation.rs`; integrated route measurements live in the A15 report.
  Run `cargo run -p cesr-stream --example parse_stream` for the current
  group-parsing example.
- The `async` feature now enables `std`, which Tokio's codec traits require.
  `--no-default-features --features async` compiles as a standalone consumer;
  no `no_std` async codec profile is claimed. Sans-I/O framing remains
  available with `alloc` alone. No public method or wire byte changed.
- [**breaking**] Remove `CesrMessage::parse` and its `CesrMessage` enum. It
  returned a body with a lazy iterator over the entire remaining input, so it
  could not establish an exact attachment boundary or enforce the supplied
  framing policy. Use `MessageFramer::new(limits).advance(prefix, eof)` for
  sans-I/O framing or `MessageCodec::new(limits)` for async buffering, then
  interpret the exact body span in `keri-codec`. The internal first-field
  version reader is shared by those paths; it is no longer a second public
  message parser. The fuzz harness and public-surface check moved to the
  bounded framer.
- Replacing a retained partial JSON first-field prefix with a shorter buffer
  now returns typed `Truncated` instead of panicking or waiting forever. The
  normal append-only caller contract is unchanged.

- [**breaking**] `CesrCodec<V>::new` now requires `FrameLimits`, and the
  unbounded `Default` constructor is removed. Migrate
  `CesrCodec::<V1>::new()` or `CesrCodec::<V2>::default()` to
  `CesrCodec::<V1>::new(limits)` or `CesrCodec::<V2>::new(limits)` with explicit
  byte, element, signature and nested-group limits. The async group codec
  checks declared counts/sizes before waiting for payload and checks enclosed
  signatures before emitting a group. Existing mapping-only tests now use
  valid enclosed-group payloads where a nested grammar is required.

- [**breaking**] CBOR and MessagePack interleaved message heads now require
  the `v` version string in the first map field, accept valid compact or
  extended text-length headers, and return `NeedBytes` for matching short
  prefixes. The declared serialization kind must match the cold-start byte;
  a mismatch returns `ParseError::VersionKindMismatch`. Producers with a later
  `v` field or a mismatched kind must correct their wire serialization.

- Add `MessageFramer` for bounded sans-I/O V1 framing and `MessageCodec` as
  its async `Bytes` adapter. Callers supply `FrameLimits` for body bytes,
  attachment bytes, top-level/nested group counts, universal-enclosure depth,
  per-group element count and recognized signatures. V1 `-T`/`-U`/`-V`
  enclosures are walked with the existing genus-version selector and group
  cursor, including nested V2 counter-table switches. A body
  with unframed attachments waits for the next body or explicit EOF; a
  complete `-V` envelope or bare group emits immediately. The adapter returns
  exact wire bytes for downstream parsing and signature verification. This is
  a new API; callers moving from one-shot `CesrMessage::parse` should retain
  the growing prefix until a `FrameSpan` is returned, then consume its
  `total_len`. Callers constructing `FrameLimits` must supply the new signature,
  nested-group and depth bounds. Other context-specific opaque quadlet payloads,
  typed V2 bodies and JSON field/depth budgets remain tracked under A14/A24.

- [**breaking**] Element-counted async groups now retain their framing position across
  fragments, including signatures inside nested `-F`/`-H` elements, avoiding
  repeated scans of complete signatures. At stream EOF,
  a partial final group returns typed `ParseError::Truncated { missing }`
  instead of a generic I/O error. Callers matching EOF errors should handle
  the new variant.

- [**breaking**] JSON cold-start framing now waits for an incomplete `v`
  first-field header and rejects a later `v` field, per CESR's version-first
  mapping rule. JSON whitespace between first-field tokens remains valid.
  Producers of reordered JSON headers must serialize `v` first. The larger
  bounded incremental contract is tracked as A14.

- Frame borrowed CESR input before owning it, so `CesrGroup::parse` and
  `Groups::over` retain only each consumed group. The async codec now splits
  completed element groups from `BytesMut` without copying the buffered tail.
  Wire bytes, typed errors, and public signatures are unchanged.

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
