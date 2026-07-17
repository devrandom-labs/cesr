# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- [**breaking**] Opaque-anchor validation moves into this crate (#193 P3): a
  new public `OpaqueScanError` (in `error`, re-exported at the crate root) is
  now the source type of `SerderError::InvalidAnchor`, replacing
  `keri_events::OpaqueSealError`. The compact-JSON object scanner lives here
  (crate-internal `OpaqueScan`), next to its strict-reader caller; the
  redundant re-validation on already-scanned anchor spans is removed. Wire
  behavior is unchanged — the keripy differential, spine byte-identity, and
  strict-vs-oracle property suites pass unmodified.

- workspace split phase 3 (#192) — `keri` moved out of `cesr` into the new
  `keri-events` crate; keri-codec now depends on `keri-events` (with its
  `internals` feature) and reaches vocabulary types as `keri_events::X` instead
  of `cesr::keri::X`. No API change to keri-codec's own surface.
- workspace split phase 2 (#192) — `stream` moved out of `cesr` into the new
  `cesr-stream` crate; keri-codec now depends on `cesr-stream` and reaches stream
  types as `cesr_stream::X` instead of `cesr::stream::X`. No API change to
  keri-codec's own surface.

### Added

- Initial release. Carved from `cesr-rs`'s `serder` module (#192 phase 1) with
  no API change: `cesr::serder::X` is now `keri_codec::X`. The KERI event codec —
  events to and from canonical JSON, SAID computation, and CESR message framing
  (`EventMessage::parse`, `SerializedEvent::frame_v1`). The version starts at
  0.1.0 because it is a new crate; the API is under active redesign in #193.
