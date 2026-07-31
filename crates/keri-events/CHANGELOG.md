# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/devrandom-labs/cesr/compare/keri-events-v0.3.0...keri-events-v0.4.0) - 2026-07-30

### Added

- *(keri-codec)* [**breaking**] #82 typed rct receipts — Message sum, endorsement groups, keripy differential ([#264](https://github.com/devrandom-labs/cesr/pull/264))
- *(keri)* [**breaking**] #90 K4 — delegation validation over typed evidence ([#263](https://github.com/devrandom-labs/cesr/pull/263))
- *(keri)* [**breaking**] #89 K3 — duplicity + superseding-recovery judge ([#262](https://github.com/devrandom-labs/cesr/pull/262))

### Fixed

- *(keri-events)* [**breaking**] #259 widen seal identifier to basic-or-self-addressing ([#260](https://github.com/devrandom-labs/cesr/pull/260))

### Added

- #82 — typed receipt vocabulary: new `Receipt<'a>` type (the coordinate of
  a receipted event: prefix, sn, said) with a public constructor — no
  self-SAID to forge, hence no `internals` gate. NOT a `KeriEvent` variant:
  receipts never enter a KEL.
- [**breaking**] #82 — `MessageType` gains the `Rct` variant
  (`code() = "rct"`, accepted by `from_code`, non-establishment).
  Exhaustive matches on `MessageType` must add an arm. The enum's rustdoc
  now records the 1.0 ilk-scope decision: `qry`/`rpy`/`exn` are documented
  OUT (routing/protocol messages for the layer above) and stay rejected.
- #90 K4 — `KeriEvent::anchor_position`: position of the event-seal
  matching a delegated event's `(i, s, d)` within this event's seals,
  counted over the event-seal subsequence (keripy filtered-subsequence
  semantics, eventing.py:3455-3463). Additive; backs the keri-rs
  delegation evidence check.
- #89 K3 — unified `sn()`/`said()`/`prefix()`/`anchors()` accessors on
  `KeriEvent`, uniform across all five variants (delegated events read
  through their inner inception/rotation). Additive; supports the keri-rs
  duplicity judge's uniform event access.

### Changed

- [**breaking**] `Seal::Event.i` and `Seal::Last.i` widened from `BasicPrefix`
  to `Identifier` (basic or self-addressing): a keripy delegation-anchor seal
  carries the delegated dip prefix — a self-addressing SAID (`E…`) — which the
  `BasicPrefix` lift rejected, failing the whole event's deserialization.
  `Seal::Back.bi` stays `BasicPrefix` (backers are non-transferable basic by
  definition). Wire bytes are unchanged for existing basic-prefix seals.
  (#259)

## [0.3.0](https://github.com/devrandom-labs/cesr/compare/keri-events-v0.2.0...keri-events-v0.3.0) - 2026-07-29

### Other

- *(keri-events)* [**breaking**] #242 Ilk → MessageType — clean-and-keep the wire tag ([#244](https://github.com/devrandom-labs/cesr/pull/244))
- *(keri-events)* [**breaking**] role-distinct primitive newtypes (VerifyingKey/Digest/Said/BasicPrefix) — #193 keri-events + cesr-stream passes ([#241](https://github.com/devrandom-labs/cesr/pull/241))
- [**breaking**] #193 P4+P5 — collapse SequenceNumber onto cesr::Number; relocate qb64↔qb2 into cesr::b64 ([#240](https://github.com/devrandom-labs/cesr/pull/240))

### Changed

- [**breaking**] removed `SequenceNumber`; event and seal sequence numbers are
  now `cesr::core::primitives::Number` (a `Copy` ordinal rendered as minimal
  hex at the codec layer). `SequenceNumber` was a codeless duplicate of
  `Number` — keripy renders the body `"s"` via `Number.numh`, not a separate
  type. (#193 P4)
- [**breaking**] event getters, `Identifier`, and `Seal` now use the
  role-distinct newtypes `VerifyingKey`/`Digest`/`Said`/`BasicPrefix` (new
  `primitive` module) instead of the cesr `Matter` aliases
  `Verfer`/`Diger`/`Saider`/`Prefixer`. Each wraps a `cesr::Matter` with
  `Deref` read-through, so a value's KERI role becomes a compile-time fact — a
  verification key can no longer be assigned where an AID prefix is expected,
  nor a SAID where a next-key digest is (same code family, previously the same
  type). Wire bytes are unchanged. (#193)

## [0.2.0](https://github.com/devrandom-labs/cesr/compare/keri-events-v0.1.0...keri-events-v0.2.0) - 2026-07-24

### Other

- *(keri-codec)* [**breaking**] split SerderError into per-domain enums, rename to CodecError ([#206](https://github.com/devrandom-labs/cesr/pull/206)) ([#219](https://github.com/devrandom-labs/cesr/pull/219))
- *(keri-events)* [**breaking**] P3 — opaque-anchor JSON validation moves to keri-codec ([#193](https://github.com/devrandom-labs/cesr/pull/193)) ([#200](https://github.com/devrandom-labs/cesr/pull/200))

### Changed

- [**breaking**] `OpaqueSeal` is now a pure verbatim wrapper (#193 P3):
  `OpaqueSeal::new` (validating) is replaced by `OpaqueSeal::new_unchecked`
  (no validation), and the compact-JSON scanner (`seal::scan_object`) plus
  `OpaqueSealError` are removed from this crate. The crate now honors its
  "pure data, no serialization" charter; compact-JSON validation of opaque
  anchors is owned by `keri-codec` on the read path (rejections surface as
  `keri_codec::SerderError::InvalidAnchor` carrying the new
  `keri_codec::OpaqueScanError`). Wire behavior is unchanged.

### Added

- Initial release. Carved from `cesr-rs`'s `keri` module (#192 phase 3) with no
  API change: `cesr::keri::X` is now `keri_events::X`. The KERI event vocabulary —
  key events (inception, rotation, interaction, delegation), seals, signing
  thresholds, `Identifier`, and `Toad`. Pure data over CESR core primitives; no
  serialization of its own (that is `keri-codec`). The `internals` feature (the
  all-field event constructors, consumed by `keri-codec`) moves here from `cesr`.
  The version starts at 0.1.0 because it is a new crate; the API is under active
  redesign in #193.
