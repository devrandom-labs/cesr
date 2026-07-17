# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
