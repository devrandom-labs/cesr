# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- [**breaking**] #129 the fold consumes borrowed events: `KeyState`/`Signed`/`Authority`/`Commitment` drop their inner `'static` pins (covariant events coerce); `KeyState::witness_threshold()` returns `Toad` (was `u32`); `KeyState::sn()` returns `SequenceNumber` by value. The keripy fold differentials now exercise the borrowed path.
- *(keri)* [**breaking**] #130 adopt `cesr::keri::SigningThreshold` — `KeyState`/`authority` signing thresholds use the moved-and-renamed type; `.satisfy(...)` → `.satisfied_by(...)`. The witness threshold field is unchanged. (#171 rung 4)

## [0.0.6](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.5...keri-rs-v0.0.6) - 2026-07-13

### Other

- updated the following local packages: cesr-rs

## [0.0.5](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.4...keri-rs-v0.0.5) - 2026-07-12

### Fixed

- *(serder)* [**breaking**] #149 witness semantics parity in establishment builders ([#163](https://github.com/devrandom-labs/cesr/pull/163))

## [0.0.4](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.3...keri-rs-v0.0.4) - 2026-07-11

### Fixed

- *(serder)* [**breaking**] #144 #148 honor prefix derivation and selectable SAID digest code on the write path ([#161](https://github.com/devrandom-labs/cesr/pull/161))

## [0.0.3](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.2...keri-rs-v0.0.3) - 2026-07-11

### Other

- updated the following local packages: cesr-rs

## [0.0.2](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.1...keri-rs-v0.0.2) - 2026-07-08

### Added

- *(#87)* [**breaking**] K1 KeyState fold + domain model (Authority/Commitment/Establishment) (#136)
- *(#87)* [**breaking**] K1 — KeyState + pure key-state fold (sans-io KERI core) (#134)

### Other

- *(#96)* [**breaking**] K0 — convert to workspace + keri-rs sibling crate (#126)
