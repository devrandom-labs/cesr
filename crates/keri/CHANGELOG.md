# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.12](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.11...keri-rs-v0.0.12) - 2026-07-29

### Added

- *(keri)* [**breaking**] #133 D1 — filter invalid signatures (keripy verifySigs parity) ([#255](https://github.com/devrandom-labs/cesr/pull/255))

### Changed

- [**breaking**] #133 D1 — `Authority::verify` now filters invalid signatures
  (keripy `verifySigs` parity): a signature that fails verification or whose
  index addresses no key is skipped, never fatal; the threshold is judged on
  the valid subset and `Verified` carries only that subset (`Verified` loses
  `Copy`; `Verified::sigs` now returns the filtered `&[&Siger]`).
  `Rejection::UnverifiedSignature` is removed;
  `MissingSignatures { verified }` counts distinct valid signature indices.

## [0.0.11](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.10...keri-rs-v0.0.11) - 2026-07-29

### Added

- *(keri)* [**breaking**] #132 rotation commitment — ondex-based exposure (partial rotation) ([#254](https://github.com/devrandom-labs/cesr/pull/254))
- *(keri)* [**breaking**] #250 D3 — accept abandoned inceptions, gate events on non-transferable state ([#252](https://github.com/devrandom-labs/cesr/pull/252))

### Changed

- [**breaking**] #132 — rotation next-key commitment is now ondex-exposure
  based (spec partial/augmented rotation). `Rejection::NextKeyCommitmentMismatch`
  is removed in favor of curable `Rejection::PriorNextThresholdUnsatisfied`
  (disposition `Awaiting(Signatures)`). `Authority::verify` now returns a
  `Verified` proof; `Commitment::opened_by` takes the revealed authority plus
  that proof.
- [**breaking**] #250 D3 — an empty-`n` inception is now accepted and deemed
  non-transferable (spec MUST; keripy parity) instead of rejected;
  `TransferabilityError::SelfAddressingWithoutNextKeys` is removed. A new
  first-in-precedence `ingest` gate rejects every event on a non-transferable
  or abandoned key state with the new `Rejection::NonTransferableState`
  (disposition `Terminal`); an empty-`n` rotation now abandons the identifier
  in both the validating fold and `KeyStateSnapshot`.

## [0.0.10](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.9...keri-rs-v0.0.10) - 2026-07-29

### Added

- *(keri)* [**breaking**] #88 K2 escrow dispositions — Rejection::disposition, terminal vs awaiting-evidence ([#251](https://github.com/devrandom-labs/cesr/pull/251))
- *(keri)* #92 K6 — KeyStateSnapshot duality (owned carrier + trusted fold) ([#249](https://github.com/devrandom-labs/cesr/pull/249))

### Other

- *(keri-events)* [**breaking**] #242 Ilk → MessageType — clean-and-keep the wire tag ([#244](https://github.com/devrandom-labs/cesr/pull/244))
- *(keri-events)* [**breaking**] role-distinct primitive newtypes (VerifyingKey/Digest/Said/BasicPrefix) — #193 keri-events + cesr-stream passes ([#241](https://github.com/devrandom-labs/cesr/pull/241))
- [**breaking**] #193 P4+P5 — collapse SequenceNumber onto cesr::Number; relocate qb64↔qb2 into cesr::b64 ([#240](https://github.com/devrandom-labs/cesr/pull/240))

### Added

- `Rejection::disposition()` with `Disposition` / `EvidenceKind` — K2 escrow
  as a pure classification: every fold rejection is `Terminal` (drop) or
  `Awaiting` specific evidence (park and re-drive). Both enums are
  deliberately exhaustive so new evidence kinds (K4/K5) are compile errors
  in hosts. (#88)

### Changed

- [**breaking**] `Rejection::MissingSignatures` is now a struct variant
  carrying `verified: usize` (the count of signatures that verified). The
  KERI spec's DDoS rule splits on this count: zero verifiable signatures
  MUST be dropped, one or more below threshold SHOULD be escrowed. (#88)
- [**breaking**] `KeyState` sequence numbers are now
  `cesr::core::primitives::Number` (was `keri_events::SequenceNumber`, now
  removed); `KeyState::sn()` returns `Number` by value. The
  `SequenceNumberOverflow` error variant name is retained. (#193 P4)
- [**breaking**] `Authority`, `Commitment`, and `KeyState` now hold the
  keri-events role newtypes (`VerifyingKey`/`Digest`/`BasicPrefix`) instead of
  the cesr `Matter` aliases. The signature-verification path is unchanged — it
  converts to `Matter` via `as_matter()` at the crypto boundary. (#193)

## [0.0.9](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.8...keri-rs-v0.0.9) - 2026-07-25

### Other

- updated the following local packages: keri-codec

## [0.0.8](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.7...keri-rs-v0.0.8) - 2026-07-24

### Other

- updated the following local packages: keri-codec

## [0.0.7](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.6...keri-rs-v0.0.7) - 2026-07-24

### Other

- move all crates into crates/ directory (#192 follow-up) ([#198](https://github.com/devrandom-labs/cesr/pull/198))

### Changed

- workspace split phase 3 (#192) — the KERI vocabulary moved from `cesr::keri` to the new `keri-events` crate; keri-rs now depends on `keri-events` and reaches those types as `keri_events::X`. Public-API-only (keri-rs does not enable `keri-events/internals`). No change to keri-rs's own surface.
- workspace split phase 1 (#192) — the `wire` feature now enables the new `keri-codec` crate instead of `cesr`'s removed `serder` feature. A parsed `keri_codec::EventMessage` still converts straight into `Signed`; the default (sans-io) build is unchanged. Internal re-point only, no public API change to keri-rs itself.
- [**breaking**] spine phase 3 — the fold verifies witness receipts (`Signed.wigs`): new `Witnessing` type and `Rejection::InsufficientWitnessReceipts { valid, required }`. Receipts verify against the event's governing witness set (declared at inception, post-cut/add for rotation, carried state for interaction) and at least TOAD distinct witnesses must have a valid receipt; TOAD 0 stays vacuous. keripy semantics per `Kever.valSigsWigsDel` (`eventing.py:2735-2799` at the pin); where keripy escrows partial witnessing the fold returns the terminal rejection and the consumer re-drives.

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
