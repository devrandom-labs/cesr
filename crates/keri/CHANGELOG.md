# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.15...keri-rs-v0.1.0) - 2026-10-02

### Added

- implement corrected CESR V1 protocol foundation
- *(keri)* registry state fold with Tevery dispositions ([#296](https://github.com/devrandom-labs/cesr/pull/296))

### Fixed

- validate protocol authority and bounded attachments
- keep keri-rs package tests self-contained

### Other

- verify release package source with local dependencies
- stage coordinated foundation crate versions
- *(keri)* cover sparse prior-next ondex recovery

### Fixed

- The validating KEL fold rejects a malformed next-key threshold before
  storing a nonempty commitment at inception or rotation. The typed wire
  reader already rejected it; `Signed::from_host_asserted_parts` callers now
  receive the same terminal `MalformedThreshold` result.
- The `keri-rs` package archive now retains the `cesr-stream` development
  dependency required by its `direct_mode` example, and its unit tests embed
  two pinned credential/discovery rows inside the crate archive instead of
  reaching into a sibling `keri-codec` checkout. This affects package
  self-containment only; public APIs and wire bytes are unchanged.

### Added

- Opt-in `IpexConversation` accepts an authenticated, linear apply-root
  two-party exchange with typed missing-evidence and terminal results. Offer
  and grant bind exact embedded ACDC, schema, issuer/holder, pathed indexed
  signature, issuance TEL and accepted KEL anchor evidence. Rejection leaves
  the owned head unchanged; hosts commit the head and replay marker atomically.
- `CredentialVerifier::status` binds an ACDC issuer, registry reference and
  credential SAID to host-accepted KEL/TEL states and rejects revoked heads;
  it is available in the no-std core. The opt-in `credential-verification` adapter
  composes SAID-verified Draft 7 schema fit, status and bounded I2I/NI2I
  chains from exact bytes. Missing facts have retryable dispositions;
  contradictory, revoked and excluded forms are terminal. Hosts retain
  accepted-state provenance and own retrieval, storage and retry policy.

### Fixed

- [**breaking**] `WitnessSetError::CutAddOverlap` was unreachable after the
  shared member-list check and has been removed. Match
  `WitnessSetError::Membership(MemberSetError::CutAddOverlap { .. })` for a
  witness or backer cut/add overlap. The ordered set update is now one private
  calculation for validated KEL, trusted replay and TEL management; each path
  retains its own validation and trust contract.
- The default `keri-rs` feature graph no longer resolves `keri-codec` or
  `keri-events/internals`. Removed a redundant codec dev-dependency and the
  `std` feature's optional-codec edge; only `wire` enables the codec. Existing
  `wire` consumers still compile with and without `std`. No public method or
  wire behavior changed.
- [**breaking**] TEL state now follows the two-log structure of PTEL:
  `RegistryState` owns only the `vcp`/`vrt` management head, while the new
  owned `CredentialState` holds one credential's `iss`/`rev` or `bis`/`brv`
  head. A host keys credential heads by `(registry SAID, credential SAID)`;
  on issuance, look up that key and call `CredentialState::incept` only when
  absent; on revocation, call `CredentialState::ingest_mut` on the retained
  head. `CredentialState::status()` replaces aggregate `vcstate`; a missing
  head is `CredentialStatus::Unknown`. The old aggregate
  `RegistryState::ingest`/`vcstate`/`fold_optional` APIs were removed instead
  of retained as compatibility wrappers. `RegistryState::ingest_mut` now
  advances only `vrt`; it rejects credential ilks as the wrong management
  transition. Both states own their persisted primitives and may outlive the
  source event buffers. Hosts retain accepted management heads at their full
  `(id, sn, SAID)` coordinate and pass `&RegistryState` through
  `TelEvidence::BackerAt` for historical `ra`; the duplicate
  `RegistryManagementEvidence` type and `management_evidence()` copy were
  removed. Lookup, indexing, transaction commit and replay storage stay in
  the host. `InconsistentCredential` rejects a supplied head belonging to a
  different credential without mutating it.
- `KeyState::ingest_mut`, `KeyState::ingest_delegated_mut`, and
  `RegistryState::ingest_mut` validate and apply transitions through a
  mutable borrow. On rejection, the caller retains the same unchanged state
  and can retry after supplying signatures, receipts or delegation/TEL
  evidence. The KEL consuming `ingest` and `ingest_delegated` methods remain
  useful fold-style entry points; retained-state hosts use the mutable
  methods. TEL credential heads now have their own mutable transition and no
  aggregate copy. `KeyStateSnapshot::view()` remains the cheap borrowed
  validation path for snapshot-backed hosts.
- KEL and TEL wire adapters now borrow parsed controller, witness and backer
  signature slices while validating. Keep the parsed `EventMessage` or
  `TelMessage` alive for the `Signed`/`SignedTel` use; hosts that retain a
  carrier independently should continue to use `from_host_asserted_parts`
  (and `with_backer_sigs` for TEL), which take ownership of the supplied
  vectors. Controller, witness, transferable-receipt and TEL-backer judgments
  resolve verification keys by reference and verify exact duplicate wire
  signatures once. `Verified::sigs()` now returns unique valid wire signatures;
  distinct signatures at the same current index remain available for
  prior-next commitment checks. Invalid-first/valid-later and transferable
  receipt out-of-range verdicts are unchanged.
- The `wire` feature now includes `alloc`, so
  `keri-rs --no-default-features --features wire` compiles without requiring
  callers to name `alloc` separately. It remains compatible with `no_std`.
- [**breaking**] TEL `vcp`, `vrt`, `iss`, `rev`, `bis` and `brv` now require an
  exact issuer KEL anchor. A `SignedTel` from a parsed `TelMessage` retains
  its `-G` source coordinate; after the host resolves that coordinate in its
  accepted issuer KEL, attach the event with
  `with_host_accepted_anchor`. Hosts using another codec must also call
  `with_source` with the original `-G` pair. Missing KEL/issuer/registry
  evidence now yields `Disposition::Awaiting`; supplied mismatches yield
  `InconsistentAnchor`, `InconsistentIssuer` or `InconsistentRegistry`
  terminal errors. A host classifies a missing management state as
  `MissingRegistry` and retries after loading it. An issuer signature on the TEL body is no longer required when
  its accepted KEL event anchors the TEL seal, matching the pinned TEL
  reference. Backed events now verify indexed `-B` receipts against their
  governing backer threshold; `-A` controller signatures no longer stand in
  for backer receipts. Save a clone of the owned `RegistryState` at each
  accepted `vcp`/`vrt`, and supply it through `TelEvidence::BackerAt` when a later
  `bis`/`brv` references that historical `ra` coordinate. Missing receipts
  await `EvidenceKind::BackerReceipts`; missing historical management state
  awaits `EvidenceKind::TelAnchor`.
- [**breaking**] `Signed` and `SignedTel` no longer expose fields for direct
  construction. Use `Signed::from(&EventMessage)` or
  `SignedTel::from(&TelMessage)` with the optional `wire` feature; these
  adapters keep parsed events paired with their exact signed body. A host
  using another codec or rehydrating an accepted record must call
  `from_host_asserted_parts` and preserve that association itself. The fold
  verifies signatures over supplied bytes but cannot detect an unrelated
  independently supplied event. `Commitment::opened_by` is crate-private;
  call `Commitment::verify_opening(revealed, bytes, sigs)` so signature
  verification and prior-next opening use the same authority and message.
- [**breaking**] KEL transitions now reject `ixn`, `rot`, and `drt` events
  naming another identifier with terminal
  `StructuralError::IdentifierMismatch`, even when the signature and prior
  SAID are otherwise valid. The same-sn judge now rejects incoming and
  recorded events from another AID, an invented recorded state head, and
  a cascade whose nearest delegating pair is not on the state's delegator
  KEL. A supplied historical establishment must match the state's
  last-establishment SAID and kind; later recorded events must be
  interactions. Callers should handle the new `EvidenceError` mismatch
  variants as inconsistent host evidence. TEL rotation anchors must name the
  issuer KEL.
  `SameSnVerdict::Duplicitous` remains a structural classification only;
  authenticate the candidate against historical authority before storing or
  reporting signed fork proof.
- [**breaking**] Direct KEL/TEL folds now enforce the same static membership
  rules as wire decoding. KEL rotations also reject a zero TOAD when the
  resolved witness set is nonempty. Handle
  `WitnessSetError::Membership` and
  `Rejection::WitnessThresholdZeroWithWitnesses` as terminal invalid input;
  valid receipt indices continue to follow the ordered post-rotation set.
- [**breaking**] Delegated key states now reject ordinary `rot` events as
  `Rejection::Delegation(PlainRotationOnDelegatedState)` (terminal). A `drt`
  on a nondelegated state now reports `DelegatorUnknown` through either fold
  entry, also terminal. `KeyState::judge_same_sn` rejects either incompatible
  recovery event kind with `EvidenceError::IncompatibleEventKind`; callers
  should route only eligible establishment events to recovery and re-drive
  eligible `drt` events through `ingest_delegated` with anchor evidence after
  rewinding. Delegated interactions remain valid through `ingest`.
- [**breaking**] `KeyState::incept` and `incept_delegated` now reject malformed
  inception identity bindings even when callers construct `KeriEvent` directly;
  delegated folds also require digestive prefixes. Match the new
  `Rejection::InceptionIdentity` and
  `StructuralError::DelegatedPrefixNotDigestive` variants when handling
  terminal invalid-input failures.

## [0.0.15](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.14...keri-rs-v0.0.15) - 2026-09-17

### Added

- *(keri)* #94 K8 — direct-mode end-to-end proof example (native + wasm32 CI) ([#282](https://github.com/devrandom-labs/cesr/pull/282))
- *(keri)* #93 K7 — Custodian trait + SaltyCustodian salty derivation ([#271](https://github.com/devrandom-labs/cesr/pull/271))

### Added

- Flagship `direct_mode` example — direct-mode KERI end to end on the pure
  sans-io core: inception, pre-rotation, delegation, agent signing,
  revocation by abandonment, escrow dispositions, and duplicity judgment
  between two in-memory parties exchanging framed wire bytes; compiled for
  `wasm32-unknown-unknown` in CI (#94).

## [0.0.14](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.13...keri-rs-v0.0.14) - 2026-07-31

### Added

- *(keri)* [**breaking**] #91 K5 — witness receipts + TOAD accounting as pure judgments ([#265](https://github.com/devrandom-labs/cesr/pull/265))

### Added

- `custody` — object-safe `Custodian` trait (`KeySpec` -> `KeyCommitment`,
  indexed signing) and deterministic `SaltyCustodian` with keripy/signify
  derivation-path conventions and salt-free resumable `SaltyParams` (#93).
- K5 #91 — out-of-band receipt validation: new `receipt` module with
  `ReceiptedEvent` (the stale check + transferable-endorsement judgment),
  `TransferableEndorsement` / `ReceiptorEstablishment` evidence types,
  `Witnessing::{receipt, witness_index, accounted_by}` (late-wig judgment,
  couple promotion, TOAD accounting over the host-accumulated distinct
  set), `WitnessIndex`, and `ReceiptError` with escrow dispositions.
  Receipts are judged one at a time against the host-asserted accepted
  event; the core keeps no counters or tables (keripy `processReceipt`,
  eventing.py:4481). The `wire` feature converts
  `keri_codec::TransferableReceipt` into `TransferableEndorsement`.
  [**breaking**] `EvidenceKind` gains `ReceiptorEstablishment`
  (exhaustive-enum addition — keripy's unverified transferable-receipt
  escrow, eventing.py:4604-4610).

## [0.0.13](https://github.com/devrandom-labs/cesr/compare/keri-rs-v0.0.12...keri-rs-v0.0.13) - 2026-07-30

### Added

- *(keri-codec)* [**breaking**] #82 typed rct receipts — Message sum, endorsement groups, keripy differential ([#264](https://github.com/devrandom-labs/cesr/pull/264))
- *(keri)* [**breaking**] #90 K4 — delegation validation over typed evidence ([#263](https://github.com/devrandom-labs/cesr/pull/263))
- *(keri)* [**breaking**] #89 K3 — duplicity + superseding-recovery judge ([#262](https://github.com/devrandom-labs/cesr/pull/262))

### Added

- #90 K4 — delegation validation over typed evidence: new `delegation`
  module with `DelegationEvidence` (`Anchored` / `HostAccepted`) and
  `AnchoredDelegation`, and the dedicated fold entries
  `KeyState::incept_delegated` / `KeyState::ingest_delegated`. Acceptance
  checks (seal binding via `KeriEvent::anchor_position`, delegator
  identity, do-not-delegate) are digest comparisons over host-supplied
  evidence — the core never walks the delegator's KEL (spec: a validator
  MUST be given or find the delegating seal; keripy `validateDelegation`
  eventing.py:3009-3416). Evidence checks run after
  signatures/thresholds/witnessing in both entries (keripy `valSigsWigsDel`
  parity). The trusted fold now carries the dip delegator.
- #89 K3 — duplicity + superseding-recovery judge: new `duplicity` module
  with `KeyState::judge_same_sn`, a pure same-sn judgment (duplicate /
  supersedes / duplicitous / yields / undecided) over host-supplied
  evidence, keripy-conformant (oracle main `9161a705`). New types
  `SameSnVerdict`, `DelegationContest`, and `EvidenceError` (boundary
  validation of the supplied evidence). The judge is routing only — no
  signature/commitment/witness checks; on `Supersedes` the host rewinds and
  re-drives the validating fold.

### Changed

- [**breaking**] #90 — `Rejection::DelegationUnsupported` is removed in
  favor of `Rejection::Delegation(DelegationError)`: `EvidenceRequired`,
  `SealNotFound`, and `DelegatorMismatch` park as
  `Awaiting(DelegationEvidence)` (keripy `.pdes`/`.udes`); `Denied` (a
  do-not-delegate delegator — spec MUST drop) and `DelegatorUnknown` are
  `Terminal`. A dip/drt at the plain entries now parks as
  `EvidenceRequired` (a dip at the plain genesis entry included — never
  `NotInception`). New `StructuralError::NotDelegatedInception` /
  `NotDelegatedRotation` guard the delegated entries.
- [**breaking**] #90 — `KeyState::delegator()` and
  `KeyStateSnapshot`'s delegator are widened from `BasicPrefix` to
  `Identifier` (the spec's `di` may be self-addressing).
- [**breaking**] #89 — new `Disposition::Contested` variant routes same-sn
  contests to the judge: stale `OutOfOrder` (`actual <= expected`) and
  `Structural(DuplicateInception)` move from `Terminal` to `Contested`
  (keripy routes both to the duplicate/duplicitous/superseding path). Both
  enums are deliberately exhaustive, so hosts get a compile error.

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
