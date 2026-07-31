# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.8.0...keri-codec-v0.8.1) - 2026-07-31

### Added

- *(keri)* #94 K8 — direct-mode end-to-end proof example (native + wasm32 CI) ([#282](https://github.com/devrandom-labs/cesr/pull/282))
- *(keri)* #93 K7 — Custodian trait + SaltyCustodian salty derivation ([#271](https://github.com/devrandom-labs/cesr/pull/271))

### Other

- *(keri-codec)* #95 K9 — semantic differential corpus vs keripy ([#283](https://github.com/devrandom-labs/cesr/pull/283))

## [0.8.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.7.0...keri-codec-v0.8.0) - 2026-07-31

### Added

- *(keri)* [**breaking**] #91 K5 — witness receipts + TOAD accounting as pure judgments ([#265](https://github.com/devrandom-labs/cesr/pull/265))

## [0.7.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.6.1...keri-codec-v0.7.0) - 2026-07-30

### Added

- *(keri-codec)* [**breaking**] #82 typed rct receipts — Message sum, endorsement groups, keripy differential ([#264](https://github.com/devrandom-labs/cesr/pull/264))
- *(keri)* [**breaking**] #90 K4 — delegation validation over typed evidence ([#263](https://github.com/devrandom-labs/cesr/pull/263))
- *(keri)* [**breaking**] #89 K3 — duplicity + superseding-recovery judge ([#262](https://github.com/devrandom-labs/cesr/pull/262))

### Fixed

- *(keri-events)* [**breaking**] #259 widen seal identifier to basic-or-self-addressing ([#260](https://github.com/devrandom-labs/cesr/pull/260))

### Added

- #82 — receipt (`rct`) codec, both directions. Write: `Serialize` for
  `Receipt` producing `SerializedReceipt` (size-backpatched body, no SAID
  splice — `d` is the receipted event's SAID, carried as data) and
  `SerializedReceipt::frame_v1` (`-F`/`-B`/`-C` endorsement groups in
  keripy `messagize` order, ≥1 endorsement enforced, transferable couple
  prefixes refused). Read: `Deserialize` for `Receipt`,
  `ReceiptMessage::parse` (typed `ReceiptCouple`/`TransferableReceipt`
  lifts, ≥1 endorsement enforced, transferable couple prefixes refused —
  stricter than keripy's silent read-side skip, matching its write-side
  rule), and the `Message` sum (`Message::parse` dispatches mixed
  event/receipt streams on the body's `t`). New error enums
  `ReceiptMessageError`, `MessageError`; new `FrameError` variants
  `MissingEndorsement`/`TransferableCouple`; new `DeserializeError`
  variant `ReceiptNotKeyEvent`. keripy differential corpus
  (`receipts.jsonl`): bodies and framed streams round-trip
  byte-identically, all signatures verified over the receipted event's
  bytes.
- [**breaking**] #82 — the `Serialize` trait gains an associated
  `type Output` (`SerializedEvent` for key events, `SerializedReceipt`
  for receipts); an `rct` body through the key-event read path now fails
  with `DeserializeError::ReceiptNotKeyEvent` instead of
  `UnknownMessageType`.

### Fixed

- *(keri-codec)* [**breaking**] #259 seal `i` lift/encode route through
  `Identifier` — `Seal::Event.i`/`Seal::Last.i` widened `BasicPrefix` →
  `Identifier` in keri-events; fixes deserialization failure on keripy
  delegation-anchor seals whose `i` is the delegated self-addressing prefix
  (`E…`). The oracle (`seal_from_json`) parses seal `i` via
  `parse_qb64_identifier`, and the proptest seal strategy now generates both
  `Identifier` arms.

## [0.6.1](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.6.0...keri-codec-v0.6.1) - 2026-07-30

### Other

- *(keri-codec)* #170 extend event corpus with legal-but-unusual shapes ([#257](https://github.com/devrandom-labs/cesr/pull/257))

## [0.6.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.5.0...keri-codec-v0.6.0) - 2026-07-29

### Added

- *(keri)* [**breaking**] #133 D1 — filter invalid signatures (keripy verifySigs parity) ([#255](https://github.com/devrandom-labs/cesr/pull/255))

## [0.5.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.4.0...keri-codec-v0.5.0) - 2026-07-29

### Added

- *(keri)* [**breaking**] #132 rotation commitment — ondex-based exposure (partial rotation) ([#254](https://github.com/devrandom-labs/cesr/pull/254))
- *(keri)* [**breaking**] #250 D3 — accept abandoned inceptions, gate events on non-transferable state ([#252](https://github.com/devrandom-labs/cesr/pull/252))

## [0.4.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.3.0...keri-codec-v0.4.0) - 2026-07-29

### Added

- *(keri)* [**breaking**] #88 K2 escrow dispositions — Rejection::disposition, terminal vs awaiting-evidence ([#251](https://github.com/devrandom-labs/cesr/pull/251))
- *(keri)* #92 K6 — KeyStateSnapshot duality (owned carrier + trusted fold) ([#249](https://github.com/devrandom-labs/cesr/pull/249))

### Fixed

- *(keri-codec)* [**breaking**] #160 mixed-code SAID verify — dummy every digestive said field, per-field writer codes ([#248](https://github.com/devrandom-labs/cesr/pull/248))

### Other

- *(keri-codec)* [**breaking**] #243 event-model consolidation — rot/drt + icp/dip builder twins ([#246](https://github.com/devrandom-labs/cesr/pull/246))
- *(keri-events)* [**breaking**] #242 Ilk → MessageType — clean-and-keep the wire tag ([#244](https://github.com/devrandom-labs/cesr/pull/244))
- *(keri-events)* [**breaking**] role-distinct primitive newtypes (VerifyingKey/Digest/Said/BasicPrefix) — #193 keri-events + cesr-stream passes ([#241](https://github.com/devrandom-labs/cesr/pull/241))
- [**breaking**] #193 P4+P5 — collapse SequenceNumber onto cesr::Number; relocate qb64↔qb2 into cesr::b64 ([#240](https://github.com/devrandom-labs/cesr/pull/240))

### Changed

- Sequence-number rendering and parsing now flow through
  `cesr::core::primitives::Number` and `Ordinal::numh` (minimal lowercase hex),
  following the removal of `keri_events::SequenceNumber`. Wire bytes are
  unchanged. (#193 P4)
- [**breaking**] the read/lift layer (`parse_qb64_*`, `FromWire`), event
  construction, the `Encode` write path, the builders, and `SerializedEvent`
  now use the keri-events role newtypes `VerifyingKey`/`Digest`/`Said`/
  `BasicPrefix`. Wire output is byte-identical (keripy differential + spine
  byte-identity suites green). (#193)
- [**breaking**] `RotationBuilder`/`DelegatedRotationBuilder` and
  `InceptionBuilder`/`DelegatedInceptionBuilder` are now type aliases of one
  parameterized type-state chain per event family
  (`RotationChain<State, Kind>` / `InceptionChain<State, Kind>`), each alias
  pinning the `Direct`/`Delegated` delegation kind; validation-rule drift
  between a tag and its delegated twin is now a compile error. Wire output
  is byte-identical for all four tags (keripy differential corpus
  unchanged). (#243)
- [**breaking**] `DelegatedInceptionBuilder::new(delegator)` replaces the
  `.keys(..).delegator(..)` chain step (delegator still compile-time
  required, via the constructor). Its `Default` impl is removed. (#243)

## [0.3.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.2.0...keri-codec-v0.3.0) - 2026-07-25

### Other

- *(cesr-stream)* [**breaking**] resolve #212 low-severity API nits ([#237](https://github.com/devrandom-labs/cesr/pull/237))
- *(keri-codec)* [**breaking**] resolve #211 API nits + split InternalError ([#236](https://github.com/devrandom-labs/cesr/pull/236))
- *(cesr-stream)* [**breaking**] API polish — collapse Groups, rename from_sigers/qb2, copy-once docs ([#210](https://github.com/devrandom-labs/cesr/pull/210)) ([#234](https://github.com/devrandom-labs/cesr/pull/234))

### Added

- `keri_codec::InternalError` — a new error enum for broken codec invariants
  (never input-dependent), unioned at the boundary as `CodecError::Internal`
  (#211, part of #193). Variants: `EventLayout(&'static str)` (a slot/span
  layout inconsistent with the rendered or parsed bytes) and
  `PlaceholderPrimitive { source }` (a dummy primitive failed to construct).

### Changed

- **[breaking]** Internal-invariant errors are now a distinct domain from
  input-validation errors (#211). `DeserializeError::InvalidEventLayout` and
  `BuilderError::PlaceholderPrimitive` are **removed**; both move to the new
  [`InternalError`] enum (`EventLayout` and `PlaceholderPrimitive`
  respectively), reachable via `CodecError::Internal`. Callers matching on
  either variant switch from
  `CodecError::Deserialize(DeserializeError::InvalidEventLayout(_))` /
  `CodecError::Builder(BuilderError::PlaceholderPrimitive { .. })` to
  `CodecError::Internal(InternalError::EventLayout(_))` /
  `CodecError::Internal(InternalError::PlaceholderPrimitive { .. })`. The
  remediation differs: an input error means "fix the message", an internal
  error means "fix the codec".

### Documentation

- Documented three low-severity API nits (#211): `EventRef`'s single-lifetime
  coupling, `EventMessage`'s partial (body-only) zero-copy with copy-once
  signatures, and `#[doc(hidden)]` on the builder type-state markers.

## [0.2.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.1.1...keri-codec-v0.2.0) - 2026-07-24

### Other

- *(keri-codec,cesr-stream)* [**breaking**] demote pub mod, curated re-exports ([#209](https://github.com/devrandom-labs/cesr/pull/209)) ([#232](https://github.com/devrandom-labs/cesr/pull/232))

### Changed

- **[breaking]** Module-layout cleanup (#209, part of #193): the `builder`,
  `serialize`, `deserialize`, `said`, `message`, and `traits` modules are now
  private (`pub(crate) mod`). Every public item they held remains reachable at
  its curated crate-root re-export (`keri_codec::InceptionBuilder`,
  `keri_codec::SerializedEvent`, `keri_codec::EventMessage`,
  `keri_codec::{Serialize, Deserialize}`, …) — only the redundant second/third
  paths (`keri_codec::serialize::SerializedEvent`, etc.) are gone. `error`
  stays `pub mod`. Consumers importing via the deep paths must switch to the
  root re-exports.

### Removed

- **[breaking]** `keri_codec::said::DUMMY_CHAR` re-export dropped (#209). It
  was a single re-export of the foreign const already available at
  `cesr::core::matter::code::DUMMY_CHAR`; the `said` module is now private.

### Internal

- `EventBuilderState` is now a sealed marker trait (private `sealed::Sealed`
  supertrait, #209) — the type-state set is closed to this crate. No effect on
  callers, who never implemented it.

## [0.1.1](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.1.0...keri-codec-v0.1.1) - 2026-07-24

### Other

- updated the following local packages: cesr-stream

## [0.1.0](https://github.com/devrandom-labs/cesr/compare/keri-codec-v0.0.1...keri-codec-v0.1.0) - 2026-07-24

### Other

- *(cesr-stream)* [**breaking**] typed ParseError replaces the Malformed(String) sink ([#208](https://github.com/devrandom-labs/cesr/pull/208)) ([#223](https://github.com/devrandom-labs/cesr/pull/223))
- *(keri-codec)* [**breaking**] split SerderError into per-domain enums, rename to CodecError ([#206](https://github.com/devrandom-labs/cesr/pull/206)) ([#219](https://github.com/devrandom-labs/cesr/pull/219))
- *(keri-codec)* [**breaking**] remove dead public surface ([#207](https://github.com/devrandom-labs/cesr/pull/207)) ([#218](https://github.com/devrandom-labs/cesr/pull/218))
- *(keri-codec)* [**breaking**] SAID onto types, EventSpec trait, serialize_event→EventRef ([#193](https://github.com/devrandom-labs/cesr/pull/193)) ([#205](https://github.com/devrandom-labs/cesr/pull/205))
- *(keri-codec)* FromWire/Field lift layer — read path becomes a functional pipeline (#193 P6) ([#204](https://github.com/devrandom-labs/cesr/pull/204))
- *(keri-codec)* zero free-floating fns in codec/* — grammar entry points move onto their types (#193 polish) ([#203](https://github.com/devrandom-labs/cesr/pull/203))
- *(keri-codec)* [**breaking**] whole wire grammar in codec/*; json.rs + canonical.rs dissolve; Serialize/Deserialize rename (#193 step 3) ([#202](https://github.com/devrandom-labs/cesr/pull/202))
- *(keri-codec)* seal wire grammar stated once — Encode/Decode traits, codec/seal module (#193 step 2) ([#201](https://github.com/devrandom-labs/cesr/pull/201))
- *(keri-events)* [**breaking**] P3 — opaque-anchor JSON validation moves to keri-codec ([#193](https://github.com/devrandom-labs/cesr/pull/193)) ([#200](https://github.com/devrandom-labs/cesr/pull/200))
- move all crates into crates/ directory (#192 follow-up) ([#198](https://github.com/devrandom-labs/cesr/pull/198))

### Removed

- [**breaking**] Dead/speculative public surface removed (#207, part of #193):
  - `SerderError::MissingBuilderField` — never produced since the builders
    moved their required fields into the type-state (present by construction
    at `build()`), so the runtime re-check this variant guarded was
    unrepresentable.
  - `SerderError::CutAddOverlap` — the `cuts ∩ adds = ∅` witness-rotation
    check that produced it is provably implied by `cuts ⊆ prior` and
    `adds ∩ prior = ∅` (any overlapping add trips `adds ∩ prior` first), so
    the branch and variant are dropped rather than kept as an unreachable
    public variant.
  - `SerializedEvent`'s unused type parameter `E` (was `SerializedEvent<E = ()>`)
    and its `event()` / `into_event()` accessors — every construction set
    `event: ()` and no `E != ()` instantiation existed (YAGNI). The bare
    `SerializedEvent` name is unchanged.

### Changed

- **BREAKING:** `FrameError::Encode` now carries the typed `cesr-stream`
  variants `ParseError::Misaligned` and
  `ParseError::Overflow(SpanKind::QuadletCount)` in place of
  `ParseError::Malformed(String)` (#208).
- [**breaking**] `SerderError` is renamed and split into one error enum per
  failure domain (#206, part of #193). The banned keripy contraction "serder"
  is gone from the public surface, and the ~24-variant mega-enum is now four
  domain enums unioned at the crate boundary:
  - `CodecError` — the union every codec entry point (`build`, `serialize`,
    `deserialize`) returns, with one `#[from]` variant per domain:
    `Version`, `Said`, `Deserialize`, `Builder`.
  - `VersionGrammarError` — version-string parsing/construction and
    version-level rules (`Version`, `InvalidVersionString`,
    `UnsupportedSerializationKind`).
  - `SaidError` — `SaidMismatch`, `Digest`.
  - `DeserializeError` — read-path body grammar (`UnknownIlk`, `MissingField`,
    `UnexpectedField`, `InvalidPrimitive`, `UnparseablePrimitive`,
    `InvalidAnchor`, `NonCanonical`, `InvalidEventLayout`) plus the new
    `ThresholdOutOfRange`.
  - `BuilderError` — write-path validation (`Toad`, `EmptyKeys`,
    `DuplicatePrefixes`, `CutNotPriorWitness`, `AddAlreadyWitness`,
    `WitnessCountOverflow`, `SnBelowMinimum`, `SigningThresholdOutOfRange`,
    `MajorityOverflow`, `PlaceholderPrimitive`, `MixedThresholdForms`,
    `IntegerFormOverflow`).

  Migration: a match on a flat `SerderError::X` becomes a match on the nested
  `CodecError::<Domain>(<Domain>Error::X)`. Leaf helpers now return their bare
  domain enum (e.g. witness/key validation returns `BuilderError`, the scanner
  and the `Decode`/`FromWire` wire traits return `DeserializeError`), so those
  are matchable without unwrapping the union; `?` lifts them into `CodecError`
  at the entry points. `EventMessageError::Body` now wraps `CodecError`.

  New variant: `DeserializeError::ThresholdOutOfRange` is the read-path
  counterpart of `BuilderError::SigningThresholdOutOfRange` — the same
  well-formedness rule, reported in the domain that produced it, so the
  read-path `FromWire` traits stay single-domain. No wire behavior changed.
- [**breaking**] SAID surface moves onto types and reuses the cesr substrate (#193): the free fns `said::said_placeholder`, `said::compute_digest`, and `said::verify_said` are removed. Placeholder generation is now `DigestCode::placeholder()` (in cesr); digest construction reuses the existing `Diger::digest` / `Saider::digest` (in cesr); SAID verification is now inferred-code methods on the parsed views — `ParsedEvent::verify_said` dispatching to `ParsedIcp`/`ParsedRot`/`ParsedIxn::verify_said` — wired directly into the read path. The caller-supplied-code verification mode (which had no in-tree caller) is dropped: verification always infers the digest code from the SAID's own qb64 prefix. `said::DUMMY_CHAR` is now a re-export of `cesr::core::matter::code::DUMMY_CHAR` (path preserved). No wire behavior changed.
- [**breaking**] `SerderError::DigestError(String)` becomes `SerderError::Digest(#[from] cesr::crypto::error::DigestError)` — a typed source chain replacing the stringified message. Downstream matches on the old variant must rename and re-shape.
- Internal: test-only proptest support (`event_strategies`) folds its per-spec builders and strategies onto an `EventSpec` trait (`Spec::strategy()` to generate, `spec.build()` to realize); the write engine `serialize_event` becomes `EventRef::serialize`. The free-fn ratchet drops 49 → 34 — the remainder is dominated by the test-only tolerant differential oracle in `deserialize::reference` (19 fns), deliberately left as free functions to keep it an independent second implementation of the strict path it checks. No wire behavior changed.
- Internal: no free-floating functions remain in `codec/*` — every grammar
  entry point now lives on its type (`ParsedEvent::parse`,
  `ParsedIcp::parse`/`fields`/`body`, `ParsedRot::parse`/`parse_delegated`,
  `ParsedIxn::parse`, `ParsedDip::parse`, `EventRef::render`,
  `ParsedSeal::codex`/`opaque`, `ParsedTholder::weighted`,
  `ThresholdField::weight_clause`). The free-fn ratchet drops 58 → 51.
  No public API change; wire bytes unchanged.

- [**breaking**] The public serde traits drop the `Keri-` stutter (#193
  step 3, owner-decided): `KeriSerialize` → `Serialize` and
  `KeriDeserialize` → `Deserialize`. The contracts are unchanged
  (`serialize()` computes the SAID and backpatches the version size;
  `deserialize()` verifies the SAID); only the names move. The
  crate-internal wire-grammar traits keep `Encode`/`Decode` (der
  precedent) — they are a narrower, non-SAID contract.
- Internal: the whole canonical wire grammar now lives in `codec/*` (#193
  step 3) — `codec/scanner.rs` (the strict Reader + list combinators),
  `codec/threshold.rs` (`kt`/`nt`/`bt` both directions, with
  `ThresholdField`/`CountField` context wrappers), qb64/config array
  encodes on the slice types, and `codec/event.rs` (the five event
  grammars, writer and parser co-located). `serialize/json.rs` and
  `deserialize/canonical.rs` no longer exist. No public API change; wire
  bytes unchanged (differential and spine suites pass unmodified).
- Internal: the seal wire grammar is now stated once per direction — new
  crate-internal `Encode`/`Decode` traits (der-precedent, #193 step 2) with
  `Seal::encode` / `[Seal]::encode` and `ParsedSeal::decode` co-located in
  `codec/seal.rs`, replacing the duplicated enumeration in the writer
  (`write_seal`/`write_seal_array`) and the strict reader (`seal_codex`/
  `seal`/`seal_opaque`). The shared JSON escaper moved onto the new
  `JsonWriter` type in `codec`. No public API change; wire bytes unchanged
  (differential and spine suites pass unmodified). `serialize/json.rs` and
  the per-type grammar in `deserialize/canonical.rs` are slated to dissolve
  into `codec/*` in step 3.

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
