# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
