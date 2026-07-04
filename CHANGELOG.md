# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **error ergonomics (#33):** removed the `terrors::OneOf` error-union layer in
  favour of purpose-built `thiserror` enums. **Breaking** (MINOR under 0.x):
  - `MatterBuilder::{from_qualified_base64, from_qualified_base2, build}` now return
    `Result<_, MatterBuildError>` (variants `Parsing`, `Validation`) instead of
    `OneOf<(ParsingError, ValidationError)>`.
  - `crypto::verify` now returns `Result<(), VerificationError>` (variants
    `Signature`, `CodeMismatch`) instead of `OneOf<(SignatureError, CodeMismatchError)>`.
  - The indexer builder's parse/validation methods (`from_qb64`, `from_qb2`,
    `with_index`, `with_indices`, `with_raw`) return the bare `IndexerParseError` /
    `IndexerValidationError` (previously wrapped in a single-element `OneOf`).
  - Consumers matching on these results switch from `.take::` / `.narrow::` to a
    normal `match` on the new enums / bare types.
  - `SerderError` gains a new `UnparseablePrimitive` variant (see _Fixed_ below).
    As `SerderError` is public and not `#[non_exhaustive]`, this is **breaking** for
    downstream exhaustive `match` on it.
  - The `terrors` dependency is dropped.

### Fixed

- **serder (#33):** a malformed-but-unparseable field value no longer collapses a
  `ParsingError` into `ValidationError::UnknownMatterCode(..)` via string
  formatting; a new `SerderError::UnparseablePrimitive { field, source }` variant
  carries the parsing error in its own failure domain.
- **stream (#33):** removed an `unreachable!()` panic on the matter-parse error path
  in `stream::parse::parse_matter`; the error mapping is now a total `match`.
- **core (#33):** `MatterBuilder::from_qualified_base64` no longer panics
  (`range end index N out of range for slice of length 0`) on a malformed qb64 whose
  decoded buffer is shorter than the code's declared lead size (e.g. `5BAA`). The
  lead-byte slices are now bounds-checked and return
  `MatterBuildError::Validation(ValidationError::StructuralIntegrityError)`. Found by
  the `deep-fuzz` `matter_from_qb64` target; the crash input is committed as a fuzz
  corpus regression seed.

### Added

- **crypto/devx (#69):** indexed signatures (`Siger`, the form attached to KERI
  events) can now be verified directly — closing the sign/verify asymmetry where
  `sign_indexed` produced a `Siger` but `verify` only accepted a `Cigar`. This
  lands as a **type-unified** verify surface rather than a one-off method:
  - A `crypto::Signature` trait implemented by both `Cigar` (non-indexed) and
    `Siger` (indexed), so a single generic `verify` covers both — the caller
    never branches on "indexed or not".
  - `KeyPair::<A>::verify<S: Signature>(&self, data, &S) -> Result<(), SignatureError>`
    — one generic method (was three duplicated `verify` methods) with per-curve
    crypto dispatched on `A` at **compile time** via the new
    `Algorithm::verify_bytes`. `kp.verify(msg, &cigar)` and `kp.verify(msg, &siger)`
    both work.
  - Free `crypto::verify<S: Signature>(verfer, data, &S)` — the verifier-key-driven
    form (mirrors keripy's `siger.verfer.verify(siger.raw, ser)`) for verifying
    with only public keys. Composes into lazy iterator chains over `stream`-parsed
    signature groups: `sigers.try_for_each(|s| verify(verfer, msg, s))`.
  - Verification is **strict**: a signature whose CESR code does not belong to the
    key's algorithm is a typed error, not a silent failure. The `Siger` index is
    CESR framing metadata and is not part of the signed payload.
  - Also adds `Algorithm::owns_indexed` and `Algorithm::NAME`.
  ([#69](https://github.com/devrandom-labs/cesr/issues/69))

### Breaking

- **crypto (#69):** verification now returns `Result<(), _>` instead of
  `Result<bool, _>`. `Ok(())` means verified; a cryptographically invalid
  signature is the new `SignatureError::Invalid`, moved out of the success channel
  so `verify(..).is_ok()` can no longer mistake a forgery for a valid signature.
  Affects `KeyPair::verify` and the free `crypto::verify`. Callers change
  `if kp.verify(..)?` to `kp.verify(..)?;` (propagate) or match on the error.
- **crypto (#69):** new `SignatureError::Invalid` and
  `SignatureError::CodeMismatch { expected, actual }` variants; `SignatureError`
  is not `#[non_exhaustive]`, so exhaustive downstream `match`es must add arms.
  The `Algorithm` trait gains required items (`NAME`, `verify_bytes`) — but it is
  **sealed**, so no external impls are affected.

## [0.3.0](https://github.com/devrandom-labs/cesr/compare/v0.2.0...v0.3.0) - 2026-07-03

### Added

- *(#68)* [**breaking**] self-addressing builder prefixes (write/read parity) (#71)
- *(#31)* prelude + flattened re-exports (#66)

### Other

- *(#32)* runnable examples for the primitive→event walk-through (#70)
- *(#64)* reproducible concurrent-parse allocation-payoff harness (#65)
- *(#30)* zero-copy stream parsing + test/coverage/mutation safeguards (#63)
- *(#57)* kill the utils dumping grounds + cohesive b64 (naming + error de-collision) (#62)
- *(#29)* add isolated base64-crate baseline; no faster codec found (#61)
- *(#57)* include stream in the no_std flake build
- *(#57)* [**breaking**] split b64 module into int/binary/charset
- *(#57)* [**breaking**] rename utils module -> b64, kill utils::utils inception
- *(#56)* [**breaking**] make encode_int infallible, fold stream::int_to_b64 into it
- *(#56)* consolidate base64 alphabet to one canonical table

### Added

- **api (#68):** `SerializedEvent::identifier() -> Option<Identifier<'static>>`
  bridge for chaining KEL events — hands an inception's self-addressing prefix to
  the next builder without re-parsing JSON.
  ([#68](https://github.com/devrandom-labs/cesr/issues/68))
- **api (#68):** `Clone` for `Matter` (all primitive aliases) and `Identifier`.
  ([#68](https://github.com/devrandom-labs/cesr/issues/68))
- **docs (#68):** examples `kel_chain` (a real `icp -> ixn -> rot` self-addressing
  chain) and `delegated_inception` (a self-addressing delegator), closing #32
  examples #5/#6.
  ([#68](https://github.com/devrandom-labs/cesr/issues/68))
- **devx (#31):** ergonomic public surface — flagship types are now reachable at
  the crate root (`cesr::Matter`, `cesr::Verfer`, `cesr::CesrGroup`, …) and at
  their module root (`cesr::core::Matter`), and a new `cesr::prelude` re-exports
  the common traits (`CesrEncode`, `KeriSerialize`/`KeriDeserialize`, `Algorithm`,
  `ConfigTrait`) plus headliner types for `use cesr::prelude::*;`. Purely
  additive — existing module paths are unchanged. The one name collision,
  `CesrVersion`, is disambiguated at the root as `cesr::CesrVersion` (core) and
  `cesr::StreamCesrVersion` (stream). Free functions remain module-qualified
  (`cesr::b64::encode_int`).
- **bench (#29):** `benches/base64.rs` — isolated `base64`-crate `URL_SAFE_NO_PAD`
  microbenchmarks at 32/64/1024 B, the reference baseline for the Base64 inner
  loop. Investigation outcome: a specialized scalar codec and stack-buffer
  allocation removal were both implemented and measured end-to-end, and both
  **regressed** (decode +8–16 %, encode +6 %). At CESR sizes the encode/decode
  seams are already overhead-bound on the fast `base64` engine plus thread-cached
  small allocations — no faster codec is available, so no production change ships.
  See #29 for the full measurement table.
- **test/ci (#30):** zero-copy safeguards — `tests/allocation.rs` (thread-local
  counting allocator) asserting group-iteration allocations stay **invariant to
  group count**, so a regression to per-group copying fails the suite; per-shape
  aliasing tests proving parsers slice rather than copy; full `GroupsV2` iterator
  coverage; a `stream_parse_scaling` benchmark (N = 1..256 groups); `cargo-mutants`
  in the dev shell for on-demand mutation testing (core stream logic: 100% of
  non-equivalent mutants killed); and on-demand `llvm-cov` coverage via
  `nix build .#coverage` plus a post-merge workflow (mirrors the `bombay` repo).
  None of these are gating checks. `QuadletGroup::to_bytes()` — O(1) shared-buffer
  accessor.
- **bench (#64):** `examples/concurrent_parse.rs` — a reproducible concurrent-parse
  allocation-payoff harness (run: `cargo run --release --example concurrent_parse
  --features stream`) answering the #30 follow-up "does the allocation reduction
  actually pay off?". It pits two real, public production arms parsing the same
  16-group stream: copy-once `groups()` (**2 allocs/stream**) vs a `parse_group()`
  loop that faithfully reproduces the pre-#30 per-group copy (**32 allocs/stream**,
  plus O(N²) remainder re-copying — exactly `origin/main`'s behavior). A
  single-threaded *armed* counting allocator self-checks the 1-vs-N invariant before
  any timing; the timed passes run *disarmed* across 1/2/4/8 threads so instrumentation
  never perturbs wall-clock. **Verdict: VINDICATED.** On a 14-core Apple M-series
  (release): copy-once/per-group throughput ratio **2.52× / 1.88× / 3.25× / 3.88×** at
  1/2/4/8 threads — copy-once wins at every thread count and the gap **widens under
  contention** (per-group scales only ~4.2× across an 8× thread increase — the
  allocator-contention signature). This does **not** contradict #30's single-thread
  regression note below: that used a 2-group fixture where O(N²)≈O(N) so the copy
  savings vanish; the win here needs both a larger group count and the faithful
  O(N²) `origin/main` baseline. Numbers are wall-clock and machine-dependent — the
  harness is a run-and-read measurement, not a CI gate.

### Changed

- **api (#68)!:** `RotationBuilder::prefix`, `InteractionBuilder::prefix`,
  `DelegatedInceptionBuilder::delegator`, and `DelegatedRotationBuilder::prefix`
  now take `impl Into<Identifier<'static>>` instead of `Prefixer<'static>`.
  Existing `Prefixer` call sites keep compiling; self-addressing (transferable)
  prefixes and delegators are now expressible, closing the write-path/read-path
  parity gap for both the direct (`icp -> ixn -> rot`) and delegated
  (`dip -> drt`) KEL chains.
  ([#68](https://github.com/devrandom-labs/cesr/issues/68))
- **perf (#30):** stream group parsing now slices a shared `bytes::Bytes` instead
  of `Bytes::copy_from_slice`, trading a small amount of per-parse CPU (Arc
  refcounting + a level of indirection) for **fewer heap allocations** — the
  intended benefit for allocator-pressure / fragmentation / no_std. Allocation
  count per multi-group message drops from ~N to **1** (0 on the async codec's
  non-quadlet decode path, which is now zero-copy on success). `unwrap_generic_group`
  and `Groups`/`GroupsV2` slice a once-copied region instead of re-copying. Public
  `parse_group` / `parse_group_v2` / `parse_message` / `groups` / `groups_v2`
  signatures are **unchanged — non-breaking**. **This is not a throughput win.**
  Measured cost (accepted, since fewer allocations is the goal): parsing is
  **~22–28 % slower on small streams** — CodSpeed on this PR:
  `controller_idx_sigs_1sig` −27.7 %, `multi_group_controller_witness` −21.7 %; the
  fixed overhead amortizes toward parity as stream size grows (per-group cost is
  ~equal to `main` at N≥16 groups). Borrowed `Matter<'a>` and a parser-combinator
  crate were evaluated and deliberately **not** adopted (see the issue).
  ([#30](https://github.com/devrandom-labs/cesr/issues/30))

### Changed

- **refactor (#57)!:** Killed the remaining "utils" dumping grounds. `stream::util`
  is removed (its `int_to_b64`/`b64_to_int` now route through `b64::encode_int` /
  `b64::decode_int`); `core::utils`'s code-size lookups moved to
  `core::matter::code::hard`; `stream::binary` is renamed `stream::qb2` (public
  `stream::qb64_to_qb2`/`qb2_to_qb64` paths unchanged). The single Base64 byte
  lookup is `b64::alphabet::b64_byte_to_index`.

### Breaking

- `RotationBuilder::prefix` / `InteractionBuilder::prefix` /
  `DelegatedInceptionBuilder::delegator` / `DelegatedRotationBuilder::prefix` now
  take `impl Into<Identifier<'static>>` instead of `Prefixer<'static>` (#68).
- `b64::decode_to_int` → `b64::decode_int` (input bound widened to `AsRef<[u8]>`).
- `core::indexer::error::{ParseError, ValidationError}` →
  `{IndexerParseError, IndexerValidationError}`.
- `stream::util` module removed; `stream::binary` module renamed `stream::qb2`
  (re-exported functions keep their `stream::` paths).

## [0.2.0](https://github.com/devrandom-labs/cesr/compare/v0.1.3...v0.2.0) - 2026-07-02

### Other

- Merge remote-tracking branch 'origin/main' into perf/p1.1-allocation-audit
- add justfile for a fast, multi-threaded local dev loop
- *(stream)* [**breaking**] encode Matter qb64 in-place, ~51% faster
- *(deps)* realign digest to 0.10 to collapse duplicate crypto stack

### Changed

- *(stream)* **BREAKING:** `matter_to_qb64` now returns `Result<Vec<u8>, ParseError>` instead of `Vec<u8>`. It Base64-encodes directly into the output buffer via `encode_slice`, removing an intermediate `String` and a padding reallocation, and replaces a release-compiled-out `debug_assert` with a real length-invariant check. `SerderError` gains a `Qb64Encoding(ParseError)` variant. Encode throughput improves ~51% (Ed25519 qb64: 84.7 ns → 41.8 ns, now faster than decode). ([#28](https://github.com/devrandom-labs/cesr/issues/28))

### Other

- *(deps)* realign `digest` to 0.10 to collapse a duplicate crypto stack in the shipped tree (drops `digest 0.11`, `crypto-common 0.2`, `hybrid-array`)

## [0.1.3](https://github.com/devrandom-labs/cesr/compare/v0.1.2...v0.1.3) - 2026-07-01

### Added

- *(diff)* keripy corpus generator (scripts/keripy_diff_gen.py)

### Fixed

- allow empty raw for zero-rawsize Matter codes ([#48](https://github.com/devrandom-labs/cesr/pull/48))
- zero-fill Indexer ondex slot for CurrentOnly codes ([#47](https://github.com/devrandom-labs/cesr/pull/47))
- *(diff)* embed corpus via include_str! for hermetic nextest

### Other

- make CodSpeed perf-gate pass the nix gate ([#41](https://github.com/devrandom-labs/cesr/pull/41))
- add CodSpeed continuous benchmarking
- *(diff)* include tests/corpus in the crane source filter
- *(diff)* extract indexer decode/encode helpers under clippy line limit
- *(diff)* rustfmt the keripy differential harness
- exclude keripy diff corpus from the typos gate
- *(diff)* nightly keripy differential parity workflow
- *(diff)* make Matter zero-raw finding a failing bug-probe ([#48](https://github.com/devrandom-labs/cesr/pull/48))
- *(diff)* composed-stream differential replay vs keripy
- *(diff)* Indexer differential replay vs keripy
- *(diff)* Counter v1+v2 differential replay vs keripy
- *(diff)* Matter differential replay vs keripy
- *(diff)* checked-in keripy corpus @v2.0.0.dev5 (653 vectors)
- *(diff)* scaffold keripy differential harness (loader + DiffVector)
- resolve P0.3 codec-entry-point open items + implementation plan
- design spec for P0.3 differential testing vs keripy

## [0.1.2](https://github.com/devrandom-labs/cesr/compare/v0.1.1...v0.1.2) - 2026-07-01

### Fixed

- *(matter)* reject malformed qb2 instead of panicking in from_qualified_base2 ([#43](https://github.com/devrandom-labs/cesr/pull/43))

### Other

- exclude release-plz CHANGELOG.md from the typos gate
- fix typo (driveable -> drivable) in fuzzing plan ([#26](https://github.com/devrandom-labs/cesr/pull/26))
- document the fuzzing harness ([#26](https://github.com/devrandom-labs/cesr/pull/26))
- add scheduled nightly deep-fuzz workflow ([#26](https://github.com/devrandom-labs/cesr/pull/26))
- add cesr-fuzz-replay corpus-replay check to the flake gate ([#26](https://github.com/devrandom-labs/cesr/pull/26))
- implementation plan for P0.2 fuzzing harness ([#26](https://github.com/devrandom-labs/cesr/pull/26))
- design spec for P0.2 fuzzing harness ([#26](https://github.com/devrandom-labs/cesr/pull/26))
- drop README-must-be-staged pre-commit enforcement
- Merge branch 'main' into perf/p0.1-benchmark-harness
- Merge branch 'main' into docs/strategy
- add foundation-first development strategy
- lift the API freeze — cesr is now in active development

## [0.1.1](https://github.com/devrandom-labs/cesr/compare/v0.1.0...v0.1.1) - 2026-06-30

### Other

- *(release)* add manual workflow_dispatch to the release workflow
- *(deps)* tune Dependabot for a frozen-API crate
- fix typos gate on merged main and list hygiene gates in README
- Merge pull request #12 from devrandom-labs/chore/repo-security
- port nexus guidelines to CLAUDE.md and gate releases on src changes

## [0.1.0](https://github.com/devrandom-labs/cesr/releases/tag/v0.1.0) - 2026-06-29

### Added

- publish to crates.io as cesr-rs (lib stays cesr) via release-plz
- cesr builds on wasm32 (getrandom js for crypto) ([#5](https://github.com/devrandom-labs/cesr/pull/5))

### Fixed

- base64 DecodeError works no_std (manual From, preserves API) ([#5](https://github.com/devrandom-labs/cesr/pull/5))

### Other

- use GitHub App token for release-plz (most-secure; keeps org locked down)
- remove references to private repos (agency, bombay) from public crate
- add release-plz for automated versioning + GitHub releases
- rustfmt import order in frozen_surface test
- import bombay git hooks + CI flake-check workflow ([#1](https://github.com/devrandom-labs/cesr/pull/1))
- freeze whole cesr surface + module/feature guide + versioning (#4, #6)
- assert frozen public API reachable as cesr::<module>::* ([#4](https://github.com/devrandom-labs/cesr/pull/4))
- pass god-level clippy (allow frozen-surface module_inception) + fmt ([#1](https://github.com/devrandom-labs/cesr/pull/1))
- no_std-ify modules (std -> core/alloc; gate std-only behind std feature) ([#5](https://github.com/devrandom-labs/cesr/pull/5))
- rewrite cross-module imports cesr_*::/keri_*:: -> crate::* ([#3](https://github.com/devrandom-labs/cesr/pull/3))
- wire cfg-gated modules + no_std preamble in lib.rs ([#3](https://github.com/devrandom-labs/cesr/pull/3))
- Nix flake harness (nexus-modeled, stable pin) + god-level clippy/deny/taplo ([#1](https://github.com/devrandom-labs/cesr/pull/1))
- copy CESR/KERI sources from agency into module dirs ([#2](https://github.com/devrandom-labs/cesr/pull/2))
- single-crate Cargo.toml with feature-gated modules (#1, #3)
- licenses, NOTICE, and pinned stable toolchain
- Initial commit
