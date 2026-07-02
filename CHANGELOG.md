# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

- **perf (#30):** stream group parsing is now zero-copy where possible. Group
  parsers slice a shared `bytes::Bytes` instead of `Bytes::copy_from_slice`; the
  async codec's non-quadlet decode path is zero-copy on the success path;
  `unwrap_generic_group` slices through nested groups; and `Groups`/`GroupsV2`
  copy the attachment region **once**, then yield O(1) slices. Allocation count
  per multi-group message drops from ~N to 1 (0 on the codec path), and
  large-stream parsing is O(N) rather than O(N²). Public `parse_group` /
  `parse_group_v2` / `parse_message` / `groups` / `groups_v2` signatures are
  **unchanged — non-breaking**. **Tradeoff (measured, accepted):** the sync
  `groups()` / `parse_group(&[u8])` convenience path is ~38 % slower on *small*
  streams (≈29 ns on a 2-group parse — dwarfed ~1700× by the downstream
  ~50 µs/signature verification) in exchange for the allocation reduction, O(N)
  scaling, and a zero-copy codec. Borrowed `Matter<'a>` / a parser-combinator
  crate were evaluated and deliberately **not** adopted (see the issue).
  ([#30](https://github.com/devrandom-labs/cesr/issues/30))

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
