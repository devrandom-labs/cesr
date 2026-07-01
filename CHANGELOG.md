# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- *(stream)* **BREAKING:** `matter_to_qb64` now returns `Result<Vec<u8>, ParseError>` instead of `Vec<u8>`. It Base64-encodes directly into the output buffer via `encode_slice`, removing an intermediate `String` and a padding reallocation, and replaces a release-compiled-out `debug_assert` with a real length-invariant check. `SerderError` gains a `Qb64Encoding(ParseError)` variant. Encode throughput improves ~51% (Ed25519 qb64: 84.7 ns → 41.8 ns, now faster than decode). ([#28](https://github.com/devrandom-labs/cesr/issues/28))

### Other

- *(deps)* realign `digest` to 0.10 to collapse a duplicate crypto stack in the shipped tree (drops `digest 0.11`, `crypto-common 0.2`, `hybrid-array`)

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
