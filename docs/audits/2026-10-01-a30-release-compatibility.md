# A30 published API compatibility check

Status: comparison recorded on CESR PR #300 at `957d8bfb`; a coordinated
version graph is staged in draft PR #302, while publication and consumer
adoption remain open. This compares the current tree with the latest published versions available to
`cargo-semver-checks`. It does not test a published replacement release.

Platform: aarch64-darwin, Rust 1.95.0, cargo-semver-checks 0.48.0. Commands:

```sh
cargo semver-checks check-release --workspace --default-features
cargo semver-checks check-release --workspace --all-features
cargo semver-checks check-release -p keri-rs --all-features --release-type minor
```

All three commands exited 1 because they detected breaking changes. The
figures count failing lint *categories*, not individual affected API items.
All-feature findings include those found with default features.

| Published crate | Default / all-feature failing categories | Representative break | Version review before publication |
| --- | ---: | --- | --- |
| `cesr-rs` 0.11.1 | 0 / 1 | All-feature `VerificationError` gained `UnsupportedAlgorithm` on an exhaustive public enum. | Review a 0.12.0 minor bump under the repository's 0.x policy. |
| `cesr-stream` 0.6.0 | 3 / 4 | `CesrMessage` and its public module were removed; `CesrCodec::new` gained a limit argument; `ParseError` gained variants. | Review 0.7.0. |
| `keri-codec` 0.9.0 | 5 / 5 | Public parse methods and `Deserialize::deserialize` gained explicit limits; public error/message variants changed. | Review 0.10.0. |
| `keri-events` 0.5.0 | 4 / 4 | The `internals` feature and several constructors/getters were removed; `MessageType` changed. | Review 0.6.0. |
| `keri-rs` 0.0.15 | 0 checks / 0 checks in automatic runs; **8** failing categories with explicit minor-release check | `Signed` lost public construction/fields; `EvidenceKind` gained variants; a public method and enum variant were removed. | Decide explicitly whether to advance to 0.1.0 under the repository's minor-for-breaking policy. Do not read the automatic zero as compatibility. |

The automatic workspace runs performed **zero** checks for `keri-rs` and
skipped 253 because a no-version-change comparison of a `0.0.x` crate is
treated as an assumed major change. The explicit `--release-type minor`
comparison ran 196 checks and found eight failing categories. These are
static public-surface checks, not a complete consumer compatibility test.

## Internal publish edges to review

The current production dependency requirements in the five crate manifests
still name the published pre-foundation series. If the proposed versions in
the table above are selected, the release PR must update these requirements
as well as each package's own version:

| Publishing crate | Required CESR crate series, current → proposed |
| --- | --- |
| `cesr-rs` | No production CESR crate dependency. |
| `cesr-stream` | `cesr-rs` 0.11 → 0.12. |
| `keri-events` | `cesr-rs` 0.11 → 0.12. |
| `keri-codec` | `cesr-rs` 0.11 → 0.12; `cesr-stream` 0.6 → 0.7; `keri-events` 0.5 → 0.6. |
| `keri-rs` | `cesr-rs` 0.11 → 0.12; `keri-events` 0.5 → 0.6; optional `wire` edge `keri-codec` 0.9 → 0.10. |

`cargo package -p keri-rs --allow-dirty --no-verify` succeeded for the
**current** 0.0.15 source and its normalized archive manifest still names
`cesr-rs` 0.11, `keri-events` 0.5 and optional `keri-codec` 0.9. Packaging
without verification neither proves the corrected dependency graph nor
authorizes publication. The versioned release PR must be checked against
each edge above before package verification in dependency order.

## Isolated proposed-version trial

In a disposable worktree at CESR head `663bf9da`, the five manifests were
temporarily set to the proposed `0.12.0`, `0.7.0`, `0.6.0`, `0.10.0` and
`0.1.0` versions above, with every versioned internal dependency edge
updated to match. `cargo update --workspace` changed only the five local
package entries in that trial's lockfile. `cargo metadata --no-deps`
reported the intended five versions, and `cargo check --workspace
--all-features --locked` exited 0. This establishes local graph resolution
and compilation, not published-crate compatibility or test behavior.

`cargo package -p cesr-rs --allow-dirty` prepared and **verified** the
proposed 0.12.0 package (72 files; 329.0 KiB compressed). The next
`cargo package -p cesr-stream --allow-dirty --no-verify` stopped before
archive creation because crates.io has no `cesr-rs` satisfying `^0.12`.
This expected failure proves that ordinary Cargo package preparation for
dependent crates must wait for their proposed dependency versions to be
published and indexed. The remaining four proposed packages were not
packaged or published in this trial. The version changes are staged in the
disposable worktree and draft PR #302; PR #300 retains the current manifest
versions.

## Packaged-source test boundary

`cargo package --list --locked` enumerated all five proposed crates and their
changelogs, source and declared example/test files. An extracted **current**
`keri-rs` 0.0.15 archive exposed a package-only defect: two unit tests used
`include_str!` paths into the sibling `keri-codec` checkout, and the
`direct_mode` example used `cesr-stream` from a path-only development
dependency that Cargo omitted from the normalized package manifest. With
local `[patch.crates-io]` entries for the current unpublished CESR code,
`cargo test --all-features --no-run` on that isolated archive failed on the
two missing files and missing `cesr_stream` import. The patch supplied local
dependency code, not the missing sibling fixture directory.

The two selected JSONL rows are now copied byte-for-byte into
`crates/keri/tests/fixtures/` and embedded from within the crate. The
`cesr-stream` development edge now has a version requirement (`0.6` on
PR #300, `0.7` on the proposed release branch), so Cargo retains it in the
normalized manifest. A new isolated `keri-rs` 0.0.15 archive contains both
rows (23 files total); with the same local dependency patches, its
`cargo test --all-features` passed **77/77 unit tests** and **3/3 active
doctests**, with one doctest ignored. This verifies that one packaged crate's
tests/examples are self-contained under the patched current graph. It does
not verify the proposed 0.1.0 package against unpublished registry versions.

A follow-up isolated-archive check found the same reverse-layer development
dependency problem in `cesr-rs`: its unit test imported `keri-events`, which
Cargo omitted from the normalized archive. The signature/threshold
composition test now lives in `keri-events`, with a versioned lower-layer
`cesr-rs` dev dependency. The extracted current `cesr-rs` 0.11.1 archive
passes **1,356 unit tests** plus its integration tests and doctests; the
extracted current `keri-events` 0.5.0 archive passes **104 unit tests**, its
two integration tests and two doctests. Both used local dependency patches.
This source move changed no public API or wire behavior.
The current CESR branch's full local Nix gate then passed with **2,590/2,590
Nextest cases**, 24 skipped, plus the supported no_std/WASM profiles and
fuzz replay. Full offline `cargo metadata --locked` resolved all four Cargo
workspaces. Refreshing the `fuzz-common` and `fuzz-afl` locks added missing
transitive packages without removing an existing external package version.

Proposed-version archive tests before that follow-up passed for
`cesr-stream` 0.7.0 (377 unit tests, four integration tests, one doctest),
`keri-events` 0.6.0 (104 unit tests, one integration test, two doctests),
and `keri-rs` 0.1.0 (77 unit tests, three active doctests). The extracted
`cesr-rs` 0.12.0 archive then failed on the test described above; it needs a
fresh run after the source move. The extracted `keri-codec` 0.10.0 archive's
all-feature integration-test build still fails: those repository tests import
`keri-rs` from a path-only dev dependency, which Cargo omits from its
normalized manifest. Adding the proposed `keri-rs` version as a dev
dependency would create a publication-order cycle because `keri-rs` itself
depends on `keri-codec`; the codec library does compile from its archive.
This archive-test limitation prompted a package-boundary change.

The current `keri-codec` 0.9.0 manifest now excludes its 26 cross-layer
integration-test files and shared helper module from the source archive while
leaving all 33 integration targets discoverable in the repository workspace.
The archive keeps seven codec-local integration files and their pinned corpora.
Its `cesr-stream` development edge now carries a `0.6` version requirement,
so Cargo retains the `async` feature needed by `frozen_surface`. The extracted
current archive passes **391 unit tests**, **33 active integration tests**
(one ignored) and **two active doctests** (five ignored) against locally
patched current CESR dependencies. This tests the shipped source while the
full workspace gate continues to exercise the cross-layer transcripts. The
full local Nix gate after this manifest change passed **2,590/2,590 Nextest
cases**, 24 skipped, fuzz replay and the supported no_std/WASM profiles.
The proposed 0.10.0 archive remains to be verified.

## Coordinated version draft

[Draft PR #302](https://github.com/devrandom-labs/cesr/pull/302), stacked on
PR #300, contains the five proposed package versions and every versioned
internal dependency requirement from the table above. Its signed commit is
`0493a728`. A fresh `nix flake check -L --option max-jobs 1` on
aarch64-darwin passed: release Nextest executed 2,590/2,590 passing tests
with 24 skipped, and the no_std and WASM checks compiled. Clippy, docs,
doctests, fuzz replay, deny, formatting and the other local flake checks
passed. The signed push repeated the gate using the same checked inputs.
Linux and other incompatible systems were omitted by this local run. This
stages the source graph for review; it neither publishes the packages nor
verifies a consumer against their eventual crates.io archives.

The initial draft updated only the root Cargo lock. The three fuzz crates
each declare an independent Cargo workspace with a separate lock: the stable
Bolero replay (`fuzz/`), the AFL++ campaign (`fuzz-afl/`) and their shared
engine-free harness (`fuzz-common/`). This is dependency isolation; the
nightly libFuzzer compiler pin alone does not require separate locks.
[PR #302 follow-up `fa1355fc`](https://github.com/devrandom-labs/cesr/pull/302)
updated all three fuzz locks to the proposed local crate versions. The
`fuzz/` lock changed only four local version entries; the other two gained
previously missing transitive packages but changed no existing external
package version. `cargo metadata --locked --no-deps` passed for all three
fuzz manifests. A new `cesr-lock-sync` Nix check compares each lock against
the local manifests; it passed and rejected a planted stale version in a
temporary lock. Stable fuzz replay now uses `--locked`. The full local Nix
gate passed again with 2,590/2,590 release tests, 24 skipped, successful
locked fuzz replay and supported no_std/WASM compile checks.

The versioned branch's follow-up `54f6bcce` adds a Linux CI step that runs
full `cargo metadata --locked --format-version 1` for the root, `fuzz-common/`,
`fuzz/` and `fuzz-afl/` workspaces. Unlike `--no-deps`, this resolves the
complete dependency graph and fails if a committed lock needs updating.
The matching `--offline` commands passed locally with 240, 175, 197 and 180
resolved packages respectively. `actionlint` and the full local Nix gate
passed after this workflow change. The exact-head [Linux CI run
#36912116423](https://github.com/devrandom-labs/cesr/actions/runs/36912116423)
also passed the four-lock resolution step and full Nix gate: release Nextest
executed 2,590/2,590 passing tests with 24 skipped; locked fuzz replay ran,
and the supported no_std/WASM profiles compiled. The local gate did not
exercise other architectures or operating systems.

On that versioned branch, automatic `cargo semver-checks --all-features`
exited 0 but classified each 0.x minor bump as a breaking release and ran
**zero** API lints (253 skipped per crate). An explicit `--release-type minor`
audit ran 196 lints per crate and reported 1, 4, 4, 5 and 8 breaking
categories for `cesr-rs`, `cesr-stream`, `keri-events`, `keri-codec` and
`keri-rs` respectively. These are the intentional breaks covered by the
repository's 0.x minor-bump policy. The automatic exit 0 must not be read
as backward compatibility.

CodSpeed separately reported `b64_decode_hot` efficiency −11.78% at
`54f6bcce` on this versioned draft, whose `cesr-rs` source and benchmark
are unchanged; it warned of different runtime environments. The
[sequential same-host A/B/A trial](2026-10-01-a30-b64-version-trial.txt) at
base `44794419`, release `54f6bcce`, base `44794419` measured medians of
2.7785, 2.7610 and 2.7547 ns. This does not reproduce the hosted magnitude;
the failed performance analysis remains an open release-review finding.

The existing [release PR #294](https://github.com/devrandom-labs/cesr/pull/294)
predates PR #300 and changes only `keri-codec` 0.9.0 → 0.10.0 and
`keri-rs` 0.0.15 → 0.0.16. It neither covers all five published API breaks
nor follows the local `CLAUDE.md` rule that breaking `0.x` APIs bump the
minor component. Its `keri-rs` version requires an explicit decision before
the release PR is merged. The configured release workflow can be dispatched
to refresh the automated release PR after the CESR changes land; its
resulting version set and dependency requirements need review against this
table and draft PR #302 before any publish step. Neither release PR has been
merged or published.

There is a direct-publication hazard in treating PR #302 as a mere staging
merge. `.github/workflows/release-plz.yml` runs `release-plz/action@v0.5`
on a relevant push to `main` without a `command` input. The
[action defaults](https://release-plz.dev/docs/github/input) run both
`release-pr` and `release`; the latter [publishes every unpublished package
version](https://release-plz.dev/docs/usage/release). PR #302 already contains
five unpublished versions, so merging it to `main` could initiate crates.io
publication before a separately reviewed release PR. Keep it as a draft
version-graph trial. After PR #300 lands, reconcile the generated release PR
with the five planned versions, dependency edges and changelogs, then review
its merge as the publication action.

The release gate still requires the final reviewed CESR head, correct
version and changelog changes in dependency order, package/consumer builds
against the **published** crates, and the wrong-controller-key regression
running unignored in the ordinary Selo graph. Product adoption belongs to
the Selo owner after Bombay is complete.
