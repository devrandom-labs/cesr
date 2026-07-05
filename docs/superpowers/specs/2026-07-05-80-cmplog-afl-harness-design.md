# P0.2c · Real CMPLOG leg via afl.rs (AFL++) — second harness

**Issue:** [#80](https://github.com/devrandom-labs/cesr/issues/80)
**Date:** 2026-07-05
**Status:** Design approved
**Builds on:** #45 (P0.2b — libFuzzer value-profile + corpus persistence, delivered in PR #81) and #26 (P0.2 — bolero harness, PR #44)

## Problem

CESR parsing is dominated by exact-byte comparisons — code-table lookups, magic
prefixes, version strings. Two comparison-coverage techniques get a fuzzer past
those gates, and they are **mechanistically complementary**:

- **libFuzzer value-profile** (Hamming-distance gradient) — excels at CESR's
  *transformed* gates (Base64-decoded `ss`/`fs`/`ls` size fields, where no
  verbatim operand exists to substitute). Delivered by #45.
- **AFL++ CMPLOG / RedQueen** (input-to-state substitution) — excels at CESR's
  *verbatim* gates (selector/derivation codes copied straight from input into a
  `src/core/matter/sizage.rs` table lookup). This card.

#45's research pass proved CMPLOG is **unreachable through bolero** — `cargo bolero
test --engine afl` runs a vendored classic **AFL 2.57b** with zero CMPLOG. Genuine
CMPLOG therefore needs a **second harness** built on `rust-fuzz/afl.rs`
(`cargo-afl`), which wraps current AFL++.

## Research findings (sourced)

Posted verbatim to [#80](https://github.com/devrandom-labs/cesr/issues/80#issuecomment-4886512467).
Load-bearing conclusions:

1. **afl.rs runs on stable Rust.** `afl` + `cargo-afl` are both `0.18.2`
   (2026-05-11). Setup needs only a C compiler + `make`
   ([setup](https://rust-fuzz.github.io/book/afl/setup.html)); it instruments via
   AFL++'s `afl-clang-fast` LLVM pass, **not** unstable rustc `-Z` flags. The
   "requires nightly" claim in search results is from `afl 0.1.0` (2016) and is
   stale. → The CMPLOG leg runs on our pinned stable `1.95.0`, with **no**
   pinned-nightly quarantine (unlike the libFuzzer leg).
2. **CMPLOG is default-on in modern afl.rs** (README: *"By default, the AFL++
   CMPLOG feature is activated"*). The raw AFL++ two-binary dance
   (`AFL_LLVM_CMPLOG=1` build + `-c program.cmplog`) is automated by `cargo-afl`.
   → "CMPLOG confirmed engaged" reduces to *confirming* (grep the startup banner),
   not hand-wiring.
3. **Entrypoint is a `[[bin]]`**, not a `#[test]`: `fn main() { afl::fuzz!(|data:
   &[u8]| { … }) }`, built via `cargo afl build`, run via `cargo afl fuzz`.
4. **macOS is CI-only** for real CMPLOG: AFL++ on Apple Silicon "only supports
   non-instrumented fuzzing". Validation runs on Linux x86_64 CI.
5. Non-obvious risk: `afl`'s `build.rs` compiles AFL++ (C). If `afl` lands in the
   crate that holds the bolero tests, the stable `cargo test` replay (the
   `cesr-fuzz-replay` gate in `nix flake check`) would need a C toolchain to build
   AFL++ — breaking the "replay needs no nightly, minimal deps" contract. **The
   design keeps `afl` out of the replay path.**

## Architecture — three crates, one shared source of truth

Today each target's logic is duplicated inside a bolero `check!()` closure.
Extracting the bodies into a shared lib gives a single source of truth for "what
each target exercises"; both engines then wire an entrypoint around the same
function.

```
fuzz-common/     NEW  lib crate. 12 byte-in bodies: pub fn <target>(data: &[u8]).
                      (matter_roundtrip is excluded — see Target set below.)
                      Deps: cesr (features = ["stream"]) only. No engine deps
                      → safe to sit in the stable replay dependency graph.

fuzz/            EDIT existing bolero crate. Each test becomes thin:
                      check!().for_each(|d| fuzz_common::matter_from_qb64(d))
                      `bolero` stays a dev-dependency; target names UNCHANGED
                      (CI matrix + corpus artifact keys depend on them).

fuzz-afl/        NEW  isolated workspace (empty [workspace] table — same trick as
                      fuzz/). One [[bin]] per target:
                      fn main() { afl::fuzz!(|d: &[u8]| fuzz_common::…(d)) }
                      Deps: afl + fuzz-common (path). `afl` is physically absent
                      from the bolero replay graph.
```

`fuzz-common` is a path-dependency of both `fuzz/` and `fuzz-afl/`. Cargo
path-deps cross workspace boundaries without requiring shared membership, so the
two isolated workspaces both consume it while staying independent roots.

### Why this satisfies the isolation contract

- `nix flake check`'s `cesr-fuzz-replay` runs `cd fuzz && cargo test` on stable.
  Its graph is `fuzz → fuzz-common → cesr` plus the `bolero` dev-dep. `afl` never
  appears. No C toolchain needed for replay.
- `fuzz-common` introduces **no external dependency** beyond `cesr` (already in
  the replay graph), so `cargo audit` / `cargo deny` / the wasm + no_std builds
  are untouched.
- `fuzz-afl/` is exercised **only** by the scheduled CI job — never by
  `nix flake check`, exactly as the nightly bolero deep-fuzz job already is.

## Target set

| Target (name shared by both engines) | afl bin? | Rationale |
|---|---|---|
| `matter_from_qb64`, `matter_from_qb2` | yes | byte-in decode panic-hunters |
| `indexer_from_qb64`, `indexer_from_qb2` | yes | byte-in decode panic-hunters |
| `stream_parse_group`, `_group_v2`, `groups`, `groups_v2` | yes | byte-in parse |
| `stream_parse_message`, `parse_version_string`, `_v2` | yes | byte-in parse |
| `qb64_qb2_roundtrip` | yes | takes `&[u8]`; round-trip asserts are crashes |
| `matter_roundtrip` | **no** | needs structured `[u8; 32]` generation that does not fit afl's raw byte-stream model; CMPLOG adds little to an encode→decode stability check |

The 12 afl bins carry **identical names** to their bolero counterparts so both
engines read from and write to the **same** `corpus-<target>` artifact introduced
by #45 — value-profile discoveries seed CMPLOG and vice-versa (the card's explicit
cross-pollination goal).

`matter_roundtrip` stays bolero-only. Its body therefore keeps bolero's
`with_type::<[u8; 32]>()` generator and is **not** extracted to `fuzz-common`
(fuzz-common only holds the byte-in `&[u8]` bodies). This keeps `fuzz-common`'s
signature uniform (`fn(&[u8])`) with no awkward byte-slice adaptation.

## CI leg — new `deep-fuzz-afl` job in `.github/workflows/fuzz.yml`

Scheduled parallel to the existing `deep-fuzz` job. **Stable toolchain, Linux
x86_64.** Matrix over the 12 shared target names. Per target:

1. **Install** `cargo install cargo-afl --locked` (built with repo-root stable).
2. **System config** `cargo afl system-config` with CI escape hatches exported
   (`AFL_SKIP_CPUFREQ=1`, `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`) so the
   locked-down GitHub runner does not abort the run.
3. **Restore corpus** from the shared `corpus-<target>` artifact (same
   resolve-run-id-then-`gh run download` pattern the libFuzzer job uses).
4. **Build** `cargo afl build --bin <target>` (in `fuzz-afl/`).
5. **Fuzz** `cargo afl fuzz -V <duration> -i <seed_dir> -o out target/debug/<target>`.
   CMPLOG is default-on; a step greps the afl-fuzz startup banner to **confirm**
   it is engaged (acceptance criterion).
6. **Fold + minimize** merge `out/default/queue/` into the shared corpus, minimize
   with native **`afl-cmin`** (bolero `reduce` cannot drive AFL), re-upload to
   `corpus-<target>` so the next night compounds across both engines.
7. **Crashes** upload `out/default/crashes/` as `crashes-afl-<target>` on failure.

Nightly-pin machinery is **not** needed here (afl.rs is stable) — a genuine
simplification over the libFuzzer leg.

## Testing & verification

- **Round-trip / replay:** the refactored bolero tests call the same
  `fuzz_common` functions; existing corpus and crash files replay unchanged under
  `cd fuzz && cargo test`. This is the regression guard that the extraction
  preserved behavior.
- **`fuzz-common` unit smoke:** a trivial test that each `pub fn` returns on empty
  input without panic (mirrors the existing `smoke` target intent) — proves the
  shared functions are wired to the real `cesr` decoders, not stubs.
- **afl harness build:** CI `cargo afl build` compiling all 12 bins is the proof
  the second harness is real; the banner-grep step proves CMPLOG is on.
- **Stable gate:** `nix flake check` must stay green with no new external deps and
  no nightly leak. Verified as the final step before the PR.

## Acceptance criteria → design mapping

- [x] afl.rs targets mirroring the bolero parse targets → the 12 `fuzz-afl/` bins.
- [x] CMPLOG confirmed engaged → default-on in afl.rs + banner-grep confirmation.
- [x] Nightly CI matrix leg per target, crash + corpus artifacts per engine →
  `deep-fuzz-afl` job (stable, not nightly — improves on the criterion).
- [x] AFL corpus minimized via `afl-cmin`, folded into the shared per-target
  artifact → fold + minimize step.
- [x] `nix flake check` stays green → isolation contract above.

## Out of scope (per card)

- Value-profile / corpus-persistence plumbing (#45, delivered).
- OSS-Fuzz onboarding (separate future card).
- Committing minimized corpus back to the repo (artifact-only).

## Risks & open items for implementation

- **`cargo afl system-config` on GitHub runners.** Historically needs root and
  touches `/proc/sys/kernel/core_pattern`. Mitigation: the `AFL_SKIP_CPUFREQ` /
  `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` escape hatches; if `system-config`
  itself fails under the runner sandbox, fall back to exporting those env vars and
  skipping it. Resolve during CI bring-up.
- **Toolchain confirmation.** afl.rs-on-stable is well-evidenced but the final
  100% proof is the CI `cargo afl build` succeeding on stable `1.95.0`. If it
  demands a newer stable, bump `rust-toolchain.toml` + `Cargo.toml` `rust-version`
  in lockstep (per CLAUDE.md) — called out in the PR if so.
- **Runner time budget.** 12 targets × per-target fuzz duration; keep the default
  short (e.g. 120s, matching the libFuzzer job's default) and matrix-parallel.
