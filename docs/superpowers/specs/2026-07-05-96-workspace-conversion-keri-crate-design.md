# K0 · Workspace conversion — sibling `keri` crate + shared infra

**Issue:** [#96](https://github.com/devrandom-labs/cesr/issues/96) (milestone: KERI · sans-io core)
**Date:** 2026-07-05
**Status:** Design approved
**Blocks:** K1–K9 (#87–#95). **Related:** #86 (crate-tier stability), #97 (reserve-crate workflow), #82 (typed Rct).

## Problem & decision

The KERI sans-io core (K1–K9) needs a home. Per #96 it lives in a **sibling crate in
this repo**, not behind feature gates in `cesr` and not in a separate repo:

- **Features partition compile-time, crates partition semver, repos partition infra.**
  One crate = one version: unstable KERI-state churn would force major bumps of the
  frozen `cesr-rs` primitives, gutting the STABILITY.md (#86) promise. A sibling crate
  versions independently. A separate repo would duplicate the flake/clippy/fuzz/CodSpeed
  infra and split the keripy differential corpus.
- Standing benefit: `keri` consumes **only** `cesr`'s public API — a permanent live test
  that the frozen surface is sufficient.

K0 is **pure infrastructure**: reserve the name, convert to a workspace, stand up an
empty `keri` crate under the full quality harness. **No KERI logic** — that is K1+.

## Prerequisite already satisfied — name reservation

`keri-rs` is **already reserved and owned** (crates.io `keri-rs@0.0.1`, owner
`joeldsouzax`, published 2026-07-05T16:44 via the #97 `reserve-crate` workflow, run
28747787867). The `[lib] name` is `keri`, mirroring the `cesr-rs`/`cesr` convention.
The reservation checkbox of #96 is therefore **done**; this spec covers only the
workspace conversion.

## Current state (pre-conversion)

Single crate `cesr-rs` (`[lib] name = "cesr"`, v0.4.0) **is** the repo root: `src/`,
`tests/`, `benches/`, `examples/`, root `Cargo.toml` carrying `[features]`,
`[dependencies]`, `[lints.rust]`, `[lints.clippy]`. Repo-wide config at root:
`clippy.toml`, `rustfmt.toml`, `taplo.toml`, `_typos.toml`, `deny.toml`, `audit.toml`,
`rust-toolchain.toml`, `release-plz.toml`, `flake.nix`, `justfile`. Three isolated fuzz
crates (`fuzz/`, `fuzz-common/`, `fuzz-afl/`), each its own empty-`[workspace]` root,
path-dep `cesr = { path = ".." }`.

The flake is crane-based: `src = ./.` builds the root crate; checks `cesr-clippy`,
`cesr-doc`, `cesr-fmt`, `cesr-toml-fmt`, `cesr-audit`, `cesr-deny`, `cesr-nextest`,
`cesr-doctest`, `cesr-wasm`, `cesr-nostd`, `cesr-fuzz-replay` (own `./fuzz` src +
lockfile), `cesr-actionlint`, `cesr-typos`, plus nix/dead-code/shellcheck. `release-plz.toml`
has a `[workspace]` table + one `[[package]] name = "cesr-rs"`.

## Modeled on nexus (with two deliberate divergences)

nexus (`/Users/joel/Code/devrandom/nexus`) is the proven reference (same kernel+satellite
shape #96 cites). We adopt its workspace patterns and diverge in exactly two places:

| nexus pattern | Here |
|---|---|
| `[workspace.dependencies]` centralizes dep versions; members use `dep.workspace = true` | **Adopt** — shared deps (`thiserror`, `serde`, etc.) live at workspace root |
| `[workspace.package]` shares version/edition/rust-version/license/authors/repository | **Adopt** |
| `[workspace.lints.clippy]` / `[workspace.lints.rust]` hold the god-level law | **Adopt** (relocate cesr's existing tables verbatim) |
| `[workspace.metadata.crane] name = "…"` | **Adopt** (`name = "cesr"`) |
| whole-workspace `cargoClippy --workspace --all-features --all-targets`, workspace `cargoNextest` | **Adopt** |
| **`crates/<member>` subdirectory layout** | **Diverge — top-level `cesr/` + `keri/`** (decision: keep top-level) |
| **`workspace-hack` crate (cargo-hakari)** + `release-plz` `allow_dirty`/`publish=false` machinery | **Diverge — none.** CLAUDE.md: cesr has no workspace-hack. Both members publish; no `publish=false` members (cesr's examples are `[[example]]` targets, not member crates) |

## Target layout

```
<root>/
  Cargo.toml            # NEW: pure virtual [workspace] manifest; members = ["cesr","keri"];
                        #      [workspace.lints.*] (moved from the old root); [workspace.package] shared keys
  Cargo.lock            # workspace lock (cesr + keri + shared deps)
  cesr/                 # MOVED via git mv — unchanged surface, publishes cesr-rs
    Cargo.toml          #   package cesr-rs; [lints] workspace = true; [features]/[deps] as before
    src/ tests/ benches/ examples/
  keri/                 # NEW — publishes keri-rs, [lib] name = "keri"
    Cargo.toml          #   depends on cesr (path = "../cesr", version) PUBLIC API only; [lints] workspace = true
    src/lib.rs          #   doc + env-feature scaffolding, NO types
  clippy.toml rustfmt.toml taplo.toml _typos.toml deny.toml audit.toml
  rust-toolchain.toml release-plz.toml flake.nix justfile CHANGELOG.md LICENSE-*  # stay at root
  fuzz/ fuzz-common/ fuzz-afl/   # stay isolated (NOT members); path dep .. -> ../cesr
```

Workspace members are **exactly** `["cesr", "keri"]`. The fuzz crates stay out of the
workspace (empty `[workspace]` roots) so bolero/afl deps never enter the main workspace's
audit/deny/lock surface — the isolation contract from #26/#80 is preserved.

## Components

### 1. Root virtual manifest (nexus-shaped)
- `[workspace] members = ["cesr", "keri"] resolver = "2"`.
- `[workspace.package]` for keys both crates share (`edition`, `rust-version`, `license`,
  `authors`, `repository`) so they stay in lockstep; each crate sets `X.workspace = true`.
  `version` is NOT shared — the crates version independently (cesr-rs frozen-ish, keri-rs
  churning); each crate keeps its own `version`.
- `[workspace.dependencies]` — centralize the version specs of dependencies both crates use
  (`thiserror`, and any others `keri` will share). cesr's member manifest then references
  them as `dep.workspace = true` (optionally adding crate-local `features`). cesr-only deps
  may stay in `cesr/Cargo.toml` directly; centralize a dep when the second consumer arrives
  (YAGNI). This keeps one version of each shared dep across the workspace.
- `[workspace.lints.rust]` + `[workspace.lints.clippy]` — the `[lints.*]` tables lifted
  **verbatim** from the old root `Cargo.toml`. The lint law is unchanged, just relocated so
  both crates inherit it via `[lints] workspace = true` (CLAUDE.md forbids relaxing it —
  this move must be level-for-level identical; verified in Testing §5).
- `[workspace.metadata.crane] name = "cesr"` — crane workspace name (nexus pattern).

### 2. `cesr/` (moved)
- `git mv` the crate into `cesr/` to preserve blame/history.
- `cesr/Cargo.toml`: keep `name = "cesr-rs"`, `[lib] name = "cesr"`, all `[features]`,
  `[dependencies]`, `[target.'cfg(wasm32)']`, `[dev-dependencies]`, `[[bench]]`,
  `[[example]]`. Replace the local `[lints.*]` tables with `[lints] workspace = true`.
  Inherit shared `[workspace.package]` keys via `.workspace = true`.
- **No source changes** — the public surface is byte-for-byte identical. This is the
  invariant the whole card rests on.

### 3. `keri/` (new, empty)
- `keri/Cargo.toml`: `name = "keri-rs"`, `version = "0.0.1"` (matches the reserved
  placeholder; first real release bumps it), `[lib] name = "keri"`,
  `description`/`license`/`repository`/`edition`/`rust-version` (shared keys via
  `.workspace = true` where possible), `[lints] workspace = true`.
- Dependency: `cesr = { package = "cesr-rs", path = "../cesr", version = "0.4", default-features = false }`
  — **public API only**; must NOT enable `internals` or `test-utils`.
- Environment features mirroring cesr's contract: `std` (default), `alloc` — so `keri`
  can be built no_std/alloc and wasm like cesr. K0 wires the feature *shape*; K1 uses it.
- `keri/src/lib.rs`: crate-level doc, `#![no_std]` with `#[cfg(feature = "std")] extern crate std;`
  and `#[cfg(feature = "alloc")] extern crate alloc;` scaffolding, and **one** trivial
  item that references cesr's public API so the link is exercised (see Testing). No KERI
  types.

### 4. Shared config
- **Lints** → `[workspace.lints.*]` (above). `clippy.toml` stays at root (crane/clippy
  read it workspace-wide).
- `rustfmt.toml`, `taplo.toml`, `_typos.toml`, `deny.toml`, `audit.toml`,
  `rust-toolchain.toml` — stay at root, already workspace-scoped in effect.
- `release-plz.toml`: keep `[workspace]` release flags; add `[[package]] name = "keri-rs"`
  beside the existing `cesr-rs`. Independent per-package versioning is release-plz-native —
  `cesr-rs` may sit frozen while `keri-rs` releases. Confirm `changelog_update`/tagging is
  per-package so a `keri` release does not bump `cesr`.

### 5. Flake restructure
- crane `src` becomes the workspace root (still `./.`, now a virtual manifest); the source
  filter keeps the existing `tests/corpus/` infix carve-out (path now under `cesr/`).
- `cargoArtifacts = buildDepsOnly` over the workspace (both crates' deps).
- Existing `cesr-*` checks (clippy, doc, fmt, toml-fmt, audit, deny, nextest, doctest)
  run workspace-wide so they cover `keri` automatically. Match nexus's clippy invocation:
  `cargoClippyExtraArgs = "--workspace --all-features --all-targets -- --deny warnings"`
  (whole workspace, all targets — lib/tests/benches/examples). `cargoArtifacts =
  buildDepsOnly` over the whole workspace; crane reads `[workspace.metadata.crane] name`.
- **`cesr-wasm` and `cesr-nostd`**: extend to build `keri` too. Either add
  `-p keri` alongside `-p cesr` in the existing derivations, or add sibling `keri-wasm`/
  `keri-nostd` checks. Decision for the plan: prefer `--workspace`-style coverage where
  the target supports it; where a per-crate `cargo build --target ...` is needed, build
  both crates. **Both crates must stay WASM + no_std clean** — this is a standing gate,
  not a one-time check.
- `cesr-fuzz-replay`: unchanged except the fuzz crates' `cesr` path dep is now `../cesr`
  (that edit lives in the fuzz crates, not the flake); the `./fuzz` src filter and its own
  `Cargo.lock` vendoring are unchanged.
- Naming: keep `cesr-*` check names for the workspace-wide checks that still gate the whole
  tree; add `keri-*`-named checks only where a check is genuinely keri-specific (wasm/nostd
  if split). Avoid churn in check names the release/CI depends on.

### 6. The API-boundary gate (two layers)
- **Compiler (free):** `keri` depends on `cesr` as a path+version dependency, so Rust's
  per-crate visibility already forbids `keri` from referencing any non-`pub` `cesr` item —
  it will not compile. No custom tooling needed for the visibility half.
- **Feature back-door grep (CI):** the only way `keri` could reach cesr internals is by
  enabling cesr's internal-exposing features (`internals`, `test-utils`). Add a small CI
  check (a flake `lintCheck`-style step or a script) asserting `keri/Cargo.toml`'s `cesr`
  dependency enables **neither**. This is the whole gate: compiler + one grep.

### 7. Fuzz crates
- `fuzz-common/`, `fuzz/`, `fuzz-afl/` stay isolated empty-`[workspace]` roots (NOT
  workspace members). Only edit: `cesr = { path = ".." }` → `cesr = { path = "../cesr" }`
  in each (and any `fuzz-common`/`fuzz-afl` cross path deps stay relative-correct). Their
  own `Cargo.lock`s regenerate. The `cesr-fuzz-replay` nix check must stay green.

## Testing & verification

1. **Round-trip / structural:** `nix flake check` green on the workspace — the single
   gate. It must exercise BOTH crates through clippy, nextest, doctest, wasm, nostd, plus
   the unchanged `cesr-fuzz-replay`.
2. **Publish dry-run:** `cargo publish --dry-run -p cesr-rs` and
   `cargo publish --dry-run -p keri-rs` both clean (proves both are independently
   publishable — the standing release contract).
3. **API-link smoke test in `keri`:** a `#[test]` (or a `pub fn`) that calls one `cesr`
   **public** function (e.g. constructs a `cesr` primitive) — proves `keri` links against
   the real public surface, and would fail to compile if it reached a non-public item.
   This is also the guard that the `keri`→`cesr` dependency is wired correctly.
4. **Boundary (negative, documented):** the plan records that enabling `internals`/
   `test-utils` on the `keri`→`cesr` dep is rejected by the grep gate; a manual local check
   confirms the gate fails when the feature is added, then is reverted.
5. **Lint-law invariance:** confirm the moved `[workspace.lints.*]` is byte-identical to
   the old root `[lints.*]` (no accidental relaxation — CLAUDE.md hard rule).

## Out of scope (explicit)

- Any KERI type, trait, or logic (`KeyState`, `KelProvider`, escrow, delegation) — K1–K9.
- The freeze cards #82–#86 (they stay `cesr/`-scoped). #82's typed `Rct` decision is
  noted as the one to watch but is not touched here.
- `cargo-hakari`/workspace-hack — cesr never had one; two crates don't need it yet
  (revisit only if dependency-feature unification actually bites).
- TEL/ACDC (#98).

## Risks & open items for implementation

- **`git mv` + tooling paths:** every path reference (flake src filter infix, fuzz path
  deps, `justfile` recipes, `release-plz.toml`, docs, CI workflow `working-directory`s,
  benches/examples discovery) must be re-pointed. The plan enumerates each; `nix flake
  check` is the backstop that nothing was missed.
- **`Cargo.lock` churn:** moving to a workspace regenerates the root lock and the fuzz
  locks; verify no unexpected dependency/version drift (diff the lock).
- **release-plz per-package independence:** confirm a `keri-rs` release does not tag/bump
  `cesr-rs`. Validate config against release-plz workspace docs before relying on it.
- **wasm/nostd for `keri`:** an empty `keri` is trivially clean, but the feature scaffolding
  (`#![no_std]` + `alloc`) must be correct so K1 inherits a working contract, not a broken
  one discovered later.
