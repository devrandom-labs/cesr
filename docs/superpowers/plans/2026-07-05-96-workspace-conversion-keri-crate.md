# K0 Workspace Conversion + `keri` Sibling Crate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the single-crate `cesr` repo into a two-crate Cargo workspace — `cesr/` (unchanged surface, publishes `cesr-rs`) + a new empty `keri/` (publishes `keri-rs`) — under the existing god-level quality harness, so KERI sans-io work (K1–K9) can begin in `keri/`.

**Architecture:** Root becomes a pure virtual `[workspace]` manifest (top-level `cesr/` + `keri/` members; nexus patterns for `[workspace.package]`/`[workspace.dependencies]`/`[workspace.lints]`/`[workspace.metadata.crane]`, but top-level layout and no workspace-hack). `cesr`'s source moves via `git mv` with a byte-identical public surface. `keri` depends on `cesr` public API only. The flake builds/checks both crates.

**Tech Stack:** Rust 2024 (stable 1.95.0), Cargo workspaces, Nix + crane, release-plz.

**Spec:** `docs/superpowers/specs/2026-07-05-96-workspace-conversion-keri-crate-design.md`

**Prerequisite already done:** `keri-rs@0.0.1` is reserved and owned (crates.io, owner `joeldsouzax`).

---

## File Structure

```
Cargo.toml            REWRITE  virtual [workspace] manifest (members, package, deps, lints, crane meta, profile)
Cargo.lock            REGEN    workspace lock
README.md             REPLACE  short workspace README (cesr + keri); old content moves to cesr/README.md
cesr/                 NEW DIR  (git mv of the current crate)
  Cargo.toml          MOVE+EDIT  package cesr-rs; inherits workspace package/lints; thiserror via workspace dep
  README.md           MOVE     (current root README.md)
  CHANGELOG.md        MOVE     (current root CHANGELOG.md)
  src/ tests/ benches/ examples/   MOVE (git mv, unchanged content)
keri/                 NEW DIR
  Cargo.toml          NEW      package keri-rs, [lib] name = keri, cesr public-API dep, workspace lints
  src/lib.rs          NEW      no_std scaffolding + one public-API link item, NO KERI logic
flake.nix             EDIT     clippy --workspace; wasm/nostd split into -p cesr-rs + -p keri-rs; add keri boundary check
release-plz.toml      EDIT     add [[package]] name = "keri-rs"
fuzz/Cargo.toml       EDIT     cesr path ".." -> "../cesr"
fuzz-common/Cargo.toml EDIT    cesr path ".." -> "../cesr"
CLAUDE.md             EDIT     note the workspace (cesr + keri) replaces "single crate, not a workspace"
```

Unchanged at root (workspace-scoped): `clippy.toml`, `rustfmt.toml`, `taplo.toml`, `_typos.toml`, `deny.toml`, `audit.toml`, `rust-toolchain.toml`, `flake.lock`, `justfile` (all recipes use `--all-features`, valid at a virtual root — no edit), `.github/`, `.githooks/`, licenses.

`fuzz-afl/Cargo.toml` is NOT edited — it depends only on `fuzz-common` (relative path unchanged). The three fuzz crates stay isolated (empty `[workspace]`), NOT workspace members.

---

## Task 1: Convert to a workspace and move `cesr` into `cesr/`

**Files:** rewrite root `Cargo.toml`; `git mv` crate dirs + README/CHANGELOG into `cesr/`; create `cesr/Cargo.toml`; new root `README.md`; edit `fuzz/Cargo.toml` + `fuzz-common/Cargo.toml`.

- [ ] **Step 1: Move the crate's files into `cesr/` (preserve history)**

```bash
cd /Users/joel/Code/devrandom/cesr
mkdir -p cesr
git mv src cesr/src
git mv tests cesr/tests
git mv benches cesr/benches
git mv examples cesr/examples
git mv README.md cesr/README.md
git mv CHANGELOG.md cesr/CHANGELOG.md
git mv Cargo.toml cesr/Cargo.toml
```

- [ ] **Step 2: Edit `cesr/Cargo.toml` — inherit workspace keys, drop the local lint tables**

In `cesr/Cargo.toml`: (a) change the shared `[package]` keys to workspace inheritance, (b) switch `thiserror` to the workspace dep, (c) replace the two `[lints.*]` tables with `[lints] workspace = true`, (d) remove `[profile.release]` (moves to root).

Change the `[package]` block's shared keys from literals to `.workspace = true`:
```toml
[package]
name = "cesr-rs"
version = "0.4.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
description = "CESR + KERI primitives for Rust as a single feature-gated, no_std-capable crate"
categories = ["cryptography", "encoding", "no-std"]
keywords = ["cesr", "keri", "identity", "cryptography"]
readme = "README.md"
```

In `[dependencies]`, replace the `thiserror` line
```toml
thiserror = { version = "2.0.18", default-features = false }
```
with (it inherits version + `default-features = false` from the workspace):
```toml
thiserror = { workspace = true }
```
Leave every other dependency line exactly as-is (they are cesr-specific; YAGNI — centralize only when `keri` shares one).

Delete the entire `[lints.rust]` and `[lints.clippy]` blocks and the `[profile.release]` block from `cesr/Cargo.toml`. In their place (end of file) add:
```toml
[lints]
workspace = true
```

- [ ] **Step 3: Write the root virtual workspace manifest**

Create a new root `Cargo.toml` (the `[workspace.lints.*]` tables are lifted **verbatim** from the old `cesr/Cargo.toml` — do not alter a single level):

```toml
[workspace]
members = ["cesr"]
resolver = "3" # edition-2024 default (MSRV-aware); explicit since a virtual workspace has no package edition to infer from

[workspace.package]
edition = "2024"
rust-version = "1.95.0"
license = "MIT OR Apache-2.0"
authors = ["Joel DSouza <joel@devrandom.co>"]
repository = "https://github.com/devrandom-labs/cesr"

# Shared dependency versions (nexus pattern). Only genuinely shared deps live here;
# cesr-specific deps stay in cesr/Cargo.toml (YAGNI). thiserror is the one non-optional
# dep both cesr and (incoming) keri use.
[workspace.dependencies]
thiserror = { version = "2.0.18", default-features = false }

[workspace.metadata.crane]
name = "cesr"

[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"
unreachable_pub = "deny"
dead_code = "deny"

[workspace.lints.clippy]
# 1. THE FOUNDATION
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
nursery = { level = "deny", priority = -1 }
# 2. THE RUTHLESS RESTRICTIONS
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
disallowed_methods = "deny"
disallowed_types = "deny"
# 3. MEMORY & PERFORMANCE STRICTNESS
clone_on_ref_ptr = "deny"
as_conversions = "deny"
str_to_string = "deny"
implicit_clone = "deny"
# 4. VARIABLE HYGIENE
shadow_reuse = "deny"
shadow_same = "deny"
shadow_unrelated = "deny"
# 5. THE "NO CHEATING" RULE
allow_attributes_without_reason = "deny"

[profile.release]
lto = true
opt-level = 3
codegen-units = 1
```

- [ ] **Step 4: Write a short root workspace README**

Create root `README.md`:
```markdown
# cesr workspace

A two-crate Cargo workspace:

- [`cesr/`](cesr) — **cesr-rs**: CESR + KERI cryptographic primitives (no_std/WASM-capable). The stable, frozen-surface foundation. See [`cesr/README.md`](cesr/README.md).
- [`keri/`](keri) — **keri-rs**: sans-io KERI core (key-state, escrow, validation) built on `cesr`'s public API. Under active development.

The crates version independently: `cesr-rs` holds a stable surface while `keri-rs` iterates. Both are gated by a single `nix flake check`.

Licensed under MIT OR Apache-2.0.
```

- [ ] **Step 5: Re-point the fuzz path dependencies**

In `fuzz/Cargo.toml` change:
```toml
cesr = { package = "cesr-rs", path = "..", features = ["stream"] }
```
to:
```toml
cesr = { package = "cesr-rs", path = "../cesr", features = ["stream"] }
```

In `fuzz-common/Cargo.toml` change the identical line the same way (`path = ".."` → `path = "../cesr"`). Do NOT touch `fuzz-afl/Cargo.toml` (it depends on `fuzz-common`, not `cesr`).

- [ ] **Step 6: Verify the workspace builds at the cargo level**

Run (the flake is not yet updated — verify with cargo directly inside the dev shell):
```bash
nix develop --command bash -c "cargo build --workspace --all-features"
nix develop --command bash -c "cargo clippy --workspace --all-features --all-targets -- --deny warnings"
nix develop --command bash -c "cargo fmt --all -- --check"
nix develop --command bash -c "cargo nextest run --all-features"
nix develop --command bash -c "cd fuzz && cargo test --no-fail-fast"
```
Expected: all succeed. Clippy clean proves the moved `[lints]` inheritance is live (a relaxed lint would let something through — but the tables are verbatim). The fuzz test proves `../cesr` resolves. If `cargo` complains the lints are unused or the manifest is malformed, fix the manifest before proceeding.

- [ ] **Step 7: Stage and commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(#96)!: convert to a workspace, move cesr into cesr/

Root becomes a virtual [workspace] manifest (members = ["cesr"]) with
workspace-shared package/deps/lints/crane metadata (nexus patterns, top-level
layout). cesr's source moves via git mv with a byte-identical public surface;
lints inherited via [lints] workspace = true. Fuzz path deps re-pointed to
../cesr. BREAKING: repo layout only — the cesr-rs crate surface is unchanged.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add the empty `keri` crate

**Files:** create `keri/Cargo.toml`, `keri/src/lib.rs`; add `"keri"` to root workspace members.

- [ ] **Step 1: Add `keri` to the workspace members**

In root `Cargo.toml`, change:
```toml
members = ["cesr"]
```
to:
```toml
members = ["cesr", "keri"]
```

- [ ] **Step 2: Create `keri/Cargo.toml`**

```toml
[package]
name = "keri-rs"
version = "0.0.1"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
description = "Sans-IO KERI (Key Event Receipt Infrastructure) core built on cesr-rs. Under active development."
categories = ["cryptography", "no-std"]
keywords = ["keri", "cesr", "identity", "cryptography"]

[lib]
# Import name is `keri` regardless of the published `keri-rs` package name.
name = "keri"

# alloc is a FLOOR, not optional: cesr's `core` feature requires alloc
# unconditionally, so keri has no no-alloc mode. Only `std` is an optional forward.
[features]
default = ["std"]
std = ["cesr/std"]

[dependencies]
# PUBLIC API ONLY. Must NOT enable cesr's `internals` or `test-utils` features
# (the only back-doors to non-public items). Enforced by the flake boundary check.
# core + alloc always (alloc is required by core).
cesr = { package = "cesr-rs", path = "../cesr", version = "0.4", default-features = false, features = ["core", "alloc"] }

[lints]
workspace = true
```

- [ ] **Step 3: Write the failing API-link test first (TDD)**

Create `keri/src/lib.rs`. K0 has no KERI types; the one job is to prove `keri` links against `cesr`'s **public** API. Use `cesr::core::matter::builder::MatterBuilder` — a public, `core`-module type (this exact path is the one `fuzz-common` already exercises, so it is known-public). The test asserts a concrete public-API fact: the public decoder rejects empty input as `Err` (and never panics).

```rust
//! `keri` — sans-IO KERI (Key Event Receipt Infrastructure) core, built on the
//! public API of the `cesr` crate. This is the K0 skeleton: infrastructure only,
//! no KERI types yet (those arrive in K1+). Its sole purpose today is to prove the
//! workspace + the `cesr` public-API dependency are wired correctly.
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(test)]
mod tests {
    // Proves `keri` compiles against and links a real, PUBLIC `cesr` item (the same
    // path fuzz-common uses). Would fail to compile if the dependency were mis-wired
    // or if this reached a non-public path.
    use cesr::core::matter::builder::MatterBuilder;

    #[test]
    fn links_cesr_public_api() {
        // Empty input is not a valid qualified-base64 primitive: the public decoder
        // must return Err (and, per the parser contract, never panic).
        let empty: &[u8] = &[];
        assert!(MatterBuilder::new().from_qualified_base64(empty).is_err());
    }
}
```

- [ ] **Step 4: Verify the test compiles and passes**

```bash
nix develop --command bash -c "cargo test -p keri-rs"
```
Expected: PASS (1 test `links_cesr_public_api`). `MatterBuilder` (needs `alloc`) is available because keri's default `std` feature enables `alloc` → `cesr/alloc`, and the `cesr` dep always carries `core`. If the call signature differs (e.g. `from_qualified_base64` takes a different argument shape), inspect `src/core/matter/builder.rs` (soon `cesr/src/...`) for the real public signature and adjust — but keep it a PUBLIC-API assertion (do NOT reach a non-public item; that is the whole point).

- [ ] **Step 5: Verify keri is clippy-clean under the workspace lints**

```bash
nix develop --command bash -c "cargo clippy -p keri-rs --all-features --all-targets -- --deny warnings"
```
Expected: clean. `missing_docs` is `warn` (not deny), so the skeleton passes; the crate doc + item doc above cover the public items.

- [ ] **Step 6: Commit**

```bash
git add keri/ Cargo.toml
git commit -m "$(cat <<'EOF'
feat(#96): add empty keri-rs crate (K0 skeleton, public-API dep on cesr)

keri-rs (lib name keri) joins the workspace as an infrastructure-only skeleton:
no_std scaffolding, std/alloc features forwarding to cesr, a public re-export of
cesr, and a test proving it links cesr's PUBLIC API. No KERI logic (that is K1+).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Update the flake for the workspace

**Files:** `flake.nix`.

- [ ] **Step 1: Make clippy workspace-wide**

In `flake.nix`, the `cesr-clippy` check currently sets:
```nix
cargoClippyExtraArgs = "--all-targets -- --deny warnings";
```
Change it to (nexus's whole-workspace form; `--all-features` already comes from `commonArgs.cargoExtraArgs`):
```nix
cargoClippyExtraArgs = "--workspace --all-targets -- --deny warnings";
```

- [ ] **Step 2: Split the wasm check across both crates**

The two crates need DIFFERENT feature sets in this build (cesr with its big
`--no-default-features --features alloc,core,…` list; keri with plain `--no-default-features`
so it stays no_std). A single root `cargo build --features …` can't express that — and worse,
it would build the un-selected `keri` with its DEFAULT features (pulling `std` into a wasm/nostd
check). So each crate is built by package with `-p`. (Note: bare `--features X` at a virtual
root is not itself rejected on the pinned 1.95.0 toolchain — the reason for `-p` is per-crate
feature control, not a hard illegality.) Replace the `cesr-wasm` `buildPhaseCargoCommand`:
```nix
buildPhaseCargoCommand = ''
  cargo build --target wasm32-unknown-unknown \
    --no-default-features --features alloc,core,b64,keri,serder,crypto,stream
'';
```
with an explicit per-crate build of BOTH members:
```nix
buildPhaseCargoCommand = ''
  cargo build -p cesr-rs --target wasm32-unknown-unknown \
    --no-default-features --features alloc,core,b64,keri,serder,crypto,stream
  cargo build -p keri-rs --target wasm32-unknown-unknown \
    --no-default-features
'';
```

- [ ] **Step 3: Split the nostd check across both crates**

Replace the `cesr-nostd` `buildPhaseCargoCommand`:
```nix
buildPhaseCargoCommand = ''
  cargo build --no-default-features --features alloc,core,b64,keri,stream
'';
```
with:
```nix
buildPhaseCargoCommand = ''
  cargo build -p cesr-rs --no-default-features --features alloc,core,b64,keri,stream
  cargo build -p keri-rs --no-default-features
'';
```

- [ ] **Step 4: Run the full gate**

Run:
```bash
nix flake check
```
Expected: GREEN. This is the real proof the conversion holds — clippy/nextest/doctest now cover both crates workspace-wide; `cesr-wasm`/`cesr-nostd` build both members; `cesr-fuzz-replay` builds against `../cesr`; the `/tests/corpus/` and `/tests/__fuzz__/` source filters still match (paths now under `cesr/`). If it complains about untracked files, `git add` them first (nix only sees tracked/staged files). If `cesr-nextest`/`cesr-clippy` fail on a `keri` item, fix `keri` (not the lints). If a wasm/nostd build fails for `keri`, the `keri` feature scaffolding is wrong — fix `keri/Cargo.toml`/`lib.rs` so both crates are genuinely wasm + no_std clean.

- [ ] **Step 5: Commit**

```bash
git add flake.nix
git commit -m "$(cat <<'EOF'
ci(#96): flake covers the workspace — clippy --workspace, per-crate wasm/nostd

Whole-workspace clippy; wasm/nostd checks build both cesr-rs and keri-rs by
package (--features is illegal at a virtual root). keri now rides the full gate.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Release wiring, API-boundary gate, and docs

**Files:** `release-plz.toml`, `flake.nix` (add boundary check), `CLAUDE.md`.

- [ ] **Step 1: Add `keri-rs` to release-plz**

In `release-plz.toml`, after the existing `[[package]] name = "cesr-rs"` block, add:
```toml
[[package]]
name = "keri-rs"
```
Both packages version independently (release-plz-native). Leave the `[workspace]` release flags as-is.

- [ ] **Step 2: Add the API-boundary check to the flake**

In `flake.nix`, inside the `checks = { ... }` attrset (next to the other `lintCheck` hygiene checks), add a check that `keri`'s manifest never enables cesr's internal back-door features:
```nix
# keri may consume cesr's PUBLIC API only. The compiler already forbids reaching
# non-pub items across the crate boundary; the ONLY back-door is enabling cesr's
# internal-exposing features. Fail if keri/Cargo.toml mentions either.
cesr-keri-boundary = lintCheck "cesr-keri-boundary" [ ripgrep ] ''
  if rg -n -e '"internals"' -e '"test-utils"' ${./keri/Cargo.toml}; then
    echo "keri/Cargo.toml must not enable cesr's internals/test-utils features"
    exit 1
  fi
'';
```

- [ ] **Step 3: Update CLAUDE.md's "single crate" statement**

In `CLAUDE.md`, the "Key Conventions" section states cesr is a **"Single crate, not a workspace."** Replace that bullet's opening with the current reality (keep the no-hakari point):
```markdown
- **Two-crate workspace.** The repo is a Cargo workspace with two published members —
  `cesr/` (`cesr-rs`, the frozen-surface primitives) and `keri/` (`keri-rs`, the sans-io
  KERI core, built on cesr's public API). Unlike nexus, there is **no** `cargo-hakari`
  workspace-hack: two crates don't need dependency-feature unification yet. Members version
  independently (cesr-rs can sit frozen while keri-rs churns). Shared config —
  `[workspace.package]`, `[workspace.dependencies]`, `[workspace.lints]` — lives in the
  root virtual manifest; the fuzz crates stay isolated (non-member) workspaces.
```

- [ ] **Step 4: Verify the gate and both publish dry-runs**

```bash
git add release-plz.toml flake.nix CLAUDE.md
nix flake check
nix develop --command bash -c "cargo publish -p cesr-rs --dry-run --allow-dirty"
nix develop --command bash -c "cargo publish -p keri-rs --dry-run --allow-dirty"
```
Expected: `nix flake check` GREEN (now including `cesr-keri-boundary`); both `cargo publish --dry-run` succeed (proves both crates are independently publishable — the standing release contract). If a dry-run fails on a missing `readme`/`description`/`license`, fix the offending crate manifest. If `cargo publish --dry-run` for `keri-rs` objects that the `cesr` path dep needs a version for publishing, confirm the `version = "0.4"` is present on the `cesr` dep line (it is, per Task 2).

- [ ] **Step 5: Manually confirm the boundary gate actually fails (bug-probe)**

Prove the gate is not a no-op:
```bash
cd /Users/joel/Code/devrandom/cesr
# temporarily add a forbidden feature
sed -i.bak 's/features = \["core", "alloc"\]/features = ["core", "alloc", "internals"]/' keri/Cargo.toml
nix build '.#checks.aarch64-darwin.cesr-keri-boundary' 2>&1 | tail -5   # expect FAILURE
mv keri/Cargo.toml.bak keri/Cargo.toml   # revert
nix build '.#checks.aarch64-darwin.cesr-keri-boundary' 2>&1 | tail -3   # expect success
```
Expected: the check FAILS with the "must not enable" message when `internals` is present, and PASSES after revert. This confirms the gate can actually fail (Test Quality rule). Ensure `keri/Cargo.toml` is reverted before committing.

- [ ] **Step 6: Commit**

```bash
git add release-plz.toml flake.nix CLAUDE.md
git commit -m "$(cat <<'EOF'
ci(#96): release keri-rs independently + enforce keri->cesr public-API boundary

release-plz gains the keri-rs package (independent versioning). A flake check
fails if keri/Cargo.toml enables cesr's internals/test-utils features (the only
back-door past the compiler's per-crate visibility). CLAUDE.md notes the workspace.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review notes

- **Spec coverage:** reserve keri-rs (already done, noted) ✅; workspace conversion + `cesr/` move (Task 1) ✅; `keri/` skeleton public-API dep (Task 2) ✅; workspace lints/package/deps/crane (Task 1) ✅; flake covers both incl. wasm/nostd per-crate (Task 3) ✅; API-boundary gate = compiler + grep (Task 2 dep + Task 4 check) ✅; release-plz independent versioning (Task 4) ✅; fuzz crates stay isolated, path re-pointed (Task 1) ✅; `nix flake check` green + publish dry-runs (Tasks 3, 4) ✅; lint-law invariance (Task 1 verbatim + Task 1 Step 6 clippy) ✅.
- **Package-name discipline:** `-p cesr-rs` / `-p keri-rs` use the PACKAGE names (not the `cesr`/`keri` lib names) everywhere a package selector is needed (wasm/nostd builds, publish, tests).
- **Virtual-root feature rule:** `--all-features` is valid at a virtual root (clippy/nextest/doc) but `--features X` is not — that is exactly why Steps 2–3 of Task 3 add `-p`.
- **No placeholders:** every manifest and source block is complete and lifted from the real current files.

## Open risks (validate during execution)

- **`readme`/publish:** `cesr/README.md` and `cesr/CHANGELOG.md` are `git mv`d so `cesr-rs` keeps a readme for `cargo publish`; the new root README is workspace-level. `keri-rs` has no readme yet (K0) — `cargo publish --dry-run` tolerates its absence; add one when keri gets real content.
- **release-plz per-package changelog path:** confirm on first real `keri-rs` release that release-plz writes `keri/CHANGELOG.md` and does not bump `cesr-rs`. Not exercised by K0's dry-run; validate against release-plz workspace docs before the first keri release.
- **Cargo.lock drift:** the root + fuzz locks regenerate on first build; diff them to confirm no unexpected version changes (only path/member additions).
- **keri link-test public path:** Task 2 uses `cesr::core::matter::builder::MatterBuilder` (verified public + `core`-gated, the path fuzz-common uses). If its decode signature has drifted, keep the test a concrete PUBLIC-API assertion (any stable public item), never a non-public reach.
