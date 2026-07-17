# Workspace Split Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mechanically carve `keri-codec`, `cesr-stream`, and `keri-events` out of the `serder`, `stream`, and `keri` modules of `cesr-rs`, changing paths only — no API redesign.

**Architecture:** Three sequential PRs, each branched off fresh `main` after the previous merges, in the order `keri-codec` → `cesr-stream` → `keri-events`. The order is forced by a Cargo build cycle: nothing can leave `cesr` while `serder` is still inside it and depends on the thing leaving. Each intermediate state compiles and passes the full gate.

**Tech Stack:** Rust 1.95.0 (edition 2024, stable, no nightly), Cargo workspace, Nix flakes (`nix flake check` is the only gate), `cargo-nextest`, crane, `ast-grep`/`sd` for mechanical rewrites.

**Spec:** `docs/superpowers/specs/2026-07-17-192-workspace-split-design.md` (commit `db9f967`). The spec is authoritative; where this plan and the spec disagree, the spec wins.

---

## How to verify anything in this plan

**The single gate:**

```bash
nix flake check
```

Never short-circuit with raw `cargo` — it misses taplo, audit, deny, wasm, no_std, and the three tripwires.

**Never pipe the gate.** `nix flake check | tail` masks the exit code and `| head` SIGPIPE-kills it. Redirect and echo:

```bash
nix flake check > /tmp/gate.log 2>&1; echo "EXIT: $?"
```

**The gate only sees committed state.** A dirty-tree run is vacuous — `git add` first, then check.

## The prime directive

**This plan changes paths. It does not change behavior.**

These are the failure modes, in order of likelihood:

1. **Editing a test to make it pass.** The keripy differential and spine byte-identity suites *are* the definition of "mechanical." If one fails, the carve is wrong — fix the carve, never the test. The only permitted test edits are import paths (`cesr::serder::` → `keri_codec::`).
2. **"Improving" something while moving it.** A better name, a collapsed free function, a tidier error. All of it is #193. Phase 1 inherits the mess intact.
3. **Lowering a free-fn budget.** A move is not a fix. Counts must be byte-identical under renamed keys.

**Red flag:** if `git diff` on a moved file shows anything other than import-path lines, stop and re-read the spec.

---

## File structure

Before the split (`cesr-rs` 0.9.0, two members):

```
Cargo.toml            [workspace] members = ["cesr", "keri"]
cesr/src/{b64,core,crypto,keri,serder,stream}/
keri/src/             keri-rs
fuzz/ fuzz-afl/ fuzz-common/    isolated non-member workspaces
```

After (five members):

```
Cargo.toml            members = ["cesr", "cesr-stream", "keri-events", "keri-codec", "keri"]
cesr/src/{b64,core,crypto}/     cesr-rs 0.10.0
cesr-stream/src/                cesr-stream 0.1.0    <- ex-stream
keri-events/src/                keri-events 0.1.0    <- ex-keri
keri-codec/src/                 keri-codec 0.1.0     <- ex-serder
keri/src/                       keri-rs 0.0.7
```

---

# PR 1 — carve `keri-codec`

**Branch:** `split/192-keri-codec` off fresh `origin/main`.

**Why first:** `serder` depends on `stream` (production: `serder/error.rs:15`, `serder/serialize.rs:30-32`, `serder/message.rs:35-37`) and on `keri` (89 refs). If `stream` or `keri` left first, `cesr` would depend on a crate that depends on `cesr` — a hard build cycle. `serder` leaves first or nothing does.

**End state:** `cesr` retains b64+core+crypto+keri+stream. `keri-codec` depends on `cesr` with the `stream`, `keri`, and `internals` features still enabled — those features dissolve later, as their modules leave in PR 2 and PR 3.

**This is the big one:** ~10,250 lines plus the cross-crate suites. It is the veto-review that matters.

### Task 1.1: Reserve the crate names

**Files:** none (crates.io side effect)

- [ ] **Step 1: Confirm availability**

```bash
for c in cesr-stream keri-events keri-codec; do
  echo -n "$c : "
  xh -q --print=h GET "https://crates.io/api/v1/crates/$c" | head -1
done
```

Expected: `HTTP/2 404` for all three (verified available 2026-07-17).

- [ ] **Step 2: Reserve all three via the reserve-crate workflow**

Reserve `cesr-stream`, `keri-events`, and `keri-codec`. Reserving all three now — not one per PR — means a name cannot be sniped between PR 1 and PR 3, which would strand the split half-done.

**This step publishes to a public registry and is irreversible.** Confirm with Joel before running it.

### Task 1.2: Create the `keri-codec` crate skeleton

**Files:**
- Create: `keri-codec/Cargo.toml`
- Modify: `Cargo.toml` (root, `members`)

- [ ] **Step 1: Add the member to the root workspace**

In `Cargo.toml`, change:

```toml
members = ["cesr", "keri"]
```

to:

```toml
members = ["cesr", "keri-codec", "keri"]
```

- [ ] **Step 2: Write `keri-codec/Cargo.toml`**

```toml
[package]
name = "keri-codec"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
description = "KERI event codec: events <-> canonical JSON, SAID computation, and CESR message framing. Under active development."
categories = ["cryptography", "encoding", "no-std"]
keywords = ["keri", "cesr", "identity", "cryptography"]

[features]
default = ["std"]
std = ["alloc", "cesr/std", "thiserror/std"]
alloc = ["cesr/alloc"]

[dependencies]
cesr = { package = "cesr-rs", path = "../cesr", version = "0.9", default-features = false, features = [
    "core",
    "b64",
    "crypto",
    "keri",
    "stream",
    "internals",
] }
thiserror = { workspace = true }

[dev-dependencies]
proptest = "1.10.0"
rstest = "0.26.1"
serde = { version = "1.0.228", features = ["derive"] }
serde_json = { version = "1.0.149", features = [
    "float_roundtrip",
    "preserve_order",
    "raw_value",
] }

[lints]
workspace = true
```

Note: `[lib]` is omitted — package name `keri-codec` gives lib name `keri_codec` by default, which is what we want. The `cesr` dep keeps `internals` per spec §5.3; PR 3 re-points it to `keri-events`.

- [ ] **Step 3: Verify the workspace still resolves**

```bash
nix develop --command cargo metadata --format-version 1 > /dev/null; echo "EXIT: $?"
```

Expected: `EXIT: 0`. (`keri-codec` has no `src/` yet, so this only checks manifest parsing — a build would fail. That is expected until Task 1.3.)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml keri-codec/Cargo.toml
git commit -m "chore(keri-codec): add crate skeleton and workspace member"
```

### Task 1.3: Move the `serder` sources

**Files:**
- Move: `cesr/src/serder/` (20 `.rs` files) → `keri-codec/src/`
- Modify: `cesr/src/lib.rs` (remove `pub mod serder;` and its prelude/keripy-mod lines)

- [ ] **Step 1: Move the tree with git so renames are detected**

```bash
git mv cesr/src/serder keri-codec/src
git mv keri-codec/src/mod.rs keri-codec/src/lib.rs
```

`serder/mod.rs` becomes the crate root `lib.rs`.

- [ ] **Step 2: Rewrite intra-module paths to crate-local**

```bash
fd -e rs . keri-codec/src -x sd 'crate::serder::' 'crate::'
```

- [ ] **Step 3: Rewrite sibling-module paths to external crates**

```bash
fd -e rs . keri-codec/src -x sd 'crate::stream::' 'cesr::stream::'
fd -e rs . keri-codec/src -x sd 'crate::keri::' 'cesr::keri::'
fd -e rs . keri-codec/src -x sd 'crate::core::' 'cesr::core::'
fd -e rs . keri-codec/src -x sd 'crate::b64::' 'cesr::b64::'
fd -e rs . keri-codec/src -x sd 'crate::crypto::' 'cesr::crypto::'
```

At this step `stream` and `keri` are still *inside* `cesr`, so they are reached as `cesr::stream::` / `cesr::keri::`. PR 2 and PR 3 re-point them to `cesr_stream::` / `keri_events::`. This is why PR 1 is the only cycle-free first move.

- [ ] **Step 4: Add the crate root preamble to `keri-codec/src/lib.rs`**

The file was a module; it now needs what `cesr/src/lib.rs` provided. Add at the very top, above the existing module docs:

```rust
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;
```

Match the exact attribute set on `cesr/src/lib.rs` — read it first and mirror it rather than trusting this snippet. If `cesr/src/lib.rs` carries lint attributes or `#![doc = ...]` lines, the same reasoning applies to the new crate root.

- [ ] **Step 5: Remove `serder` from `cesr/src/lib.rs`**

Delete:

```rust
#[cfg(feature = "serder")]
pub mod serder;
```

Delete from `pub mod prelude` (spec §4.4):

```rust
    #[cfg(feature = "serder")]
    #[doc(no_inline)]
    pub use crate::serder::{KeriDeserialize, KeriSerialize};
```

Delete the two in-tree test module declarations (they move in Task 1.5):

```rust
#[cfg(test)]
#[cfg(all(feature = "serder", feature = "std"))]
mod keripy_diff;

#[cfg(test)]
#[cfg(all(feature = "serder", feature = "std"))]
mod keripy_parity;
```

- [ ] **Step 6: Add the fragmented prelude to `keri-codec/src/lib.rs`**

Per spec §4.4, `keri-codec` takes exactly the prelude rows that were its own — no more:

```rust
/// Re-exports of the traits needed for method resolution on codec types.
pub mod prelude {
    #[doc(no_inline)]
    pub use crate::{KeriDeserialize, KeriSerialize};
}
```

The `#[cfg(feature = "serder")]` gate drops — the feature no longer exists.

- [ ] **Step 7: Remove the `serder` feature from `cesr/Cargo.toml`**

Delete the line:

```toml
serder = ["keri", "crypto", "stream", "internals"]
```

Do **not** remove `internals` — `keri-codec` still enables it (spec §5.3).

Delete the `serder` bench and the four `serder`-gated examples from `cesr/Cargo.toml` (they move in Task 1.6):

```toml
[[bench]]
name = "serder"
harness = false
required-features = ["serder"]
```

and the `[[example]]` blocks for `incept_aid`, `multisig_threshold_icp`, `kel_chain`, `delegated_inception`.

- [ ] **Step 8: Build and read the errors**

```bash
nix develop --command cargo build -p keri-codec > /tmp/build.log 2>&1; echo "EXIT: $?"
```

Expected: **failure**, with unresolved-import errors. This is the plan working — the compiler is now enumerating every path the mechanical rewrite missed. Read `/tmp/build.log` and fix each import. Expect two categories:

- Items `serder` reached via `cesr`'s crate-private paths that are not `pub` in `cesr`. Each one is a genuine finding: it means the module boundary was porous. **Do not add `pub` to `cesr` to fix it** — that is a surface change. Report it and stop; it may need a spec amendment.
- `use` statements now needing `cesr::` that the `sd` pass missed because they were written as bare `super::` or `crate::` without a module segment.

- [ ] **Step 9: Iterate until `keri-codec` builds**

```bash
nix develop --command cargo build -p keri-codec > /tmp/build.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "refactor(keri-codec)!: move serder module into its own crate

Mechanical carve per spec 2026-07-17-192-workspace-split-design.md.
Paths only; no API change. BREAKING: cesr::serder is now keri_codec."
```

### Task 1.4: Move the cross-crate test suites

**Files:**
- Move: `cesr/tests/{frozen_surface,spine,spine_write,kel_chain,serder_allocation}.rs` → `keri-codec/tests/`
- Move: `keri/tests/{differential,transitions}.rs` → `keri-codec/tests/`

- [ ] **Step 1: Move the suites**

```bash
mkdir -p keri-codec/tests
git mv cesr/tests/frozen_surface.rs keri-codec/tests/
git mv cesr/tests/spine.rs keri-codec/tests/
git mv cesr/tests/spine_write.rs keri-codec/tests/
git mv cesr/tests/kel_chain.rs keri-codec/tests/
git mv cesr/tests/serder_allocation.rs keri-codec/tests/
git mv keri/tests/differential.rs keri-codec/tests/
git mv keri/tests/transitions.rs keri-codec/tests/
```

Confirm against spec §4.3 before running: `allocation.rs` stays (moves to `cesr-stream` in PR 2), `prelude.rs` stays with `cesr`, `properties.rs` stays (moves to `keri-events` in PR 3).

- [ ] **Step 2: Rewrite only the import paths**

```bash
fd -e rs . keri-codec/tests -x sd 'cesr::serder::' 'keri_codec::'
fd -e rs . keri-codec/tests -x sd '\buse cesr::serder\b' 'use keri_codec'
```

**Nothing else in these files may change.** `cesr::core::`, `cesr::keri::`, `cesr::stream::` all still resolve — `keri-codec` depends on `cesr` with those features on.

- [ ] **Step 3: Add the dev-dependencies the moved suites need**

`differential.rs` and `transitions.rs` came from `keri/` and may use `keri-rs`. Check:

```bash
rg -n '^use |extern crate' keri-codec/tests/differential.rs keri-codec/tests/transitions.rs
```

If either references `keri::`, add to `keri-codec/Cargo.toml` `[dev-dependencies]`:

```toml
keri = { package = "keri-rs", path = "../keri", features = ["wire"] }
```

This is a dev-cycle (`keri-rs` → `keri-codec` → dev → `keri-rs`), which Cargo permits.

- [ ] **Step 4: Run the moved suites**

```bash
nix develop --command cargo nextest run -p keri-codec > /tmp/test.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`, all tests passing.

**If a keripy differential or spine byte-identity test fails, the carve is wrong.** Do not touch the test. Diff the moved file against `main` — the only lines that may differ are imports:

```bash
git diff origin/main -- keri-codec/tests/spine.rs
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(keri-codec): move cross-crate suites with the codec

Import paths only; assertions unchanged per spec 7.2 (wire behavior frozen)."
```

### Task 1.5: Move the in-tree keripy test modules

**Files:**
- Move: `cesr/src/keripy_diff/` → `keri-codec/src/keripy_diff/`
- Move: `cesr/src/keripy_parity/` → `keri-codec/src/keripy_parity/`
- Modify: `keri-codec/src/lib.rs`

- [ ] **Step 1: Move both trees**

```bash
git mv cesr/src/keripy_diff keri-codec/src/keripy_diff
git mv cesr/src/keripy_parity keri-codec/src/keripy_parity
```

- [ ] **Step 2: Declare them in `keri-codec/src/lib.rs`**

Their gate loses the `serder` feature (spec §4.2), keeping only `std`:

```rust
#[cfg(test)]
#[cfg(feature = "std")]
mod keripy_diff;

#[cfg(test)]
#[cfg(feature = "std")]
mod keripy_parity;
```

- [ ] **Step 3: Rewrite their import paths**

```bash
fd -e rs . keri-codec/src/keripy_diff keri-codec/src/keripy_parity -x sd 'crate::serder::' 'crate::'
fd -e rs . keri-codec/src/keripy_diff keri-codec/src/keripy_parity -x sd 'crate::core::' 'cesr::core::'
fd -e rs . keri-codec/src/keripy_diff keri-codec/src/keripy_parity -x sd 'crate::stream::' 'cesr::stream::'
fd -e rs . keri-codec/src/keripy_diff keri-codec/src/keripy_parity -x sd 'crate::keri::' 'cesr::keri::'
```

- [ ] **Step 4: Run them**

```bash
nix develop --command cargo nextest run -p keri-codec keripy > /tmp/test.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`. Test names must still contain `keripy` or the nightly filter silently never runs them.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(keri-codec): move keripy_diff and keripy_parity modules"
```

### Task 1.6: Move the serder benches and examples

**Files:**
- Move: `cesr/benches/serder.rs` → `keri-codec/benches/`
- Move: `cesr/examples/{incept_aid,multisig_threshold_icp,kel_chain,delegated_inception}.rs` → `keri-codec/examples/`
- Modify: `keri-codec/Cargo.toml`

- [ ] **Step 1: Move them**

```bash
mkdir -p keri-codec/benches keri-codec/examples
git mv cesr/benches/serder.rs keri-codec/benches/
for e in incept_aid multisig_threshold_icp kel_chain delegated_inception; do
  git mv "cesr/examples/$e.rs" keri-codec/examples/
done
```

- [ ] **Step 2: Rewrite their import paths**

```bash
fd -e rs . keri-codec/benches keri-codec/examples -x sd 'cesr::serder::' 'keri_codec::'
fd -e rs . keri-codec/benches keri-codec/examples -x sd '\buse cesr::serder\b' 'use keri_codec'
```

- [ ] **Step 3: Declare the bench in `keri-codec/Cargo.toml`**

`required-features` drops entirely (spec §4.6) — the feature that gated it was the module, and the module is now the crate:

```toml
[[bench]]
name = "serder"
harness = false
```

Add the bench harness to `[dev-dependencies]`:

```toml
criterion = { version = "5.0.1", package = "codspeed-criterion-compat", default-features = false, features = [
    "cargo_bench_support",
] }
```

The four examples need no `[[example]]` blocks — with no `required-features`, Cargo auto-discovers them.

- [ ] **Step 4: Verify they build**

```bash
nix develop --command cargo build -p keri-codec --benches --examples > /tmp/build.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore(keri-codec): move serder bench and examples"
```

### Task 1.7: Re-point `keri-rs` and the fuzz workspaces

**Files:**
- Modify: `keri/Cargo.toml`, `keri/src/**` (wire-feature paths)
- Modify: `fuzz-common/Cargo.toml`, `fuzz-common/src/lib.rs`

- [ ] **Step 1: Re-point `keri-rs`'s `wire` feature**

In `keri/Cargo.toml`, the `wire` feature currently reads:

```toml
wire = ["cesr/serder"]
```

Change to:

```toml
wire = ["dep:keri-codec"]
```

and add to `[dependencies]`:

```toml
keri-codec = { path = "../keri-codec", version = "0.1", default-features = false, optional = true }
```

Remove `"serder"` from the `[dev-dependencies]` `cesr` features list.

- [ ] **Step 2: Rewrite `keri-rs`'s wire-edge paths**

```bash
fd -e rs . keri/src -x sd 'cesr::serder::' 'keri_codec::'
fd -e rs . keri/src -x sd '\buse cesr::serder\b' 'use keri_codec'
```

- [ ] **Step 3: Re-point `fuzz-common`**

In `fuzz-common/Cargo.toml`:

```toml
cesr = { package = "cesr-rs", path = "../cesr", features = ["stream"] }
keri-codec = { path = "../keri-codec" }
```

Then:

```bash
fd -e rs . fuzz-common/src -x sd 'cesr::serder::' 'keri_codec::'
fd -e rs . fuzz-common/src -x sd '\buse cesr::serder\b' 'use keri_codec'
```

`fuzz/Cargo.toml` (`features = ["stream"]`) is untouched in PR 1 — `stream` is still in `cesr`.

- [ ] **Step 4: Verify keri-rs builds both ways**

```bash
nix develop --command cargo build -p keri-rs > /tmp/b1.log 2>&1; echo "no-wire EXIT: $?"
nix develop --command cargo build -p keri-rs --features wire > /tmp/b2.log 2>&1; echo "wire EXIT: $?"
```

Expected: `EXIT: 0` for both. Building *without* `wire` is the one that matters — it proves the sans-io core still never sees wire bytes.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(keri,fuzz): re-point serder consumers at keri-codec"
```

### Task 1.8: Update the flake gates

**Files:**
- Modify: `flake.nix`, `free-fn-budget.toml`

- [ ] **Step 1: Remap the free-fn budget**

In `free-fn-budget.toml`, rename the key and re-point the directory. `serder = 58` becomes:

```toml
keri-codec = 58
```

**The count does not change.** A move is not a fix. Those 58 free functions are the strongest argument for #193 and must survive PR 1 intact so #193 inherits an honest baseline.

Update the counting-rule comment: the per-module `cesr/src/<module>` path is now per-crate `<crate>/src`.

- [ ] **Step 2: Re-point the ratchet check in `flake.nix`**

The check counts `^pub(\(crate\)|\(super\))? fn ` per directory. Its directory list must now include `${./keri-codec/src}` mapped to the `keri-codec` budget key.

- [ ] **Step 3: Extend the version-owner file list**

In `cesr-version-owner`, change:

```nix
files=$(rg --files -g '*.rs' ${./cesr/src} ${./keri/src} | rg -v '/core/version\.rs$')
```

to include the new crate:

```nix
files=$(rg --files -g '*.rs' ${./cesr/src} ${./keri-codec/src} ${./keri/src} | rg -v '/core/version\.rs$')
```

The owner is unchanged: `cesr/src/core/version.rs`, which stays in `cesr`.

- [ ] **Step 4: Extend the keri-boundary check**

`cesr-keri-boundary` asserts `keri/Cargo.toml` names neither `"internals"` nor `"test-utils"`. That intent — keri-rs consumes public API only — now spans multiple deps. The rg pattern already matches the feature strings anywhere in the file, so update the comment to say "any dependency" and re-verify it still trips:

```bash
nix build '.#checks.aarch64-darwin.cesr-keri-boundary' > /tmp/gate.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`.

- [ ] **Step 5: Add per-crate build coverage**

`cesr-wasm` and `cesr-nostd` build `cesr` for `wasm32-unknown-unknown` and no_std+alloc. Add equivalent coverage for `keri-codec` (`-p keri-codec --no-default-features --features alloc`). Read the existing derivations and mirror their structure rather than inventing a new shape.

- [ ] **Step 6: Verify the ratchet actually trips**

A gate that cannot fail is not a gate. Prove it:

```bash
echo 'pub fn ratchet_probe_delete_me() {}' >> keri-codec/src/lib.rs
git add -A
nix build '.#checks.aarch64-darwin.cesr-fn-ratchet' > /tmp/gate.log 2>&1; echo "EXIT: $? (expect NON-ZERO)"
git restore --staged keri-codec/src/lib.rs
git checkout keri-codec/src/lib.rs
```

Expected: non-zero exit — the budget is 58 and the probe makes 59. If this passes, the ratchet is not watching `keri-codec` and Step 2 is wrong.

- [ ] **Step 7: Commit**

```bash
git add flake.nix free-fn-budget.toml
git commit -m "ci: remap tripwire gates for keri-codec

Budget key serder -> keri-codec at the same count of 58; version-owner
file list extended. A move is not a fix."
```

### Task 1.9: Bump versions and update docs

**Files:**
- Modify: `cesr/Cargo.toml`, `keri/Cargo.toml`, `CLAUDE.md`, `CHANGELOG.md`
- Create: `keri-codec/CHANGELOG.md`

- [ ] **Step 1: Bump the versions**

`cesr/Cargo.toml`: `version = "0.9.0"` → `version = "0.10.0"`. Breaking — `serder` left the crate. Per the `0.x` convention, breaking is a MINOR bump.

`keri/Cargo.toml`: `version = "0.0.6"` → `version = "0.0.7"`, and its `cesr` dep `version = "0.9"` → `version = "0.10"`.

`keri-codec/Cargo.toml`: its `cesr` dep `version = "0.9"` → `version = "0.10"`.

- [ ] **Step 2: Write the CHANGELOG entries**

`cesr/CHANGELOG.md` — a breaking change must be called out (CLAUDE.md):

```markdown
## 0.10.0

### Breaking

- The `serder` module has moved to the new `keri-codec` crate. `cesr::serder::X`
  is now `keri_codec::X`. The `serder` feature is removed.
- `cesr::prelude` no longer re-exports `KeriDeserialize` / `KeriSerialize`; they
  are in `keri_codec::prelude`.

No behavior changed. This is a mechanical carve (#192 phase 1); the wire format
is byte-identical and the keripy differential suites pass unchanged.
```

Create `keri-codec/CHANGELOG.md`:

```markdown
## 0.1.0

Initial release. Carved from `cesr-rs` 0.9's `serder` module (#192 phase 1) with
no API change. Version starts at 0.1.0 because it is a new crate; the API is
under active redesign in #193.
```

- [ ] **Step 3: Update CLAUDE.md**

The module table becomes a crate table. Reword the "single feature-gated crate" framing and the `serder` → `stream` note (which is now a crate dep). Update the feature list: the module gates are gone.

- [ ] **Step 4: Add release-plz config for the new crate**

Mirror the existing per-crate config shape.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: crate table, changelogs, and version bumps for the keri-codec carve"
```

### Task 1.10: Full gate and PR

- [ ] **Step 1: Run the only gate that counts**

```bash
git add -A
nix flake check > /tmp/gate.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`. If not, read `/tmp/gate.log`. **Never pipe this command.**

- [ ] **Step 2: Prove the wire format did not move**

The acceptance criterion of the whole card:

```bash
nix develop --command cargo test --all-features keripy > /tmp/keripy.log 2>&1; echo "EXIT: $?"
rg -c 'test result: ok' /tmp/keripy.log
```

Expected: `EXIT: 0`. Then confirm no assertion was touched:

```bash
git diff origin/main --stat -- keri-codec/tests/ | tail -1
git diff origin/main -- keri-codec/tests/ | rg '^[+-]' | rg -v '^[+-][+-]' | rg -v '^[+-]use ' | rg -v '^[+-]$'
```

Expected: the second command prints **nothing**. Any line it prints is a changed assertion — a spec violation. Investigate before proceeding.

- [ ] **Step 3: Confirm the free-fn counts are unchanged**

```bash
rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' keri-codec/src -g '*.rs' | wc -l
```

Expected: `58`, matching the pre-split `serder` budget exactly.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin split/192-keri-codec
gh pr create --base main --title "refactor(keri-codec)!: carve serder into its own crate (#192 phase 1/3)" --body "..."
```

The body must call out the breaking change (CLAUDE.md) and link the spec. Note in the body that this is PR 1 of 3 sequential PRs and that **the landing order is load-bearing** — `serder` must leave before `stream` or `keri` can, or the workspace cycles.

- [ ] **Step 5: Wait for the merge before starting PR 2**

Sequential, not stacked (spec §6.2). Required checks are "Nix Flake Check" and "fuzz-gate"; CodSpeed is advisory. Branch protection is strict, so the PR goes behind after any merge — `gh pr update-branch` as needed.

**Do not** start PR 2 until PR 1 is merged into `main`.

---

# PR 2 — carve `cesr-stream`

**Branch:** `split/192-cesr-stream` off fresh `origin/main` (after PR 1 merges).

**Why now possible:** `serder` — the only thing inside `cesr` that depended on `stream` — is gone. `cesr-stream` → `cesr` is now a one-way edge.

**End state:** `cesr` retains b64+core+crypto+keri. `keri-codec` depends on `cesr` + `cesr-stream`.

### Task 2.1: Create the `cesr-stream` skeleton

**Files:**
- Create: `cesr-stream/Cargo.toml`
- Modify: `Cargo.toml` (root)

- [ ] **Step 1: Add the member**

```toml
members = ["cesr", "cesr-stream", "keri-codec", "keri"]
```

- [ ] **Step 2: Write `cesr-stream/Cargo.toml`**

```toml
[package]
name = "cesr-stream"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
description = "CESR stream framing: counters, groups, cold-start detection, and text/binary stream parsing. Under active development."
categories = ["cryptography", "encoding", "no-std"]
keywords = ["cesr", "keri", "streaming", "parsing"]

[features]
default = ["std"]
std = ["alloc", "cesr/std", "thiserror/std"]
alloc = ["cesr/alloc"]
async = ["dep:tokio-util", "dep:futures-core"]

[dependencies]
bytes = { version = "1.10.1", default-features = false }
cesr = { package = "cesr-rs", path = "../cesr", version = "0.10", default-features = false, features = [
    "core",
    "b64",
] }
futures-core = { version = "0.3.31", default-features = false, optional = true }
thiserror = { workspace = true }
tokio-util = { version = "0.7.15", default-features = false, features = ["codec"], optional = true }

[dev-dependencies]
criterion = { version = "5.0.1", package = "codspeed-criterion-compat", default-features = false, features = [
    "cargo_bench_support",
] }
proptest = "1.10.0"
rstest = "0.26.1"
tokio = { version = "1.49.0", default-features = false, features = ["rt", "macros"] }

[[bench]]
name = "matter"
harness = false

[[bench]]
name = "counter"
harness = false

[[bench]]
name = "stream"
harness = false

[lints]
workspace = true
```

The `async` feature moves here from `cesr` (spec §5.2), bringing `tokio-util` and `futures-core`. `bytes` becomes non-optional — it was only optional because the `stream` feature gated it.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml cesr-stream/Cargo.toml
git commit -m "chore(cesr-stream): add crate skeleton and workspace member"
```

### Task 2.2: Move the `stream` sources

**Files:**
- Move: `cesr/src/stream/` (12 `.rs` files) → `cesr-stream/src/`
- Modify: `cesr/src/lib.rs`, `cesr/Cargo.toml`

- [ ] **Step 1: Move and promote the module root**

```bash
git mv cesr/src/stream cesr-stream/src
git mv cesr-stream/src/mod.rs cesr-stream/src/lib.rs
```

- [ ] **Step 2: Rewrite paths**

```bash
fd -e rs . cesr-stream/src -x sd 'crate::stream::' 'crate::'
fd -e rs . cesr-stream/src -x sd 'crate::core::' 'cesr::core::'
fd -e rs . cesr-stream/src -x sd 'crate::b64::' 'cesr::b64::'
```

- [ ] **Step 3: Add the crate root preamble**

Same as Task 1.3 Step 4 — mirror `cesr/src/lib.rs`'s attribute set onto `cesr-stream/src/lib.rs`.

- [ ] **Step 4: Add the fragmented prelude**

Per spec §4.4, `cesr-stream` takes exactly its own rows:

```rust
/// Re-exports of the traits and headliner types for stream framing.
pub mod prelude {
    #[doc(no_inline)]
    pub use crate::{CesrEncode, CesrGroup, CesrMessage};
}
```

- [ ] **Step 5: Remove `stream` from `cesr`**

In `cesr/src/lib.rs` delete `#[cfg(feature = "stream")] pub mod stream;` and the two prelude blocks re-exporting `CesrEncode` and `CesrGroup`/`CesrMessage`.

In `cesr/Cargo.toml` delete the `stream` feature, the `async` feature (it moved), the now-unused `bytes` / `tokio-util` / `futures-core` deps, the `matter` / `counter` / `stream` benches, and the `concurrent_parse` / `parse_stream` examples.

- [ ] **Step 6: Re-point `keri-codec` at the new crate**

In `keri-codec/Cargo.toml` add:

```toml
cesr-stream = { path = "../cesr-stream", version = "0.1", default-features = false }
```

and drop `"stream"` from its `cesr` features list. Then:

```bash
fd -e rs . keri-codec/src keri-codec/tests keri-codec/benches keri-codec/examples -x sd 'cesr::stream::' 'cesr_stream::'
fd -e rs . keri-codec/src keri-codec/tests -x sd '\buse cesr::stream\b' 'use cesr_stream'
```

- [ ] **Step 7: Build**

```bash
nix develop --command cargo build --workspace > /tmp/build.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`. Iterate on unresolved imports as in Task 1.3 Step 8 — same rule: a private-item error is a finding to report, not a `pub` to add.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(cesr-stream)!: move stream module into its own crate

Mechanical carve per spec. BREAKING: cesr::stream is now cesr_stream;
the async feature moves to cesr-stream."
```

### Task 2.3: Move stream tests, benches, examples, and fuzz

**Files:**
- Move: `cesr/tests/allocation.rs`, `cesr/benches/{matter,counter,stream}.rs`, `cesr/examples/{concurrent_parse,parse_stream}.rs`
- Modify: `fuzz/Cargo.toml`, `fuzz-common/Cargo.toml`, fuzz sources

- [ ] **Step 1: Move them**

```bash
mkdir -p cesr-stream/tests cesr-stream/benches cesr-stream/examples
git mv cesr/tests/allocation.rs cesr-stream/tests/
git mv cesr/benches/matter.rs cesr-stream/benches/
git mv cesr/benches/counter.rs cesr-stream/benches/
git mv cesr/benches/stream.rs cesr-stream/benches/
git mv cesr/examples/concurrent_parse.rs cesr-stream/examples/
git mv cesr/examples/parse_stream.rs cesr-stream/examples/
```

`matter.rs` goes to `cesr-stream` despite its name: it references `cesr::stream::qb`, so its `required-features = ["stream"]` was accurate, not stale (spec §4.6).

- [ ] **Step 2: Rewrite their paths**

```bash
fd -e rs . cesr-stream/tests cesr-stream/benches cesr-stream/examples -x sd 'cesr::stream::' 'cesr_stream::'
fd -e rs . cesr-stream/tests cesr-stream/benches cesr-stream/examples -x sd '\buse cesr::stream\b' 'use cesr_stream'
```

- [ ] **Step 3: Re-point both fuzz workspaces**

`fuzz/Cargo.toml`:

```toml
cesr-stream = { path = "../cesr-stream" }
```

replacing the `cesr = { ..., features = ["stream"] }` entry if `cesr` is otherwise unused; keep `cesr` if the targets still reference `cesr::core`.

`fuzz-common/Cargo.toml`: same substitution, keeping its `keri-codec` dep from PR 1.

```bash
fd -e rs . fuzz fuzz-afl fuzz-common -x sd 'cesr::stream::' 'cesr_stream::'
```

- [ ] **Step 4: Verify the fuzz corpus still replays**

```bash
nix build '.#checks.aarch64-darwin.cesr-fuzz-replay' > /tmp/gate.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`. The corpus is real inputs that previously found real bugs; a replay failure means the parser's behavior moved.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(cesr-stream): move stream tests, benches, examples, and fuzz targets"
```

### Task 2.4: Gates, docs, and PR

- [ ] **Step 1: Remap the budget**

In `free-fn-budget.toml`, `stream = 2` → `cesr-stream = 2`. Count unchanged. Re-point the directory in the flake check to `${./cesr-stream/src}`.

- [ ] **Step 2: Extend version-owner**

Add `${./cesr-stream/src}` to the file list.

- [ ] **Step 3: Add per-crate wasm/no_std coverage for `cesr-stream`**

Mirror the existing derivations.

- [ ] **Step 4: Prove the ratchet trips on the new crate**

```bash
echo 'pub fn ratchet_probe_delete_me() {}' >> cesr-stream/src/lib.rs
git add -A
nix build '.#checks.aarch64-darwin.cesr-fn-ratchet' > /tmp/gate.log 2>&1; echo "EXIT: $? (expect NON-ZERO)"
git restore --staged cesr-stream/src/lib.rs && git checkout cesr-stream/src/lib.rs
```

Expected: non-zero.

- [ ] **Step 5: Changelogs**

Create `cesr-stream/CHANGELOG.md` (0.1.0, carved from `cesr-rs` 0.10's `stream` module). Add a `cesr` 0.11.0 entry — `stream` leaving is another breaking change, so bump `cesr` 0.10.0 → **0.11.0** and update the dependent version requirements in `cesr-stream`, `keri-codec`, and `keri`.

- [ ] **Step 6: Full gate**

```bash
git add -A
nix flake check > /tmp/gate.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`.

- [ ] **Step 7: Verify wire behavior again**

```bash
nix develop --command cargo test --all-features keripy > /tmp/keripy.log 2>&1; echo "EXIT: $?"
git diff origin/main -- keri-codec/tests/ | rg '^[+-]' | rg -v '^[+-][+-]' | rg -v '^[+-]use ' | rg -v '^[+-]$'
```

Expected: `EXIT: 0` and no assertion diff.

- [ ] **Step 8: Push, PR, wait for merge**

```bash
git push -u origin split/192-cesr-stream
gh pr create --base main --title "refactor(cesr-stream)!: carve stream into its own crate (#192 phase 2/3)" --body "..."
```

Do not start PR 3 until this merges.

---

# PR 3 — carve `keri-events`

**Branch:** `split/192-keri-events` off fresh `origin/main` (after PR 2 merges).

**End state:** `cesr` is b64+core+crypto only. The DAG in spec §3 is complete.

### Task 3.1: Create the `keri-events` skeleton

**Files:**
- Create: `keri-events/Cargo.toml`
- Modify: `Cargo.toml` (root)

- [ ] **Step 1: Add the member**

```toml
members = ["cesr", "cesr-stream", "keri-events", "keri-codec", "keri"]
```

- [ ] **Step 2: Write `keri-events/Cargo.toml`**

```toml
[package]
name = "keri-events"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
description = "KERI event vocabulary: key events, seals, thresholds, identifiers. Under active development."
categories = ["cryptography", "no-std"]
keywords = ["keri", "cesr", "identity", "events"]

[features]
default = ["std"]
std = ["alloc", "cesr/std", "thiserror/std"]
alloc = ["cesr/alloc"]
# Internal all-field event constructors, consumed by keri-codec.
# Carried across the split unchanged per spec 5.3; #193 removes it.
internals = []

[dependencies]
cesr = { package = "cesr-rs", path = "../cesr", version = "0.11", default-features = false, features = [
    "core",
] }
thiserror = { workspace = true }

[dev-dependencies]
proptest = "1.10.0"
rstest = "0.26.1"

[lints]
workspace = true
```

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml keri-events/Cargo.toml
git commit -m "chore(keri-events): add crate skeleton and workspace member"
```

### Task 3.2: Move the `keri` sources

**Files:**
- Move: `cesr/src/keri/` (16 `.rs` files) → `keri-events/src/`
- Modify: `cesr/src/lib.rs`, `cesr/Cargo.toml`

- [ ] **Step 1: Move and promote**

```bash
git mv cesr/src/keri keri-events/src
git mv keri-events/src/mod.rs keri-events/src/lib.rs
```

- [ ] **Step 2: Rewrite paths**

```bash
fd -e rs . keri-events/src -x sd 'crate::keri::' 'crate::'
fd -e rs . keri-events/src -x sd 'crate::core::' 'cesr::core::'
fd -e rs . keri-events/src -x sd 'crate::b64::' 'cesr::b64::'
```

- [ ] **Step 3: Crate root preamble and prelude**

Mirror `cesr/src/lib.rs`'s attributes. Add the fragmented prelude (spec §4.4):

```rust
/// Re-exports of the traits and headliner types for the KERI event vocabulary.
pub mod prelude {
    #[doc(no_inline)]
    pub use crate::{ConfigTrait, Identifier, KeriEvent};
}
```

- [ ] **Step 4: Verify `internals` survived the move**

The five gated constructors must still be gated, on the new crate's own feature:

```bash
rg -n '#\[cfg\(feature = "internals"\)\]' keri-events/src | wc -l
```

Expected: `5` — `inception.rs`, `rotation.rs`, `interaction.rs`, and two in `delegation.rs` (spec §5.3). The attribute text is unchanged; it now refers to `keri-events`'s feature rather than `cesr`'s.

- [ ] **Step 5: Remove `keri` from `cesr`**

In `cesr/src/lib.rs` delete `#[cfg(feature = "keri")] pub mod keri;` and the prelude blocks re-exporting `ConfigTrait` and `Identifier`/`KeriEvent`.

In `cesr/Cargo.toml` delete the `keri` feature and the `internals` feature — `internals` now lives on `keri-events`.

- [ ] **Step 6: Re-point `keri-codec`**

In `keri-codec/Cargo.toml`:

```toml
keri-events = { path = "../keri-events", version = "0.1", default-features = false, features = ["internals"] }
```

Drop `"keri"` and `"internals"` from its `cesr` features list. Then:

```bash
fd -e rs . keri-codec/src keri-codec/tests keri-codec/benches keri-codec/examples -x sd 'cesr::keri::' 'keri_events::'
fd -e rs . keri-codec/src keri-codec/tests -x sd '\buse cesr::keri\b' 'use keri_events'
```

- [ ] **Step 7: Re-point `keri-rs`**

In `keri/Cargo.toml` add `keri-events` and drop `"keri"` from the `cesr` features list:

```toml
keri-events = { path = "../keri-events", version = "0.1", default-features = false }
```

```bash
fd -e rs . keri/src keri/tests -x sd 'cesr::keri::' 'keri_events::'
fd -e rs . keri/src keri/tests -x sd '\buse cesr::keri\b' 'use keri_events'
```

**`keri-rs` must not enable `keri-events/internals`** — the boundary check enforces this and it is the whole point of §5.3.

- [ ] **Step 8: Add cesr's dev-dependency for the back-edge**

Per spec §4.5, `cesr/src/crypto/verify.rs:193` imports `SigningThreshold` in a `#[cfg(test)]` module. Add to `cesr/Cargo.toml` `[dev-dependencies]`:

```toml
keri-events = { path = "../keri-events", default-features = false, features = ["std"] }
```

Then rewrite that one import:

```bash
sd 'use crate::keri::SigningThreshold;' 'use keri_events::SigningThreshold;' cesr/src/crypto/verify.rs
```

This is a dev-cycle (`cesr` → dev → `keri-events` → `cesr`), which Cargo permits. The test moves nowhere and asserts the same thing.

- [ ] **Step 9: Move the keri test suite**

```bash
mkdir -p keri-events/tests
git mv keri/tests/properties.rs keri-events/tests/
fd -e rs . keri-events/tests -x sd 'cesr::keri::' 'keri_events::'
fd -e rs . keri-events/tests -x sd '\buse cesr::keri\b' 'use keri_events'
```

- [ ] **Step 10: Build the workspace**

```bash
nix develop --command cargo build --workspace > /tmp/build.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "refactor(keri-events)!: move keri module into its own crate

Mechanical carve per spec. BREAKING: cesr::keri is now keri_events; the
internals feature moves to keri-events (see spec 5.3)."
```

### Task 3.3: Gates, docs, and PR

- [ ] **Step 1: Remap the budget**

`free-fn-budget.toml`: `keri = 1` → `keri-events = 1`. Count unchanged. Re-point the directory to `${./keri-events/src}`.

Final budget table:

```toml
[budget]
b64 = 6
core = 0
crypto = 6
cesr-stream = 2
keri-events = 1
keri-codec = 58
keri-rs = 0
```

Every count identical to `main` before the split.

- [ ] **Step 2: Extend version-owner to the final five roots**

```nix
files=$(rg --files -g '*.rs' ${./cesr/src} ${./cesr-stream/src} ${./keri-events/src} ${./keri-codec/src} ${./keri/src} | rg -v '/core/version\.rs$')
```

- [ ] **Step 3: Update the boundary check**

`cesr-keri-boundary` must now assert `keri/Cargo.toml` enables neither `internals` (on `keri-events`) nor `test-utils` (on `cesr`). Verify it can still fail:

```bash
sd 'default-features = false }' 'default-features = false, features = ["internals"] }' keri/Cargo.toml
git add -A
nix build '.#checks.aarch64-darwin.cesr-keri-boundary' > /tmp/gate.log 2>&1; echo "EXIT: $? (expect NON-ZERO)"
git checkout keri/Cargo.toml
```

Expected: non-zero. A boundary check that cannot trip is decoration.

- [ ] **Step 4: Per-crate wasm/no_std for `keri-events`**

Mirror the existing derivations.

- [ ] **Step 5: Versions and changelogs**

`cesr` 0.11.0 → **0.12.0** (`keri` leaving is breaking). Update the dependent requirements across `cesr-stream`, `keri-events`, `keri-codec`, `keri`. Create `keri-events/CHANGELOG.md` (0.1.0). Add the `cesr` 0.12.0 breaking entry.

- [ ] **Step 6: Final CLAUDE.md pass**

The module table is now fully a crate table. Verify no stale references to the `b64`/`core`/`crypto`/`stream`/`keri`/`serder` *feature* gates remain, and that the "single feature-gated crate" framing is gone from both `CLAUDE.md` and `cesr/Cargo.toml`'s `description`.

- [ ] **Step 7: The full gate**

```bash
git add -A
nix flake check > /tmp/gate.log 2>&1; echo "EXIT: $?"
```

Expected: `EXIT: 0`.

- [ ] **Step 8: Verify every acceptance criterion from spec §8**

```bash
# 1. Five crates, no production cycle
nix develop --command cargo metadata --format-version 1 | jq -r '.workspace_members[]' | sort

# 4. Budget counts unchanged
for d in "cesr/src/b64:6" "cesr/src/core:0" "cesr/src/crypto:6" "cesr-stream/src:2" "keri-events/src:1" "keri-codec/src:58"; do
  dir="${d%%:*}"; want="${d##*:}"
  got=$(rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' "$dir" -g '*.rs' | wc -l | tr -d ' ')
  echo "$dir: got=$got want=$want $([ "$got" = "$want" ] && echo OK || echo MISMATCH)"
done

# 5. keri-rs builds with and without wire
nix develop --command cargo build -p keri-rs > /dev/null 2>&1; echo "no-wire: $?"
nix develop --command cargo build -p keri-rs --features wire > /dev/null 2>&1; echo "wire: $?"

# 3. Wire behavior frozen
nix develop --command cargo test --all-features keripy > /tmp/keripy.log 2>&1; echo "keripy: $?"
```

Expected: five members; every budget `OK`; all three builds `0`.

- [ ] **Step 9: The veto criterion — prove no API changed**

Spec §8 point 7. Compare the public surface against the pre-split tag:

```bash
git diff v0.9.0 --stat -- '*/tests/' | tail -1
git diff v0.9.0 -- '*/tests/' | rg '^[+-]' | rg -v '^[+-][+-]' | rg -v '^[+-]use ' | rg -v '^[+-]$'
```

Expected: the second command prints **nothing**. Every test assertion in the repo is byte-identical to the pre-split state; only imports moved. This is the strongest single piece of evidence that the carve was mechanical.

- [ ] **Step 10: Push and PR**

```bash
git push -u origin split/192-keri-events
gh pr create --base main --title "refactor(keri-events)!: carve keri into its own crate (#192 phase 3/3)" --body "..."
```

Body: call out the breaking change, link the spec, note this completes #192 and unblocks #193.

- [ ] **Step 11: Close the card**

Once merged, check off #192's checklist and note in #193 that it is unblocked.

---

## What is explicitly NOT in this plan

Spec §9. Every one of these is #193:

- Publishing or designing away the five `internals` constructors.
- `keri-codec`'s 58 free functions.
- Lifting the cross-crate suites into a `cesr-conformance` member.
- keripy-lexicon type renames (`Serder`, `Diger`, `Siger`, `Verfer`, `Matter`, …).

If a task in this plan tempts you toward any of them, the answer is no. Phase 1 changes paths.
