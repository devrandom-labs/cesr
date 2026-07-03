# Prelude + Flattened Re-exports (P2.1 · #31) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `cesr` an ergonomic public surface — flagship types reachable as `cesr::Matter` and `cesr::core::Matter`, plus a `cesr::prelude` carrying the traits (and a few headliner types) you glob-import.

**Architecture:** Two-tier, purely-additive `pub use` re-exports. Tier 1: each module root re-exports its own flagship types (so `cesr::core::Matter` resolves). Tier 2: `src/lib.rs` re-exports those module-root types to the crate root (so `cesr::Matter` resolves) and defines `pub mod prelude`. Name collisions are resolved by keeping the bare name on the canonical owner and aliasing the other with a module prefix. Every re-export is `#[cfg(feature = "…")]`-gated so it exists only when its module compiles.

**Tech Stack:** Rust 2024, `no_std` + feature gates, `doc_cfg` (already enabled), `#[doc(inline)]`, `cargo nextest` / `cargo test`, the `nix flake check` gate.

**Reference:** spec at `docs/superpowers/specs/2026-07-03-prelude-flatten-design.md`.

---

## Files

- **Modify:** `src/lib.rs` — crate-root re-exports + `pub mod prelude`.
- **Modify:** `src/core/mod.rs` — add module-root re-exports for `Matter` and the `primitives` flagship types.
- **Modify (maybe):** other `src/<module>/mod.rs` files — only if a headliner named in the resolution test is not already re-exported at that module's root (most already are; verify per Task).
- **Create:** `tests/prelude.rs` — resolution tests (the executable spec of what must be reachable).
- **Modify:** `README.md` — fix the `matter::matter::Matter` example (lines ~45).
- **Modify:** `CHANGELOG.md` — `[Unreleased] → ### Added` entry.

---

## Task 0: Post the mandated research comment to issue #31

The issue requires research findings posted **before** implementation. They already live in the spec's "Research findings" section.

- [ ] **Step 1: Post the comment**

```bash
cd /Users/joel/Code/devrandom/cesr
gh issue comment 31 --repo devrandom-labs/cesr --body "$(cat <<'EOF'
## Research findings (P2.1)

**Prelude conventions.** `std::prelude` and `rayon::prelude` are trait-dominated — traits must be in scope for method resolution; concrete types are named (thus imported) explicitly. `tokio` shipped a grab-bag `tokio::prelude` in 0.x and **removed it at 1.0**; `bytes`/`serde` ship no prelude, exposing types at the crate root. Conclusion: a prelude earns its keep for **traits**, not a re-glob of every concrete type.

**Re-exports / no_std / docs.** Crate-root `pub use` is the idiomatic flatten tool; each must be `#[cfg(feature = "…")]`-gated so a lifted type exists only when its module compiles. `doc_cfg` (already enabled) renders the gate on docs.rs; `#[doc(inline)]` pulls real docs onto the root page.

**SemVer.** Adding re-exports + a prelude is **additive → non-breaking** (recorded in CHANGELOG regardless). Removing the `matter::matter::Matter` inception path is the only breaking option and buys nothing → keep it, stop advertising it.

**Decisions (locked):** aggressive crate-root flatten of *types* (functions stay module-qualified per the naming convention); prefix-the-loser collisions (only real one: `CesrVersion` core-vs-stream → core keeps the bare name, stream becomes `StreamCesrVersion`); traits-focused prelude (`CesrEncode`, `KeriSerialize`, `KeriDeserialize`, `Algorithm`, `ConfigTrait` + headliner types).

Full design: `docs/superpowers/specs/2026-07-03-prelude-flatten-design.md`.
EOF
)"
```

Expected: prints the new comment URL.

---

## Task 1: `tests/prelude.rs` — failing resolution test for module-root paths

**Files:**
- Test: `tests/prelude.rs` (create)

This test is the executable spec: it names every path that must resolve. It fails to **compile** until the re-exports exist — that is the red state.

- [ ] **Step 1: Write the failing test**

Create `tests/prelude.rs`:

```rust
//! Resolution tests for the flattened public surface (#31).
//! These prove import paths exist; failure mode is a compile error.

// Tier-1: module-root flagship paths must resolve.
#[cfg(feature = "core")]
#[test]
fn core_module_root_paths_resolve() {
    // Type-level use is enough; we only assert these names resolve.
    #[allow(unused_imports)]
    use cesr::core::{Diger, Matter, Signer, Verfer};
    let _ = core::any::type_name::<Matter<'_, cesr::core::matter::code::VerKeyCode>>();
}
```

- [ ] **Step 2: Run it and verify it FAILS to compile**

Run: `nix develop --command cargo test --test prelude --features core 2>&1 | tail -20`
Expected: FAIL — `unresolved import cesr::core::Matter` (or `Diger`/`Signer`/`Verfer`), because `core/mod.rs` does not yet re-export them.

---

## Task 2: Module-root re-exports in `src/core/mod.rs`

**Files:**
- Modify: `src/core/mod.rs`

Make `cesr::core::Matter` and the primitive aliases resolve. `stream`, `crypto`, `keri`, `serder` already re-export their flagships at their module roots (verified: `stream::CesrGroup`, `crypto::KeyPair`, `keri::Identifier`, `serder::KeriSerialize`, etc.). `core` is the gap — it only `pub mod`s `matter`/`primitives` without lifting their contents.

- [ ] **Step 1: Add the re-exports**

In `src/core/mod.rs`, after the existing `pub mod primitives;` line, add:

```rust
pub use matter::Matter;
pub use primitives::{
    Cigar, Dater, Diger, Labeler, Noncer, Number, Prefixer, Saider, Seqner, Signer, Siger,
    Texter, Tholder, Verfer, Verser,
};
```

(These names come from `src/core/primitives/mod.rs`'s `pub use` / `pub type` lines and `src/core/matter/mod.rs`'s `pub use matter::Matter`.)

- [ ] **Step 2: Run the resolution test — verify it PASSES**

Run: `nix develop --command cargo test --test prelude --features core 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/core/mod.rs tests/prelude.rs
git commit -m "feat(#31): re-export core flagship types at module root

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Crate-root flatten in `src/lib.rs` (with the collision alias)

**Files:**
- Modify: `src/lib.rs`
- Test: `tests/prelude.rs` (extend)

- [ ] **Step 1: Extend the test with crate-root paths + the collision**

Append to `tests/prelude.rs`:

```rust
// Tier-2: crate-root flat paths must resolve.
#[cfg(feature = "core")]
#[test]
fn crate_root_core_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{Diger, Matter, Signer, Verfer};
}

#[cfg(feature = "crypto")]
#[test]
fn crate_root_crypto_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{Ed25519, KeyPair, Secp256k1, Secp256r1};
}

#[cfg(feature = "stream")]
#[test]
fn crate_root_stream_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{CesrGroup, CesrMessage, ColdCode};
}

#[cfg(feature = "keri")]
#[test]
fn crate_root_keri_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{Identifier, Ilk, KeriEvent, Role, Seal};
}

// The one real collision: core keeps the bare name, stream is prefixed.
// core::CesrVersion is itself stream-gated, so both exist only when stream is on.
#[cfg(all(feature = "core", feature = "stream"))]
#[test]
fn cesr_version_collision_is_disambiguated() {
    #[allow(unused_imports)]
    use cesr::{CesrVersion, StreamCesrVersion};
}
```

- [ ] **Step 2: Run to verify the new tests FAIL to compile**

Run: `nix develop --command cargo test --test prelude --features core,crypto,stream,keri 2>&1 | tail -20`
Expected: FAIL — `unresolved import cesr::Matter` etc.

- [ ] **Step 3: Add crate-root re-exports to `src/lib.rs`**

In `src/lib.rs`, after the `pub mod stream;` block (before the `#[cfg(test)]` line), add:

```rust
#[cfg(feature = "core")]
#[doc(inline)]
pub use core::{
    Cigar, Dater, Diger, Labeler, Matter, Noncer, Number, Prefixer, Saider, Seqner, Signer, Siger,
    Texter, Tholder, Verfer, Verser,
};
#[cfg(feature = "crypto")]
#[doc(inline)]
pub use crypto::{Algorithm, Ed25519, KeyPair, Secp256k1, Secp256r1};
#[cfg(feature = "keri")]
#[doc(inline)]
pub use keri::{Identifier, Ilk, KeriError, KeriEvent, KeyState, Role, Seal};
#[cfg(feature = "serder")]
#[doc(inline)]
pub use serder::{
    InceptionBuilder, InteractionBuilder, KeriDeserialize, KeriSerialize, RotationBuilder,
    SerderError,
};
#[cfg(feature = "stream")]
#[doc(inline)]
pub use stream::{
    CesrCodec, CesrEncode, CesrGroup, CesrMessage, ColdCode, Groups, GroupsV2, ParseError, Tritet,
    V1, V2,
};

// Collision: core keeps the bare `CesrVersion`; stream's is module-prefixed.
// core::CesrVersion is stream-gated, so guard the bare export on both features.
#[cfg(all(feature = "core", feature = "stream"))]
#[doc(inline)]
pub use core::CesrVersion;
#[cfg(feature = "stream")]
#[doc(inline)]
pub use stream::CesrVersion as StreamCesrVersion;
```

Note: functions (`encode_int`, `parse_message`, `verify`, …) are intentionally **not** lifted — they stay `cesr::b64::encode_int`, `cesr::stream::parse_message` per the naming convention.

- [ ] **Step 4: Run to verify tests PASS**

Run: `nix develop --command cargo test --test prelude --features core,crypto,stream,keri,serder 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs tests/prelude.rs
git commit -m "feat(#31): flatten flagship types to the crate root

CesrVersion collision resolved: core keeps the bare name, stream is
re-exported as StreamCesrVersion.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `cesr::prelude`

**Files:**
- Modify: `src/lib.rs`
- Test: `tests/prelude.rs` (extend)

- [ ] **Step 1: Extend the test — prelude glob brings traits into scope**

Append to `tests/prelude.rs`:

```rust
#[cfg(all(feature = "core", feature = "stream"))]
#[test]
fn prelude_glob_resolves() {
    // Glob import must not error and must bring the headliner types + traits in.
    #[allow(unused_imports)]
    use cesr::prelude::*;
    // Reference a couple of headliners to prove they are in scope via the glob.
    #[allow(unused_imports)]
    use cesr::prelude::{CesrGroup, Matter};
}
```

- [ ] **Step 2: Run to verify it FAILS to compile**

Run: `nix develop --command cargo test --test prelude --features core,stream 2>&1 | tail -20`
Expected: FAIL — `unresolved import cesr::prelude`.

- [ ] **Step 3: Add the prelude module to `src/lib.rs`**

Append to `src/lib.rs` (after the crate-root re-exports from Task 3):

```rust
/// The common imports for working with `cesr`.
///
/// `use cesr::prelude::*;` brings the traits you need in scope for method
/// resolution, plus a handful of headliner types so you can write code from the
/// glob alone. Every other public type is reachable at the crate root
/// (`cesr::Matter`) or its module path (`cesr::core::Matter`).
pub mod prelude {
    // Traits — the primary payload (needed implicitly for method resolution).
    #[cfg(feature = "crypto")]
    #[doc(no_inline)]
    pub use crate::crypto::Algorithm;
    #[cfg(feature = "keri")]
    #[doc(no_inline)]
    pub use crate::keri::ConfigTrait;
    #[cfg(feature = "serder")]
    #[doc(no_inline)]
    pub use crate::serder::{KeriDeserialize, KeriSerialize};
    #[cfg(feature = "stream")]
    #[doc(no_inline)]
    pub use crate::stream::CesrEncode;

    // Headliner types — enough to write code from the glob alone.
    #[cfg(feature = "core")]
    #[doc(no_inline)]
    pub use crate::core::{Diger, Matter, Signer, Verfer};
    #[cfg(feature = "keri")]
    #[doc(no_inline)]
    pub use crate::keri::{Identifier, KeriEvent};
    #[cfg(feature = "stream")]
    #[doc(no_inline)]
    pub use crate::stream::{CesrGroup, CesrMessage};
}
```

- [ ] **Step 4: Run to verify tests PASS**

Run: `nix develop --command cargo test --test prelude --features core,crypto,stream,keri,serder 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs tests/prelude.rs
git commit -m "feat(#31): add cesr::prelude (traits + headliner types)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Fix README and CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Fix the README example**

In `README.md`, replace the line:

```rust
use cesr::core::matter::matter::Matter; // import name is always `cesr`
```

with:

```rust
use cesr::Matter;          // flagship types at the crate root
use cesr::prelude::*;      // or bring the common traits + types in at once
```

- [ ] **Step 2: Add the CHANGELOG entry**

In `CHANGELOG.md`, under `## [Unreleased]` → `### Added`, add a bullet:

```markdown
- **devx (#31):** ergonomic public surface — flagship types are now reachable at
  the crate root (`cesr::Matter`, `cesr::Verfer`, `cesr::CesrGroup`, …) and at
  their module root (`cesr::core::Matter`), and a new `cesr::prelude` re-exports
  the common traits (`CesrEncode`, `KeriSerialize`/`KeriDeserialize`, `Algorithm`,
  `ConfigTrait`) plus headliner types for `use cesr::prelude::*;`. Purely
  additive — existing module paths are unchanged. The one name collision,
  `CesrVersion`, is disambiguated at the root as `cesr::CesrVersion` (core) and
  `cesr::StreamCesrVersion` (stream). Free functions remain module-qualified
  (`cesr::b64::encode_int`).
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs(#31): document flat imports + prelude; drop matter::matter example

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Full gate

- [ ] **Step 1: Stage everything new (flake check needs staged files)**

```bash
cd /Users/joel/Code/devrandom/cesr
git add -A
```

- [ ] **Step 2: Run the single gate**

Run: `nix flake check`
Expected: all checks pass — clippy, rustfmt, taplo, audit, deny, nextest (incl. new `tests/prelude.rs` across feature combos), doctests, `cesr-wasm`, `cesr-nostd`.

- [ ] **Step 3: If clippy/fmt complain, fix inline and re-run**

Likely nits: `cargo fmt` re-wrapping the `pub use { … }` lists; a `redundant_pub_crate` or `unused_imports` in the test (the `#[allow(unused_imports)]` guards against the latter). Fix and re-run `nix flake check` until green. Do **not** relax any lint.

---

## Self-Review

- **Spec coverage:** §1 crate-root flatten → Tasks 2,3. §2 collision → Task 3 (`StreamCesrVersion`). §3 prelude → Task 4. §4 SemVer/back-compat → Task 5 (CHANGELOG, README; `matter::matter` left compilable). §5 testing → `tests/prelude.rs` (Tasks 1,3,4) + `nix flake check` (Task 6). Research comment → Task 0. All covered.
- **Placeholder scan:** every step has concrete code/commands; no TBD.
- **Type consistency:** the type list in `src/lib.rs` (Task 3), `src/core/mod.rs` (Task 2), and `tests/prelude.rs` uses the same names throughout (`Matter`, `Verfer`, `Diger`, `Signer`, `CesrGroup`, `CesrMessage`, `KeriEvent`, `Identifier`, `CesrVersion`/`StreamCesrVersion`). `CesrCodec` is treated as a struct (root type, not a prelude trait) consistent with the spec.

### Known verification points during execution
- Confirm each headliner named in `tests/prelude.rs` is actually re-exported at its module root before lifting it in `lib.rs`; if a name is missing at a module root, add the module-root `pub use` first (same pattern as Task 2). The `cargo test --test prelude` red/green cycle catches any miss.
- If `cargo fmt` reorders the re-export lists, accept its ordering.
