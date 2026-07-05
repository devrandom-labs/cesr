# `Matter::to_qb64` in `core` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `Matter<C>` an infallible `to_qb64`/`to_qb64b` text encoder in `core`, delete the misplaced `stream::encode::matter_to_qb64`, and simplify `serder` accordingly — resolving issue #67's feature-overreach, read/write-asymmetry, and error-domain smells.

**Architecture:** Move the existing byte-producing encoder body from `stream/encode.rs` onto `impl<'a, C: CesrCode> Matter<'a, C>` in `core`, dropping its `Result` (its only failure modes are unreachable internal-invariant breaks for a validated `Matter`, handled with `assert!`/`unreachable!` exactly as `Indexer::to_qb64` already does). `serder`'s `to_qb64_string`/`identifier_to_qb64_string` become infallible (`-> String`), which lets `SerderError::Qb64Encoding(ParseError)` and `SerderError::Encoding(FromUtf8Error)` be deleted; ~40 call sites shed their `?`/`.unwrap()`/`.expect()` under compiler guidance.

**Tech Stack:** Rust (edition 2024, stable 1.95.0), `base64` (already `core`-gated via `core = ["dep:base64", ...]`), `thiserror`, `cargo-nextest`, Nix flake gate.

**Verification gate (whole crate):** `nix develop --command cargo nextest run` for fast test loops; the authoritative gate is `nix flake check` (clippy god-level, fmt, taplo, audit, deny, nextest across feature combos, doctest, wasm, no_std). Per repo rules, **never** use `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` in production code; `assert!`/`assert_eq!`/`unreachable!` are permitted for provably-impossible invariants (as `Indexer::to_qb64` already uses).

---

## File Structure

- **`src/core/matter/matter.rs`** — Modify. Add `to_qb64b`/`to_qb64` inherent methods to `impl<'a, C: CesrCode> Matter<'a, C>`; add a `#[cfg(test)] mod to_qb64` with the relocated round-trip tests. Add top-of-file imports (`SizeType`, `base64::Engine`, `URL_SAFE_NO_PAD`, `String`, `Vec`).
- **`src/stream/encode.rs`** — Modify. Delete `matter_to_qb64` and its `#[cfg(test)] mod matter_qb64`. Remove now-unused module-level imports (`Matter`, `CesrCode`, `SizeType`); move `base64::Engine` + `general_purpose as b64` into the `mod tests` block (still used by other tests).
- **`src/serder/primitives.rs`** — Modify. `to_qb64_string`/`identifier_to_qb64_string` return `String`. Drop `matter_to_qb64` and `SerderError` imports. Update the two unit tests.
- **`src/serder/error.rs`** — Modify. Delete `Qb64Encoding` and `Encoding` variants; drop `ParseError` and `FromUtf8Error` imports.
- **`src/serder/serialize.rs`, `serialize/{icp,rot,ixn,dip,drt}.rs`, `said.rs`, `deserialize.rs`** — Modify. Remove trailing `?` (production) and `.unwrap()`/`.expect(...)` (tests) after the two now-infallible functions. Compiler-guided.
- **`src/keripy_diff/matter.rs`** — Modify. Replace `.unwrap_or_else(|e| panic!(...))` on the now-`String` result with a direct binding.
- **`CHANGELOG.md`** — Modify. Add breaking-change entries under `## [Unreleased] → ### Changed`.

---

## Task 1: Add `Matter::to_qb64b` / `to_qb64` in `core`

**Files:**
- Modify: `src/core/matter/matter.rs`
- Test: `src/core/matter/matter.rs` (new `#[cfg(test)] mod to_qb64`)

- [ ] **Step 1: Add the test module (failing test first)**

At the **end** of `src/core/matter/matter.rs`, *inside* the existing `#[cfg(test)] mod tests { ... }` block (just before its closing `}`), add this submodule. It mirrors the round-trips being retired from `stream/encode.rs`, adapted to the new inherent methods:

```rust
    mod to_qb64 {
        use super::*;
        use crate::core::matter::builder::MatterBuilder;
        use crate::core::matter::code::{MatterCode, VerKeyCode};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        fn build_and_check(expected: &[u8]) {
            let matter = MatterBuilder::new()
                .from_qualified_base64(expected)
                .expect("valid qb64 should parse");
            // qb64b (bytes) round-trips
            assert_eq!(matter.to_qb64b(), expected, "to_qb64b mismatch");
            // qb64 (String) round-trips and agrees with qb64b
            assert_eq!(matter.to_qb64().as_bytes(), expected, "to_qb64 mismatch");
            assert_eq!(
                matter.to_qb64().into_bytes(),
                matter.to_qb64b(),
                "to_qb64 and to_qb64b disagree"
            );
        }

        fn fixed_qb64(code_char: &str, raw: &[u8], ps: usize) -> Vec<u8> {
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(raw);
            let payload_b64 = B64.encode(&padded);
            format!("{code_char}{}", &payload_b64[ps..]).into_bytes()
        }

        #[test]
        fn ed25519_verkey_roundtrip() {
            build_and_check(&fixed_qb64("D", &[0xABu8; 32], 1));
        }

        #[test]
        fn ed25519_sig_roundtrip() {
            build_and_check(&fixed_qb64("0B", &[0xEFu8; 64], 2));
        }

        #[test]
        fn blake3_256_digest_roundtrip() {
            build_and_check(&fixed_qb64("E", &[0xCDu8; 32], 1));
        }

        #[test]
        fn short_number_roundtrip() {
            build_and_check(b"MAAB");
        }

        #[test]
        fn strb64_variable_soft_roundtrip() {
            // Variable-size code (StrB64 lead-0): ss > 0, exercising the
            // soft-field write branch (xtra underscores + soft tail).
            build_and_check(b"4AACnhE8oa_r");
        }

        #[test]
        fn narrowed_verkey_encodes_same_as_untyped() {
            let qb64 = b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let untyped = MatterBuilder::new()
                .from_qualified_base64(&qb64[..])
                .expect("valid qb64");
            assert_eq!(*untyped.code(), MatterCode::Ed25519);
            let typed: Matter<'_, VerKeyCode> = untyped.narrow().expect("narrow to verkey");
            assert_eq!(typed.to_qb64b(), qb64, "typed to_qb64b mismatch");
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `nix develop --command cargo nextest run -E 'test(/core::matter::matter::tests::to_qb64/)' 2>&1 | tail -20`
Expected: **compile error** — `no method named `to_qb64b` / `to_qb64` found for struct `Matter``.

- [ ] **Step 3: Add the imports**

At the top of `src/core/matter/matter.rs`, the current imports are:

```rust
use super::code::{CesrCode, MatterCode};
use super::error::ValidationError;
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, vec};
```

Replace that block with (adds `SizeType`, base64 items, and `String`/`Vec` to the alloc prelude):

```rust
use super::code::{CesrCode, MatterCode};
use super::error::ValidationError;
use super::sizage::SizeType;
use alloc::borrow::Cow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
```

- [ ] **Step 4: Implement the methods**

Add this block immediately **after** the existing `impl<'a, C: CesrCode> Matter<'a, C> { ... }` block that contains `new`/`code`/`raw`/`soft` (i.e. right after its closing `}`, before `impl<C: CesrCode> Matter<'_, C>` for `into_static`):

```rust
impl<C: CesrCode> Matter<'_, C> {
    /// Encodes this primitive into its qualified Base64 (qb64) CESR wire
    /// format as bytes (`qb64b`).
    ///
    /// The output is allocated once at the final size `fs`; the Base64 payload
    /// is written directly into it, then the header (code + soft field) is
    /// written over the first `cs` bytes. Supports all fixed- and variable-size
    /// CESR codes.
    ///
    /// # Panics
    ///
    /// Panics only on an internal-invariant break (a corrupt sizage table or a
    /// mis-sized output buffer) — impossible for any `Matter` built through the
    /// validated builder. This mirrors [`Indexer::to_qb64`] and is the
    /// programmer-bug carve-out, not a data-validation path.
    #[must_use]
    pub fn to_qb64b(&self) -> Vec<u8> {
        let sizage = self.code.get_sizage();
        let hs = sizage.hs();
        let ss = sizage.ss();
        let xs = sizage.xs();
        let ls = sizage.ls();
        let cs = hs + ss;
        let ps = cs % 4;

        let code_str = self.code.as_str();
        let raw = self.raw();

        let fs = match sizage.fs() {
            SizeType::Fixed(fixed) => usize::from(*fixed),
            SizeType::Small | SizeType::Large => {
                let raw_with_lead = raw.len() + ls;
                let quadlets = raw_with_lead.div_ceil(3);
                (quadlets * 4) + cs
            }
        };

        // Base64-encode `[ls+ps zero bytes] ++ raw`. The leading zero bytes
        // realign the payload to a 3-byte boundary; their Base64 image is `ps`
        // pad chars that land in the header region and are overwritten below.
        let pad_len = ls + ps;
        let mut padded = Vec::with_capacity(pad_len + raw.len());
        padded.resize(pad_len, 0);
        padded.extend_from_slice(raw);

        let mut out = vec![0u8; fs];
        let b64_start = cs - ps;
        let written = match URL_SAFE_NO_PAD.encode_slice(&padded, &mut out[b64_start..]) {
            Ok(n) => n,
            Err(_) => {
                unreachable!("qb64 output buffer is sized to fs; base64 cannot overflow")
            }
        };
        assert_eq!(
            b64_start + written,
            fs,
            "qb64 length mismatch for code {code_str}: expected {fs}, got {}",
            b64_start + written
        );

        out[..hs].copy_from_slice(code_str.as_bytes());
        if ss > 0 {
            out[hs..hs + xs].fill(b'_');
            out[hs + xs..cs].copy_from_slice(self.soft().as_bytes());
        }
        out
    }

    /// Encodes this primitive into its qualified Base64 (qb64) CESR wire format
    /// as a `String`.
    ///
    /// qb64 output is pure ASCII (URL-safe Base64 alphabet + CESR code chars),
    /// so UTF-8 validity is guaranteed by construction.
    ///
    /// # Panics
    ///
    /// Never, in practice: see [`Self::to_qb64b`]. The `from_utf8` step cannot
    /// fail because qb64 bytes are ASCII.
    #[must_use]
    pub fn to_qb64(&self) -> String {
        match String::from_utf8(self.to_qb64b()) {
            Ok(s) => s,
            Err(_) => unreachable!("qb64 bytes are ASCII (base64 alphabet + CESR code chars)"),
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop --command cargo nextest run -E 'test(/core::matter::matter::tests::to_qb64/)' 2>&1 | tail -20`
Expected: **PASS** — all 6 tests green (`ed25519_verkey_roundtrip`, `ed25519_sig_roundtrip`, `blake3_256_digest_roundtrip`, `short_number_roundtrip`, `strb64_variable_soft_roundtrip`, `narrowed_verkey_encodes_same_as_untyped`).

- [ ] **Step 6: Clippy-check the new code**

Run: `nix develop --command cargo clippy --all-features --all-targets 2>&1 | tail -30`
Expected: no new warnings/errors in `src/core/matter/matter.rs`. (If clippy flags the module-level arithmetic, do **not** silence it — it is identical to the code being retired from `stream/encode.rs`, whose inputs are a trusted sizage table + an already-validated `Matter`; note this in the commit if raised.)

- [ ] **Step 7: Commit**

```bash
git add src/core/matter/matter.rs
git commit -m "feat(#67): infallible Matter::to_qb64 / to_qb64b in core

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Delete `stream::encode::matter_to_qb64`

**Files:**
- Modify: `src/stream/encode.rs`

- [ ] **Step 1: Delete the encoder function**

In `src/stream/encode.rs`, delete the section header comment and the whole `matter_to_qb64` function — from this line:

```rust
// ── Matter qb64 encoding helper ──────────────────────────────────────────
```

through the end of the function (its closing `}` after `Ok(out)`), i.e. the entire block currently spanning the doc comment + `pub fn matter_to_qb64<C: CesrCode>(...) -> Result<Vec<u8>, ParseError> { ... }`.

- [ ] **Step 2: Delete the retired test module**

In the same file, inside `#[cfg(test)] mod tests`, delete the comment `// ── matter_to_qb64 tests ──…` and the entire `mod matter_qb64 { ... }` submodule (the one containing `ed25519_verkey_roundtrip`, `ed25519_sig_roundtrip`, `blake3_256_digest_roundtrip`, `short_number_roundtrip`, `narrow_and_encode_verkey`, `strb64_variable_soft_roundtrip`). These now live in `core` (Task 1).

- [ ] **Step 3: Fix imports**

The module-level imports `Matter`, `CesrCode`, and `SizeType` were used **only** by the deleted function. `base64::Engine` and `general_purpose as b64` are still used by other test submodules (`element_groups`), so they must move into the test module.

Delete these three module-level `use` lines:

```rust
use crate::core::matter::Matter;
use crate::core::matter::code::CesrCode;
use crate::core::matter::sizage::SizeType;
```

Delete these two module-level `use` lines:

```rust
use base64::Engine;
use base64::engine::general_purpose as b64;
```

…and re-add them inside the `#[cfg(test)] mod tests` block, immediately after its opening `use super::*;`:

```rust
    use base64::Engine as _;
    use base64::engine::general_purpose as b64;
```

- [ ] **Step 4: Verify the stream crate builds and tests pass**

Run: `nix develop --command cargo nextest run -E 'package(cesr) and test(/stream::encode/)' 2>&1 | tail -20`
Expected: **PASS** — remaining `encode.rs` tests (counters, element/quadlet groups, version strings, `encode_cesr`) green; no reference to `matter_to_qb64` remains.

- [ ] **Step 5: Clippy-check for stray unused imports**

Run: `nix develop --command cargo clippy --all-features --all-targets 2>&1 | tail -30`
Expected: no `unused_imports` in `src/stream/encode.rs`. If any remain, remove them.

- [ ] **Step 6: Commit**

```bash
git add src/stream/encode.rs
git commit -m "refactor(#67)!: remove stream::encode::matter_to_qb64 (moved to core)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Make `serder` qb64 helpers infallible and drop dead error variants

**Files:**
- Modify: `src/serder/primitives.rs`
- Modify: `src/serder/error.rs`
- Modify: `src/serder/serialize.rs`, `src/serder/serialize/{icp,rot,ixn,dip,drt}.rs`, `src/serder/said.rs`, `src/serder/deserialize.rs`
- Modify: `src/keripy_diff/matter.rs`

- [ ] **Step 1: Rewrite `primitives.rs` helpers as infallible**

In `src/serder/primitives.rs`, replace the import block and the two functions.

Delete these two imports:

```rust
use crate::stream::encode::matter_to_qb64;
```
```rust
use crate::serder::error::SerderError;
```

Replace `to_qb64_string` and `identifier_to_qb64_string` with:

```rust
/// Encode a [`Matter`] primitive as a qualified Base64 (qb64) string.
///
/// qb64 output is pure ASCII (URL-safe Base64 alphabet + CESR code chars), so
/// this is infallible for any validly-constructed primitive.
#[must_use]
pub fn to_qb64_string<C: CesrCode>(matter: &Matter<'_, C>) -> String {
    matter.to_qb64()
}

/// Encode an [`Identifier`] as a qualified Base64 (qb64) string.
///
/// Dispatches to the inner `Prefixer` or `Saider` depending on the variant.
#[must_use]
pub fn identifier_to_qb64_string(id: &Identifier<'_>) -> String {
    match id {
        Identifier::Basic(prefixer) => to_qb64_string(prefixer),
        Identifier::SelfAddressing(saider) => to_qb64_string(saider),
    }
}
```

- [ ] **Step 2: Update the two `primitives.rs` unit tests**

In the `#[cfg(test)] mod tests` of the same file, the two assertions currently read:

```rust
        let qb64 = to_qb64_string(&verfer).expect("qb64 encoding should succeed");
```
and
```rust
        let qb64 = to_qb64_string(&saider).expect("qb64 encoding should succeed");
```

Remove the `.expect(...)` from both (the function now returns `String`):

```rust
        let qb64 = to_qb64_string(&verfer);
```
```rust
        let qb64 = to_qb64_string(&saider);
```

- [ ] **Step 3: Delete the two dead error variants**

In `src/serder/error.rs`, delete this import (only the `ParseError` one — keep the `ParsingError`/`ValidationError` import):

```rust
use crate::stream::error::ParseError;
```

Delete this import (its only user is the `Encoding` variant, removed next):

```rust
use alloc::string::FromUtf8Error;
```

Delete both of these variants from `enum SerderError`:

```rust
    /// UTF-8 encoding error when converting CESR bytes to a string.
    #[error("encoding error: {0}")]
    Encoding(#[from] FromUtf8Error),

    /// qb64 encoding of a CESR primitive failed.
    #[error("qb64 encoding error: {0}")]
    Qb64Encoding(#[from] ParseError),
```

- [ ] **Step 4: Fix `keripy_diff` call site**

In `src/keripy_diff/matter.rs`, the current binding is:

```rust
        let qb64 = to_qb64_string(&built)
            .unwrap_or_else(|e| panic!("to_qb64_string for {:?}: {e:?}", v.qb64));
```

Replace with:

```rust
        let qb64 = to_qb64_string(&built);
```

- [ ] **Step 5: Compiler-guided sweep of all remaining call sites**

The signature change turns every `to_qb64_string(x)?` / `identifier_to_qb64_string(x)?` into a compile error ("the `?` operator can only be applied to values that implement `Try`"), and every `.unwrap()` / `.expect(...)` chained onto them into "no method found for `String`". Fix each by deleting the trailing `?` / `.unwrap()` / `.expect(...)`. Run the build repeatedly until clean:

Run: `nix develop --command cargo build --all-features 2>&1 | tail -40`

Known production `?` sites (remove the trailing `?`):
- `src/serder/serialize.rs`: lines with `to_qb64_string(d)?`, `to_qb64_string(rd)?`, `to_qb64_string(i)?`, `to_qb64_string(m)?` (in `map.insert(...)` / `arr.push(...)`).
- `src/serder/serialize/drt.rs`: `identifier_to_qb64_string(rot.prefix())?`, `to_qb64_string(rot.prior_event_said())?`, `to_qb64_string(&said)?`.
- `src/serder/serialize/dip.rs`: `identifier_to_qb64_string(event.delegator())?`, `to_qb64_string(&said)?`.
- `src/serder/serialize/ixn.rs`: `identifier_to_qb64_string(event.prefix())?`, `to_qb64_string(event.prior_event_said())?`, `to_qb64_string(&said)?`.
- `src/serder/serialize/rot.rs`: `identifier_to_qb64_string(event.prefix())?`, `to_qb64_string(event.prior_event_said())?`, `to_qb64_string(&said)?`.
- `src/serder/serialize/icp.rs`: `to_qb64_string(&said)?`.
- `src/serder/said.rs`: `to_qb64_string(&computed)?`.
- `src/serder/deserialize.rs`: `to_qb64_string(&computed)?` (two sites).

Known test `.unwrap()`/`.expect(...)` sites (remove the call):
- `src/serder/said.rs`: `to_qb64_string(&saider).expect("qb64 encoding")`, and the `to_qb64_string(&a)/(&b)` `.expect(...)` pairs.
- `src/serder/serialize/dip.rs` and `icp.rs`: `...to_qb64_string(&computed).unwrap()`.
- `src/serder/deserialize.rs`: `to_qb64_string(m).unwrap()`, and the several `identifier_to_qb64_string(...).unwrap()` assertions.

**Important — do not blanket-delete `?` in these functions.** Only the two qb64 helpers became infallible; other `?` operators in the same expressions/functions (JSON, digest, parsing) must stay. Fix exactly the sites the compiler flags on the two helper calls.

Repeat `cargo build --all-features` until it succeeds with zero errors.

- [ ] **Step 6: Run the serder tests**

Run: `nix develop --command cargo nextest run -E 'package(cesr) and test(/serder/)' --all-features 2>&1 | tail -30`
Expected: **PASS** — all serder serialize/deserialize/said/primitives tests green.

- [ ] **Step 7: Clippy-check**

Run: `nix develop --command cargo clippy --all-features --all-targets 2>&1 | tail -30`
Expected: no errors. In particular no `unused_imports` in `serder/error.rs` or `serder/primitives.rs`, and no "variant never constructed" for `SerderError`.

- [ ] **Step 8: Commit**

```bash
git add src/serder/ src/keripy_diff/matter.rs
git commit -m "refactor(#67)!: infallible serder qb64 helpers; drop dead SerderError variants

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: CHANGELOG + full gate

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add CHANGELOG entries**

In `CHANGELOG.md`, under `## [Unreleased]` → `### Changed`, add (keep the existing entries; append these bullets):

```markdown
- **core / serder (#67):** qb64 text encoding moved to `core`. **Breaking**
  (MINOR under 0.x):
  - `Matter<C>` gains infallible `to_qb64() -> String` and `to_qb64b() -> Vec<u8>`;
    encoding a key/digest to text no longer requires the `stream` feature.
  - `stream::encode::matter_to_qb64` **removed** (use `Matter::to_qb64b`).
  - `serder::primitives::{to_qb64_string, identifier_to_qb64_string}` now return
    `String` instead of `Result<String, SerderError>`.
  - `SerderError` loses the `Qb64Encoding` and `Encoding` variants (their only
    producers are gone). Breaking for downstream exhaustive `match` on `SerderError`.
```

- [ ] **Step 2: Run the full gate**

Run: `nix flake check`
Expected: **all checks pass** — clippy, rustfmt, taplo, cargo-audit, cargo-deny, nextest (across feature combinations), doctest, `cesr-wasm`, `cesr-nostd`. The relocated round-trip tests compile and pass under the `core`-only feature set, proving encode no longer depends on `stream`.

If `taplo`/`fmt` flag formatting: run `nix develop --command cargo fmt` and `nix develop --command taplo fmt`, then re-run `nix flake check`.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(#67): changelog for Matter::to_qb64 move to core

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review Notes (traceability to spec)

- Spec §1 "New inherent methods" → **Task 1** (`to_qb64b` byte core + `to_qb64` String wrapper, infallible, `assert!`/`unreachable!` on invariants).
- Spec §2 "Delete `stream::encode::matter_to_qb64`" → **Task 2** (function + `mod matter_qb64` removed; imports fixed).
- Spec §3 "Migrate `serder`" → **Task 3** (infallible helpers; `Qb64Encoding` + `Encoding` removed; ~40 call sites swept; `keripy_diff` fixed).
- Spec §4 "Tests in `core`" → **Task 1 Step 1** (6 round-trips relocated + qb64/qb64b consistency assertion + `from_qualified_base64`↔`to_qb64b` round-trip).
- Spec "Breaking changes" → **Task 4** (CHANGELOG) + `!`-marked commits in Tasks 2 & 3.
- Non-goals (no `to_qb2`, no `Indexer`/`Siger` change, no new error type) respected — no task introduces them.
```
