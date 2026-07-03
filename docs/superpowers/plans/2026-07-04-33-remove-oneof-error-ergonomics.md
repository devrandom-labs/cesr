# Remove `terrors::OneOf` — Error Ergonomics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every `terrors::OneOf<(...)>` return with a purpose-built `thiserror` enum (or a bare error type where the union has one member), and drop the `terrors` dependency entirely.

**Architecture:** Two new domain error enums — `MatterBuildError` (matter builder) and `VerificationError` (crypto verify) — each a 2-variant `thiserror` enum with `#[from]` on both variants so `?` keeps working. The indexer's single-element `OneOf<(E,)>` unions collapse to bare `E`. Serder gains a new `UnparseablePrimitive` variant so a `ParsingError` is no longer string-jammed into a `ValidationError`. No `#[non_exhaustive]` (pre-1.0; exhaustive matching serves tag-pinning consumers).

**Tech Stack:** Rust (edition 2024, stable 1.95.0), `thiserror`, `nix flake check` gate.

**Spec:** `docs/superpowers/specs/2026-07-04-33-remove-oneof-error-ergonomics-design.md`

**Branch:** `feat/33-remove-oneof` (already created off `origin/main`).

---

## File Map

| File | Change |
|---|---|
| `src/core/matter/error.rs` | **Add** `MatterBuildError` enum + unit tests |
| `src/core/matter/builder.rs` | Swap 4 return types `OneOf<(ParsingError, ValidationError)>` → `MatterBuildError`; rewrite `OneOf::new(x)` → `MatterBuildError::from(x)` / `.map_err(OneOf::new)` → `.map_err(MatterBuildError::from)`; drop `use terrors::OneOf`; delete two `#[allow(clippy::type_complexity …)]` |
| `src/crypto/error.rs` | **Add** `VerificationError` enum + unit tests |
| `src/crypto/verify.rs` | Swap 2 return types → `VerificationError`; rewrite `OneOf::new`/`.map_err(OneOf::new)`; drop `use terrors::OneOf`; migrate test `.narrow::<T,_>()` → `matches!` on enum |
| `src/core/indexer/builder.rs` | Swap 5 return types to bare `IndexerParseError` / `IndexerValidationError`; rewrite `OneOf::new(x)` → `x`; drop `use terrors::OneOf`; migrate test `.take::<T>()` → drop the call |
| `src/serder/error.rs` | **Add** `UnparseablePrimitive { field, source: ParsingError }` variant + `use` for `ParsingError` |
| `src/serder/deserialize.rs` | Change `map_qb64_error` param to `MatterBuildError`, rewrite as a `match`; add regression test |
| `Cargo.toml` | Remove `dep:terrors` from `core` feature (line 49) and the `terrors = …` dep (line 96) |
| `CHANGELOG.md` | Add `### Changed` entry under `[Unreleased]` |

**Ordering rationale:** matter first (its enum is consumed by serder), then crypto and indexer (independent), then serder (depends on `MatterBuildError`), then Cargo.toml removal (only safe once all `OneOf` uses are gone), then the full gate.

---

## Task 1: Add `MatterBuildError` to matter/error.rs

**Files:**
- Modify: `src/core/matter/error.rs` (append after `ValidationError`, before any `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Append a test module at the end of `src/core/matter/error.rs`:

```rust
#[cfg(test)]
mod build_error_tests {
    use super::{MatterBuildError, ParsingError, ValidationError};

    #[test]
    fn from_parsing_error_lands_in_parsing_variant() {
        let e: MatterBuildError = ParsingError::EmptyStream.into();
        assert_eq!(e, MatterBuildError::Parsing(ParsingError::EmptyStream));
    }

    #[test]
    fn from_validation_error_lands_in_validation_variant() {
        let ve = ValidationError::StructuralIntegrityError;
        let e: MatterBuildError = ve.clone().into();
        assert_eq!(e, MatterBuildError::Validation(ve));
    }

    #[test]
    fn display_is_transparent_to_source() {
        let e: MatterBuildError = ParsingError::EmptyStream.into();
        assert_eq!(e.to_string(), ParsingError::EmptyStream.to_string());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test --features core --lib core::matter::error::build_error_tests 2>&1 | tail -20`
Expected: FAIL — `cannot find type MatterBuildError in this scope`.

- [ ] **Step 3: Add the enum**

Insert immediately after the closing `}` of `ValidationError` (currently line 171), before the test module:

```rust
/// Error returned by [`MatterBuilder`](super::builder::MatterBuilder) parse and
/// build operations: either the input was structurally unparseable
/// ([`ParsingError`]) or it parsed but violated a CESR validation rule
/// ([`ValidationError`]).
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum MatterBuildError {
    /// The input could not be parsed into a CESR primitive.
    #[error(transparent)]
    Parsing(#[from] ParsingError),

    /// The input parsed but failed a validation constraint.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test --features core --lib core::matter::error::build_error_tests 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 5: Export the type**

Confirm `MatterBuildError` is re-exported wherever `ParsingError` / `ValidationError` are. Run:
`grep -rn "ParsingError" src/core/matter/mod.rs src/core/mod.rs src/lib.rs`
For each place that re-exports `ValidationError`, add `MatterBuildError` alongside it (same `pub use` line). If `ParsingError`/`ValidationError` are not re-exported there, do nothing.

- [ ] **Step 6: Commit**

```bash
git add src/core/matter/error.rs src/core/matter/mod.rs
git commit -m "feat(#33): add MatterBuildError enum replacing OneOf union"
```

---

## Task 2: Migrate matter/builder.rs to `MatterBuildError`

**Files:**
- Modify: `src/core/matter/builder.rs`

- [ ] **Step 1: Change the import**

Delete line 18 `use terrors::OneOf;`. Add `MatterBuildError` to the `super::error` import on line 4:

```rust
use super::{
    MatterPart,
    code::{CesrCode, MatterCode},
    error::{MatterBuildError, ParsingError, ValidationError},
    matter::Matter,
    sizage::{Sizage, SizeType},
};
```

- [ ] **Step 2: Change the four return types**

At lines 101, 219, 367, 420 replace:
`) -> Result<Matter<'a, MatterCode>, OneOf<(ParsingError, ValidationError)>> {`
and `) -> Result<Matter<'_, MatterCode>, OneOf<(ParsingError, ValidationError)>> {`
and `pub fn build(self) -> Result<Matter<'a, C>, OneOf<(ParsingError, ValidationError)>> {`
with the same signature but `MatterBuildError` in place of `OneOf<(ParsingError, ValidationError)>`. E.g.:

```rust
pub fn build(self) -> Result<Matter<'a, C>, MatterBuildError> {
```

- [ ] **Step 3: Rewrite the error-construction sites**

Apply these two mechanical rules across the whole file (matches every remaining `OneOf` occurrence except the ones already removed):

1. `OneOf::new(EXPR)` → `MatterBuildError::from(EXPR)` — works for both a `ParsingError` and a `ValidationError` value via `#[from]`.
2. `.map_err(OneOf::new)` → `.map_err(MatterBuildError::from)`.

Concretely this covers, e.g.:
- `return Err(OneOf::new(ParsingError::EmptyStream));` → `return Err(MatterBuildError::from(ParsingError::EmptyStream));`
- `MatterCode::from_base64_stream(&stream).map_err(OneOf::new)?` → `.map_err(MatterBuildError::from)?`
- `.map_err(|err| OneOf::new(ParsingError::InvalidUtf8(err)))?` → `.map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?`
- `.ok_or_else(|| OneOf::new(ParsingError::EmptyStream))?` → `.ok_or_else(|| MatterBuildError::from(ParsingError::EmptyStream))?`

Verify none remain: `grep -n "OneOf" src/core/matter/builder.rs` must print nothing.

- [ ] **Step 4: Delete the two `type_complexity` allows**

Remove both attribute blocks (currently at lines ~355–358 and ~408–411):

```rust
#[allow(
    clippy::type_complexity,
    reason = "OneOf error union is inherently complex"
)]
```

The return type is now a plain enum, so the lint no longer fires and the allow would be unused.

- [ ] **Step 5: Migrate the in-file test extraction site**

At line ~734 the test uses `.narrow::<crate::core::matter::error::ValidationError, _>()`. Replace the extraction with a `match`/`matches!` on `MatterBuildError`. Read the surrounding test (lines ~725–745) and rewrite, e.g.:

```rust
// before: let ve = err.narrow::<ValidationError, _>().unwrap(); assert on ve
// after:
let MatterBuildError::Validation(ve) = err else {
    panic!("expected Validation variant, got {err:?}");
};
// ... existing assertions on `ve` unchanged
```

- [ ] **Step 6: Run the matter tests to verify they pass**

Run: `nix develop --command cargo test --features core --lib core::matter 2>&1 | tail -20`
Expected: PASS (all existing matter tests, now returning `MatterBuildError`).

- [ ] **Step 7: Commit**

```bash
git add src/core/matter/builder.rs
git commit -m "refactor(#33): matter builder returns MatterBuildError, drop OneOf"
```

---

## Task 3: Add `VerificationError` to crypto/error.rs

**Files:**
- Modify: `src/crypto/error.rs`

Note: `SignatureError` and `CodeMismatchError` do **not** derive `PartialEq`, so `VerificationError` cannot derive `PartialEq` either. Tests use `matches!`, not `assert_eq!`.

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` in `src/crypto/error.rs`:

```rust
    #[test]
    fn verification_error_from_signature_error() {
        let e: VerificationError = SignatureError::Invalid.into();
        assert!(matches!(e, VerificationError::Signature(SignatureError::Invalid)));
    }

    #[test]
    fn verification_error_from_code_mismatch() {
        let cm = CodeMismatchError::IncompatibleCodes {
            verkey: "Ed25519".into(),
            signature: "ECDSA256k1Sig".into(),
        };
        let e: VerificationError = cm.into();
        assert!(matches!(
            e,
            VerificationError::CodeMismatch(CodeMismatchError::IncompatibleCodes { .. })
        ));
    }

    #[test]
    fn verification_error_display_is_transparent() {
        let e: VerificationError = SignatureError::Invalid.into();
        assert_eq!(e.to_string(), SignatureError::Invalid.to_string());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test --features crypto --lib crypto::error 2>&1 | tail -20`
Expected: FAIL — `cannot find type VerificationError in this scope`.

- [ ] **Step 3: Add the enum**

Insert after `CodeMismatchError` (currently ends line 95), before the `#[cfg(test)]` module:

```rust
/// Error returned by signature verification ([`verify`](crate::crypto::verify)):
/// either the verifying-key/signature codes are incompatible
/// ([`CodeMismatchError`]) or the cryptographic check failed
/// ([`SignatureError`]).
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// The cryptographic verification failed or the key/signature bytes were malformed.
    #[error(transparent)]
    Signature(#[from] SignatureError),

    /// The signature's CESR code does not belong to the verifying key's algorithm.
    #[error(transparent)]
    CodeMismatch(#[from] CodeMismatchError),
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test --features crypto --lib crypto::error 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Export the type**

`grep -rn "CodeMismatchError" src/crypto/mod.rs src/lib.rs` — add `VerificationError` to the same `pub use` lines that export `CodeMismatchError`/`SignatureError`.

- [ ] **Step 6: Commit**

```bash
git add src/crypto/error.rs src/crypto/mod.rs
git commit -m "feat(#33): add VerificationError enum replacing OneOf union"
```

---

## Task 4: Migrate crypto/verify.rs to `VerificationError`

**Files:**
- Modify: `src/crypto/verify.rs`

- [ ] **Step 1: Change imports**

Delete line 9 `use terrors::OneOf;`. Change line 12 to include `VerificationError`:

```rust
use crate::crypto::error::{CodeMismatchError, SignatureError, VerificationError};
```

- [ ] **Step 2: Change both return types**

Lines 42 and 66: `) -> Result<(), OneOf<(SignatureError, CodeMismatchError)>> {` →
`) -> Result<(), VerificationError> {`

- [ ] **Step 3: Rewrite the error-construction sites**

- Lines 52 and 68: `Err(OneOf::new(CodeMismatchError::IncompatibleCodes { … }))` →
  `Err(VerificationError::CodeMismatch(CodeMismatchError::IncompatibleCodes { … }))`
- Line 73: `A::verify_bytes(verfer.raw(), data, sig.raw()).map_err(OneOf::new)` →
  `A::verify_bytes(verfer.raw(), data, sig.raw()).map_err(VerificationError::from)`

Verify: `grep -n "OneOf" src/crypto/verify.rs` prints nothing.

- [ ] **Step 4: Migrate the test extraction sites**

Four tests use `err.narrow::<T, _>()`. Rewrite each as a `matches!` on the enum:

- Line ~202–207 (`verify_rejects_wrong_data_standalone`):
```rust
        let err = verify(&verfer, b"wrong", &sig).err().unwrap();
        assert!(matches!(err, VerificationError::Signature(SignatureError::Invalid)));
```
- Line ~280–285 (`verify_secp256k1_sig_with_ed25519_verfer_fails`):
```rust
        let err = verify(&verfer_e, b"test", &sig_k).err().unwrap();
        assert!(matches!(
            err,
            VerificationError::CodeMismatch(CodeMismatchError::IncompatibleCodes { .. })
        ));
```
- Line ~466–471 (`verify_indexed_rejects_tampered_data`):
```rust
        let err = verify(&verfer, b"tampered", &siger).err().unwrap();
        assert!(matches!(err, VerificationError::Signature(SignatureError::Invalid)));
```
- Line ~482–487 (`verify_indexed_rejects_cross_algorithm_code`):
```rust
        let err = verify(&ed_verfer, b"event", &k1_siger).err().unwrap();
        assert!(matches!(
            err,
            VerificationError::CodeMismatch(CodeMismatchError::IncompatibleCodes { .. })
        ));
```

Verify: `grep -n "narrow::" src/crypto/verify.rs` prints nothing.

- [ ] **Step 5: Run the crypto tests to verify they pass**

Run: `nix develop --command cargo test --features crypto --lib crypto::verify 2>&1 | tail -25`
Expected: PASS (all verify tests).

- [ ] **Step 6: Commit**

```bash
git add src/crypto/verify.rs
git commit -m "refactor(#33): crypto verify returns VerificationError, drop OneOf"
```

---

## Task 5: Migrate indexer/builder.rs to bare error types

**Files:**
- Modify: `src/core/indexer/builder.rs`

The single-element `OneOf<(E,)>` unions carry no information beyond `E`, so they collapse to bare `E`.

- [ ] **Step 1: Change the import**

Delete line 11 `use terrors::OneOf;`. Confirm `IndexerParseError` and `IndexerValidationError` are already imported (they are used in the bodies); if not, add them from `super::error`.

- [ ] **Step 2: Change the five return types**

- Lines 84, 198: `) -> Result<(Indexer<'static>, usize), OneOf<(IndexerParseError,)>> {` →
  `) -> Result<(Indexer<'static>, usize), IndexerParseError> {`
- Line 296, 330: `) -> Result<IndexerBuilder<IWithIndex>, OneOf<(IndexerValidationError,)>> {` →
  `) -> Result<IndexerBuilder<IWithIndex>, IndexerValidationError> {`
- Line 385: `) -> Result<Indexer<'a>, OneOf<(IndexerValidationError,)>> {` →
  `) -> Result<Indexer<'a>, IndexerValidationError> {`

- [ ] **Step 3: Rewrite the error-construction sites**

Apply the mechanical rule `OneOf::new(EXPR)` → `EXPR` across the whole file. This covers every remaining `OneOf::new(...)` — e.g.:
- `.ok_or_else(|| OneOf::new(IndexerParseError::EmptyStream))?` → `.ok_or(IndexerParseError::EmptyStream)?`
- `return Err(OneOf::new(IndexerParseError::StreamTooShort { … }));` → `return Err(IndexerParseError::StreamTooShort { … });`
- `.map_err(|_| OneOf::new(IndexerParseError::InvalidBase64))?` → `.map_err(|_| IndexerParseError::InvalidBase64)?`
- `.map_err(|e| OneOf::new(IndexerParseError::from(e)))?` → `.map_err(IndexerParseError::from)?`
- `return Err(OneOf::new(IndexerValidationError::IndexTooLarge { … }));` → `return Err(IndexerValidationError::IndexTooLarge { … });`

Verify: `grep -n "OneOf" src/core/indexer/builder.rs` prints nothing.

- [ ] **Step 4: Migrate the four test extraction sites**

At lines 560, 580, 598, 612 the tests end with `.err().unwrap().take::<IndexerValidationError>();`. The builder now returns the bare error, so delete the `.take::<IndexerValidationError>()` call — `.err().unwrap()` already yields an `IndexerValidationError`. E.g.:

```rust
        let err = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(64)
            .err()
            .unwrap();
        assert_eq!(
            err,
            IndexerValidationError::IndexTooLarge { code: IndexedSigCode::Ed25519, index: 64, max: 63 }
        );
```

Verify: `grep -n "take::" src/core/indexer/builder.rs` prints nothing.

- [ ] **Step 5: Run the indexer tests to verify they pass**

Run: `nix develop --command cargo test --features core --lib core::indexer 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/core/indexer/builder.rs
git commit -m "refactor(#33): indexer builder returns bare error types, drop OneOf"
```

---

## Task 6: Serder — new `UnparseablePrimitive` variant + fix `map_qb64_error`

**Files:**
- Modify: `src/serder/error.rs`
- Modify: `src/serder/deserialize.rs`

This fixes the latent bug where a `ParsingError` is jammed into `ValidationError::UnknownMatterCode(err.to_string())`.

- [ ] **Step 1: Write the failing regression test**

Add to the `#[cfg(test)] mod tests` in `src/serder/deserialize.rs` (create the module if none exists; otherwise append). The test drives a genuine *parse* failure (unknown/malformed qb64 code) through `map_qb64_error` and asserts it surfaces as the new parsing-domain variant:

```rust
    #[test]
    fn unparseable_qb64_field_surfaces_as_parsing_domain_error() {
        // A malformed qb64 primitive (bad code) is a parse failure, not a
        // validation failure — it must not be collapsed into UnknownMatterCode.
        let err = super::parse_qb64_diger("!!not-qb64!!", "d").unwrap_err();
        assert!(
            matches!(err, SerderError::UnparseablePrimitive { field: "d", .. }),
            "expected UnparseablePrimitive, got {err:?}"
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test --features serder --lib serder::deserialize::tests::unparseable 2>&1 | tail -20`
Expected: FAIL — either `no variant named UnparseablePrimitive` or the match fails because the error is currently an `InvalidPrimitive`/`UnknownMatterCode`.

- [ ] **Step 3: Add the new SerderError variant**

In `src/serder/error.rs`, add the import (after line 11's `use crate::core::matter::error::ValidationError;`):

```rust
use crate::core::matter::error::ParsingError;
```

Add the variant inside `SerderError` (after `InvalidPrimitive`, ~line 49):

```rust
    /// Field value could not be parsed as a CESR primitive (malformed code or
    /// length) — distinct from a value that parsed but failed validation.
    #[error("unparseable primitive in field '{field}': {source}")]
    UnparseablePrimitive {
        /// The JSON field name.
        field: &'static str,
        /// The underlying CESR parsing error.
        source: ParsingError,
    },
```

- [ ] **Step 4: Rewrite `map_qb64_error`**

In `src/serder/deserialize.rs`, change the import on line 9 to also bring in `MatterBuildError` and `ParsingError`:

```rust
use crate::core::matter::error::{MatterBuildError, ParsingError, ValidationError};
```

Replace the whole `map_qb64_error` function (currently lines 420–434) with:

```rust
fn map_qb64_error(field: &'static str, err: MatterBuildError) -> SerderError {
    match err {
        MatterBuildError::Validation(source) => SerderError::InvalidPrimitive { field, source },
        MatterBuildError::Parsing(source) => SerderError::UnparseablePrimitive { field, source },
    }
}
```

(The `ParsingError` import is used by this match arm's type; if clippy reports it unused, remove it — but it is referenced via `SerderError::UnparseablePrimitive`'s inferred type, so keep unless the compiler says otherwise.)

- [ ] **Step 5: Run the regression test to verify it passes**

Run: `nix develop --command cargo test --features serder --lib serder::deserialize::tests::unparseable 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Run the full serder suite**

Run: `nix develop --command cargo test --features serder --lib serder 2>&1 | tail -25`
Expected: PASS (existing serder tests unaffected; `parse_qb64_diger`'s `?` now propagates the new error type transparently).

- [ ] **Step 7: Commit**

```bash
git add src/serder/error.rs src/serder/deserialize.rs
git commit -m "fix(#33): serder routes ParsingError to a parsing-domain variant, not a stringified ValidationError"
```

---

## Task 7: Drop the `terrors` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Verify no source references remain**

Run: `grep -rn "terrors\|OneOf\|\.narrow::\|\.take::<" src/`
Expected: no matches in `src/`. If any remain, fix them before proceeding (they will fail to compile without `terrors` anyway).

- [ ] **Step 2: Remove from the `core` feature**

In `Cargo.toml` line 49, delete `"dep:terrors", ` from the `core` feature list:

```toml
core = ["b64", "dep:base64", "dep:num-traits", "dep:strum", "dep:zeroize"]
```

- [ ] **Step 3: Remove the dependency declaration**

Delete line 96: `terrors = { version = "0.3.3", optional = true }`.

- [ ] **Step 4: Verify it builds without terrors**

Run: `nix develop --command cargo build --features serder 2>&1 | tail -15`
Expected: builds clean, no `terrors` in the resolved graph.

Run: `nix develop --command bash -c "cargo tree --features serder 2>/dev/null | grep -c terrors"`
Expected: `0`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(#33): drop terrors dependency"
```

---

## Task 8: CHANGELOG + full gate

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add the CHANGELOG entry**

Under `## [Unreleased]`, add a `### Changed` section (after the existing `### Added`):

```markdown
### Changed

- **error ergonomics (#33):** removed the `terrors::OneOf` error-union layer in
  favour of purpose-built `thiserror` enums. **Breaking** (MINOR under 0.x):
  - `MatterBuilder::{from_qualified_base64, from_qualified_base2, build}` now return
    `Result<_, MatterBuildError>` (variants `Parsing`, `Validation`) instead of
    `OneOf<(ParsingError, ValidationError)>`.
  - `crypto::verify` now returns `Result<(), VerificationError>` (variants
    `Signature`, `CodeMismatch`) instead of `OneOf<(SignatureError, CodeMismatchError)>`.
  - The indexer builder's parse/validation methods return the bare
    `IndexerParseError` / `IndexerValidationError` (previously wrapped in a
    single-element `OneOf`).
  - Consumers matching on these results switch from `.take::` / `.narrow::` to a
    normal `match` on the new enums / bare types.
  - The `terrors` dependency is dropped.

### Fixed

- **serder (#33):** a malformed-but-parseable field value no longer collapses a
  `ParsingError` into `ValidationError::UnknownMatterCode(..)` via string
  formatting; a new `SerderError::UnparseablePrimitive { field, source }` variant
  carries the parsing error in its own failure domain.
```

- [ ] **Step 2: Commit the CHANGELOG**

```bash
git add CHANGELOG.md
git commit -m "docs(#33): changelog for OneOf removal + serder parsing-domain fix"
```

- [ ] **Step 3: Run the full gate**

Run: `nix flake check 2>&1 | tail -40`
Expected: all checks pass (clippy god-level, rustfmt, taplo, audit, deny, nextest across feature combos, doctest, `cesr-wasm`, `cesr-nostd`).

If clippy flags a now-unused import or a leftover allow, fix it and re-run. If `cargo fmt` reports diffs, run `nix develop --command cargo fmt` and amend the relevant commit.

- [ ] **Step 4: Final verification of the outcome**

Run: `grep -rn "terrors\|OneOf" src/ Cargo.toml`
Expected: no matches anywhere.

---

## Self-Review Notes

- **Spec coverage:** Task 1–2 (MatterBuildError), Task 3–4 (VerificationError), Task 5 (indexer bare types), Task 6 (serder variant + bug fix), Task 7 (drop terrors), Task 8 (CHANGELOG + gate). All spec sections mapped.
- **Type consistency:** `MatterBuildError { Parsing, Validation }` and `VerificationError { Signature, CodeMismatch }` used identically in their definition tasks and all consuming/test tasks. `map_qb64_error(field, err: MatterBuildError)` matches Task 1's enum.
- **`PartialEq` caveat** is called out where it matters: matter/indexer errors derive it (tests use `assert_eq!`); crypto errors do not (tests use `matches!`).
