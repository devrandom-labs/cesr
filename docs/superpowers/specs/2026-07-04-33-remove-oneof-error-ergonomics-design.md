# Remove `terrors::OneOf` — error-ergonomics review (#33)

**Date:** 2026-07-04
**Issue:** #33 · P2.3 — Error ergonomics review (Phase 2 · DevX & API)
**Status:** Approved design, ready for implementation plan

## Problem

`cesr` returns error unions as `terrors::OneOf<(...)>`. From a downstream seat this
is awkward:

- Consumers must extract variants with a runtime downcast, `.take::<T>() -> Option<T>`
  / `.narrow::<T, _>()`, instead of a compile-checked `match`. No exhaustiveness, no
  compiler help when a new failure mode is added.
- Two of the call sites use **single-element** `OneOf<(E,)>` — a union of one type.
  That is pure ceremony: the caller unwraps a "union" that was never a union.
- The union type leaks `terrors` into every downstream `match` and adds a dependency
  to the `cargo audit` / `cargo deny` surface.

CLAUDE.md already points at the exit: *"When `OneOf` grows large (many variants),
group errors into a `thiserror` enum instead."* The unions here are 1–2 variants —
they never earned the machinery.

## Scope of the actual usage

The entire crate has only **three distinct `OneOf` shapes**, in four files:

| Shape | Sites | File |
|---|---|---|
| `OneOf<(ParsingError, ValidationError)>` | `from_qualified_base64`, `from_qualified_base2`, `build` (×2) | `src/core/matter/builder.rs` |
| `OneOf<(SignatureError, CodeMismatchError)>` | `verify`, `verify_*` (2 fns) | `src/crypto/verify.rs` |
| `OneOf<(IndexerParseError,)>` / `OneOf<(IndexerValidationError,)>` | `from_qb64`, `from_qb2`, `with_index`, `with_indices`, `with_raw` (5 sites) | `src/core/indexer/builder.rs` |

`src/serder/deserialize.rs` does **not** expose `OneOf` publicly — its public API
returns `SerderError`. It only *consumes* the matter builder's `OneOf` inside the
private helper `map_qb64_error`.

## Design

### Decisions (locked)

1. **Replacement:** per-call-site `thiserror` enum (one error enum per module domain,
   per CLAUDE.md naming conventions). `#[from]` on each variant so `?` keeps working.
2. **`#[non_exhaustive]`:** **not** added now. Pre-1.0, a new error variant is an
   intentional breaking MINOR bump (CLAUDE.md Versioning). Exhaustive matching gives
   tag-pinning consumers a compile error exactly when they upgrade into a new failure
   mode — that is the desired behaviour until the 1.0 freeze, when `#[non_exhaustive]`
   is added deliberately.
3. **Scope:** full removal in one PR. `terrors` dropped from `Cargo.toml` entirely.

### New / changed error types

| Module | Today | After | Location |
|---|---|---|---|
| `core::matter` | `OneOf<(ParsingError, ValidationError)>` | **new** `MatterBuildError { Parsing, Validation }` | `src/core/matter/error.rs` |
| `crypto::verify` | `OneOf<(SignatureError, CodeMismatchError)>` | **new** `VerificationError { Signature, CodeMismatch }` | `src/crypto/error.rs` |
| `core::indexer` | `OneOf<(IndexerParseError,)>` / `OneOf<(IndexerValidationError,)>` | **bare** `IndexerParseError` / `IndexerValidationError` | no new type |
| `serder` | consumes matter `OneOf` internally | consumes `MatterBuildError` via `match` | public API unchanged |

Both new enums follow this shape:

```rust
#[derive(Debug, Error)]
pub enum MatterBuildError {
    #[error(transparent)]
    Parsing(#[from] ParsingError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
```

```rust
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    CodeMismatch(#[from] CodeMismatchError),
}
```

### Naming rationale

Noun-form (`MatterBuildError`, `VerificationError`) matches the existing house style
(`SignatureError`, `ValidationError`, `SerderError`, `IndexerParseError`) rather than
action-form (`VerifyError`).

### Call-site changes

- **matter builder** (`from_qualified_base64`, `from_qualified_base2`, both `build`
  sites returning the 2-variant shape): return type `OneOf<…>` → `MatterBuildError`.
  Internal `.map_err(...)` conversions become `?` where `#[from]` covers them. The
  existing `build` site that already returns bare `ValidationError` is unchanged.
- **crypto verify** (both functions): `OneOf<…>` → `VerificationError`.
- **indexer builder** (5 sites): drop the `OneOf` wrapper; return the bare
  `IndexerParseError` / `IndexerValidationError`.
- **serder** — add a new parsing-domain variant to `SerderError`, since the existing
  `InvalidPrimitive { field, source: ValidationError }` is typed to `ValidationError`
  and cannot faithfully hold a `ParsingError`:
  ```rust
  /// Field value could not be parsed as a CESR primitive (malformed code/length).
  #[error("unparseable primitive in field '{field}': {source}")]
  UnparseablePrimitive {
      field: &'static str,
      source: ParsingError,
  },
  ```
  Then rewrite `map_qb64_error` as:
  ```rust
  match err {
      MatterBuildError::Validation(ve) => SerderError::InvalidPrimitive { field, source: ve },
      MatterBuildError::Parsing(pe)    => SerderError::UnparseablePrimitive { field, source: pe },
  }
  ```
  This **fixes a latent bug**: today the `Err(remainder)` branch jams a `ParsingError`
  into `ValidationError::UnknownMatterCode(parsing_err.to_string())`, collapsing a
  parsing failure into a validation variant via string (violates "one variant = one
  failure domain" and "never erase structured errors"). A new variant — rather than
  retyping `InvalidPrimitive.source` — is used because `InvalidPrimitive` is also
  raised by genuinely-validation paths (`parse_sn`, `narrow::<DigestCode>()`) that
  must keep a `ValidationError` source. In scope because the migration forces a
  rewrite of that `match`.

### Dependency

- Remove `terrors` from `Cargo.toml`: the `dep:terrors` entry in the `core` feature
  (line 49) and the `terrors = { version = "0.3.3", optional = true }` declaration
  (line 96).
- Remove the 4 `use terrors::…` / `terrors::` references in `src/`.

## Testing

Per CLAUDE.md "Testing — Categories First" and "Test Quality":

1. **Variant-reachability / source-chain tests** — for each new enum, a test that
   drives the real builder/verify path to each variant and asserts
   `matches!(e, MatterBuildError::Parsing(_))` etc., and that the `#[from]` source is
   preserved (`std::error::Error::source()` chain intact).
2. **Migrate existing extraction tests** — every
   `.err().unwrap().take::<T>()` / `.narrow::<T, _>()` becomes an exhaustive `match`
   or `matches!` on the new enum. Assert the specific variant, not "some error".
3. **serder bug-fix regression test** — a genuine *parsing* failure (malformed qb64
   code) fed to the serder deserialize path must now surface as a **parsing-domain**
   `SerderError`, not `UnknownMatterCode`. This test must fail against the current
   code and pass after the fix.
4. **Cross-feature-combination** — the new enums compile and behave under every
   feature combo that reaches them; covered by `nix flake check` running nextest
   across combinations plus the wasm and no_std builds.

## Verification gate

Full `nix flake check`: clippy (god-level), rustfmt, taplo, `cargo audit`,
`cargo deny`, `cargo nextest` across feature combinations, `cargo test --doc`,
`cesr-wasm`, `cesr-nostd`.

## Breaking-change note (for PR + CHANGELOG)

Public return types change on the matter builder (`from_qualified_base64`,
`from_qualified_base2`, `build`), `crypto::verify`, and the indexer builder. Under the
`0.x` convention this is a **MINOR** bump. Consumers matching on these results must
switch from `OneOf` extraction (`.take::` / `.narrow::`) to matching the new enums
(`MatterBuildError`, `VerificationError`) or the bare indexer error types. A new
`SerderError::UnparseablePrimitive` variant is added (additive, but public-enum
change). Call out in the PR description and `CHANGELOG`.

## Out of scope

- No change to the underlying component errors (`ParsingError`, `ValidationError`,
  `SignatureError`, `CodeMismatchError`, `IndexerParseError`, `IndexerValidationError`)
  beyond `#[from]` wiring — their variants are unchanged.
- No `miette`/`snafu` adoption. `thiserror` remains the enum derive; this change only
  removes the `OneOf` union layer.
- `#[non_exhaustive]` deferred to the 1.0 stabilization.
