# Design — `Matter::to_qb64` in `core` (Issue #67)

**Date:** 2026-07-04
**Issue:** [#67](https://github.com/devrandom-labs/cesr/issues/67) — *qb64 encoding of a Matter requires the `stream` feature (encode/decode live in different layers)*
**Type:** DevX / layering cleanup. Breaking change (allowed pre-1.0; see CLAUDE.md · Active Development).

## Problem

Encoding a `Matter`-family primitive (`Verfer`, `Diger`, `Saider`, `Prefixer`, `Signer`, `Cigar`) to its
qb64 text form is only possible via `stream::encode::matter_to_qb64`, gated behind the **`stream`** feature.
There is **no `to_qb64` on `Matter` in `core`**. Three concrete smells:

1. **Feature over-reach.** A consumer who only wants to encode a key/digest to text must enable the whole
   `stream` parsing subsystem. The text codec is a `b64`/`core` concern.
2. **Read/write asymmetry.** Decode (`MatterBuilder::from_qualified_base64`) lives in `core`; encode lives in
   `stream`. The two directions of the same text form sit in different features.
3. **Error-domain mismatch** (Mandatory Rule 3). `matter_to_qb64` returns `Result<_, ParseError>` — a
   *read-path* (parsing) error type — on a *write* path. `serder` even re-wraps it as
   `SerderError::Qb64Encoding(ParseError)`.

## Design decisions (confirmed with user)

- **Infallible API**, mirroring the existing sibling primitives `Indexer::to_qb64` / `Siger::to_qb64`
  (which return `String` and `assert!` on internal-invariant break). The only ways the encoder can "fail"
  are internal-invariant breaks (corrupt sizage table / base64 buffer mismatch) that are **unreachable for
  any `Matter` built through the validated builder**. Per Mandatory Rule 4, a panic on a programmer-bug
  invariant is correct; untrusted bytes only enter on the *decode* side, which stays `Result`-typed.
- **Remove the old encoder** `stream::encode::matter_to_qb64` and migrate all call sites (no back-compat
  alias). Fully resolves the asymmetry and error-domain smells.

## Changes

### 1. New inherent methods — `src/core/matter/matter.rs`

On `impl<'a, C: CesrCode> Matter<'a, C>`:

- `pub fn to_qb64b(&self) -> Vec<u8>` — the byte-producing core. This is the current
  `stream::encode::matter_to_qb64` body with the `Result` removed: the two internal error branches
  (base64 `encode_slice` failure; final-length ≠ `fs` mismatch) become invariant `assert!`s, mirroring
  `Indexer::to_qb64`'s `assert_eq!` on final length. Uses `base64` (already a `core`-gated dependency:
  `core = ["b64", "dep:base64", ...]`) and `sizage`.
- `pub fn to_qb64(&self) -> String` — `String::from_utf8(self.to_qb64b())`. qb64 output is pure ASCII
  (URL-safe Base64 alphabet + CESR code chars + `_` pad), so UTF-8 validity is guaranteed by construction;
  the `from_utf8` result is unwrapped behind an invariant assert (never fails).

Doc comments state the qb64/qb64b relationship and the `# Panics` invariant, matching `Indexer`'s style.

### 2. Delete `stream::encode::matter_to_qb64`

- Remove the function and its doc comment from `src/stream/encode.rs`.
- Remove its `#[cfg(test)] mod matter_qb64` test module from `src/stream/encode.rs` — its round-trips move
  to `core` (see §4), where they run **without** the `stream` feature.

### 3. Migrate `serder`

- `src/serder/primitives.rs::to_qb64_string` → becomes infallible: body is `matter.to_qb64()`. Return type
  changes `Result<String, SerderError>` → `String`.
- `identifier_to_qb64_string` and any transitive callers shed their `?`/`Result` where this encoder was the
  sole failure source. Callers that still fail for *other* reasons keep their `Result`.
- Remove `SerderError::Qb64Encoding(#[from] ParseError)` (`src/serder/error.rs`).
- Audit `SerderError::Encoding(#[from] FromUtf8Error)`: if `to_qb64_string` was its only producer, remove it
  too; otherwise keep. (Decision made at implementation time by grepping producers.)

### 4. Tests — `src/core/matter/matter.rs` test module

Move the six existing round-trips from `stream/encode.rs` into `core` and adapt them to the new inherent
methods (Testing Categories 1 & 3 — round-trip, now under `core`-only feature set):

- Ed25519 verkey, Ed25519 signature, Blake3-256 digest, Short number, narrowed `VerKeyCode`,
  StrB64 variable-soft (exercises the `ss > 0` soft-field write branch).

Add:

- **Round-trip** `from_qualified_base64(x).to_qb64b() == x` and `.to_qb64().as_bytes() == x` for each vector
  (Category 1).
- **Consistency**: `m.to_qb64().into_bytes() == m.to_qb64b()` (the two entry points agree).
- Reuse existing boundary/property vectors where present; no new `proptest` harness required beyond the
  existing per-code vectors unless a gap is found.

## Non-goals (YAGNI / scope)

- No `to_qb2` on `Matter` (not requested by the issue).
- No changes to `Indexer` / `Siger` (already infallible and correct).
- No new public error type (the infallible path needs none).
- No unrelated refactor of `stream::encode.rs`'s counter/group encoders.

## Breaking changes (call out in PR + CHANGELOG)

- `stream::encode::matter_to_qb64` **removed**.
- `SerderError` loses the `Qb64Encoding` variant (and possibly `Encoding`).
- `serder::primitives::to_qb64_string` / `identifier_to_qb64_string` signatures shed their `Result`.

## Verification

Single gate: `nix flake check` (clippy, fmt, taplo, audit, deny, nextest across feature combinations,
doctest, wasm build, no_std build). The relocated round-trip tests must compile and pass under the
`core`-only feature set (no `stream`), proving the feature-decoupling goal.
