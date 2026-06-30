# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`cesr` is a single feature-gated Rust crate providing CESR (Composable Event Streaming Representation) and KERI (Key Event Receipt Infrastructure) cryptographic primitives. It is no_std/WASM-capable: the full crate compiles for `wasm32-unknown-unknown` and for no_std targets when the right features are selected.

The crate consolidates what were six separate crates — `cesr-utils`, `cesr-core`, `cesr-crypto`, `cesr-stream`, `keri-core`, `keri-serder` — into one crate with independent feature gates per module. Consumers migrate to the new import paths on their own schedule.

The six original crates map exactly to the six modules of this crate. Public API paths are preserved verbatim: `cesr_core::Matter` is now `cesr::core::Matter`, and so on. No behavior or signature changed in the extraction.

## Modules & Features

Each module is independently gated by a Cargo feature of the same name. Module features compose: enabling `serder` transitively pulls in `keri`, `crypto`, `stream`, and `core`.

| Module   | Feature  | Internal deps            | Origin crate     |
|----------|----------|--------------------------|------------------|
| `utils`  | `utils`  | —                        | `cesr-utils`     |
| `core`   | `core`   | `utils`                  | `cesr-core`      |
| `crypto` | `crypto` | `core`                   | `cesr-crypto`    |
| `stream` | `stream` | `core`, `utils`          | `cesr-stream`    |
| `keri`   | `keri`   | `core`                   | `keri-core`      |
| `serder` | `serder` | `keri`, `crypto`, `stream` | `keri-serder`  |

Environment features:

- `std` (default) — enables the standard library and threads/OS-RNG across all dependencies.
- `alloc` — enables heap allocation without `std`; required by most modules in no_std contexts.

Extra capability features:

- `async` — async codec via `tokio-util` (requires `stream`).
- `internals` — exposes internal constructors used by `serder` (was `keri-core`'s `internals`).
- `test-utils` — test-only escape hatches (`new_unchecked`, etc.) preserved from `cesr-core`.

Default features: `["std", "core", "utils"]`.

## FROZEN — EXTEND ONLY, NEVER ALTER

**The entire cesr public surface — all six modules — is frozen.**

You may:
- **Add** new code tables, new types, new functions, new trait impls.
- **Add** new modules, new tests, new examples, new doc-comment sections.

You may NOT:
- Change signatures of any existing public function, method, or trait.
- Change the behavior or semantics of any existing public item.
- Change existing error variants or error semantics.
- Rename, remove, or restructure existing public types, methods, or modules.

If a task requires altering frozen behavior, **STOP and ask the user first.** This rule has no exceptions. ("Freeze every library codebase" — user standing instruction.)

## Build & Verification

**Prerequisites:** Nix with flakes enabled. Enter the dev shell once with `nix develop` (or `direnv allow`); all tools (`cargo`, `cargo-nextest`, `taplo`, `cargo-deny`, `cargo-audit`, `actionlint`) are provided by the flake.

**The single gate:**

```bash
nix flake check
```

This runs, in order:

- `clippy` (god-level — see [Clippy policy](#clippy-policy))
- `rustfmt` check
- `taplo` TOML format check
- `cargo audit`
- `cargo deny`
- `cargo nextest` (1683 tests across all feature combinations)
- `cargo test --doc` (doctest examples)
- `cesr-wasm` — compiles the crate for `wasm32-unknown-unknown` to verify WASM build
- `cesr-nostd` — compiles the crate with no_std + alloc to verify bare-metal build

`nix flake check` is the ONLY command to run before committing or pushing. Do not short-circuit with raw `cargo` commands — those miss the TOML, audit, deny, wasm, and no_std checks.

**Useful shortcuts:**

```bash
# Run a specific named check
nix build '.#checks.aarch64-darwin.<check-name>'

# Run any tool inside the nix shell without entering it
nix develop --command bash -c "<command>"

# Build (fast sanity check, not the gate)
nix develop --command cargo build

# Run tests directly (nextest only, no other checks)
nix develop --command cargo nextest run

# Format Rust code
nix develop --command cargo fmt

# Format TOML files
nix develop --command taplo fmt
```

**Toolchain:** pinned stable `1.95.0` in `rust-toolchain.toml`. No nightly features. The crate carries no `#![feature(...)]` gates. Bump `channel` and `rust-version` in `Cargo.toml` in lockstep.

## Import Style — MANDATORY

These rules apply to all production code (`src/` directories). Test modules (`#[cfg(test)]`) are exempt.

1. **NO inline `use` inside functions, methods, or impl blocks.** All imports go at the top of the file. If names collide, use `as` aliases:

   ```rust
   // GOOD — top of file with aliases
   use ed25519_dalek::Signature as Ed25519Sig;
   use k256::ecdsa::Signature as K256Sig;

   // BAD — inline use inside function body
   fn verify_ed25519() {
       use ed25519_dalek::Signature; // NEVER DO THIS
   }
   ```

2. **NO fully-qualified paths to construct types.** Import the type at the top of the file, then use its short name:

   ```rust
   // GOOD
   use crate::error::SignatureError;
   fn foo() -> SignatureError { SignatureError::SomeVariant }

   // BAD — fully-qualified inline
   fn foo() -> crate::error::SignatureError { crate::error::SignatureError::SomeVariant }
   ```

3. `super::` in submodules and `Self::` in impl blocks are fine.

Hooks in `.githooks/` enforce these rules at commit time.

## Clippy Policy

The `[lints.clippy]` table in `Cargo.toml` is the law. It enables `all`, `pedantic`, and `nursery` at `deny`, plus a suite of ruthless restrictions (`unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `as_conversions`, `shadow_*`, etc.).

- **NEVER** relax lint levels.
- **NEVER** change `clippy.toml` or `[lints]` without explicit user approval.
- Every `#[allow(...)]` attribute **must** carry a `reason = "..."` field. The `allow_attributes_without_reason` lint enforces this.
- Only add `#[allow(...)]` on specific items, never at module or crate level, and only when the user says so.

## Code Comments Policy

Write clean, self-documenting code. Do not add comments explaining what the code does. Only add comments to explain the **why** behind complex business logic or unusual workarounds.

## Error Handling

- `thiserror` for error enums.
- `terrors::OneOf` for error type unions in return types (`Result<T, OneOf<(E1, E2, ...)>>`).
- In tests, use `.err().unwrap().take::<ErrorType>()` to extract from `OneOf` — not `.unwrap_err()` + deref.
- When `OneOf` grows large (many variants), group errors into a `thiserror` enum instead.

## Mandatory Rules

These rules are ported from the nexus codebase, where each one earned its place by catching a real bug. Storage-adapter-specific rules (database atomicity, adapter concurrency) are omitted — cesr is a pure primitives crate with no persistence layer. The rules that remain apply directly to codec, parsing, and crypto code.

### 1. No Assumptions, No Opinions — Facts Only

- **Never assume.** If you don't know something, say so and research it. Do not fill gaps with plausible-sounding guesses about APIs, crate behavior, algorithm properties, or wire-format details. The CESR/KERI wire formats are specified — when in doubt, read the spec or the reference implementation, don't invent.
- **Never give opinions.** No "I think," "it would be cleaner," "this feels better." Claims must be grounded in verifiable evidence.
- **Facts must cite sources.** Every technical claim about algorithms, cryptography, encoding, or systems behavior must cite a primary source: a spec/RFC, the reference implementation repository, or a peer-reviewed paper — not a blog post or "common knowledge."
- **Uncertainty is a fact too.** When evidence is incomplete or contradictory, state the uncertainty explicitly rather than collapsing it into a confident-sounding answer.

### 2. Arithmetic Safety

- **No bare arithmetic** in production code paths that compute sizes, offsets, lengths, or counts. Use `checked_add`/`checked_sub`/`checked_mul` and return `Err` on overflow. `saturating_*` is banned in these paths — it silently caps and converts an overflow into a misleading downstream error (e.g. a truncated frame that parses as valid).
- **No `unwrap_or(sentinel)`** for failed conversions. `u64::try_from(x).unwrap_or(u64::MAX)` hides the root cause. Return a proper error.
- **`debug_assert` is NOT a safety check.** It is compiled out in release — it protects nothing in production. If violating an invariant would mis-parse data or produce silently wrong bytes, use a runtime check (`return Err(...)` or `assert!`). Reserve `debug_assert` for conditions provably impossible by construction.

### 3. Error Handling

Builds on the [Error Handling](#error-handling) section above (`thiserror`, `terrors::OneOf`). Additionally:

- **One variant = one failure domain.** Never jam unrelated errors into an existing variant. A malformed-length error and an invalid-base64 error are different domains — give them different variants.
- **Never discard the original error** with `|_|` in `map_err`. Wrap it via `#[source]`/`#[from]`, or at minimum preserve its message.
- **Never erase structured errors into `Box<dyn Error>`** when callers need to match on them. Never box string literals as errors.
- **Input-validation errors are not corruption errors.** A too-long input (caller's bad data) and a corrupt code table (internal invariant break) demand different remediation — keep them distinct variants.
- **Unknown values must be `Option`, not sentinels.** When a count or version is genuinely unknowable, use `Option<T>`, not a magic `0`.
- **Read-path and write-path must enforce the same invariants the same way.** If decode rejects a value, encode must not silently emit it.

Because the public surface is **frozen** (see [FROZEN](#frozen--extend-only-never-alter)), adding a *new* error variant to an existing public enum is a behavior change — STOP and ask first. New error *types* on new APIs are fine.

### 4. API Design

- **No unused generic parameters or associated types.** If a type parameter is always one concrete type and a trait's associated type is never used in any method, it should not exist. Add the generic when the second concrete use case actually arrives. YAGNI. (Adding such a generic to a frozen API is itself a breaking change — see FROZEN.)
- **Internal wire-format helpers must be `pub(crate)`, not `pub`.** Encoding/decoding functions, size constants, and internal error types that don't belong in the public API must not be reachable by downstream crates.
- **`pub mod` leaks every item in the module.** Use private `mod` with controlled `pub use` re-exports.
- **`#[doc(hidden)]` is not access control.** Test-only methods must be `#[cfg(test)]` or behind a test feature (`test-utils`), not `#[doc(hidden)] pub`.
- **Panics are for programmer bugs, not data or capacity limits.** Parsing untrusted bytes must never panic — return `Result`. A panic on malformed input is a denial-of-service bug in a parser.
- **Rust naming conventions are load-bearing.** `new_unchecked` means *no validation, caller upholds preconditions*. If it validates and panics, it is `new`, not `new_unchecked`.
- **Trait contracts must document semantics.** Is a range bound inclusive or exclusive? Is a sentinel value valid input or only an absent marker? Document it on the trait, not in one impl.
- **Each module defends its own boundary.** A downstream module must not trust an upstream module's guarantees without its own check at the seam where untrusted data could enter.

### 5. Code Style — Functional-First, Allocate-Last

- **Prefer combinators over imperative control flow** when the transformation is a simple data flow: `.map()`, `.and_then()`, `.map_or_else()`, `.filter()`, `.fold()`. Reserve imperative style for cases where it measurably improves performance or enables compile-time safety combinators cannot express.
- **Lazy over eager.** Prefer iterator chains over collecting intermediate `Vec`s. Only `.collect()` when you need the collection as a concrete value.
- **Borrow before own.** Default to `&T` and lifetimes; clone/allocate only when borrowing is impossible. `Cow<'a, T>` bridges the conditional-ownership gap. This matters doubly in no_std/`alloc` contexts where every allocation is a feature-gated cost.
- **No gratuitous allocations.** Every `Vec::new()`, `.to_owned()`, `.to_string()`, `Box::new()`, `.clone()` on a hot path must justify itself. Prefer stack allocation (`ArrayVec`, `[T; N]`) for bounded collections; `&str` over `String`, `&[u8]` over `Vec<u8>`.
- **`let ... else` over `if let ... else { return }`** when the else branch is an early return/error — it keeps the happy path primary.
- **All `use` imports at the top of the file** — see the [Import Style](#import-style--mandatory) section, which the commit hooks enforce.

### 6. Testing — Categories First

Every new feature MUST include tests in these cross-cutting categories before reaching for narrower per-function tests:

1. **Round-trip / sequence tests** — encode → decode → re-encode stability, and multi-step interactions on the same value, not just operations in isolation. For codecs this is the single highest-value category: `decode(encode(x)) == x` and `encode(decode(bytes)) == bytes`.
2. **Defensive boundary tests** — feed each module inputs that violate its upstream module's guarantees: truncated frames, oversize lengths, invalid code points, non-UTF-8 where text is expected. A parser must reject these as typed errors, never panic.
3. **Cross-feature-combination tests** — the crate is feature-gated six ways; a type's behavior must hold under every feature combination it compiles in (this is why `nix flake check` runs nextest across feature combinations, plus the `wasm` and `no_std` builds).
4. **Property-based tests** (`proptest`) — with ranges that include boundaries: `0`, `1`, `MAX-1`, `MAX`, and for byte strings empty / max-length / max-length+1.

### 7. Test Quality

Every test must satisfy ALL of these:

- **Calls the actual code under test.** Don't reimplement the production logic in the test and prove properties of the reimplementation. Call the real function with the real input.
- **Can actually fail.** A test where both branches of a conditional pass is worthless. Every test needs an assertion that would fail if the invariant broke.
- **Asserts the specific correct result**, not "something happened." `assert!(s.contains('3'))` matches any string with a `3` — use `assert_eq!` with the exact expected value.
- **`println!` is not an assertion.** Corruption and round-trip violations must be asserted on, not logged.
- **Bug-probe tests must FAIL when the bug exists.** If a known bug is accepted for now, use `#[ignore]`, not a green test that documents the issue in a comment.
- **Each invariant tested once in a canonical location** — don't duplicate the same property test across files with different types.

## Key Conventions

- **Edition & toolchain**: Rust edition 2024; pinned **stable** `1.95.0` in `rust-toolchain.toml` — the single source of truth for both rustup users and the Nix flake (consumed via fenix `fromToolchainFile`). **No nightly**; the crate carries no `#![feature(...)]` gates. When bumping Rust, bump `channel` in `rust-toolchain.toml` and `rust-version` in `Cargo.toml` together.
- **Single crate, not a workspace.** Unlike nexus (a multi-crate workspace with a `cargo-hakari` workspace-hack), cesr is one crate. There is no workspace-hack, no hakari step, and the release pipeline has none of nexus's hakari/`allow_dirty` machinery — feature *modules*, not member *crates*, are the unit of composition here.
- **Strict clippy**: see the [Clippy Policy](#clippy-policy) section — `all` + `pedantic` + `nursery` denied, plus the restriction suite. The `[lints]` table is the law; never relax it without approval.
- **Commit style**: conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `ci:`) — release-plz derives version bumps from them, so a `feat:`/`fix:` on `src/**` cuts a release while `docs:`/`chore:` do not.
- **Dual license**: MIT OR Apache-2.0.
- **CI is the Nix flake** — `nix flake check` is the only gate (clippy, fmt, taplo, audit, deny, nextest, doctest, wasm build, no_std build). See [Build & Verification](#build--verification).

## Versioning

Consumers pin `cesr` by **git tag** (`vMAJOR.MINOR.PATCH`):

```toml
cesr = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", features = ["keri", "serder"] }
```

Because the entire public surface is frozen, `MINOR` and `PATCH` increments never break existing import paths. A breaking change (un-freezing) requires a `MAJOR` bump and a deliberate, user-approved decision to relax the freeze. `v0.1.0` is the initial extraction tag.
