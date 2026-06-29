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

## Versioning

Consumers pin `cesr` by **git tag** (`vMAJOR.MINOR.PATCH`):

```toml
cesr = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", features = ["keri", "serder"] }
```

Because the entire public surface is frozen, `MINOR` and `PATCH` increments never break existing import paths. A breaking change (un-freezing) requires a `MAJOR` bump and a deliberate, user-approved decision to relax the freeze. `v0.1.0` is the initial extraction tag.
