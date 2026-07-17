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
| `b64`    | `b64`    | —                        | `cesr-utils`     |
| `core`   | `core`   | `b64`                    | `cesr-core`      |
| `crypto` | `crypto` | `core`                   | `cesr-crypto`    |
| `stream` | `stream` | `core`, `b64`            | `cesr-stream`    |
| `keri`   | `keri`   | `core`                   | `keri-core`      |
| `serder` | `serder` | `keri`, `crypto`, `stream` | `keri-serder`  |

The `serder` → `stream` dependency is load-bearing since spine phase 2: `serder::EventMessage::parse` is the end-to-end read entry point (wire bytes → `stream` framing → `serder` body codec → typed event + attached signatures + remainder). The `keri-rs` workspace member consumes it behind its opt-in `wire` feature.

Environment features:

- `std` (default) — enables the standard library and threads/OS-RNG across all dependencies.
- `alloc` — enables heap allocation without `std`; required by most modules in no_std contexts.

Extra capability features:

- `async` — async codec via `tokio-util` (requires `stream`).
- `internals` — exposes internal constructors used by `serder` (was `keri-core`'s `internals`).
- `test-utils` — test-only escape hatches (`new_unchecked`, etc.) preserved from `cesr-core`.

Default features: `["std", "core", "b64"]`.

## ACTIVE DEVELOPMENT — API MAY CHANGE (pre-1.0)

**The API freeze is lifted.** cesr is in active development toward parity with the
current `keripy` reference implementation, with zero-copy and performance as
first-class goals. The public surface is **not** frozen: signatures, types,
trait shapes, and internal representations may be redesigned where it improves
correctness, ergonomics, or performance.

You may:
- **Change** signatures, rename types, restructure modules, alter error variants.
- **Add** new code tables, types, functions, trait impls, modules, examples.
- **Refactor** internals for zero-copy / performance, including breaking changes.

Discipline that still holds (these are quality rules, not a freeze):
- **Breaking changes are allowed but never accidental.** A breaking change must be
  intentional and called out in the PR description and `CHANGELOG`.
- While `0.x`, a breaking change is a **MINOR** bump (SemVer 0.x convention); see
  [Versioning](#versioning). Don't break the API as a side effect of an unrelated
  change — scope it.
- Every change still passes the full gate (`nix flake check`) and the
  [Mandatory Rules](#mandatory-rules) below: no panics on untrusted input, no
  `unwrap`/`expect` in production, no_std/WASM stays green, tests cover new behavior.
- Prefer additive evolution where it costs nothing; reach for a breaking change
  when it genuinely buys correctness, DevX, or performance.

When a change is large or reshapes a public contract, note it in the PR so reviewers
(and downstream consumers pinning a tag) see it coming.

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
- `cesr-version-owner` — spine tripwire: version-string wire grammar exists only in `cesr/src/core/version.rs`; fails on grammar tokens (`KERI10`, `b"JSON"`, …) in any other production source
- `cesr-fn-ratchet` — spine tripwire: per-module free `pub fn` counts may only go down; budgets and the counting rule live in `free-fn-budget.toml` (lower a budget when a count drops, never raise one)

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

## Naming Conventions

- Functions are `verb_noun`; the owning module is the domain qualifier — no
  redundant `b64_`/`_b64` affixes inside `b64`. Codec pairs are
  `encode_<x>` / `decode_<x>` (e.g. `b64::encode_int` / `b64::decode_int`).
- One error enum per module domain. When two modules would otherwise share an
  error name, prefix with the domain (e.g. `IndexerParseError`).

## Clippy Policy

Shared rule (see the global CLAUDE.md): the `[lints.clippy]` table in `Cargo.toml` is the law — `all` + `pedantic` + `nursery` at `deny` plus the restriction suite. Never relax lint levels or change `clippy.toml`/`[lints]` without explicit user approval; every `#[allow]` carries a `reason`, on specific items only. The same goes for the comments policy: self-documenting code, comments only for the why.

## Error Handling

- `thiserror` for error enums, **including error unions**. When an operation can fail
  in two or more distinct domains, model the union as a dedicated `thiserror` enum with
  one `#[from]` variant per source error (e.g.
  `MatterBuildError { Parsing(#[from] ParsingError), Validation(#[from] ValidationError) }`).
  `#[from]` keeps `?` propagation ergonomic and preserves the source chain; prefer
  `#[error(transparent)]` on a variant that simply forwards to its source's `Display`.
- A single-domain fallible operation returns its **bare** error type — never wrap a lone
  error in a union type.
- In tests, match the error enum directly (`matches!(e, MatterBuildError::Parsing(_))` or a
  `let ... else` bind) and assert the specific variant — do not stringify.
- Name a union enum after its operation/domain, following the one-error-enum-per-module
  convention (`MatterBuildError`, `VerificationError`).

> Historical note: the crate previously used `terrors::OneOf<(E1, E2, ...)>` for error
> unions. It was removed in #33 (error-ergonomics pass) in favour of the `thiserror`-enum
> convention above, which is matchable without a runtime downcast and drops a dependency.
> Do **not** reintroduce `terrors`.

## Mandatory Rules

### Shared devrandom rules (EXTREMELY IMPORTANT)

The shared devrandom engineering rules — **Facts Only, Arithmetic Safety, Error Handling, API Design, Functional-First/Allocate-Last style, Test Quality, Clippy policy, shared conventions** — apply here in full; canonical text lives in the user-global `~/.claude/CLAUDE.md` ("Engineering rules — EXTREMELY IMPORTANT"). They were originally ported from nexus, where each earned its place by catching a real bug. Storage-adapter rules (database atomicity, adapter concurrency) do not apply — cesr is a pure primitives crate.

cesr-specific addenda:

- **Facts:** the CESR/KERI wire formats are specified — when in doubt, read the spec or the `keripy` reference implementation, don't invent.
- **Errors:** adding or changing an error variant on a public enum is a breaking change — allowed during active development, but call it out in the PR and the `CHANGELOG` (see [Active Development](#active-development--api-may-change-pre-10)).
- **Style:** borrow-before-own matters doubly in no_std/`alloc` contexts where every allocation is a feature-gated cost. Import placement is additionally enforced by the commit hooks — see [Import Style](#import-style--mandatory).

### 6. Testing — Categories First

Every new feature MUST include tests in these cross-cutting categories before reaching for narrower per-function tests:

1. **Round-trip / sequence tests** — encode → decode → re-encode stability, and multi-step interactions on the same value, not just operations in isolation. For codecs this is the single highest-value category: `decode(encode(x)) == x` and `encode(decode(bytes)) == bytes`.
2. **Defensive boundary tests** — feed each module inputs that violate its upstream module's guarantees: truncated frames, oversize lengths, invalid code points, non-UTF-8 where text is expected. A parser must reject these as typed errors, never panic.
3. **Cross-feature-combination tests** — the crate is feature-gated six ways; a type's behavior must hold under every feature combination it compiles in (this is why `nix flake check` runs nextest across feature combinations, plus the `wasm` and `no_std` builds).
4. **Property-based tests** (`proptest`) — with ranges that include boundaries: `0`, `1`, `MAX-1`, `MAX`, and for byte strings empty / max-length / max-length+1.

### 7. Test Quality

Shared rule — every test must satisfy all of the test-quality requirements in the global CLAUDE.md (calls the actual SUT, can actually fail, asserts the specific value, bug-probes fail while the bug exists, one canonical location per invariant).

## Key Conventions

- **Edition & toolchain**: Rust edition 2024; pinned **stable** `1.95.0` in `rust-toolchain.toml` — the single source of truth for both rustup users and the Nix flake (consumed via fenix `fromToolchainFile`). **No nightly**; the crate carries no `#![feature(...)]` gates. When bumping Rust, bump `channel` in `rust-toolchain.toml` and `rust-version` in `Cargo.toml` together.
- **Two-crate workspace.** The repo is a Cargo workspace with two published members —
  `cesr/` (`cesr-rs`, the frozen-surface primitives) and `keri/` (`keri-rs`, the sans-io
  KERI core, built on cesr's public API). Unlike nexus, there is **no** `cargo-hakari`
  workspace-hack: two crates don't need dependency-feature unification yet. Members version
  independently (cesr-rs can sit frozen while keri-rs churns). Shared config —
  `[workspace.package]`, `[workspace.dependencies]`, `[workspace.lints]` — lives in the
  root virtual manifest; the fuzz crates stay isolated (non-member) workspaces.
- **Strict clippy**: see the [Clippy Policy](#clippy-policy) section — `all` + `pedantic` + `nursery` denied, plus the restriction suite. The `[lints]` table is the law; never relax it without approval.
- **Commit style**: conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `ci:`) — release-plz derives version bumps from them, so a `feat:`/`fix:` on `src/**` cuts a release while `docs:`/`chore:` do not.
- **Dual license**: MIT OR Apache-2.0.
- **CI is the Nix flake** — `nix flake check` is the only gate (clippy, fmt, taplo, audit, deny, nextest, doctest, wasm build, no_std build). See [Build & Verification](#build--verification).

## Versioning

Consumers pin `cesr` by **git tag** (`vMAJOR.MINOR.PATCH`):

```toml
cesr = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", features = ["keri", "serder"] }
```

cesr is `0.x` and under [active development](#active-development--api-may-change-pre-10). Following the SemVer `0.x` convention, a **breaking** change bumps the **MINOR** version (`0.1 → 0.2`) and a backward-compatible change bumps **PATCH** (`0.1.1 → 0.1.2`). Consumers pinning a tag therefore opt into a known API and upgrade deliberately. Breaking changes are expected during the keripy-parity + performance push; each is documented in the `CHANGELOG`. The `1.0.0` line will be the first API-stability commitment.
