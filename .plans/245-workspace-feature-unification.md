# Fix #245 — cesr-rs lib tests fail under workspace feature unification

## Context

Workspace feature unification enables cesr-rs's `crypto` feature (via keri-rs /
keri-codec deps) while nothing enables `test-utils`. The 9 test uses of
`Matter::new_unchecked` in `crates/cesr/src/crypto/{keypair,verify}.rs` then
fail with E0599 (`new_unchecked` is `#[cfg(feature = "test-utils")]`, see
`crates/cesr/src/core/matter/matter.rs:56`). Repro from workspace root:
`cargo nextest run --no-run` → `error: could not compile cesr-rs (lib test)
due to 9 previous errors`.

Chosen fix: **self dev-dependency** enabling `test-utils` for cesr-rs's own
test targets. This makes the lib-test target compile AND run those 9 tests in
every feature-unification state. The alternative (cfg-gating the 9 test uses)
was rejected: it would silently skip the tests whenever `crypto` is on without
`test-utils` — silent coverage loss.

Invariants:
- `test-utils` must NOT leak into non-test builds of cesr-rs or any dependent
  crate (a dev-dependency cannot, by Cargo semantics — this is the point).
- No source-file changes; Cargo.toml only.
- No lint/feature-table changes beyond the one dev-dep line.

## Steps

1. In `crates/cesr/Cargo.toml`, add to the existing `[dev-dependencies]`
   table (keep alphabetical ordering of the table if present):

   ```toml
   cesr-rs = { path = ".", features = ["test-utils"] }
   ```

   Expected outcome: cesr-rs test targets always build with `test-utils`
   enabled; the 9 `Matter::new_unchecked` test uses resolve in all
   unification states.

2. Run `taplo fmt crates/cesr/Cargo.toml` so the TOML formatting gate passes.

## Verification

From the workspace root (inside `nix develop`):

- `cargo nextest run --no-run` — must compile (this is the failing repro).
- `cargo nextest run -p cesr-rs` — the 9 crypto tests must run and pass.
- Final gate is run by the controller after review: `nix flake check`.

Quote the actual command output in your final report — do not assert success
without it.

## Out of scope

- Any `.rs` source file.
- The `[features]` table, `[lints]`, clippy config.
- Other crates' manifests.
