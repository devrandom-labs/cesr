# 93-k7-custody — Custodian trait + SaltyCustodian (K7)

## Context

Full task detail — file paths, complete code blocks, source-cited facts — lives in
`docs/superpowers/plans/2026-07-31-93-k7-custody.md`. **Read that file first**; this
file is the dispatch wrapper with execution overrides. The spec is
`docs/superpowers/specs/2026-07-31-93-k7-custody-design.md`.

Invariants that must hold (from the spec; the detailed plan carries the citations):

- Stretch is argon2id13, p=1, tier costs (t,m KiB): Low (2, 65536), Medium (3, 262144),
  High (4, 1048576); test-utils-gated temp (1, 8). Byte-identical to keripy —
  the committed fixtures are the referee.
- Derivation path = `stem + hex(ridx) + hex(kidx)` lowercase, no separators.
  Keripy stem = `hex(pidx)`, Signify stem = `"signify:aid"`.
- incept: current at (ridx, kidx), next at (ridx+1, kidx+count).
  rotate: promote committed next set; new next one rung further.
- All index arithmetic checked (`checked_add`), overflow is a typed error.
- Secrets in `Zeroizing`; stretched seeds never pass through a non-zeroizing buffer
  (hence `KeyPair::from_seed_bytes`).
- No new free `pub fn`s (fn-ratchet); methods only. God-level clippy: fix code,
  never `#[allow]` without a fight.

## Execution overrides (these OVERRIDE the detailed plan where they conflict)

1. **NEVER run tests.** No `cargo test`, no `cargo nextest run` — they hang in this
   sandbox. Verification per step is `cargo check` + `cargo clippy` only (commands
   below). The controller runs the real test suite after you finish. Write every
   test exactly as the detailed plan specifies — you just don't execute them.
2. **Fixtures already exist and are committed** — `crates/cesr/tests/fixtures/keripy_salt_vectors.json`
   and `crates/keri-codec/tests/fixtures/keripy_custody_vectors.json` (Manager oracle).
   Detailed-plan Tasks 4.1/4.2 and 8.1/8.2 (python generators + runs) are DONE —
   skip them; do not touch `scripts/`. The salt qb64 constant for Task 2's test is
   confirmed: `0AAwMTIzNDU2Nzg5YWJjZGVm`.
3. **Do not commit.** Leave all edits in the working tree; the controller reviews
   and commits. Ignore every `git commit` step in the detailed plan.
4. Where a detailed-plan snippet says "adapt to the real signature", the named
   file:line is authoritative — read it, adapt, keep the asserted behavior.

## Steps

Step numbers = detailed-plan task numbers. File sets are per detailed plan.

1. **argon2 dep wiring** (`crates/cesr/Cargo.toml`) — SEQUENTIAL (everything depends on it).
2. **`Tier`/`SaltError`/`Salt`** (`crates/cesr/src/crypto/{salt.rs,error.rs,mod.rs}`) — SEQUENTIAL — depends on step 1.
3. **stretch/temp/key_pair + `KeyPair::from_seed_bytes`** (`crates/cesr/src/crypto/{salt.rs,keypair.rs}`) — SEQUENTIAL — depends on step 2.
4. **cesr differential test** (`crates/cesr/tests/keripy_salt.rs`, dev-deps in `crates/cesr/Cargo.toml`) — depends on step 3. PARALLEL OK with steps 5-7 (disjoint files).
5. **custody module skeleton** (`crates/keri/src/{custody.rs,lib.rs}`) — depends on step 3 (uses `Salt`/`Tier`).
6. **SaltyCustodian paths + incept** (`crates/keri/src/custody.rs`) — SEQUENTIAL — depends on step 5.
7. **rotate/sign/params/resume** (`crates/keri/src/custody.rs`) — SEQUENTIAL — depends on step 6.
8. **keri-codec custody differential test** (`crates/keri-codec/tests/keripy_custody.rs`) — depends on step 7. PARALLEL OK with step 9 (disjoint files).
9. **end-to-end chain test** (`crates/keri-codec/tests/custody_chain.rs`, possibly one-line `pub` change in `crates/keri-codec/tests/common/mod.rs`) — depends on step 7.
10. **proptests + CHANGELOG** (`crates/keri/src/custody.rs`, `crates/cesr/CHANGELOG.md`, `crates/keri/CHANGELOG.md`) — depends on step 7. Skip detailed-plan steps 10.4-10.6 (cards/push/PR are the controller's).

Steps 4, 8, 9 are test-writing only — sonic-suitable if the trait surface from
step 7 is final.

## Verification

Per step (and once at the end, all three):

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p cesr-rs --no-default-features --features "alloc,crypto"
```

All must be clean. Tests run later in the controller-driven `nix flake check`
(unsandboxed commit hook) — not by you.

## Out of scope

- `scripts/`, fixtures, `.plans/`, `docs/` — read-only.
- No `RandyCustodian`, no encrypted-salt export, no dual-index (`ondex`) signing.
- No changes to `clippy.toml`, `[lints]`, `free-fn-budget.toml`, `rust-toolchain.toml`.
- No commits, no pushes, no `gh`.
