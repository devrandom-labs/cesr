# 243-event-model-consolidation

Full step-by-step plan with complete code blocks:
`docs/superpowers/plans/2026-07-28-243-event-model-consolidation.md` — READ IT FIRST; it is the source of truth for every code block, test keep/drop list, and doc comment. This file adds only the execution contract.

## Context

- Branch `refactor/243-event-model-consolidation` (already checked out; spec + plan committed).
- Goal: delete `crates/keri-codec/src/builder/drt.rs` and `dip.rs`; parameterize the rotation and inception type-state chains over a sealed delegation-kind marker. `keri-codec` ONLY.
- Invariants that must hold:
  - Wire bytes byte-identical for all four tags (`rot`/`drt`/`icp`/`dip`) — the keripy differential corpus (`src/keripy_parity/`) passes untouched except the one `replay_delcept` call-site reorder.
  - `keri-events`, `cesr`, `cesr-stream`, `keri` crates: ZERO edits.
  - Sealed pattern: `RotationKind`/`InceptionKind` are `pub trait ...: Sealed` bounding public structs, markers `#[doc(hidden)]`, exactly like existing `EventBuilderState`.
  - `SnBelowMinimum` labels stay verbatim: `"rotation"` / `"delegated rotation"`.
  - God-level clippy: no `#[allow]` additions, no lint relaxation. `missing_const_for_fn` (nursery) may demand `const` on chain methods — add `const` if the compiler accepts, never allow.
  - No new free `pub fn` (fn-ratchet gate); `seal` is a trait method.

## Steps

1. **SEQUENTIAL** — Task 1 of the detailed plan: shared `Direct` marker in `builder.rs`, parameterized `RotationBuilder<State, Kind>` in `rot.rs`, `mod delegated` test submodule (8 kept drt tests pasted verbatim from drt.rs), delete `drt.rs`, drop the 12 named duplicate tests. Follow the detailed plan's code blocks exactly.
2. **SEQUENTIAL — depends on step 1** (both touch `builder.rs`): Task 2 of the detailed plan: `InceptionKind` + data-bearing `Delegated { delegator }` in `icp.rs`, `DelegatedInceptionBuilder::new(delegator)` entry, `mod delegated` (6 kept dip tests, chains reordered to `new(delegator).keys(..)`), delete `dip.rs`, update `builder.rs` wiring, update the four call sites (`src/keripy_parity/validation.rs` `replay_delcept`, `examples/delegated_inception.rs`, `tests/common/mod.rs:512`, `tests/kel_chain.rs:105`) — exact edits in the detailed plan Step 2.3.
3. **SEQUENTIAL — depends on step 2**: CHANGELOG entry in `crates/keri-codec/CHANGELOG.md` per the detailed plan's Task 3 text, matching the file's existing heading style.

## Verification

After step 1 and again after step 2 (foreground — NEVER background nix commands):

```bash
nix develop --command cargo nextest run -p keri-codec
```

Expected: green; test count drops by 12 after step 1, by a further 7 after step 2. After step 2 also:

```bash
nix develop --command cargo build -p keri-codec --examples
```

Quote the tail of each command's real output in your final report — assertions without output don't count.

## Out of scope

- **NO git commits, no push, no PR** — the controller reviews and commits.
- No edits outside `crates/keri-codec/` (+ its `examples/`).
- No changes to domain types (`keri-events`), `deserialize.rs`, `serialize.rs`, `codec/`, error enums, `Cargo.toml`, lints, or `free-fn-budget.toml`.
- Do not rewrite the kept tests — copy verbatim (only the dip chain reorder listed in the detailed plan).
- `nix flake check` is NOT yours to run — controller runs the gate.
