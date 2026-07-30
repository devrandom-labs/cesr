# 90 · K4 delegation validation over typed evidence

## Context

Full plan with COMPLETE code for every step:
`docs/superpowers/plans/2026-07-30-90-k4-delegation-validation.md` — read it
FIRST; it contains the exact types, method bodies, error variants, doc
comments, and test functions. This file adds only execution constraints,
ordering, and parallelism. Design rationale (spec MUST anchors, keripy line
anchors): `docs/superpowers/specs/2026-07-30-90-k4-delegation-validation-design.md`.

Invariants that must hold:

- keri-rs free-fn budget is 0 (`free-fn-budget.toml`): NO new file-scope
  `pub`/`pub(crate)`/`pub(super)` fn in `crates/keri/src` — shared logic is
  methods (`KeriEvent::anchor_position` in keri-events,
  `DelegationEvidence::authorizes` in keri).
- The evidence checks (`authorizes`) run AFTER signatures/thresholds/
  witnessing in both delegated entries (keripy `valSigsWigsDel` order). The
  drt delegator-presence gate (`DelegatorUnknown`, Terminal) precedes
  `rotate` by design — a state-shape precondition like
  `NonTransferableState`, not an evidence check.
- `disposition()` stays total — no wildcard arm over `DelegationError`.
- Import style: all `use` at file top; no inline `use`, no fully-qualified
  construction. Clippy god-level: fix code, never `#[allow]`.
- Do NOT commit. Do NOT run cargo test / cargo nextest (sandboxed here —
  they hang). Tests are verified by the controller via `nix flake check`.

## Steps

Each step = the same-numbered Task in the full plan doc; files and code live
there. Ordering/parallelism:

1. `KeriEvent::anchor_position` (keri-events) — Task 1.
   Files: `crates/keri-events/src/event/mod.rs`.
   PARALLEL OK (disjoint from step 2).
   Verify: `cargo check -p keri-events --all-targets`.

2. Error reshape — Task 2. `DelegationError` in, `DelegationUnsupported`
   out, `StructuralError::NotDelegatedInception`/`NotDelegatedRotation`,
   disposition arms, `ingest` dip/drt arm AND the `incept` dip arm
   (a dip at the plain genesis entry parks as `EvidenceRequired`, never
   `NotInception`), lib.rs doc-line + re-export, transitions.rs assertion
   updates + the new `delegated_inception_at_genesis_requires_evidence`
   test. Line numbers in the full plan drifted ±12 lines — grep, don't
   trust them.
   Files: `crates/keri/src/{error,state,lib}.rs`,
   `crates/keri-codec/tests/transitions.rs`.
   PARALLEL OK with step 1 only.
   Verify: `cargo check -p keri-rs --all-targets`.

3. `delegation.rs` module + duplicity switch to `anchor_position` — Task 3.
   Files: `crates/keri/src/delegation.rs` (new),
   `crates/keri/src/{duplicity,lib}.rs`.
   SEQUENTIAL — depends on steps 1 and 2.
   Verify: `cargo check -p keri-rs --all-targets`.

4. Delegator widening to `Identifier` + trusted-fold dip delegator — Task 4.
   Files: `crates/keri/src/state.rs`.
   SEQUENTIAL — depends on step 2 (same file).
   Verify: `cargo check -p keri-rs --all-targets && cargo check -p keri-codec --all-targets`.

5. Fold entries `incept_delegated`/`ingest_delegated` + crate-doc rewrite —
   Task 5.
   Files: `crates/keri/src/{state,lib}.rs`.
   SEQUENTIAL — depends on steps 3 and 4.
   Verify: `cargo clippy -p keri-rs --all-targets -- -D warnings`.

6. Fixtures + acceptance/negative integration tests — Task 6.
   Files: `crates/keri-codec/tests/common/mod.rs` (widen
   `delegated_inception` delegator param to `Identifier<'static>`, add
   `delegated_rotation_full`; update callers in `transitions.rs` and
   `duplicity.rs`), `crates/keri-codec/tests/delegation.rs` (new).
   SEQUENTIAL — depends on step 5.
   Verify: `cargo check -p keri-codec --all-targets`.

7. Differential invariant + revoked-then-used recovery tests — Task 7.
   Files: `crates/keri-codec/tests/delegation.rs`.
   SEQUENTIAL — depends on step 6 (same file).
   Verify: `cargo check -p keri-codec --all-targets`.

8. Property tests — Task 8.
   Files: `crates/keri-codec/tests/delegation.rs`.
   SEQUENTIAL — depends on step 7 (same file).
   Verify: `cargo check -p keri-codec --all-targets`.

9. keripy differential corpus — Task 9. Generator + corpus + differential
   test. Riskiest step: the Kevery must be validator-role (no local habs) or
   `validateDelegation` short-circuits — `scripts/keripy_duplicity_gen.py`
   already runs a bare `Kevery(db=db)` with dip/deltate scenarios; reuse
   that pattern. Verified working interpreter invocation (probe ran
   2026-07-30, prints `2.0.0-dev6`):

   ```bash
   PYTHONPATH=/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages:/Users/joel/Code/keripy/src \
   DYLD_LIBRARY_PATH=/nix/store/1lhfaycm5fznrydp51q1dvgr6acp1xjm-libsodium-1.0.22-unstable-2026-04-09/lib \
   ~/.local/bin/python3.14 scripts/keripy_delegation_gen.py --out crates/keri-codec/tests/corpus/delegation.jsonl
   ```

   Files: `scripts/keripy_delegation_gen.py` (new),
   `crates/keri-codec/tests/corpus/delegation.jsonl` (generated),
   `crates/keri-codec/tests/keripy_delegation.rs` (new).
   PARALLEL OK with steps 7-8 (disjoint files) once step 6 is done.
   If the validator-role setup cannot be made to run the seal path, STOP
   this step and report blocked for it — never hand-compute vectors.
   Verify: `cargo check -p keri-codec --all-targets` and every corpus
   `expected` value in {accepted, awaiting, denied}.

10. #83 boundary rustdoc + CHANGELOGs — Task 10 steps 1-2 only (no push, no
    PR — controller does that).
    Files: `crates/keri-events/src/event/delegation.rs`,
    `crates/keri/CHANGELOG.md`, `crates/keri-events/CHANGELOG.md`.
    PARALLEL OK with steps 7-9.
    Verify: `cargo check -p keri-events --all-targets`.

Suggested fan-out: steps 1∥2 first; 3→4→5 sequential; then 6; then 7→8
sequential with 9 and 10 in parallel. Mechanical caller updates in step 6
(`.into()` on delegator args) are sonic-suitable.

## Verification

- Per-step commands above (`cargo check` / `cargo clippy` ONLY — no tests
  in this sandbox).
- Final: `cargo clippy --workspace --all-targets -- -D warnings` must be
  clean. The controller runs `nix flake check` (nextest, doctest, wasm,
  no_std, fn-ratchet) after review — write tests to pass it, don't run it.

## Out of scope

- No commits, no push, no PR.
- No changes to `clippy.toml`, `[lints]`, `free-fn-budget.toml`.
- No new free functions in `crates/keri/src` (budget 0).
- `judge_same_sn`/cascade semantics (K3, landed) — only the
  `seal_position` → `anchor_position` mechanical switch.
- Evidence acquisition, escrow storage, `DelegateIsDelegator` semantics —
  docs mention only.
- Do not touch `fuzz/`, `benches/`, `examples/` unless a grep in a step
  demands a caller fix.
