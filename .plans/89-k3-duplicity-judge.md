# 89 — K3 duplicity + superseding-recovery judge

Execution tier: k3. Detailed step code:
`docs/superpowers/plans/2026-07-30-89-k3-duplicity-superseding.md` — its code
blocks are the source of truth; follow them verbatim where given. Spec with
keripy line anchors:
`docs/superpowers/specs/2026-07-30-89-k3-duplicity-superseding-design.md`.

PREREQUISITE: seal-identifier widening (#259) merged and this branch rebased —
the cascade compares `Seal::Event.i` (an `Identifier`) to event prefixes.

## Context

`KeyState::judge_same_sn(incoming, recorded, delegation_chain)` →
`Result<SameSnVerdict, EvidenceError>`: pure same-sn judgment (duplicate /
supersedes / duplicitous / yields / undecided), keripy-conformant (oracle
main `9161a705`; rule anchors in the spec). New module
`crates/keri/src/duplicity.rs`; unified accessors on
`keri_events::KeriEvent`; new `Disposition::Contested` in
`crates/keri/src/error.rs`.

Invariants:
- Judge is routing only: NO signature/commitment/witness checks in it — on
  `Supersedes` the host rewinds and re-drives `KeyState::ingest`.
- Boundary validation: judge checks its own evidence (`IncomingNotStale`,
  `RecordedSnMismatch`, `SealNotFound {level}`); never trusts the host.
- Cascade is a bounded iteration over the pair slice — no recursion, no
  depth parameter.
- No new free `pub fn` in keri-rs (fn-ratchet); rule helpers are private
  free fns, entry is a method.
- No panics/unwrap on any input; arithmetic per shared rules (sn compares
  only — no arithmetic beyond `.value()` comparisons is expected; if any
  add/sub appears, it must be checked_*).
- Error enums via thiserror; every variant documented; import style rules
  (no inline `use`, no fully-qualified construction) — hooks enforce.

## Steps

1. PARALLEL OK (files disjoint from step 2's). `crates/keri-events/src/event/mod.rs`:
   unified `sn()/said()/prefix()/anchors()` on `KeriEvent` + the two unit
   tests — detailed plan Task 1 verbatim. Outcome: `cargo check -p keri-events --tests` clean.
2. PARALLEL OK (files disjoint from step 1's). `crates/keri/src/error.rs`:
   `Disposition::Contested` variant; stale `OutOfOrder` arm →
   `Contested`; `Structural(DuplicateInception)` carved out → `Contested`
   (specific arm before the blanket `Structural(_)` arm); doc-comment
   updates; test updates and additions — detailed plan Task 3 verbatim
   (tests: `out_of_order_stale_is_contested`,
   `out_of_order_stale_at_u128_boundary_is_contested`,
   `duplicate_inception_is_contested`, repoint `structural_error_is_terminal`
   at `InteractionOnEstablishmentOnly`).
3. SEQUENTIAL — depends on 1 and 2. Create `crates/keri/src/duplicity.rs`
   (detailed plan Task 2 Step 1 — full module code given) and wire
   `crates/keri/src/lib.rs` (module decl, re-exports
   `DelegationContest, EvidenceError, SameSnVerdict`, crate-doc paragraph —
   Task 2 Step 2). Outcome: `cargo check -p keri-rs` clean, doc-links resolve
   (`cargo doc -p keri-rs --no-deps` if in doubt).
4. SEQUENTIAL — depends on 3. Gate integration tests:
   `crates/keri-codec/tests/duplicity.rs` (detailed plan Task 4 Step 2 — full
   test code given; adapt to `common::Event`'s real field names) plus the
   `interaction_anchoring` fixture in `crates/keri-codec/tests/common/mod.rs`
   (copy `interaction`'s body, thread the seals `Vec` where it passes the
   empty anchor list). Outcome: `cargo check -p keri-codec --tests` clean.
5. SEQUENTIAL — depends on 4 (same test file). Cascade tests — detailed plan
   Task 5: eight named tests (B1, B2 win, B2 loss, B3, tie-climb-decide,
   exhausted→Undecided, empty-chain→Undecided, unlinked-pair→
   `SealNotFound {level: 0}`). Delegate-side state via
   `KeyStateSnapshot::genesis/advance` + `.view()`; delegator events anchor
   drt `(i,s,d)` via `interaction_anchoring` — the seal's `i` MUST equal the
   delegate event's `prefix()` (check which `Identifier` arm
   `common::delegated_inception` produces and build the seal to match).
   Assert exact verdict variants.
6. SEQUENTIAL — depends on 5 (same test file). Property module — detailed
   plan Task 6: `judge_is_total` (boundary sns incl. 0/1/large, chain len
   0/1/deep — reaching the end without panic is the property) and
   `supersedes_is_antisymmetric` (`!(judge(a,b)==Supersedes &&
   judge(b,a)==Supersedes)`). Use the fixture helpers, never reimplement
   judge logic. Outcome: `cargo check -p keri-codec --tests` clean.
7. SEQUENTIAL — depends on 3. Fold round-trip test
   `supersedes_verdict_rewinds_and_refolds` — detailed plan Task 7 verbatim
   (same file as 4-6, so runs after 6 in practice; if executing with the
   task tool, fold 7 into the same agent as 4-6).
8. SEQUENTIAL — depends on 3. keripy differential generator + test — detailed
   plan Tasks 8-9: `scripts/keripy_duplicity_gen.py` (model on
   `scripts/keripy_keystate_gen.py`; scenario list + `outcome()` helper given
   in the detailed plan), Rust side `crates/keri-codec/tests/keripy_duplicity.rs`
   (follows `crates/keri-codec/tests/differential.rs` structure; names must
   contain `keripy`). WRITE the script and the Rust test; do NOT execute the
   python generator (needs the keripy env + DYLD_LIBRARY_PATH — Claude runs
   it and checks in the corpus). Guard the Rust test so a missing/empty
   corpus file is a clear failure message, and add the corpus path to the
   plan report. Cascade scenarios (Task 9) port keripy's
   `tests/core/test_delegating.py::test_delegation_supersede` construction
   into the script; if that port needs information you cannot obtain, emit
   blocked with the specific gap instead of inventing vectors.
9. SEQUENTIAL — depends on all. CHANGELOGs — detailed plan Task 10 Step 1:
   `crates/keri/CHANGELOG.md` (breaking: `Disposition::Contested`; new
   `duplicity` module), `crates/keri-events/CHANGELOG.md` (additive unified
   accessors).

## Verification (sandbox-safe — NO cargo test / nextest, they hang)

- Per step: `cargo check -p <crate> --tests` as listed.
- Final: `cargo check --workspace --all-targets` and
  `cargo clippy --workspace --all-targets` — clippy is god-level and law:
  fix code, never relax lints; `#[allow]` only with `reason` and only if
  genuinely unavoidable.
- `cargo fmt --check` (hooks enforce formatting and import style).
- Tests + wasm/no_std run later via `nix flake check` (Claude drives,
  unsandboxed). include_str corpus test will be exercised then.

## Out of scope

- `crates/keri/src/state.rs` fold logic (no changes to ingest/incept).
- K4 delegation folding; K5 receipts; first-seen policy; any storage/escrow
  mechanics.
- Running the python generator or nextest (Claude-side).
- No commits — leave the tree dirty; Claude reviews and commits.
- No lint-level, clippy.toml, free-fn-budget.toml, or hook changes.
