# #250 — D3 resolution: abandoned-at-birth inceptions and the inert-state gate

**Date:** 2026-07-29
**Issue:** #250 (K1 divergence D3, found during #88 K2)
**Decision:** Option B — full spec fix. Drop `SelfAddressingWithoutNextKeys`,
derive state transferability, gate all events on non-transferable state.

## Evidence

- **KERI spec** (ToIP `tswg-keri-specification`, `spec/spec-body.md`, "Next key
  digest list field"):
  - Inception with empty `n`: "the associated AID MUST be deemed
    non-transferable, and no more key events MUST be allowed in that KEL."
  - Rotation with empty `n`: "the associated AID MUST be deemed abandoned, and
    no more key events MUST be allowed in its KEL."
- **keripy** (`src/keri/core/eventing.py`, 9161a705 2026-07-28):
  - Inception accepts empty `n` on a transferable prefix; the only inception
    transferability check is the non-transferable-prefix-with-non-empty-`n`
    rejection (2374-2378).
  - `Kever.transferable` = `ndigers` non-empty AND prefix code transferable
    (2166) — a derived state property, not a prefix-code echo.
  - `Kever.update` rejects ALL further events on a non-transferable state
    ("Unexpected event … is nontransferable or abandoned state", 2477); the
    rotation-specific check at 2672 is downstream of that gate.
- **Our K1 fold** (`crates/keri/src/state.rs`) rejects the inception outright
  (`TransferabilityError::SelfAddressingWithoutNextKeys`, state.rs:650). That
  is nonconformance with the spec MUST, not a deliberate tightening. Two
  further latent gaps share the same root cause:
  1. `ingest` has no transferability gate at all — an interaction on a basic
     non-transferable AID is accepted today (keripy and the spec reject it).
  2. Rotation-to-empty-`n` (abandonment) leaves a state that still accepts
     interactions; a later rotation dies only via a misleading
     `NextKeyCommitmentMismatch`.

## Design

### 1. Transferability becomes derived state

`decide_transferability` keeps `NonTransferableCommitsNextKeys` (keripy 2374
parity) and loses `SelfAddressingWithoutNextKeys`. Result:
`Transferability::Transferable` iff the prefix code is transferable AND
`next_keys` is non-empty (keripy 2166). `TransferabilityError` shrinks to one
variant and remains the inception-shape error domain.

### 2. Inert-state gate in `ingest`

First check in `KeyState::ingest`, before the event-kind match (keripy's 2477
gate precedes everything): a non-transferable state rejects every event with a
new `Rejection::NonTransferableState` (spec vocabulary — "non-transferable" /
"abandoned" — no keripy lexicon).
Disposition: **Terminal** — state-determined, no evidence can cure it.
`DuplicateInception` / `DelegationUnsupported` become second in precedence,
matching keripy's error order.

### 3. Abandonment via rotation

`rotated()` recomputes: empty `rot.next_keys()` → `NonTransferable`, otherwise
carry. The next event dies at the gate. The spec's "abandoned" is modeled as
`NonTransferable` — no third enum variant; keripy lumps them and two states
carry the same operational meaning (no more key events).

### 4. Trusted snapshot fold mirrors

`KeyStateSnapshot::genesis` derives transferability with the same rule;
`rolled()` applies the same empty-`n` rule. Both stay total and deterministic
(garbage-in-deterministic-out preserved — no new checks, only computation).

### 5. K2 disposition bookkeeping

`Rejection::disposition()` (no-wildcard match): removed variant leaves, new
variant enters as `Terminal`. Rustdoc on the new variant records the keripy
equivalent (eventing.py:2477, bare `ValidationError` drop) and re-drive
trigger (none). The D3 note on `crates/keri/src/error.rs:134` is rewritten to
"resolved by #250"; the K2 design doc's D3 entry gets a resolution pointer.

### 6. Tests

- Inception, transferable prefix, empty `n`: accepted; state folds
  `NonTransferable`; subsequent rotation AND interaction each rejected with
  the new variant (exact `matches!`, per error-testing convention).
- Basic non-transferable inception then interaction: rejected (probe for
  latent gap 1 — fails on today's code, proving the gap real).
- Rotation-to-empty-`n`: accepted; any subsequent event rejected.
- Snapshot/fold equivalence (existing property suite) extended over the
  abandonment path.
- `crates/keri-codec/tests/transitions.rs:231` updated (asserts the deleted
  variant today).
- Disposition unit test: new variant → `Terminal`.
- Differential vector test name contains "keripy" (nightly filter rule).

### 7. Breaking change + docs

keri-rs 0.x MINOR bump semantics: `TransferabilityError` variant removed,
`Rejection` variant added, fold behavior change (accepts previously rejected
inceptions, rejects previously accepted interactions). CHANGELOG entries for
all three. PR closes #250.

## Out of scope

K9 differential vectors (#95) — they now need no D3 carve-out. Delegation
validation (K4). D1/D2 (#132/#133). Escrow/host runtime.
