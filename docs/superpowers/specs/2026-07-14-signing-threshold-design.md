# SigningThreshold — serder Redesign Rung 4 (#171 / closes #130)

> **Status:** design approved 2026-07-14. Next step: writing-plans.
> **Companion docs (on `main`):**
> - Redesign spec: `docs/superpowers/specs/2026-07-13-serder-domain-redesign-design.md`
> - Rungs 4–6 handoff: `docs/superpowers/plans/2026-07-14-171-rungs-4-6-handoff.md`

## Goal

Migrate `Tholder` out of `cesr::core::primitives` into `cesr::keri` as
`SigningThreshold`, folding in #130's leaner weighted representation and the
`satisfy` → `satisfied_by` rename. Rung 4 of the serder domain redesign: domain
types live in `cesr::keri`; `cesr::core` stays CESR-encoding-only.

This rung is a **move + rename + representation change**. It must not change a
single wire byte — the #145 keripy byte-identity corpora and the
`keripy_parity::formulas` satisfaction sweep are the gate.

## Context / what is already true

- **#130 is partly stale.** Its text claims weighted `satisfy` "returns `false`
  (a stub)". That is no longer true: `Tholder::satisfy` already implements exact
  weighted rational satisfaction (checked integer arithmetic, no floats) with
  fail-closed semantics. The satisfaction *logic* is done. What remains from #130
  is (a) the leaner representation and (b) the `satisfied_by(indices)` rename.
- **Callers pass mixed iterables.** `keri/src/authority.rs` calls
  `satisfy(indices: Vec<u32>)` *and* `satisfy(0..n: Range<u32>)`. The current
  `impl IntoIterator<Item = u32>` signature is load-bearing; forcing `&[u32]`
  (as #130's text literally says) would make the `0..n` caller `.collect()` a
  throwaway `Vec`. We keep `impl IntoIterator` and note the divergence from the
  issue text in the PR.
- **No `smallvec`/`arrayvec` dependency exists**, and #130 says "no arbitrary
  cap" — so an inline/stack representation is out without adding a dependency.
  "Lean" here means *fewer heap allocations*, not stack storage.
- **`cesr::keri` is `no_std` + `alloc`.** Use `core::`/`alloc::` imports only;
  mirror `toad.rs` / `sequence.rs` / `threshold_form.rs`. Verify with
  `cargo build -p cesr-rs --no-default-features --features "alloc,core,b64,keri"`.

## Design

### Type & location

New module `cesr/src/keri/threshold.rs` (sibling to `toad.rs`, `sequence.rs`,
`threshold_form.rs`), exported from `cesr/src/keri/mod.rs`. The old module
`cesr/src/core/primitives/tholder.rs` and its `core`/crate re-exports
(`core::primitives::mod`, `core::mod`, `lib.rs`) are **deleted**.

```rust
pub enum SigningThreshold {
    /// Simple threshold: at least N signatures required.
    Simple(u64),
    /// Weighted fractional threshold, flattened.
    Weighted {
        /// All clauses' (numerator, denominator) fractions, in clause order.
        weights: Vec<(u64, u64)>,
        /// Cumulative end index of each clause into `weights`.
        /// Strictly increasing; the terminal entry equals `weights.len()`.
        clause_ends: Vec<u32>,
    },
}
```

Clause *i* is the slice `weights[clause_ends[i-1] .. clause_ends[i]]` (with
`clause_ends[-1]` taken as `0`). Example — the nested value
`[[1/2, 1/2], [1/1]]` becomes `weights = [(1,2),(1,2),(1,1)]`,
`clause_ends = [2, 3]`. Allocation count: at most 2, independent of clause
count (vs. today's `1 + N`).

### Construction & invariant

A crate-private constructor validates the flattened invariant so a malformed
`(weights, clause_ends)` pair is unrepresentable outside the module:

- `clause_ends` is non-empty and strictly increasing,
- its terminal entry equals `weights.len()` (`u32::try_from`, checked),
- no two adjacent entries are equal (an equal-adjacent pair is an **empty
  clause** — the flattened analogue of a `Vec` inner clause of len 0).

Every site that builds a `Weighted` today — parser conversion
(`deserialize/canonical.rs`), the serder builders, event reification — goes
through this constructor. Building from nested clause data (`&[Vec<(u64,u64)>]`
or an iterator of clauses) is offered as a helper that flattens and validates
in one pass.

### Methods

- `satisfied_by(&self, indices: impl IntoIterator<Item = u32>) -> bool` —
  renamed from `satisfy`. Identical fail-closed semantics; the weighted arm
  walks clauses via `clause_ends` slicing instead of nested-vec iteration.
  Clause width is `clause_ends[i] - clause_ends[i-1]` (`checked_sub`), replacing
  the running `base`/`end` bookkeeping. All summation stays `checked_*`.
- `check_well_formed(&self, key_count: usize) -> Result<(), SigningThresholdError>` —
  unchanged rules; weighted checks derive from `clause_ends`/`weights`:
  - `EmptyClauseList` — `weights` empty / `clause_ends` empty,
  - `EmptyClause` — any equal-adjacent `clause_ends` pair,
  - `ExceedsKeyCount` — `weights.len() > key_count`.

The `clause_reaches_one` exact-rational helper carries over verbatim (operates
on a single clause slice + a `signed` mask; already checked-arithmetic).

### Error

`ThresholdError` → **`SigningThresholdError`** (same four variants, same
`Display` strings): `BelowMinimum`, `ExceedsKeyCount { required, key_count }`,
`EmptyClause`, `EmptyClauseList`. `thiserror`, `PartialEq`, `Eq`.

`SerderError::SigningThresholdOutOfRange { field, source }` — the `source` type
and the top-of-file import swap from `core::primitives::ThresholdError` to
`keri::SigningThresholdError`. Bridged via `#[from]`/`#[source]` as today.

## Consumers to update

All are mechanical renames (`Tholder` → `SigningThreshold`, `satisfy` →
`satisfied_by`, error type/import swap) except where the flattened constructor
replaces a nested-`Vec` literal.

- **Event bodies & accessors** — `cesr/src/keri/event/{inception,rotation,delegation,mod}.rs`:
  `threshold` / `next_threshold` fields and their accessor return types.
- **serder writers** — `serialize.rs` (`tholder_to_json`) and
  `serialize/direct.rs` (`write_tholder`); the per-ilk render paths in
  `serialize/{icp,rot,dip,drt}.rs`. Iterate clauses via `clause_ends` slices.
- **serder builders** — `builder/{icp,rot,dip,drt}.rs`, `validate_threshold` /
  the `check_well_formed` call in `builder/icp.rs`.
- **serder parser** — `deserialize/canonical.rs` (wire → `SigningThreshold`
  via the flattening constructor), `deserialize/reference.rs`.
- **`SerderError`** — `cesr/src/serder/error.rs` source-type + import swap.
- **keri-rs** — `keri/src/authority.rs` (`satisfy` → `satisfied_by`,
  `check_well_formed`); `keri/src/state.rs` threshold field types.
- **Tests / parity / examples** — `keripy_parity/formulas.rs`,
  `crypto/verify.rs` (test asserts), `examples/multisig_threshold_icp.rs`,
  `keri/tests/*` referencing the type.

## Testing

Categories-first (round-trip, defensive boundary, cross-feature, property),
per the project testing rules.

- **Port every existing `tholder.rs` test** to the new type + constructor:
  the `satisfied_by` unit tests, `check_well_formed` matrix, weighted
  multi-clause AND semantics, and the three proptests.
- **New invariant tests:**
  - Nested → flattened equivalence: for a set of nested clause literals, the
    flattened `SigningThreshold` yields the same `satisfied_by` result as the
    old nested semantics on the same index sets (encode → satisfy fixpoint).
  - Constructor rejects malformed input: non-increasing `clause_ends`, terminal
    `!= weights.len()`, equal-adjacent (empty clause), empty `clause_ends`.
  - Weighted boundary proptest with `clause_ends` covering `0`, `1`,
    single-clause, and equal-adjacent rejection.
- **Zero wire-byte change is the gate.** `keripy_parity::events` (26-vector
  byte-identity sweep), `said_codes`, `seal_events`, `keripy_parity::formulas`
  (satisfaction vs keripy), and the two keri-rs fold differentials must stay
  green. Any diff there = real regression, STOP.

## Out of scope

- The keri-rs `KeyState` vocabulary adoption (`witness_threshold: Toad`,
  `KeyState::sn() -> SequenceNumber`) — that is the rung-2/rung-4 **follow-on**
  cleanup PR, batched separately (handoff §"Follow-on").
- Any change to `ThresholdForm` (rung 3, the per-event `intive` wire flag) — it
  is orthogonal; wire form lives on the event, not inside the threshold value,
  so `SigningThreshold` equality stays purely arithmetic.
- Rungs 5 (writer deletion) and 6 (zero-copy `KeriEvent`).

## Gate & process

- One branch (`171-signing-threshold`) → PR → `nix flake check` on committed
  state → merge. Never substitute raw `cargo` for the gate.
- Breaking change (type move + rename + error rename): call it out in the PR
  description and `CHANGELOG`; MINOR bump per the 0.x SemVer convention.
- gh account `joeldsouzax`; attach the issue work to org Project #5.
- Do **not** paste keripy qb64 into `.rs` test source (trips `cesr-typos`);
  build test events via the builders, leave byte-agreement to the corpus sweep.
