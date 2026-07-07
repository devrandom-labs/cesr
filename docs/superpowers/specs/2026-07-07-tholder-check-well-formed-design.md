# Design — `Tholder::check_well_formed`: one threshold rule for write + read paths

**Date:** 2026-07-07
**Type:** cesr consolidation + bug fix. Replaces the unreleased `Tholder::is_well_formed` (added earlier this session, keri-only) with a structured-error form; additive `ThresholdError`. serder + keri internals only.

## Problem

Threshold well-formedness is validated in **two** places that do not share code, and they **disagree**:

- **Write path** — `serder::builder::validate_threshold` (`serder/builder/icp.rs:209`), called by the icp/rot/dip/drt builders. For `Weighted` it checks only `total_weights <= key_count`.
- **Read path** — `Tholder::is_well_formed` (`core/primitives/tholder.rs`), called by keri's `check_established_threshold`. For `Weighted` it *also* rejects empty clauses and an empty clause-list.

Consequence: the builder can construct a `Weighted(vec![vec![]])` (empty clause) or `Weighted(vec![])` threshold that the keri fold rejects — a read/write asymmetry (Mandatory Rule 3: "read-path and write-path must enforce the same invariants the same way") and a latent bug, independent of aesthetics.

Only the threshold rule is genuinely shared. Witness-threshold (TOAD ≤ count) and transferability/next-key are checked **only** in the keri fold — the serder builder doesn't touch them — so they stay keri domain logic; there is no write/read duplication to consolidate there.

## Design decisions (confirmed with user)

- **`Tholder` owns the rule; both paths adapt.** One definition on the primitive, called by serder (write) and keri (read).
- **Structured error, not bool.** `check_well_formed` returns `Result<(), ThresholdError>` so serder can keep its granular, labelled messages and keri can map to its taxonomy. Replaces the bool `is_well_formed` (unreleased this session, only keri consumes it — safe to swap).
- **Domain-named error variants**, one per distinct failure domain (Mandatory Rule 3), co-located with `Tholder`.

## Changes

### 1. New error + method — `core/primitives/tholder.rs`

```rust
/// Why a threshold is not well-formed for a given key count.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThresholdError {
    #[error("simple threshold must require at least one signature")]
    BelowMinimum,
    #[error("threshold requires {required} of {key_count} keys")]
    ExceedsKeyCount { required: usize, key_count: usize },
    #[error("weighted threshold has an empty clause")]
    EmptyClause,
    #[error("weighted threshold has no clauses")]
    EmptyClauseList,
}

impl Tholder {
    /// Returns `Ok(())` if this threshold is structurally valid for a signing
    /// key set of `key_count` keys, else the specific [`ThresholdError`].
    ///
    /// A `Simple` threshold must require at least one signature and no more than
    /// `key_count`. A `Weighted` threshold must have at least one clause, no empty
    /// clause, and no more weights in total than `key_count`. A threshold over
    /// zero keys is never well-formed.
    pub fn check_well_formed(&self, key_count: usize) -> Result<(), ThresholdError> {
        match self {
            Self::Simple(n) => {
                let required = usize::try_from(*n)
                    .map_err(|_| ThresholdError::ExceedsKeyCount { required: usize::MAX, key_count })?;
                if required < 1 { return Err(ThresholdError::BelowMinimum); }
                if required > key_count {
                    return Err(ThresholdError::ExceedsKeyCount { required, key_count });
                }
                Ok(())
            }
            Self::Weighted(clauses) => {
                if clauses.is_empty() { return Err(ThresholdError::EmptyClauseList); }
                if clauses.iter().any(Vec::is_empty) { return Err(ThresholdError::EmptyClause); }
                let total: usize = clauses.iter().map(Vec::len).sum();
                if total > key_count {
                    return Err(ThresholdError::ExceedsKeyCount { required: total, key_count });
                }
                Ok(())
            }
        }
    }
}
```

Remove `is_well_formed`. Export `ThresholdError` from `core`'s primitives re-exports alongside `Tholder`.

Semantics are preserved from `is_well_formed` (same accept/reject set); only the return type gains structure. `BelowMinimum` before the range check preserves that `Simple(0)` is malformed; the `usize::try_from` failure folds into `ExceedsKeyCount` (an unrepresentable count cannot be met).

### 2. Write path — `serder/builder/icp.rs`

`validate_threshold` becomes a thin adapter (keeps the `label` context):

```rust
pub(crate) fn validate_threshold(threshold: &Tholder, key_count: usize, label: &str) -> Result<(), SerderError> {
    threshold
        .check_well_formed(key_count)
        .map_err(|e| SerderError::Validation(format!("{label} threshold: {e}")))
}
```

This **fixes the bug**: the builder now rejects the empty-clause / empty-clause-list weighted thresholds it previously accepted. The four builders (icp/rot/dip/drt) already call `validate_threshold`; they are unchanged.

### 3. Read path — `keri/src/state.rs`

`check_established_threshold` becomes a thin adapter:

```rust
fn check_established_threshold(keys: &[Verfer<'_>], tholder: &Tholder) -> Result<(), Rejection> {
    tholder
        .check_well_formed(keys.len())
        .map_err(|_| Rejection::new(RejectionReason::InvalidEvent))
}
```

`keys.len() == 0` still errors via the rule, so the empty-keys case stays covered. Behavior-preserving for keri (same accept/reject set as `is_well_formed`).

## Error handling

- `ThresholdError`: `thiserror`, one variant per failure domain, `Display` messages that read well when serder embeds them via `format!("{label} threshold: {e}")`. `PartialEq`/`Eq` so tests match variants directly.
- serder maps → `SerderError::Validation` (preserves source `Display`); keri maps → `Rejection::InvalidEvent`. Neither discards the reason.

## Testing (TDD — categories first)

`core/primitives/tholder.rs` tests (migrate existing `is_well_formed` tests to the `Result` shape):
- Happy: simple in-range, simple == count, weighted within count → `Ok`.
- Each error variant asserted exactly: `Simple(0)` → `BelowMinimum`; `Simple(n>count)` and `Weighted(total>count)` → `ExceedsKeyCount { .. }`; `Weighted(vec![vec![]])` → `EmptyClause`; `Weighted(vec![])` → `EmptyClauseList`; `key_count==0` for both variants → the appropriate error.

Bug-regression:
- A serder-builder test that a weighted threshold with an empty clause is now **rejected at construction** (previously accepted) — this is the read/write asymmetry closing.

Cross-path:
- keri's 30 `state.rs` tests stay green (behavior-preserving read side).
- serder builder tests stay green except the newly-rejected empty-clause case.

## Not in scope

- The `check_a()?; check_b()?;` transition sequence stays — clear as-is; not turned into a combinator.
- Witness-threshold and transferability/next-key stay keri-local (no write/read duplication).
- The rotate/interact sn+prior-digest "chains onto state" dedup is a separate future keri polish.
