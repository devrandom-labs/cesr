# SigningThreshold Implementation Plan (#171 rung 4 / closes #130)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `Tholder` from `cesr::core::primitives` into `cesr::keri` as `SigningThreshold`, with a flattened weighted representation (fewer heap allocations) and the `satisfy` → `satisfied_by` rename, changing zero wire bytes.

**Architecture:** New self-contained domain type in `cesr/src/keri/threshold.rs`, mirroring the merged siblings `toad.rs`/`sequence.rs`/`threshold_form.rs`. The weighted arm becomes `Weighted(WeightedThreshold)` where `WeightedThreshold` holds flat `weights: Vec<(u64,u64)>` + cumulative `clause_ends: Vec<u32>` behind private fields and a validating constructor, so a malformed flattened pair is unrepresentable outside the module. Build the type in isolation first (it coexists with `Tholder`), then perform one atomic compiler-driven swap that deletes `Tholder`.

**Tech Stack:** Rust 2024, `no_std` + `alloc`, `thiserror`, `proptest`. Gate: `nix flake check` (clippy god-level, corpus byte-identity, keripy parity sweep).

**Spec:** `docs/superpowers/specs/2026-07-14-signing-threshold-design.md`

---

## Design reference (types every task refers to)

```rust
// cesr/src/keri/threshold.rs

pub enum SigningThreshold {
    Simple(u64),
    Weighted(WeightedThreshold),
}

pub struct WeightedThreshold {
    // all clauses' (numerator, denominator) fractions, in clause order
    weights: Vec<(u64, u64)>,
    // cumulative end index of each clause into `weights`; non-decreasing,
    // terminal entry == weights.len(). Equal-adjacent entries = an empty clause.
    clause_ends: Vec<u32>,
}

pub enum SigningThresholdError {
    BelowMinimum,
    ExceedsKeyCount { required: usize, key_count: usize },
    EmptyClause,
    EmptyClauseList,
    TooManyWeights { count: usize },   // NEW: flattened-repr overflow guard
}
```

**Why the 5th variant (`TooManyWeights`)?** The flattened repr stores clause
boundaries as `u32` (clause boundaries live in the same index space as the
`u32` signer positions `satisfied_by` compares against). Building `clause_ends`
therefore does a checked `u32::try_from` on cumulative clause lengths. Per the
arithmetic-safety rule (no bare cast, no `unwrap_or` sentinel), the constructor
returns `Result` and this variant is the fail-loud home for the (practically
unreachable: >2³²−1 weights) overflow. This refines the spec, which listed four
variants but already mandated "checked `u32::try_from`" — call it out in the PR.

**Representational vs well-formedness invariant (important):**
- The constructor enforces only the *representational* invariant (clause_ends
  non-decreasing, terminal == `weights.len()`, `u32` fit). Empty clauses
  (equal-adjacent) and the empty clause-list (`weights=[]`, `clause_ends=[]`)
  remain *representable* — exactly as `Tholder::Weighted(vec![vec![]])` and
  `Tholder::Weighted(vec![])` are today.
- `check_well_formed` continues to own the *well-formedness* rules
  (`EmptyClause`, `EmptyClauseList`, `ExceedsKeyCount`). This preserves the
  current split where an empty clause is a valid value that fails validation,
  not a parse error — so no corpus round-trip changes when it fires.

---

## Task 1: Create the `SigningThreshold` domain type

**Files:**
- Create: `cesr/src/keri/threshold.rs`
- Modify: `cesr/src/keri/mod.rs` (add `pub mod threshold;` + `pub use`)

The type is `pub`-exported, so it coexists with `Tholder` without tripping
`dead_code = deny`. All logic + tests land here; consumers are swapped in Task 2.

- [ ] **Step 1: Write the module with the failing tests first**

Create `cesr/src/keri/threshold.rs` with the full type, then the ported +
new tests. Write the tests referencing the final API before the impl compiles
so the first `cargo build` failure is "method/type not found".

Type + error + constructors + reader:

```rust
//! Signing threshold — the KERI key-agreement domain type (keripy: Tholder).

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use thiserror::Error;

/// Signing threshold — either a simple numeric threshold or a weighted
/// fractional threshold structure.
///
/// Wire form (integer vs hex-string) is NOT part of this value; it lives on the
/// event as [`crate::keri::ThresholdForm`], so equality here is purely
/// arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningThreshold {
    /// Simple threshold: at least N signatures required.
    Simple(u64),
    /// Weighted threshold: clauses of `(numerator, denominator)` fractions.
    Weighted(WeightedThreshold),
}

/// A weighted signing threshold in flattened form.
///
/// Clauses are stored contiguously in `weights`, with `clause_ends[i]` the
/// cumulative end index of clause `i`. Clause `i` is
/// `weights[clause_ends[i-1]..clause_ends[i]]` (with `clause_ends[-1]` taken as
/// `0`). At most two allocations regardless of clause count. The private fields
/// and validating constructor make a representationally inconsistent pair
/// unbuildable outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedThreshold {
    weights: Vec<(u64, u64)>,
    clause_ends: Vec<u32>,
}

/// Why a [`SigningThreshold`] is not well-formed for a given key count, or
/// cannot be represented.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningThresholdError {
    /// A simple threshold that requires zero signatures.
    #[error("simple threshold must require at least one signature")]
    BelowMinimum,
    /// The threshold addresses more key positions than exist.
    #[error("threshold requires {required} keys but only {key_count} available")]
    ExceedsKeyCount {
        /// Number of key positions the threshold requires.
        required: usize,
        /// Number of keys available.
        key_count: usize,
    },
    /// A weighted threshold containing a clause with no weights.
    #[error("weighted threshold has an empty clause")]
    EmptyClause,
    /// A weighted threshold with no clauses at all.
    #[error("weighted threshold has no clauses")]
    EmptyClauseList,
    /// More weights than the flattened representation's `u32` boundary space.
    #[error("weighted threshold has {count} weights, exceeding the u32 range")]
    TooManyWeights {
        /// The oversized weight count.
        count: usize,
    },
}

impl WeightedThreshold {
    /// Build a flattened weighted threshold from nested clauses, validating the
    /// representational invariant.
    ///
    /// Empty clauses and an empty clause-list are permitted here (they are
    /// representable but not well-formed — see [`SigningThreshold::check_well_formed`]).
    ///
    /// # Errors
    ///
    /// [`SigningThresholdError::TooManyWeights`] if the total weight count
    /// exceeds `u32::MAX`.
    pub fn from_nested(clauses: Vec<Vec<(u64, u64)>>) -> Result<Self, SigningThresholdError> {
        let total: usize = clauses.iter().map(Vec::len).sum();
        let mut weights: Vec<(u64, u64)> = Vec::with_capacity(total);
        let mut clause_ends: Vec<u32> = Vec::with_capacity(clauses.len());
        for clause in clauses {
            weights.extend_from_slice(&clause);
            let end = u32::try_from(weights.len())
                .map_err(|_| SigningThresholdError::TooManyWeights { count: weights.len() })?;
            clause_ends.push(end);
        }
        Ok(Self {
            weights,
            clause_ends,
        })
    }

    /// Iterate the clauses as fraction slices, in order.
    ///
    /// Cast-free and fail-closed: a boundary that (impossibly, given the
    /// construction invariant) fails `usize` conversion or slicing is skipped
    /// rather than panicking.
    pub fn clauses(&self) -> impl Iterator<Item = &[(u64, u64)]> {
        let mut start: usize = 0;
        self.clause_ends.iter().filter_map(move |&end| {
            let end_us = usize::try_from(end).ok()?;
            let clause = self.weights.get(start..end_us)?;
            start = end_us;
            Some(clause)
        })
    }
}

impl SigningThreshold {
    /// Returns `true` if the signers at `indices` satisfy this threshold.
    ///
    /// `indices` are key-list positions of already-verified signatures. Simple:
    /// the count of distinct indices must reach N. Weighted: each clause owns a
    /// contiguous run of positions and the summed fractions of its signed
    /// positions must reach `>= 1`. Duplicates are deduplicated; indices outside
    /// every clause are ignored. Fails closed on any unrepresentable case.
    #[must_use]
    pub fn satisfied_by(&self, indices: impl IntoIterator<Item = u32>) -> bool {
        let mut distinct: Vec<u32> = indices.into_iter().collect();
        distinct.sort_unstable();
        distinct.dedup();

        match self {
            Self::Simple(threshold) => {
                let Ok(required) = usize::try_from(*threshold) else {
                    return false;
                };
                distinct.len() >= required
            }
            Self::Weighted(w) => {
                if w.clause_ends.is_empty() {
                    return false;
                }
                // Mirrors the original Tholder::satisfy: each clause owns the
                // contiguous position run `[base, end)`; clauses are sourced from
                // the flattened iterator instead of a nested Vec.
                let mut base: u32 = 0;
                for clause in w.clauses() {
                    let Ok(width) = u32::try_from(clause.len()) else {
                        return false;
                    };
                    let Some(end) = base.checked_add(width) else {
                        return false;
                    };
                    let mut signed: Vec<bool> = vec![false; clause.len()];
                    for &idx in &distinct {
                        if idx >= base
                            && idx < end
                            && let Some(local) =
                                idx.checked_sub(base).and_then(|o| usize::try_from(o).ok())
                            && let Some(slot) = signed.get_mut(local)
                        {
                            *slot = true;
                        }
                    }
                    if clause_reaches_one(clause, &signed) != Some(true) {
                        return false;
                    }
                    base = end;
                }
                true
            }
        }
    }

    /// Returns `Ok(())` if this threshold is well-formed for `key_count` keys.
    ///
    /// # Errors
    ///
    /// The [`SigningThresholdError`] variant naming the first rule violated.
    pub fn check_well_formed(&self, key_count: usize) -> Result<(), SigningThresholdError> {
        match self {
            Self::Simple(threshold) => {
                let required = usize::try_from(*threshold).map_err(|_| {
                    SigningThresholdError::ExceedsKeyCount {
                        required: usize::MAX,
                        key_count,
                    }
                })?;
                if required < 1 {
                    return Err(SigningThresholdError::BelowMinimum);
                }
                if required > key_count {
                    return Err(SigningThresholdError::ExceedsKeyCount {
                        required,
                        key_count,
                    });
                }
                Ok(())
            }
            Self::Weighted(w) => {
                if w.clause_ends.is_empty() {
                    return Err(SigningThresholdError::EmptyClauseList);
                }
                if w.clauses().any(<[(u64, u64)]>::is_empty) {
                    return Err(SigningThresholdError::EmptyClause);
                }
                let total = w.weights.len();
                if total > key_count {
                    return Err(SigningThresholdError::ExceedsKeyCount {
                        required: total,
                        key_count,
                    });
                }
                Ok(())
            }
        }
    }
}

/// Exact test that the summed fractions at signed positions within one clause
/// reach `>= 1`. Returns `None` on arithmetic overflow or a zero denominator.
fn clause_reaches_one(clause: &[(u64, u64)], signed: &[bool]) -> Option<bool> {
    let mut acc_num: u64 = 0;
    let mut acc_den: u64 = 1;
    for (i, &(num, den)) in clause.iter().enumerate() {
        if den == 0 {
            return None;
        }
        if matches!(signed.get(i), Some(true)) {
            let lhs = acc_num.checked_mul(den)?;
            let rhs = num.checked_mul(acc_den)?;
            acc_num = lhs.checked_add(rhs)?;
            acc_den = acc_den.checked_mul(den)?;
        }
    }
    Some(acc_num >= acc_den)
}
```

> **Clippy note:** the code above is deliberately cast-free (no bare `as`) —
> `clauses()` uses `usize::try_from` + `Vec::get`, and `satisfied_by` widens via
> `usize::try_from`. Keep it that way; a bare `as` will trip the restriction
> suite and must never be silenced with `#[allow]`. The `&& let` let-chains are
> stable on the pinned 1.95 / edition-2024 toolchain.

Then the tests (ported verbatim in intent from `tholder.rs`, retargeted to the
new API, plus the new invariant tests):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn weighted(clauses: Vec<Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }

    #[test]
    fn simple_counts_distinct_indices() {
        let th = SigningThreshold::Simple(2);
        assert!(!th.satisfied_by([]));
        assert!(!th.satisfied_by([0]));
        assert!(th.satisfied_by([0, 1]));
        assert!(th.satisfied_by([0, 1, 2]));
        assert!(!th.satisfied_by([0, 0]));
    }

    #[test]
    fn simple_zero_is_always_met() {
        assert!(SigningThreshold::Simple(0).satisfied_by([]));
    }

    #[test]
    fn weighted_single_clause() {
        let th = weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]);
        assert!(!th.satisfied_by([0]));
        assert!(th.satisfied_by([0, 1]));
        assert!(th.satisfied_by([1, 2]));
        assert!(th.satisfied_by([0, 1, 2]));
    }

    #[test]
    fn weighted_multi_clause_is_and_of_clauses() {
        let th = weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 1), (1, 1)]]);
        assert!(!th.satisfied_by([0, 1]));
        assert!(!th.satisfied_by([2]));
        assert!(th.satisfied_by([0, 1, 2]));
    }

    #[test]
    fn weighted_empty_clause_list_is_never_satisfied() {
        let th = weighted(vec![]);
        assert!(!th.satisfied_by([]));
        assert!(!th.satisfied_by([0, 1, 2]));
    }

    #[test]
    fn weighted_index_outside_any_clause_is_ignored() {
        let th = weighted(vec![vec![(1, 2), (1, 2)]]);
        assert!(!th.satisfied_by([0, 5]));
        assert!(th.satisfied_by([0, 1, 5]));
    }

    #[test]
    fn well_formed_simple() {
        assert_eq!(SigningThreshold::Simple(2).check_well_formed(3), Ok(()));
        assert_eq!(SigningThreshold::Simple(3).check_well_formed(3), Ok(()));
        assert_eq!(
            SigningThreshold::Simple(0).check_well_formed(3),
            Err(SigningThresholdError::BelowMinimum)
        );
        assert_eq!(
            SigningThreshold::Simple(4).check_well_formed(3),
            Err(SigningThresholdError::ExceedsKeyCount { required: 4, key_count: 3 })
        );
    }

    #[test]
    fn well_formed_weighted() {
        assert_eq!(weighted(vec![vec![(1, 2), (1, 2)]]).check_well_formed(2), Ok(()));
        assert_eq!(weighted(vec![vec![(1, 2), (1, 2)]]).check_well_formed(3), Ok(()));
        assert_eq!(
            weighted(vec![]).check_well_formed(2),
            Err(SigningThresholdError::EmptyClauseList)
        );
        assert_eq!(
            weighted(vec![vec![]]).check_well_formed(2),
            Err(SigningThresholdError::EmptyClause)
        );
        assert_eq!(
            weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]).check_well_formed(2),
            Err(SigningThresholdError::ExceedsKeyCount { required: 3, key_count: 2 })
        );
    }

    #[test]
    fn from_nested_flattens_boundaries() {
        let w = WeightedThreshold::from_nested(vec![vec![(1, 2), (1, 2)], vec![(1, 1)]]).unwrap();
        let clauses: Vec<&[(u64, u64)]> = w.clauses().collect();
        assert_eq!(clauses, vec![&[(1, 2), (1, 2)][..], &[(1, 1)][..]]);
    }

    #[test]
    fn from_nested_empty_clause_is_representable() {
        // equal-adjacent boundary; representable, caught by check_well_formed.
        let w = WeightedThreshold::from_nested(vec![vec![(1, 1)], vec![]]).unwrap();
        assert_eq!(w.clauses().count(), 2);
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn weighted(clauses: Vec<Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }

    proptest! {
        #[test]
        fn simple_matches_count(threshold in 0u64..8, idxs in proptest::collection::vec(0u32..8, 0..12)) {
            let th = SigningThreshold::Simple(threshold);
            let mut d = idxs.clone();
            d.sort_unstable();
            d.dedup();
            let expected = u64::try_from(d.len()).unwrap() >= threshold;
            prop_assert_eq!(th.satisfied_by(idxs.iter().copied()), expected);
        }

        #[test]
        fn adding_signer_is_monotone(threshold in 0u64..6, mut idxs in proptest::collection::vec(0u32..6, 0..8), extra in 0u32..6) {
            let th = SigningThreshold::Simple(threshold);
            let before = th.satisfied_by(idxs.iter().copied());
            idxs.push(extra);
            let after = th.satisfied_by(idxs.iter().copied());
            prop_assert!(!before || after);
        }

        #[test]
        fn weighted_halves_boundary(n in 1usize..6, idxs in proptest::collection::vec(0u32..6, 0..8)) {
            let clause: Vec<(u64, u64)> = core::iter::repeat_n((1u64, 2u64), n).collect();
            let th = weighted(vec![clause]);
            let d: Vec<u32> = {
                let mut v: Vec<u32> = idxs.iter().copied()
                    .filter(|&i| usize::try_from(i).is_ok_and(|u| u < n)).collect();
                v.sort_unstable();
                v.dedup();
                v
            };
            let expected = d.len() >= 2;
            prop_assert_eq!(th.satisfied_by(idxs.iter().copied()), expected);
        }

        #[test]
        fn flattened_matches_nested_semantics(
            clauses in proptest::collection::vec(
                proptest::collection::vec((1u64..4, 1u64..4), 1..4), 1..4),
            idxs in proptest::collection::vec(0u32..10, 0..10),
        ) {
            // Reference: evaluate against the nested clauses directly.
            let flat = weighted(clauses.clone());
            let mut distinct: Vec<u32> = idxs.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let mut base = 0u32;
            let mut nested_ok = true;
            for clause in &clauses {
                let width = u32::try_from(clause.len()).unwrap();
                let end = base + width;
                let mut num = 0u64; let mut den = 1u64;
                for (i, &(cn, cd)) in clause.iter().enumerate() {
                    let pos = base + u32::try_from(i).unwrap();
                    if distinct.contains(&pos) {
                        num = num * cd + cn * den;
                        den *= cd;
                    }
                }
                if !(num >= den) { nested_ok = false; }
                base = end;
            }
            prop_assert_eq!(flat.satisfied_by(idxs.iter().copied()), nested_ok);
        }
    }
}
```

Add to `cesr/src/keri/mod.rs` (alphabetical among the existing `pub mod` /
`pub use` blocks, next to `threshold_form`):

```rust
pub mod threshold;
pub use threshold::{SigningThreshold, SigningThresholdError, WeightedThreshold};
```

- [ ] **Step 2: Run the type's tests, expect failure then iterate to green**

Run: `nix develop --command cargo nextest run -p cesr-rs --all-features signing_threshold threshold::`
Expected first run: compile error (bare `as` cast lint / not-yet-resolved items); fix per the clippy note above until all `threshold::tests` and `threshold::prop_tests` PASS.

- [ ] **Step 3: Verify no_std + alloc build**

Run: `nix develop --command cargo build -p cesr-rs --no-default-features --features "alloc,core,b64,keri"`
Expected: builds clean (module uses only `core::`/`alloc::`).

- [ ] **Step 4: Commit**

```bash
git add cesr/src/keri/threshold.rs cesr/src/keri/mod.rs
git commit -m "feat(keri)!: add SigningThreshold domain type (#130, #171)

Flattened weighted representation (weights + cumulative clause_ends) behind a
validating constructor; satisfied_by/check_well_formed ported from Tholder.
Coexists with Tholder until the rung-4 swap. Breaking: new public type."
```

---

## Task 2: Atomic swap — replace `Tholder` everywhere, delete the old module

**This task is one commit.** The event accessor return type is the linchpin;
changing it breaks every consumer simultaneously, so intermediate states do not
compile. Make all edits, then let `cargo build` drive the remaining fixes.

**Files (edit all, then build):**
- Modify (non-trivial, code below): `cesr/src/serder/deserialize.rs`, `cesr/src/serder/deserialize/reference.rs`, `cesr/src/serder/serialize.rs`, `cesr/src/serder/serialize/direct.rs`
- Modify (rename `Tholder`→`SigningThreshold`, `ThresholdError`→`SigningThresholdError`, import path `core::primitives`→`keri`): `cesr/src/keri/event/{inception,rotation,delegation,mod}.rs`, `cesr/src/serder/builder/{icp,rot,dip,drt}.rs`, `cesr/src/serder/error.rs`, `cesr/src/serder/deserialize/canonical.rs` (test imports at L827), `cesr/src/keripy_parity/{formulas,validation}.rs`, `cesr/src/crypto/verify.rs`, `cesr/src/serder/traits.rs`, `cesr/examples/multisig_threshold_icp.rs`, `keri/src/authority.rs`, `keri/src/state.rs`, `keri/tests/*`
- Delete: `cesr/src/core/primitives/tholder.rs`
- Modify (remove `tholder` re-exports): `cesr/src/core/primitives/mod.rs` (L16, L28), `cesr/src/core/mod.rs` (L27), `cesr/src/lib.rs` (L36)

- [ ] **Step 1: Delete the old module and its re-exports**

```bash
git rm cesr/src/core/primitives/tholder.rs
```
Then remove `pub mod tholder;` and `pub use tholder::{Tholder, ThresholdError};`
from `cesr/src/core/primitives/mod.rs`, drop `Tholder` from the `pub use` list
in `cesr/src/core/mod.rs:27`, and drop `Tholder` from the re-export in
`cesr/src/lib.rs:36`.

- [ ] **Step 2: Rewrite the strict reader's weighted reifier**

In `cesr/src/serder/deserialize.rs`, update the import (L13) to pull
`SigningThreshold` from `crate::keri` (keep `Diger, Prefixer, Saider, Verfer, Verser`
from `core::primitives`), then replace `tholder_from_parsed` (L260-288):

```rust
fn tholder_from_parsed(t: &ParsedTholder<'_>) -> Result<SigningThreshold, SerderError> {
    match t {
        ParsedTholder::Hex(s) => {
            let n = u64::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!("invalid hex threshold: {s}")),
            })?;
            Ok(SigningThreshold::Simple(n))
        }
        ParsedTholder::Number(s) => {
            let n = s.parse::<u64>().map_err(|_| SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!("invalid integer threshold: {s}")),
            })?;
            Ok(SigningThreshold::Simple(n))
        }
        ParsedTholder::Weighted(clauses) => {
            let nested: Vec<Vec<(u64, u64)>> = clauses
                .iter()
                .map(|clause| clause.iter().map(|w| parse_weight(w)).collect())
                .collect::<Result<_, SerderError>>()?;
            let weighted = WeightedThreshold::from_nested(nested)
                .map_err(|source| SerderError::SigningThresholdOutOfRange { field: "kt", source })?;
            Ok(SigningThreshold::Weighted(weighted))
        }
    }
}
```

Add `WeightedThreshold` to the `crate::keri` import.

- [ ] **Step 3: Rewrite the tolerant reference reader's weighted branch**

In `cesr/src/serder/deserialize/reference.rs`, swap the imports to
`SigningThreshold`/`WeightedThreshold` from `crate::keri`, and in
`tholder_from_json` (L432-484) return `SigningThreshold`, replacing the two
`Ok(Tholder::Simple(n))` with `Ok(SigningThreshold::Simple(n))` and the final
`Ok(Tholder::Weighted(clauses?))` with:

```rust
        let weighted = WeightedThreshold::from_nested(clauses?)
            .map_err(|source| SerderError::SigningThresholdOutOfRange { field: "kt", source })?;
        return Ok(SigningThreshold::Weighted(weighted));
```

- [ ] **Step 4: Update the two writers to iterate flattened clauses**

In `cesr/src/serder/serialize.rs`, `tholder_to_json` — replace the `Weighted`
arm to iterate `w.clauses()`:

```rust
        SigningThreshold::Weighted(w) => {
            let outer: Vec<Value> = w
                .clauses()
                .map(|clause| {
                    let inner: Vec<Value> = clause
                        .iter()
                        .map(|(num, den)| Value::String(weight_to_string(*num, *den)))
                        .collect();
                    Value::Array(inner)
                })
                .collect();
            if let [single] = <[Value]>::as_ref(&outer) {
                single.clone()
            } else {
                Value::Array(outer)
            }
        }
```

In `cesr/src/serder/serialize/direct.rs`, `write_tholder` — replace the
`Weighted` arm (the `write_weight_clause` helper is unchanged, it already takes
`&[(u64,u64)]`):

```rust
        SigningThreshold::Weighted(w) => {
            let mut clauses = w.clauses();
            match (clauses.next(), clauses.next()) {
                (Some(single), None) => write_weight_clause(buf, single),
                (Some(first), Some(second)) => {
                    buf.push(b'[');
                    write_weight_clause(buf, first);
                    buf.push(b',');
                    write_weight_clause(buf, second);
                    for clause in clauses {
                        buf.push(b',');
                        write_weight_clause(buf, clause);
                    }
                    buf.push(b']');
                }
                (None, _) => buf.extend_from_slice(b"[]"),
            }
        }
```

> Note the single-clause collapse (`[["1/2","1/2"]]` → `["1/2","1/2"]`) is
> keripy's wire behavior and MUST be preserved — the byte-identity corpus gates
> it. The `(None, _)` empty-list arm renders `[]`, matching the current
> `clauses.iter()` loop over an empty outer vec.

- [ ] **Step 5: Update `SerderError` source type**

In `cesr/src/serder/error.rs`: change the import (L11) from
`use crate::core::primitives::ThresholdError;` to
`use crate::keri::SigningThresholdError;`, and the `SigningThresholdOutOfRange`
variant's `source` field (L168) type from `ThresholdError` to
`SigningThresholdError`.

- [ ] **Step 6: Mechanical renames across remaining consumers**

Across every file in the "rename" list, apply: `Tholder` → `SigningThreshold`,
`.satisfy(` → `.satisfied_by(`, `ThresholdError` → `SigningThresholdError`, and
fix imports so the type comes from `crate::keri` (or `cesr::keri` in `keri/`
crate and examples/tests) instead of `core::primitives`. Weighted literals in
tests (`Tholder::Weighted(vec![...])`) become
`SigningThreshold::Weighted(WeightedThreshold::from_nested(vec![...]).unwrap())`
— add a local `weighted(...)` test helper where several appear (e.g.
`crypto/verify.rs`, `keripy_parity/formulas.rs`). In `keri/src/state.rs`,
threshold field types change to `cesr::keri::SigningThreshold` (witness
threshold stays `u32`/`Toad` — untouched, that is the follow-on PR).

Use the compiler as the worklist:

Run: `nix develop --command cargo build --workspace --all-features 2>&1 | rg 'Tholder|satisfy|ThresholdError' `
Iterate until no references remain and the workspace builds.

- [ ] **Step 7: Full test run**

Run: `nix develop --command cargo nextest run --workspace --all-features`
Expected: PASS, including `keripy_parity::formulas` (satisfaction sweep) and
`keripy_parity::events` (26-vector byte-identity), and the keri-rs
`differential` fold tests. Any byte-identity failure = a real regression, STOP.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(keri,serder)!: migrate Tholder -> keri::SigningThreshold (#130, #171)

Delete core::primitives::tholder; all consumers (events, builders, both
writers, both readers, SerderError, keri-rs authority/state, parity, examples)
now use cesr::keri::SigningThreshold with the flattened weighted repr and
satisfied_by. Zero wire-byte change (gated by #145 corpora). Breaking: type
moved + renamed, satisfy -> satisfied_by, ThresholdError -> SigningThresholdError."
```

---

## Task 3: CHANGELOG, gate, PR

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add the CHANGELOG entry**

Under the unreleased/`0.x` breaking section, add:

```markdown
### Changed (breaking)
- `Tholder` moved from `cesr::core::primitives` to `cesr::keri` and renamed
  `SigningThreshold` (#171 rung 4, closes #130). Weighted thresholds now use a
  flattened representation (`WeightedThreshold` = flat weights + cumulative
  clause boundaries) cutting per-threshold allocations from `1 + N` to `2`.
  `satisfy` → `satisfied_by`; `ThresholdError` → `SigningThresholdError` (adds
  `TooManyWeights`). No wire-format change. keri-rs `state`/`authority` updated.
```

- [ ] **Step 2: Run the full gate**

Run: `nix flake check 2>&1 | tee /tmp/gate.log; echo "exit=$?"`
Expected: `exit=0`. (Do not pipe to `head`/`tail` — redirect + echo, per house rule.)

- [ ] **Step 3: Commit + push + PR**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): SigningThreshold migration (#171 rung 4)"
git push -u origin 171-signing-threshold
gh pr create --title "refactor(keri,serder)!: rung 4 — SigningThreshold (#130, #171)" \
  --body "$(cat <<'BODY'
Rung 4 of the serder domain redesign (#171). Migrates `Tholder` into
`cesr::keri` as `SigningThreshold`, closing #130.

## Breaking
- `cesr::core::primitives::Tholder` → `cesr::keri::SigningThreshold`
- Weighted repr flattened: `WeightedThreshold { weights, clause_ends }`, `1+N` → `2` allocations
- `satisfy` → `satisfied_by(impl IntoIterator<Item = u32>)` (kept `IntoIterator`, diverging from #130's literal `&[u32]` to avoid a throwaway `Vec` at the `0..n` caller in keri-rs `authority`)
- `ThresholdError` → `SigningThresholdError` (+ `TooManyWeights` overflow guard for the `u32` clause boundaries)

## Not changed
- Zero wire bytes: #145 byte-identity corpora + `keripy_parity::formulas` sweep green
- keri-rs `KeyState` witness threshold / `sn()` vocabulary — the separate follow-on PR

🤖 Generated with [Claude Code](https://claude.com/claude-code)
BODY
)"
```

Attach the PR/issue to org Project #5 (`gh` account `joeldsouzax`).

---

## Self-review notes (checked against the spec)

- **Spec coverage:** type+location (T1), flattened repr + constructor + invariant (T1), `satisfied_by` signature (T1), `check_well_formed` (T1), `SigningThresholdError` rename + `SerderError` bridge (T1/T2 S5), every consumer in the spec's list (T2 S6), zero-wire-byte gate (T2 S7 / T3 S2), out-of-scope keri-rs vocab left untouched (T2 S6 note). ✓
- **Divergence from spec:** added `TooManyWeights` (5th variant) — justified by the spec's own "checked `u32::try_from`" mandate + arithmetic-safety rule; flagged in PR + CHANGELOG. ✓
- **Type consistency:** `SigningThreshold`, `WeightedThreshold`, `SigningThresholdError`, `WeightedThreshold::from_nested`, `.clauses()`, `.satisfied_by(...)`, `SerderError::SigningThresholdOutOfRange { field, source }` used identically in every task. ✓
- **No placeholders:** every code step shows full code; the one deferred detail (bare-`as` removal in `clauses()`) is called out with the exact fix constraint, not left vague. ✓
