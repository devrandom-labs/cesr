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
/// event as [`crate::ThresholdForm`], so equality here is purely
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
            let end = u32::try_from(weights.len()).map_err(|_| {
                SigningThresholdError::TooManyWeights {
                    count: weights.len(),
                }
            })?;
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
            Err(SigningThresholdError::ExceedsKeyCount {
                required: 4,
                key_count: 3
            })
        );
    }

    #[test]
    fn well_formed_weighted() {
        assert_eq!(
            weighted(vec![vec![(1, 2), (1, 2)]]).check_well_formed(2),
            Ok(())
        );
        assert_eq!(
            weighted(vec![vec![(1, 2), (1, 2)]]).check_well_formed(3),
            Ok(())
        );
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
            Err(SigningThresholdError::ExceedsKeyCount {
                required: 3,
                key_count: 2
            })
        );
    }

    #[test]
    fn weighted_overflow_in_fraction_sum_fails_closed() {
        // Summing two 1/(u64::MAX) fractions overflows the checked rational
        // arithmetic; an unrepresentable sum must read as unsatisfied, not panic.
        let th = weighted(vec![vec![(1, u64::MAX), (1, u64::MAX)]]);
        assert!(!th.satisfied_by([0, 1]));
    }

    #[test]
    fn weighted_zero_denominator_is_never_satisfied() {
        let th = weighted(vec![vec![(1, 0)]]);
        assert!(!th.satisfied_by([0]));
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
        fn weighted_adding_signer_is_monotone(
            clauses in proptest::collection::vec(
                proptest::collection::vec((1u64..4, 1u64..4), 1..4), 1..3),
            mut idxs in proptest::collection::vec(0u32..8, 0..8),
            extra in 0u32..8,
        ) {
            let th = weighted(clauses);
            let before = th.satisfied_by(idxs.iter().copied());
            idxs.push(extra);
            let after = th.satisfied_by(idxs.iter().copied());
            prop_assert!(!before || after);
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
                if num < den { nested_ok = false; }
                base = end;
            }
            prop_assert_eq!(flat.satisfied_by(idxs.iter().copied()), nested_ok);
        }
    }
}
