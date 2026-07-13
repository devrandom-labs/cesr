//! Witness threshold (TOAD) — the KERI witness-agreement domain type.

use thiserror::Error;

/// Witness agreement threshold (keripy: TOAD, "threshold of accountable
/// duplicity").
///
/// Owns the invariants keripy enforces in `incept()`/`rotate()` at pin
/// `de59bc7d` (`eventing.py`): `0` iff the witness set is empty, otherwise
/// `1..=witness_count`. Constructed via [`Toad::ample`] (BFT default),
/// [`Toad::exact`] (validated), or [`Toad::from_wire`] (unvalidated — for
/// rotation parsing, where the governing witness set is unknowable from the
/// event body alone and the fold validates instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Toad(u32);

/// Violations of the TOAD domain rules.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ToadError {
    /// Threshold outside `1..=witness_count` (or nonzero with no witnesses).
    #[error("witness threshold {toad} out of range for {witnesses} witnesses")]
    OutOfRange {
        /// The rejected threshold value.
        toad: u32,
        /// The governing witness-set size.
        witnesses: usize,
    },
    /// The computed or supplied threshold exceeds the KERI `bt` field's u32
    /// range.
    #[error("witness threshold for {witnesses} witnesses exceeds the u32 range")]
    Overflow {
        /// The governing witness-set size.
        witnesses: usize,
    },
}

impl Toad {
    /// BFT sufficient-majority default for `witness_count` witnesses.
    ///
    /// Port of keripy `ample(n, f=None, weak=True)`: for the maximum fault
    /// count `f` satisfying `n >= 3f + 1`, minimize `m` subject to
    /// `(n + f + 1) / 2 <= m <= n - f`; both floor and ceiling candidates
    /// for `f` are tried and the smaller `m` wins. Zero witnesses → 0.
    ///
    /// # Errors
    ///
    /// [`ToadError::Overflow`] when the threshold exceeds `u32::MAX`.
    pub fn ample(witness_count: usize) -> Result<Self, ToadError> {
        let Some(faultable) = witness_count.checked_sub(1) else {
            return Ok(Self(0));
        };
        let f_floor = (faultable / 3).max(1);
        let f_ceil = faultable.div_ceil(3).max(1);
        let m_floor = least_strong_majority(witness_count, f_floor)?;
        let m_ceil = least_strong_majority(witness_count, f_ceil)?;
        let threshold = witness_count.min(m_floor).min(m_ceil);
        u32::try_from(threshold)
            .map(Self)
            .map_err(|_| ToadError::Overflow {
                witnesses: witness_count,
            })
    }

    /// A caller-chosen threshold, validated against its governing witness set:
    /// `0` iff `witness_count == 0`, else `1..=witness_count`.
    ///
    /// # Errors
    ///
    /// [`ToadError::OutOfRange`] when the rule is violated.
    pub fn exact(toad: u32, witness_count: usize) -> Result<Self, ToadError> {
        let valid = if witness_count == 0 {
            toad == 0
        } else {
            toad >= 1 && usize::try_from(toad).is_ok_and(|t| t <= witness_count)
        };
        if valid {
            Ok(Self(toad))
        } else {
            Err(ToadError::OutOfRange {
                toad,
                witnesses: witness_count,
            })
        }
    }

    /// A threshold read off the wire without set-size validation.
    ///
    /// Rotation events carry only witness deltas (`br`/`ba`), so the
    /// governing set size is unknowable at parse time; the key-state fold
    /// validates against the resolved set instead. Performs NO validation.
    #[must_use]
    pub const fn from_wire(toad: u32) -> Self {
        Self(toad)
    }

    /// The threshold value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Least `m` satisfying the strong-majority lower bound
/// `m >= (n + f + 1) / 2` for `f` faulty witnesses out of `n`.
fn least_strong_majority(n: usize, f: usize) -> Result<usize, ToadError> {
    n.checked_add(f)
        .and_then(|sum| sum.checked_add(1))
        .map(|sum| sum.div_ceil(2))
        .ok_or(ToadError::Overflow { witnesses: n })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Verbatim transcription of keripy `ample(n, f=None, weak=True)`
    /// (`eventing.py:89-94`, keripy `de59bc7d`). Python's `max(0, n - 1)`
    /// is `saturating_sub(1)` and `ceil(a / b)` on non-negative ints is
    /// `div_ceil`; both are exact for the bounded test domain.
    fn keripy_oracle(n: usize) -> usize {
        let f1 = 1usize.max(n.saturating_sub(1) / 3);
        let f2 = 1usize.max(n.saturating_sub(1).div_ceil(3));
        n.min((n + f1 + 1).div_ceil(2))
            .min((n + f2 + 1).div_ceil(2))
    }

    /// Expectations lifted from keripy `tests/core/test_eventing_v1.py`
    /// `test_ample` (weak defaults), keripy `de59bc7d` / v2.0.0.dev5.
    #[test]
    fn matches_keripy_test_eventing_v1_table() {
        let expected = [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 4),
            (7, 5),
            (8, 6),
            (9, 6),
            (10, 7),
            (11, 8),
            (12, 8),
            (13, 9),
        ];
        for (n, want) in expected {
            assert_eq!(Toad::ample(n).unwrap().value(), want, "ample({n})");
        }
    }

    #[test]
    fn ample_zero_witnesses() {
        assert_eq!(Toad::ample(0).unwrap().value(), 0);
    }

    #[test]
    fn ample_one_witness() {
        assert_eq!(Toad::ample(1).unwrap().value(), 1);
    }

    #[test]
    fn ample_two_witnesses() {
        assert_eq!(Toad::ample(2).unwrap().value(), 2);
    }

    #[test]
    fn ample_three_witnesses() {
        assert_eq!(Toad::ample(3).unwrap().value(), 3);
    }

    #[test]
    fn ample_four_witnesses() {
        assert_eq!(Toad::ample(4).unwrap().value(), 3);
    }

    #[test]
    fn ample_six_witnesses() {
        assert_eq!(Toad::ample(6).unwrap().value(), 4);
    }

    #[test]
    fn ample_ten_witnesses() {
        assert_eq!(Toad::ample(10).unwrap().value(), 7);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn ample_errors_when_intermediate_sum_overflows() {
        let err = Toad::ample(usize::MAX).unwrap_err();
        assert!(matches!(err, ToadError::Overflow { .. }));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn ample_errors_when_threshold_exceeds_u32() {
        let n = 7_000_000_000usize;
        let err = Toad::ample(n).unwrap_err();
        assert!(matches!(err, ToadError::Overflow { .. }));
    }

    /// Random sampling alone can miss a single divergent point (256 draws
    /// over 257 values skip any given `n` ~37% of the time), so the full
    /// issue-#147 range is also swept exhaustively.
    #[test]
    fn matches_keripy_oracle_exhaustively_to_256() {
        for n in 0usize..=256 {
            assert_eq!(
                Toad::ample(n).unwrap().value(),
                u32::try_from(keripy_oracle(n)).unwrap(),
                "ample({n})"
            );
        }
    }

    proptest! {
        #[test]
        fn matches_keripy_oracle(n in 0usize..=256) {
            prop_assert_eq!(
                Toad::ample(n).unwrap().value(),
                u32::try_from(keripy_oracle(n)).unwrap()
            );
        }
    }

    #[test]
    fn exact_zero_witnesses_accepts_only_zero() {
        assert_eq!(Toad::exact(0, 0).unwrap().value(), 0);
        assert_eq!(
            Toad::exact(1, 0).unwrap_err(),
            ToadError::OutOfRange {
                toad: 1,
                witnesses: 0
            }
        );
    }

    #[test]
    fn exact_bounds_are_one_to_count_inclusive() {
        assert_eq!(
            Toad::exact(0, 3).unwrap_err(),
            ToadError::OutOfRange {
                toad: 0,
                witnesses: 3
            }
        );
        assert_eq!(Toad::exact(1, 3).unwrap().value(), 1);
        assert_eq!(Toad::exact(3, 3).unwrap().value(), 3);
        assert_eq!(
            Toad::exact(4, 3).unwrap_err(),
            ToadError::OutOfRange {
                toad: 4,
                witnesses: 3
            }
        );
    }

    #[test]
    fn from_wire_performs_no_validation() {
        assert_eq!(Toad::from_wire(7).value(), 7);
        assert_eq!(Toad::from_wire(0).value(), 0);
    }
}
