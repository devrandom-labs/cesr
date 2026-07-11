//! BFT witness threshold computation ported from keripy `eventing.py`.

use alloc::format;

use crate::serder::error::SerderError;

/// Compute the sufficient immune (ample) majority threshold for `n` witnesses.
///
/// Port of keripy `ample(n, f=None, weak=True)` (`eventing.py`, keripy
/// `de59bc7d`): for the maximum fault count `f` satisfying `n >= 3f + 1`,
/// minimize `m` subject to `(n + f + 1) / 2 <= m <= n - f`. Both the floor
/// and ceiling candidates for `f` are tried and the smaller `m` wins.
/// Returns `0` when `n` is `0`.
///
/// # Errors
///
/// Returns [`SerderError::Validation`] when the computed threshold exceeds
/// `u32::MAX` (witness counts beyond the KERI `bt` field's range).
pub fn ample(n: usize) -> Result<u32, SerderError> {
    let Some(faultable) = n.checked_sub(1) else {
        return Ok(0);
    };
    let f_floor = (faultable / 3).max(1);
    let f_ceil = faultable.div_ceil(3).max(1);
    let m_floor = least_strong_majority(n, f_floor)?;
    let m_ceil = least_strong_majority(n, f_ceil)?;
    let threshold = n.min(m_floor).min(m_ceil);
    u32::try_from(threshold).map_err(|_| threshold_overflow(n))
}

/// Least `m` satisfying the strong-majority lower bound `m >= (n + f + 1) / 2`
/// for `f` faulty witnesses out of `n` (keripy `ceil((n + f + 1) / 2)`).
fn least_strong_majority(n: usize, f: usize) -> Result<usize, SerderError> {
    n.checked_add(f)
        .and_then(|sum| sum.checked_add(1))
        .map(|sum| sum.div_ceil(2))
        .ok_or_else(|| threshold_overflow(n))
}

fn threshold_overflow(n: usize) -> SerderError {
    SerderError::Validation(format!(
        "witness threshold for {n} witnesses exceeds the supported u32 range"
    ))
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
            assert_eq!(ample(n).unwrap(), want, "ample({n})");
        }
    }

    #[test]
    fn ample_zero_witnesses() {
        assert_eq!(ample(0).unwrap(), 0);
    }

    #[test]
    fn ample_one_witness() {
        assert_eq!(ample(1).unwrap(), 1);
    }

    #[test]
    fn ample_two_witnesses() {
        assert_eq!(ample(2).unwrap(), 2);
    }

    #[test]
    fn ample_three_witnesses() {
        assert_eq!(ample(3).unwrap(), 3);
    }

    #[test]
    fn ample_four_witnesses() {
        assert_eq!(ample(4).unwrap(), 3);
    }

    #[test]
    fn ample_six_witnesses() {
        assert_eq!(ample(6).unwrap(), 4);
    }

    #[test]
    fn ample_ten_witnesses() {
        assert_eq!(ample(10).unwrap(), 7);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn ample_errors_when_intermediate_sum_overflows() {
        let err = ample(usize::MAX).unwrap_err();
        assert!(matches!(err, SerderError::Validation(_)));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn ample_errors_when_threshold_exceeds_u32() {
        let n = 7_000_000_000usize;
        let err = ample(n).unwrap_err();
        assert!(matches!(err, SerderError::Validation(_)));
    }

    /// Random sampling alone can miss a single divergent point (256 draws
    /// over 257 values skip any given `n` ~37% of the time), so the full
    /// issue-#147 range is also swept exhaustively.
    #[test]
    fn matches_keripy_oracle_exhaustively_to_256() {
        for n in 0usize..=256 {
            assert_eq!(
                ample(n).unwrap(),
                u32::try_from(keripy_oracle(n)).unwrap(),
                "ample({n})"
            );
        }
    }

    proptest! {
        #[test]
        fn matches_keripy_oracle(n in 0usize..=256) {
            prop_assert_eq!(
                ample(n).unwrap(),
                u32::try_from(keripy_oracle(n)).unwrap()
            );
        }
    }
}
