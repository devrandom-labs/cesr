//! BFT witness threshold computation ported from keripy `eventing.py`.

/// Compute the sufficient immune majority threshold for `n` witnesses.
///
/// For `n` witnesses, returns `ceil(n * 2/3)` which is the minimum number of
/// witness receipts needed for Byzantine fault tolerance. Returns `0` when
/// `n` is `0`.
///
/// Ported from keripy `ample()` in `eventing.py`.
#[must_use]
pub fn ample(n: usize) -> u32 {
    if n == 0 {
        return 0;
    }
    let f = (n * 2).div_ceil(3);
    u32::try_from(f.max(1)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ample_zero_witnesses() {
        assert_eq!(ample(0), 0);
    }

    #[test]
    fn ample_one_witness() {
        assert_eq!(ample(1), 1);
    }

    #[test]
    fn ample_two_witnesses() {
        assert_eq!(ample(2), 2);
    }

    #[test]
    fn ample_three_witnesses() {
        assert_eq!(ample(3), 2);
    }

    #[test]
    fn ample_four_witnesses() {
        assert_eq!(ample(4), 3);
    }

    #[test]
    fn ample_six_witnesses() {
        assert_eq!(ample(6), 4);
    }

    #[test]
    fn ample_ten_witnesses() {
        assert_eq!(ample(10), 7);
    }
}
