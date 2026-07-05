//! Signing-threshold satisfaction over a signer index-set.

use alloc::vec::Vec;

use cesr::core::primitives::Tholder;

/// Returns `true` if the signers at `indices` satisfy `tholder`.
///
/// `indices` are the key-list positions whose signatures a caller has already
/// cryptographically verified. Duplicates are tolerated (deduplicated internally).
#[must_use]
pub fn satisfied_by(tholder: &Tholder, indices: &[u32]) -> bool {
    let mut distinct: Vec<u32> = indices.to_vec();
    distinct.sort_unstable();
    distinct.dedup();

    match tholder {
        Tholder::Simple(threshold) => {
            let Ok(count) = u64::try_from(distinct.len()) else {
                return true; // more distinct signers than u64::MAX — any threshold is met
            };
            count >= *threshold
        }
        Tholder::Weighted(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_threshold_counts_distinct_indices() {
        let th = Tholder::Simple(2);
        assert!(!satisfied_by(&th, &[]));
        assert!(!satisfied_by(&th, &[0]));
        assert!(satisfied_by(&th, &[0, 1]));
        assert!(satisfied_by(&th, &[0, 1, 2]));
        assert!(!satisfied_by(&th, &[0, 0])); // duplicates must not inflate the count
    }

    #[test]
    fn simple_threshold_zero_is_always_met() {
        assert!(satisfied_by(&Tholder::Simple(0), &[]));
    }
}
