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
        Tholder::Weighted(clauses) => {
            let mut base: u32 = 0;
            for clause in clauses {
                let Ok(width) = u32::try_from(clause.len()) else {
                    return false;
                };
                let Some(end) = base.checked_add(width) else {
                    return false;
                };
                let mut signed: Vec<bool> = alloc::vec![false; clause.len()];
                for &idx in &distinct {
                    if idx >= base && idx < end {
                        let Some(offset) = idx.checked_sub(base) else {
                            continue;
                        };
                        let Ok(local) = usize::try_from(offset) else {
                            continue;
                        };
                        if let Some(slot) = signed.get_mut(local) {
                            *slot = true;
                        }
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

/// Exact test that the summed fractions at signed positions within one clause reach `>= 1`.
///
/// `signed[i]` marks whether clause-local position `i` signed. Returns `None` on arithmetic
/// overflow or a zero denominator (malformed weight).
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

#[cfg(test)]
mod weighted_tests {
    use super::*;

    fn half_x3() -> Tholder {
        Tholder::Weighted(alloc::vec![alloc::vec![(1, 2), (1, 2), (1, 2)]])
    }

    #[test]
    fn weighted_single_clause() {
        let th = half_x3();
        assert!(!satisfied_by(&th, &[0])); // 1/2 < 1
        assert!(satisfied_by(&th, &[0, 1])); // 1/2 + 1/2 = 1
        assert!(satisfied_by(&th, &[1, 2]));
        assert!(satisfied_by(&th, &[0, 1, 2])); // 3/2 >= 1
    }

    #[test]
    fn weighted_multi_clause_is_and_of_clauses() {
        // clause 0 owns positions {0,1}; clause 1 owns positions {2,3}.
        let th = Tholder::Weighted(alloc::vec![
            alloc::vec![(1, 2), (1, 2)],
            alloc::vec![(1, 1), (1, 1)],
        ]);
        assert!(!satisfied_by(&th, &[0, 1])); // clause 1 unmet
        assert!(!satisfied_by(&th, &[2])); // clause 0 unmet
        assert!(satisfied_by(&th, &[0, 1, 2])); // c0: 1/2+1/2=1 ; c1: pos2=1 >=1
    }

    #[test]
    fn weighted_index_outside_any_clause_is_ignored() {
        let th = Tholder::Weighted(alloc::vec![alloc::vec![(1, 2), (1, 2)]]);
        assert!(!satisfied_by(&th, &[0, 5]));
        assert!(satisfied_by(&th, &[0, 1, 5]));
    }
}
