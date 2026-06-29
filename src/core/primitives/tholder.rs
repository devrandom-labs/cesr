#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
/// Signing threshold — either a simple numeric threshold
/// or a weighted fractional threshold structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tholder {
    /// Simple threshold: at least N signatures required
    Simple(u64),
    /// Weighted threshold: list of clauses, each clause is a list of (numerator, denominator) fractions
    Weighted(Vec<Vec<(u64, u64)>>),
}

impl Tholder {
    /// Check if a count of signatures satisfies a simple threshold.
    /// For weighted thresholds, use a more specific verification method.
    #[must_use]
    pub const fn satisfy(&self, count: u64) -> bool {
        match self {
            Self::Simple(threshold) => count >= *threshold,
            Self::Weighted(_) => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use super::*;

    #[test]
    fn simple_threshold() {
        let th = Tholder::Simple(2);
        assert!(th.satisfy(2));
        assert!(th.satisfy(3));
        assert!(!th.satisfy(1));
    }

    #[test]
    fn weighted_threshold() {
        // Single clause: [(1,2), (1,2)] — need at least half of each
        let th = Tholder::Weighted(vec![vec![(1, 2), (1, 2)]]);
        if let Tholder::Weighted(clauses) = &th {
            assert_eq!(clauses.len(), 1);
        } else {
            panic!("expected weighted");
        }
    }
}
