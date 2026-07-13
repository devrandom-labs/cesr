//! Event sequence number — hex-rendered ordinal, not a CESR primitive.

use core::fmt;

/// A KERI event sequence number.
///
/// In the event body (`s`) and in seal fields (`Seal::Source.s`,
/// `Seal::Event.s`) this renders as minimal lowercase hex — keripy's
/// `Number(num=n).numh` — never as a qb64 primitive. The CESR `Seqner`
/// Matter remains in `cesr::core` for genuinely qb64 contexts (streams,
/// receipts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNumber(u128);

impl SequenceNumber {
    /// Wrap an ordinal.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The ordinal value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for SequenceNumber {
    /// Minimal lowercase hex; zero renders as `"0"`, never empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn displays_minimal_lowercase_hex() {
        assert_eq!(SequenceNumber::new(0).to_string(), "0");
        assert_eq!(SequenceNumber::new(1).to_string(), "1");
        assert_eq!(SequenceNumber::new(10).to_string(), "a");
        assert_eq!(SequenceNumber::new(255).to_string(), "ff");
        assert_eq!(
            SequenceNumber::new(u128::MAX).to_string(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(SequenceNumber::new(2) < SequenceNumber::new(10));
    }
}
