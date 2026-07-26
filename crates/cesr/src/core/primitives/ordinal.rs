//! The ordinal-whole-number contract shared by `cesr` integer primitives.
//!
//! An ordinal renders two ways: as a `u128` value, and as minimal lowercase
//! hex (keripy's `Number.numh`) for embedding in JSON event bodies. The qb64
//! `Matter` rendering is a separate concern owned by each primitive.

use core::fmt;

/// An unsigned whole-number ordinal renderable as minimal lowercase hex.
pub trait Ordinal {
    /// The ordinal value.
    fn num(&self) -> u128;

    /// Minimal lowercase hex, no leading zeros; zero renders as `"0"`.
    ///
    /// Returns a `Display` adapter so callers can write directly into a buffer
    /// without allocating (`no_std` / alloc-free).
    fn numh(&self) -> impl fmt::Display
    where
        Self: Sized,
    {
        NumHex(self.num())
    }
}

/// Zero-allocation `Display` adapter rendering a `u128` as minimal lowercase hex.
struct NumHex(u128);

impl fmt::Display for NumHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    struct Bare(u128);
    impl Ordinal for Bare {
        fn num(&self) -> u128 {
            self.0
        }
    }

    #[test]
    fn numh_renders_minimal_lowercase_hex() {
        assert_eq!(Bare(0).numh().to_string(), "0");
        assert_eq!(Bare(1).numh().to_string(), "1");
        assert_eq!(Bare(10).numh().to_string(), "a");
        assert_eq!(Bare(255).numh().to_string(), "ff");
        assert_eq!(
            Bare(u128::MAX).numh().to_string(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn num_returns_value() {
        assert_eq!(Bare(42).num(), 42);
    }
}
