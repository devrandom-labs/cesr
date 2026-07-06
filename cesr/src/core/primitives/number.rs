use crate::core::matter::code::NumberCode;

/// An unsigned integer with an automatically selected CESR number code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    code: NumberCode,
    value: u128,
}

impl Number {
    /// Creates a `Number` choosing the smallest code that fits `value`.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        let code = NumberCode::for_value(value);
        Self { code, value }
    }

    /// Creates a `Number` with an explicitly specified code.
    #[must_use]
    pub const fn with_code(code: NumberCode, value: u128) -> Self {
        Self { code, value }
    }

    /// Returns the CESR number code for this value.
    #[must_use]
    pub const fn code(&self) -> &NumberCode {
        &self.code
    }

    /// Returns the raw integer value.
    #[must_use]
    pub const fn value(&self) -> u128 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::NumberCode;

    #[test]
    fn number_picks_smallest_code() {
        let n_short = Number::new(255);
        assert_eq!(*n_short.code(), NumberCode::Short);
        assert_eq!(n_short.value(), 255);

        let n_long = Number::new(0xFFFF_FFFF);
        assert_eq!(*n_long.code(), NumberCode::Long);

        let n_big = Number::new(u128::from(u64::MAX));
        assert_eq!(*n_big.code(), NumberCode::Big);
    }

    #[test]
    fn number_zero() {
        let n = Number::new(0);
        assert_eq!(*n.code(), NumberCode::Short);
        assert_eq!(n.value(), 0);
    }
}
