use super::number::Number;

/// CESR sequence number, wrapping a [`Number`] for event ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seqner {
    inner: Number,
}

impl Seqner {
    /// Creates a `Seqner` from a sequence number value.
    #[must_use]
    pub const fn new(sn: u128) -> Self {
        Self {
            inner: Number::new(sn),
        }
    }

    /// Returns the sequence number value.
    #[must_use]
    pub const fn value(&self) -> u128 {
        self.inner.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seqner_wraps_number() {
        let s = Seqner::new(42);
        assert_eq!(s.value(), 42);
    }
}
