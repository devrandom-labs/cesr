use alloc::borrow::Cow;

/// ISO-8601 `DateTime` encoded as CESR Matter.
/// Code is always `MatterCode::DateTime` (`1AAG`).
pub struct Dater<'a> {
    datetime: Cow<'a, str>,
}

impl<'a> Dater<'a> {
    /// Creates a `Dater` from an ISO-8601 datetime string.
    #[must_use]
    pub const fn new(datetime: Cow<'a, str>) -> Self {
        Self { datetime }
    }

    /// Returns the stored datetime string.
    #[must_use]
    pub fn datetime(&self) -> &str {
        self.datetime.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;

    #[test]
    fn dater_holds_datetime_string() {
        let dt = Dater::new(Cow::from("2025-03-01T00:00:00.000000+00:00"));
        assert_eq!(dt.datetime(), "2025-03-01T00:00:00.000000+00:00");
    }
}
