/// CESR protocol version for code table selection.
///
/// V1.0 and V2.0 use different counter code tables — the same wire code
/// (e.g. `-A`) maps to different semantic groups depending on version.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum CesrVersion {
    /// CESR V1.0 — 22 counter codes.
    V1_0,
    /// CESR V2.0 — 59 counter codes (default).
    #[default]
    V2_0,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_v2() {
        assert_eq!(CesrVersion::default(), CesrVersion::V2_0);
    }

    #[test]
    fn equality() {
        assert_eq!(CesrVersion::V1_0, CesrVersion::V1_0);
        assert_ne!(CesrVersion::V1_0, CesrVersion::V2_0);
    }
}
