/// The size variant for an indexed CESR primitive's full size.
///
/// Indexed primitives can be either fixed-size (known at compile time from the
/// code) or variable-size (encoded in the soft part of the code at runtime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XizageSize {
    /// Fixed total size in Base64 characters (known from the code alone).
    Fixed(u16),
    /// Variable size; the full size must be computed from the index at parse time.
    Variable,
}

/// A blueprint that defines the size and structure of a CESR indexed primitive.
///
/// This is the indexed-signature counterpart to [`crate::core::matter::sizage::Sizage`].
/// Its main purpose is to make CESR indexed codes self-framing by providing the
/// metadata a parser needs to determine the exact boundaries of an indexed
/// primitive within a data stream.
///
/// It is the Rust equivalent of the `Xizage` namedtuple in the `keripy`
/// reference implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xizage {
    /// **Hard Size (`hs`):** The number of characters in the stable, primary
    /// part of the primitive's code.
    pub hs: u8,
    /// **Soft Size (`ss`):** The number of characters in the variable part of
    /// the code, which encodes the index value.
    pub ss: u8,
    /// **Ondex Size (`os`):** The number of characters used to encode the
    /// "other index" (ondex), a secondary index in dual-indexed codes.
    /// Zero for single-indexed codes.
    pub os: u8,
    /// **Full Size (`fs`):** The total character length of the entire primitive.
    /// [`XizageSize::Fixed`] for fixed-size primitives and
    /// [`XizageSize::Variable`] for variable-size primitives.
    pub fs: XizageSize,
    /// **Lead Size (`ls`):** The number of leading zero-bytes to pad the raw
    /// binary data with before Base64 encoding.
    pub ls: u8,
}

impl Xizage {
    /// Creates a new `Xizage` size descriptor with the given field sizes.
    #[must_use]
    pub const fn new(hs: u8, ss: u8, os: u8, fs: XizageSize, ls: u8) -> Self {
        Self { hs, ss, os, fs, ls }
    }

    /// Returns the hard size as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn hs(&self) -> usize {
        self.hs as usize
    }

    /// Returns the soft size as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn ss(&self) -> usize {
        self.ss as usize
    }

    /// Returns the ondex size as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn os(&self) -> usize {
        self.os as usize
    }

    /// Returns the lead size as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn ls(&self) -> usize {
        self.ls as usize
    }

    /// Returns a reference to the full-size descriptor.
    #[inline]
    #[must_use]
    pub const fn fs(&self) -> &XizageSize {
        &self.fs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn xizage_construction_and_accessors() {
        let x = Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0);
        assert_eq!(x.hs(), 1);
        assert_eq!(x.ss(), 1);
        assert_eq!(x.os(), 0);
        assert_eq!(x.ls(), 0);
        assert_eq!(*x.fs(), XizageSize::Fixed(88));
    }

    #[test]
    fn xizage_variable_size() {
        let x = Xizage::new(2, 2, 0, XizageSize::Variable, 0);
        assert_eq!(*x.fs(), XizageSize::Variable);
    }

    #[rstest]
    #[case(1, 1, 0, XizageSize::Fixed(88), 0)]
    #[case(2, 2, 1, XizageSize::Fixed(88), 1)]
    #[case(2, 4, 2, XizageSize::Variable, 0)]
    fn xizage_parameterized(
        #[case] hs: u8,
        #[case] ss: u8,
        #[case] os: u8,
        #[case] fs: XizageSize,
        #[case] ls: u8,
    ) {
        let x = Xizage::new(hs, ss, os, fs.clone(), ls);
        assert_eq!(x.hs(), usize::from(hs));
        assert_eq!(x.ss(), usize::from(ss));
        assert_eq!(x.os(), usize::from(os));
        assert_eq!(x.ls(), usize::from(ls));
        assert_eq!(*x.fs(), fs);
    }

    #[test]
    fn xizage_equality() {
        let a = Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0);
        let b = Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0);
        let c = Xizage::new(2, 2, 1, XizageSize::Fixed(88), 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn xizage_clone() {
        let original = Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
