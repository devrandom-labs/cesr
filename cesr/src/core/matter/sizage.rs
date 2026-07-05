/// Describes whether a CESR primitive's total length is fixed or variable.
#[derive(Debug)]
pub enum SizeType {
    /// Fixed total size; the value is the number of Base64 characters.
    Fixed(u8),
    /// Variable size using a small (1-byte) length field.
    Small,
    /// Variable size using a large (2-byte) length field.
    Large,
}

/// A blueprint that defines the size and structure of a CESR primitive.
///
/// This struct acts as a "descriptor" or instruction manual for a single CESR
/// primitive code. Its main purpose is to make the CESR protocol "self-framing"
/// by providing the necessary metadata for a parser to determine the exact
/// boundaries of a primitive within a data stream.
///
/// It is the Rust equivalent of the `Sizage` namedtuple in the `keripy`
/// reference implementation.
#[derive(Debug)]
pub struct Sizage {
    /// **Hard Size (`hs`):** The number of characters in the stable, primary
    /// part of the primitive's code.
    pub hs: u8,
    /// **Soft Size (`ss`):** The number of characters in the variable part of
    /// the code, which often encodes the length of the following raw data.
    pub ss: u8,
    /// **Extra Size (`xs`):** The number of extra prepad characters (`_`) used
    /// in some special tag codes.
    pub xs: u8,
    /// **Full Size (`fs`):** The total character length of the entire primitive.
    /// This is `Some(size)` for fixed-size primitives and `None` for
    /// variable-size primitives.
    pub fs: SizeType,
    /// **Lead Size (`ls`):** The number of leading zero-bytes to pad the raw
    /// binary data with before Base64 encoding.
    pub ls: u8,
}

impl Sizage {
    /// Creates a new `Sizage` descriptor with the given field sizes.
    #[must_use]
    pub const fn new(hs: u8, ss: u8, xs: u8, fs: SizeType, ls: u8) -> Self {
        Self { hs, ss, xs, fs, ls }
    }

    /// Returns the hard size (number of fixed code characters) as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn hs(&self) -> usize {
        self.hs as usize
    }

    /// Returns the soft size (variable code characters) as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn ss(&self) -> usize {
        self.ss as usize
    }

    /// Returns the extra size (prepad characters) as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn xs(&self) -> usize {
        self.xs as usize
    }

    /// Returns the lead size (leading zero-byte count) as `usize`.
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn ls(&self) -> usize {
        self.ls as usize
    }

    /// Returns a reference to the full-size descriptor.
    #[inline]
    #[must_use]
    pub const fn fs(&self) -> &SizeType {
        &self.fs
    }
}
