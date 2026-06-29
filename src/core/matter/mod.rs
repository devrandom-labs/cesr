use std::fmt::Display;

/// Builder for constructing and parsing `Matter` primitives.
pub mod builder;
/// CESR code enums (`MatterCode`, `SeedCode`, `VerKeyCode`, `SignatureCode`, `DigestCode`, etc.).
pub mod code;
/// Parse and build error types for Matter streams.
pub mod error;
/// `Matter<C>` generic CESR primitive type.
#[allow(
    clippy::module_inception,
    reason = "Matter module contains the Matter type"
)]
pub mod matter;

pub use matter::Matter;
/// Sizing table (`Sizage`) for Matter codes.
pub mod sizage;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod test_vectors_boundary;

/// Identifies which structural component of a CESR Matter field was involved in an error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MatterPart {
    /// The fixed-length code header (hard + soft fields).
    Head,
    /// The soft (variable) portion of the code field.
    Soft,
    /// The extra field used by certain multi-field codes.
    Xtra,
    /// Padding bits prepended to align binary data to a sextet boundary.
    PadBits,
    /// Lead bytes used for alignment in binary (qb2) encoding.
    LeadBytes,
    /// Raw payload bytes carrying the primitive's value.
    Raw,
}

impl Display for MatterPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
