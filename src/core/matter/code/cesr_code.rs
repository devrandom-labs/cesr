use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::matter::error::ValidationError;
use crate::matter::sizage::Sizage;

/// Sealed trait that all CESR typed codes must implement.
///
/// Provides the ability to convert to the untyped `MatterCode`, retrieve
/// the Base64 string representation, and look up the `Sizage` and raw byte size.
#[allow(
    private_bounds,
    reason = "Sealed trait pattern restricts implementors to this crate"
)]
pub trait CesrCode: Sealed + Copy + Eq + std::fmt::Debug {
    /// Converts this typed code to the untyped [`MatterCode`].
    fn to_matter_code(&self) -> MatterCode;
    /// Returns the canonical Base64 string representation of this code.
    fn as_str(&self) -> &'static str;

    /// Returns the [`Sizage`] descriptor for this code.
    fn get_sizage(&self) -> Sizage {
        self.to_matter_code().get_sizage()
    }

    /// Returns the expected raw byte size for this code.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` for variable-size codes.
    fn raw_size(&self) -> Result<usize, ValidationError> {
        self.to_matter_code().raw_size()
    }
}
