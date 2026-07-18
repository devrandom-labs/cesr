use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::core::matter::error::ValidationError;
use crate::core::matter::sizage::Sizage;
#[cfg(feature = "alloc")]
use crate::core::matter::sizage::SizeType;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; used only by the `placeholder` default method"
)]
use alloc::string::{String, ToString};

/// Placeholder character for a self-addressing field before its digest is
/// computed and back-patched.
///
/// `#` is deliberately outside the Base64 alphabet, so a placeholder value is
/// never mistaken for a real qb64 primitive.
pub const DUMMY_CHAR: char = '#';

/// Sealed trait that all CESR typed codes must implement.
///
/// Provides the ability to convert to the untyped `MatterCode`, retrieve
/// the Base64 string representation, and look up the `Sizage` and raw byte size.
#[allow(
    private_bounds,
    reason = "Sealed trait pattern restricts implementors to this crate"
)]
pub trait CesrCode: Sealed + Copy + Eq + core::fmt::Debug {
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

    /// Returns a placeholder qb64 string of this code's full character width,
    /// filled with [`DUMMY_CHAR`].
    ///
    /// Reserves a self-addressing field's exact byte span before its digest is
    /// computed and back-patched over the placeholder. The width equals the
    /// code's fixed full size (`fs`).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidSizingOperation`] for variable-size
    /// codes, which have no fixed placeholder width.
    #[cfg(feature = "alloc")]
    fn placeholder(&self) -> Result<String, ValidationError> {
        match self.get_sizage().fs {
            SizeType::Fixed(n) => Ok(core::iter::repeat_n(DUMMY_CHAR, usize::from(n)).collect()),
            SizeType::Small | SizeType::Large => Err(ValidationError::InvalidSizingOperation(
                self.to_matter_code().to_string(),
            )),
        }
    }
}
