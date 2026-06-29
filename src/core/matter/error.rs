use super::MatterPart;
use crate::utils::error::Error as CesrUtilError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;
use base64::DecodeError;
use core::str::Utf8Error;
use thiserror::Error as ThisError;

/// Errors produced while parsing a CESR Matter stream.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum ParsingError {
    /// The input stream is empty.
    #[error("Input stream is empty.")]
    EmptyStream,

    /// The stream ended before enough bytes were available to parse the given part.
    #[error("Input stream is too short; more bytes were expected to complete parsing of `{0}`.")]
    StreamTooShort(MatterPart),

    /// The code prefix does not match any known Matter code.
    #[error("Unrecognized code: '{0}' does not correspond to a known Matter code.")]
    UnknownMatterCode(String),

    /// A structural component of the code was malformed.
    #[error("Malformed code: the {part} component was invalid. Found '{found}'.")]
    MalformedCode {
        /// Which structural part was malformed.
        part: MatterPart,
        /// The invalid content that was found.
        found: String,
    },

    /// The variable-size lead character is not a valid CESR lead byte.
    #[error("The character '{0}' is not a valid lead character for a variable-sized primitive.")]
    InvalidVariableSizeLead(char),

    /// Variable-length logic was applied to a fixed-size code.
    #[error("Attempted to apply variable-length logic to the fixed-size code '{0}'.")]
    MismatchedSizingLogic(String),

    /// A low-level Base64 conversion error occurred.
    #[error("A low-level conversion error occurred")]
    Conversion(#[from] CesrUtilError),

    /// An invalid UTF-8 sequence was encountered during parsing.
    #[error("Invalid UTF-8 sequence encountered during parsing.")]
    InvalidUtf8(#[from] Utf8Error),

    /// Base64 decoding failed.
    #[error("Base64 decoding failed.")]
    Base64(DecodeError),
}

impl From<DecodeError> for ParsingError {
    fn from(e: DecodeError) -> Self {
        Self::Base64(e)
    }
}

/// Errors produced while validating Matter builder inputs.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum ValidationError {
    /// The code string does not correspond to a known Matter code.
    #[error("Unrecognized code: '{0}' does not correspond to a known Matter code.")]
    UnknownMatterCode(String),

    /// A structural component of the code was malformed.
    #[error("Malformed code: the {part} component was invalid. Found '{found}'.")]
    MalformedCode {
        /// Which structural part was malformed.
        part: MatterPart,
        /// The invalid content that was found.
        found: String,
    },

    /// The code requires a soft field but none was provided.
    #[error("The code '{code}' requires a 'soft' component, but it was not provided.")]
    MissingSoft {
        /// The CESR code that requires a soft field.
        code: String,
    },

    /// The soft field has the wrong length for the given code.
    #[error(
        "The 'soft' component has an incorrect length for code '{code}': expected {expected}, but found {found}."
    )]
    IncorrectSoftLength {
        /// The CESR code.
        code: String,
        /// Expected soft field length.
        expected: usize,
        /// Actual soft field length found.
        found: usize,
    },

    /// The soft field contains non-Base64 characters.
    #[error("The 'soft' component for code '{code}' contains invalid Base64 characters.")]
    InvalidSoftFormat {
        /// The CESR code.
        code: String,
    },

    /// The code requires raw data but none was provided.
    #[error("The code '{code}' requires a raw data payload, but it was not provided.")]
    MissingRaw {
        /// The CESR code.
        code: String,
    },

    /// Raw data was provided for a code that has no raw payload.
    #[error("The code '{code}' must not have a raw data payload.")]
    UnexpectedRaw {
        /// The CESR code.
        code: String,
    },

    /// The raw data length does not match the code's expected size.
    #[error("Incorrect raw data size for code '{code}': expected {expected}, but found {found}.")]
    IncorrectRawSize {
        /// The CESR code.
        code: String,
        /// Expected number of raw bytes.
        expected: usize,
        /// Actual number of raw bytes found.
        found: usize,
    },

    /// A fixed-size code was used where a variable-size promotion is required.
    #[error(
        "The code '{0}' is a fixed-size code and cannot be promoted to a variable-size equivalent."
    )]
    IncompatiblePromotion(String),

    /// The requested promotion for the given code and lead size is not a valid CESR transformation.
    #[error(
        "The requested promotion for code '{code}' with a lead size of {lead} is not a valid CESR transformation."
    )]
    InvalidPromotionTarget {
        /// The CESR code being promoted.
        code: String,
        /// The lead size that was requested.
        lead: usize,
    },

    /// The result of a code promotion was invalid or unknown.
    #[error("Promotion from '{from}' to '{to}' resulted in an invalid or unknown code.")]
    InvalidPromotionResult {
        /// The source code.
        from: String,
        /// The target code.
        to: String,
    },

    /// Cannot determine a fixed raw size for a variable-size code.
    #[error("Cannot get a fixed raw size for the variable-sized code '{0}'.")]
    InvalidSizingOperation(String),

    /// Non-canonical encoding: padding bits in the given part were non-zero.
    #[error("Non-canonical encoding: non-zero bits were found in the '{0}' padding section.")]
    NonCanonicalEncoding(MatterPart),

    /// The parsed components do not add up to the expected total length.
    #[error(
        "Structural integrity error: the parsed components do not match the expected total length of the primitive."
    )]
    StructuralIntegrityError,
}
