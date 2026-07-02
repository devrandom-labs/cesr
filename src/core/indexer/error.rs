use super::code::IndexedSigCode;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;
use thiserror::Error as ThisError;

/// Errors produced while parsing an indexed CESR signature stream.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum ParseError {
    /// The input stream is empty.
    #[error("empty CESR stream")]
    EmptyStream,

    /// The stream ended before enough characters were available.
    #[error("stream too short: need {need} chars, got {got}")]
    StreamTooShort {
        /// Number of characters needed.
        need: usize,
        /// Number of characters available.
        got: usize,
    },

    /// The code prefix does not match any known indexed signature code.
    #[error("unknown indexed sig code: '{0}'")]
    UnknownCode(String),

    /// A Base64 decode failure was encountered in the stream.
    #[error("invalid base64 in indexed sig stream")]
    InvalidBase64,

    /// Non-canonical encoding: index had unnecessary leading zeros.
    #[error("non-canonical encoding: leading zeros in indexed sig")]
    NonCanonical,

    /// The ondex field was non-zero for a `CurrentOnly` code.
    #[error("ondex must be 0 for current-only code, got {0}")]
    OndexNotZeroForCurrentOnly(u32),
}

/// Errors produced while validating an indexed CESR signature builder.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum ValidationError {
    /// The signer index exceeds the maximum allowed by the code.
    #[error("index {index} exceeds max {max} for code {code:?}")]
    IndexTooLarge {
        /// The indexed signature code.
        code: IndexedSigCode,
        /// The index that was supplied.
        index: u32,
        /// The maximum index permitted.
        max: u32,
    },

    /// The ondex exceeds the maximum allowed by the code.
    #[error("ondex {ondex} exceeds max {max} for code {code:?}")]
    OndexTooLarge {
        /// The indexed signature code.
        code: IndexedSigCode,
        /// The ondex that was supplied.
        ondex: u32,
        /// The maximum ondex permitted.
        max: u32,
    },

    /// An ondex was provided for a `CurrentOnly` code which has no ondex field.
    #[error("ondex not allowed for current-only code {0:?}")]
    OndexOnCurrentOnly(IndexedSigCode),

    /// The ondex differs from index on a Both-mode code with os=0 (no wire
    /// space for a separate ondex). keripy raises `InvalidVarIndexError` here.
    #[error("ondex {ondex} must equal index {index} for code {code:?} (os=0)")]
    OndexMustEqualIndex {
        /// The indexed signature code.
        code: IndexedSigCode,
        /// The index that was supplied.
        index: u32,
        /// The ondex that was supplied.
        ondex: u32,
    },

    /// The raw byte slice length does not match the code's expected raw size.
    #[error("unexpected raw size for {code:?}: expected {expected}, got {got}")]
    UnexpectedRawSize {
        /// The indexed signature code.
        code: IndexedSigCode,
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes received.
        got: usize,
    },
}

impl From<super::code::CodeError> for ParseError {
    fn from(e: super::code::CodeError) -> Self {
        match e {
            super::code::CodeError::UnknownCode(s) => Self::UnknownCode(s),
        }
    }
}

impl From<crate::b64::error::Error> for ParseError {
    fn from(e: crate::b64::error::Error) -> Self {
        match e {
            crate::b64::error::Error::InvalidBase64Char(_)
            | crate::b64::error::Error::InvalidBase64Value(_)
            | crate::b64::error::Error::IntegerOverflow => Self::InvalidBase64,
            crate::b64::error::Error::ShortBinaryStream => Self::StreamTooShort { need: 0, got: 0 },
        }
    }
}
