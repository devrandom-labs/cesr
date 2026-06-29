//! Error types for KERI event serialization, deserialization, and SAID computation.

use std::string::FromUtf8Error;

use crate::core::matter::error::ValidationError;

/// Errors during KERI event serialization, deserialization, and SAID computation.
#[derive(Debug, thiserror::Error)]
pub enum SerderError {
    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Version string is malformed or unsupported.
    #[error("invalid version string: {0}")]
    InvalidVersionString(String),

    /// SAID verification failed: computed digest does not match.
    #[error("SAID mismatch: expected {expected}, computed {computed}")]
    SaidMismatch {
        /// The SAID from the event's `d` field.
        expected: String,
        /// The freshly computed SAID.
        computed: String,
    },

    /// Unknown ilk code in the `t` field.
    #[error("unknown ilk: {0}")]
    UnknownIlk(String),

    /// Required field missing from event JSON.
    #[error("missing field: {0}")]
    MissingField(&'static str),

    /// Field value is not a valid qb64 CESR primitive.
    #[error("invalid primitive in field '{field}': {source}")]
    InvalidPrimitive {
        /// The JSON field name.
        field: &'static str,
        /// The underlying CESR validation error.
        source: ValidationError,
    },

    /// Digest computation failed.
    #[error("digest error: {0}")]
    DigestError(String),

    /// UTF-8 encoding error when converting CESR bytes to a string.
    #[error("encoding error: {0}")]
    Encoding(#[from] FromUtf8Error),

    /// Validation constraint violated (e.g. threshold, witness count).
    #[error("validation error: {0}")]
    Validation(String),
}
