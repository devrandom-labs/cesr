//! Error types for KERI event serialization, deserialization, and SAID computation.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;

use crate::core::matter::error::{ParsingError, ValidationError};

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

    /// A field present on the wire that the event's v1 grammar forbids
    /// (e.g. `c` on `rot`/`drt` — config traits are inception-only in KERI v1).
    #[error("unexpected field `{0}` for this event type")]
    UnexpectedField(&'static str),

    /// Field value is not a valid qb64 CESR primitive.
    #[error("invalid primitive in field '{field}': {source}")]
    InvalidPrimitive {
        /// The JSON field name.
        field: &'static str,
        /// The underlying CESR validation error.
        source: ValidationError,
    },

    /// Field value could not be parsed as a CESR primitive (malformed code or
    /// length) — distinct from a value that parsed but failed validation.
    #[error("unparseable primitive in field '{field}': {source}")]
    UnparseablePrimitive {
        /// The JSON field name.
        field: &'static str,
        /// The underlying CESR parsing error.
        source: ParsingError,
    },

    /// Input deviates from the fixed canonical event grammar at a specific
    /// byte: whitespace, reordered/duplicate/unknown fields, string escapes,
    /// or malformed framing. Canonical KERI event JSON is byte-deterministic,
    /// so any deviation is rejected by construction.
    #[error("non-canonical event JSON at byte {offset}: expected {expected}, found {found:?}")]
    NonCanonical {
        /// Byte offset in the raw input where the grammar was violated.
        offset: usize,
        /// What the grammar required at that offset.
        expected: &'static str,
        /// The byte actually found, or `None` at end of input.
        found: Option<u8>,
    },

    /// A version-string field's value does not fit its fixed-width hex
    /// encoding — rendering it anyway would widen the string and corrupt the
    /// 17-byte frame.
    #[error("version string field '{field}' exceeds its fixed-width capacity of {max}")]
    VersionStringOverflow {
        /// The version-string field that does not fit.
        field: &'static str,
        /// The largest value the field's fixed width can encode.
        max: u32,
    },

    /// A serialization backend or the canonical parser reported a slot layout
    /// inconsistent with the bytes it rendered or parsed — an internal bug,
    /// surfaced as a typed error so a corrupt frame can never escape.
    #[error("invalid event layout: {0}")]
    InvalidEventLayout(&'static str),

    /// Digest computation failed.
    #[error("digest error: {0}")]
    DigestError(String),

    /// Validation constraint violated (e.g. threshold, witness count).
    #[error("validation error: {0}")]
    Validation(String),
}
