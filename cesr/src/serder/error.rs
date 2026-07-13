//! Error types for KERI event serialization, deserialization, and SAID computation.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;

use crate::core::matter::error::{MatterBuildError, ParsingError, ValidationError};
use crate::core::primitives::ThresholdError;
use crate::keri::seal::OpaqueSealError;
use crate::keri::toad::ToadError;

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

    /// An anchor (`a` array element) that is neither a codex seal shape nor
    /// a well-formed compact-JSON object.
    ///
    /// Two offset bases compose in the rendered message: `offset` is
    /// absolute (the anchor object's first byte within the raw event),
    /// while any offset carried by `source` is relative to that object
    /// start.
    #[error("invalid anchor object at offset {offset}: {source}")]
    InvalidAnchor {
        /// Absolute byte offset of the anchor object's start in the raw
        /// event; offsets inside `source` are relative to this point.
        offset: usize,
        /// The compact-JSON scan rejection, with offsets relative to the
        /// anchor object's start.
        #[source]
        source: OpaqueSealError,
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

    /// Witness-threshold domain rule violated.
    #[error(transparent)]
    Toad(#[from] ToadError),

    /// A builder terminal-state field that must be set before `build()`.
    #[error("builder field `{0}` is required")]
    MissingBuilderField(&'static str),

    /// A key list that must be non-empty.
    #[error("`{0}` must not be empty")]
    EmptyKeys(&'static str),

    /// A prefix list carrying duplicate entries.
    #[error("`{0}` must not contain duplicates")]
    DuplicatePrefixes(&'static str),

    /// A rotation witness removal that is not a prior witness.
    #[error("witness removals must all be prior witnesses")]
    CutNotPriorWitness,

    /// A rotation witness addition that is already a prior witness.
    #[error("witness additions must not already be prior witnesses")]
    AddAlreadyWitness,

    /// Overlapping rotation witness removals and additions.
    ///
    /// Currently unreachable: `cuts ⊆ prior` and `adds ∩ prior = ∅` already
    /// imply disjointness; the branch is kept for keripy check-order parity
    /// (see `validate_rotation_witnesses`).
    #[error("witness removals and additions must be disjoint")]
    CutAddOverlap,

    /// Post-rotation witness count exceeds addressable size.
    #[error("post-rotation witness count overflows usize")]
    WitnessCountOverflow,

    /// A sequence number that must be at least 1 (rotation, delegated
    /// rotation, and interaction events are never event 0).
    #[error("{0} sn must be >= 1")]
    SnBelowMinimum(&'static str),

    /// A signing threshold out of range for the named key set.
    #[error("{field} threshold: {source}")]
    SigningThresholdOutOfRange {
        /// Which threshold: "signing" or "next signing".
        field: &'static str,
        /// The specific well-formedness rule violated.
        #[source]
        source: ThresholdError,
    },

    /// Majority computation exceeded the threshold value range.
    #[error("majority for {keys} keys exceeds the threshold range")]
    MajorityOverflow {
        /// The governing key-set size.
        keys: usize,
    },

    /// A dummy/placeholder primitive failed to construct — an internal
    /// invariant, never input-dependent.
    #[error("placeholder primitive construction failed: {source}")]
    PlaceholderPrimitive {
        /// The underlying construction error.
        #[source]
        source: MatterBuildError,
    },

    /// Numeric threshold fields mixing integer and hex-string wire forms —
    /// not in keripy's output language (one `intive` flag per event).
    #[error("threshold field `{field}` wire form disagrees with `bt`")]
    MixedThresholdForms {
        /// The disagreeing field: "kt" or "nt".
        field: &'static str,
    },

    /// A signing threshold too large for integer wire form (keripy
    /// `MaxIntThold = 2^32 - 1`).
    #[error("threshold {value} exceeds integer wire form range (2^32-1)")]
    IntegerFormOverflow {
        /// The oversized threshold value.
        value: u64,
    },
}
