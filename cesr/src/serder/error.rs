//! Error types for KERI event serialization, deserialization, and SAID computation.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;

use crate::core::matter::error::{MatterBuildError, ParsingError, ValidationError};
use crate::core::version::{SerializationKind, VersionError};
use crate::keri::SigningThresholdError;
use crate::keri::seal::OpaqueSealError;
use crate::keri::toad::ToadError;
use crate::stream::error::ParseError;

/// Errors during KERI event serialization, deserialization, and SAID computation.
#[derive(Debug, thiserror::Error)]
pub enum SerderError {
    /// JSON parse/render failure inside the test-only tolerant reference
    /// oracle (`deserialize::reference`). Test builds only — no production
    /// code path uses `serde_json`.
    #[cfg(test)]
    #[error("reference-oracle JSON error: {0}")]
    ReferenceJson(#[from] serde_json::Error),

    /// Version string parsing or construction failed (see [`VersionError`]).
    #[error(transparent)]
    Version(#[from] VersionError),

    /// Version string parsed but violates a serder-level rule: a non-JSON
    /// serialization kind on the strict read path, or a size field that
    /// contradicts the actual input length.
    #[error("invalid version string: {0}")]
    InvalidVersionString(String),

    /// A serialization kind with no body codec. Only JSON events can be
    /// written today; the strict reader enforces the same limit on the
    /// read path (non-JSON version strings are rejected), so this is the
    /// write-path half of one invariant.
    #[error("no body codec for serialization kind {}", .0.as_str())]
    UnsupportedSerializationKind(SerializationKind),

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

    /// The JSON writer or the canonical parser reported a slot layout
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
        source: SigningThresholdError,
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

/// Errors while parsing one framed key event message off the wire
/// ([`EventMessage::parse`](crate::serder::EventMessage::parse)).
///
/// The first error union spanning the stream/serder seam: stream framing and
/// attachment parsing fail as [`Frame`](Self::Frame), body deserialization
/// and SAID verification fail as [`Body`](Self::Body), and the two
/// message-level shapes a key event message cannot carry get their own
/// variants.
#[derive(Debug, thiserror::Error)]
pub enum EventMessageError {
    /// CESR framing or attachment-group parsing failed (stream domain).
    #[error(transparent)]
    Frame(#[from] ParseError),

    /// The event body failed canonical deserialization or SAID verification
    /// (serder domain).
    #[error(transparent)]
    Body(#[from] SerderError),

    /// The input begins with a bare CESR attachment group — there is no event
    /// body to parse.
    #[error("input is a bare attachment group, not an event message")]
    BareAttachment,

    /// An attachment group that cannot belong to a key event message
    /// (anything other than controller/witness indexed signatures, or a
    /// nested attachment frame).
    #[error("unexpected attachment group for a key event message: {group}")]
    UnexpectedGroup {
        /// Name of the offending [`CesrGroup`](crate::stream::CesrGroup)
        /// variant.
        group: &'static str,
    },
}

/// Errors while framing a serialized event with its attachments as a V1
/// CESR message
/// ([`SerializedEvent::frame_v1`](crate::serder::SerializedEvent::frame_v1)),
/// the write mirror of [`EventMessageError`].
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Both signature groups are empty — a message must attach at least one
    /// authenticator (keripy's `messagize` refuses the same shape,
    /// `eventing.py:1582-1583` at the pin).
    #[error("nothing to attach: controller and witness signature groups are both empty")]
    MissingAuthenticator,

    /// Attachment qb64 encoding failed (stream domain): a group count
    /// exceeding its counter code's capacity, or a non-quadlet attachment
    /// region.
    #[error(transparent)]
    Encode(#[from] ParseError),
}
