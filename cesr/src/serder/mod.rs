//! The canonical event body codec: `keri` domain types ⇄ canonical JSON,
//! with SAID computation and verification.
//!
//! Serialization writes keripy's exact wire bytes (single canonical JSON
//! writer); deserialization is a strict single-pass canonical parser with
//! in-place SAID verification. This module also hosts the read spine —
//! [`EventMessage::parse`] is the crate's front door for wire bytes,
//! composing `stream` framing with the body codec into one typed pipeline.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};

/// Type-state builders for KERI events.
pub mod builder;
/// Event deserialization from canonical JSON with SAID verification.
pub mod deserialize;
/// Error types for serialization, deserialization, and SAID operations.
pub mod error;
/// Shared proptest strategies over the builder-reachable KERI event space,
/// reused by the write-path and read-path differential property tests.
#[cfg(test)]
pub(crate) mod event_strategies;
/// The read spine: wire bytes → typed event + attached signatures.
pub mod message;
/// Primitive-to-string conversion helpers.
pub mod primitives;
/// SAID (Self-Addressing IDentifier) computation.
pub mod said;
/// Event serialization to canonical JSON with SAID computation.
pub mod serialize;
/// Serde traits for method-syntax serialization.
pub mod traits;

pub use builder::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder,
};
pub use deserialize::{
    deserialize_delegated_inception, deserialize_delegated_rotation, deserialize_event,
    deserialize_inception, deserialize_interaction, deserialize_rotation,
};
pub use error::{EventMessageError, SerderError};
pub use message::EventMessage;
// Version-string types moved to `core::version` (#spine-1); re-exported here
// so serder-centric imports keep one obvious home.
pub use crate::core::version::{Protocol, SerializationKind, VersionString};
pub use serialize::{
    EventRef, SerializedEvent, serialize, serialize_delegated_inception,
    serialize_delegated_rotation, serialize_inception, serialize_interaction, serialize_rotation,
};
pub use traits::{KeriDeserialize, KeriSerialize};
