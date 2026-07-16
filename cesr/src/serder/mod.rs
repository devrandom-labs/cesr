//! KERI event JSON serialization, deserialization, SAID computation, and
//! version strings.
//!
//! This crate serializes [`keri_core`] domain types to canonical JSON
//! matching keripy's default wire format, computes Self-Addressing
//! Identifier (SAID) digests, and deserializes JSON back into domain types
//! via a strict canonical parser with in-place (offset-based) SAID
//! verification.

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
pub use error::SerderError;
// Version-string types moved to `core::version` (#spine-1); re-exported here
// so serder-centric imports keep one obvious home.
pub use crate::core::version::{Protocol, SerializationKind, VersionString};
pub use serialize::{
    EventRef, SerializedEvent, serialize, serialize_delegated_inception,
    serialize_delegated_rotation, serialize_inception, serialize_interaction, serialize_rotation,
};
pub use traits::{KeriDeserialize, KeriSerialize};
