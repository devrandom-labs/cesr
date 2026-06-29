//! KERI event JSON serialization, deserialization, SAID computation, and
//! version strings.
//!
//! This crate serializes [`keri_core`] domain types to canonical JSON
//! matching keripy's default wire format, computes Self-Addressing
//! Identifier (SAID) digests, and deserializes JSON back into domain types
//! with SAID verification.

/// BFT witness threshold computation.
pub mod ample;
/// Type-state builders for KERI events.
pub mod builder;
/// Event deserialization from canonical JSON with SAID verification.
pub mod deserialize;
/// Error types for serialization, deserialization, and SAID operations.
pub mod error;
/// Primitive-to-string conversion helpers.
pub mod primitives;
/// SAID (Self-Addressing IDentifier) computation.
pub mod said;
/// Event serialization to canonical JSON with SAID computation.
pub mod serialize;
/// Serde traits for method-syntax serialization.
pub mod traits;
/// Version string parsing and generation.
pub mod version;

pub use ample::ample;
pub use builder::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder,
};
pub use deserialize::{
    deserialize_delegated_inception, deserialize_delegated_rotation, deserialize_event,
    deserialize_inception, deserialize_interaction, deserialize_rotation,
};
pub use error::SerderError;
pub use serialize::{
    SerializedEvent, serialize, serialize_delegated_inception, serialize_delegated_rotation,
    serialize_inception, serialize_interaction, serialize_rotation,
};
pub use traits::{KeriDeserialize, KeriSerialize};
