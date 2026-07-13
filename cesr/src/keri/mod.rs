//! KERI domain types — events, seals, key state.
//!
//! This is the foundational crate of the `keri-*` family. It defines
//! pure data types with no serialization, verification, or persistence.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};

/// Configuration traits constraining identifier behavior.
pub mod config;
/// Error types for KERI domain operations.
pub mod error;
/// KERI event types.
pub mod event;
/// Typed KERI identifier (basic or self-addressing derivation).
pub mod identifier;
/// Event type identifiers (ilks).
pub mod ilk;
/// Infrastructure roles.
pub mod role;
/// Anchoring seals binding events to external data.
pub mod seal;
/// Witness threshold (TOAD).
pub mod toad;

pub use config::ConfigTrait;
pub use error::KeriError;
pub use event::{
    DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent, KeriEvent,
    RotationEvent,
};
pub use identifier::Identifier;
pub use ilk::Ilk;
pub use role::Role;
pub use seal::{OpaqueSeal, OpaqueSealError, Seal};
pub use toad::{Toad, ToadError};
