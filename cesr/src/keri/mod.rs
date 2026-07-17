//! The KERI domain vocabulary: typed events, identifiers, seals, thresholds.
//!
//! This module's one job is naming — pure data types with no serialization,
//! verification, or persistence (the `serder` module owns the wire form;
//! the `keri-rs` crate owns the key-state fold). Primary entry point:
//! [`KeriEvent`], the unified event enum everything downstream consumes.

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
/// Event sequence number.
pub mod sequence;
/// Signing threshold (keripy `Tholder`).
pub mod threshold;
/// Wire encoding of numeric threshold fields (keripy `intive`).
pub mod threshold_form;
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
pub use sequence::SequenceNumber;
pub use threshold::{SigningThreshold, SigningThresholdError, WeightedThreshold};
pub use threshold_form::ThresholdForm;
pub use toad::{Toad, ToadError};
