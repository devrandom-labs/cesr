//! The KERI domain vocabulary: typed events, identifiers, seals, thresholds.
//!
//! This module's one job is naming — pure data types with no serialization,
//! verification, or persistence (the `serder` module owns the wire form;
//! the `keri-rs` crate owns the key-state fold). Primary entry point:
//! [`KeriEvent`], the unified event enum everything downstream consumes.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

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
/// Event message-type tags.
pub mod message_type;
/// Role-distinct KERI primitive newtypes over cesr `Matter`.
pub mod primitive;
/// Receipt (`rct`) — endorsement of a key event by its KEL coordinate.
pub mod receipt;
/// Infrastructure roles.
pub mod role;
/// Anchoring seals binding events to external data.
pub mod seal;
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
pub use message_type::MessageType;
pub use primitive::{BasicPrefix, Digest, Said, VerifyingKey};
pub use receipt::Receipt;
pub use role::Role;
pub use seal::{OpaqueSeal, Seal};
pub use threshold::{SigningThreshold, SigningThresholdError, WeightedThreshold};
pub use threshold_form::ThresholdForm;
pub use toad::{Toad, ToadError};

/// Re-exports of the traits and headliner types for the KERI event vocabulary.
pub mod prelude {
    #[doc(no_inline)]
    pub use crate::{ConfigTrait, Identifier, KeriEvent};
}
