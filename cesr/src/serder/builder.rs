//! Type-state builders for KERI event construction.
//!
//! Builders enforce required fields at compile time and apply smart defaults
//! matching keripy's `incept()`, `rotate()`, `interact()`, `delcept()`, and
//! `deltate()` functions.

/// Delegated inception event builder.
pub mod dip;
/// Delegated rotation event builder.
pub mod drt;
/// Inception event builder.
pub mod icp;
/// Interaction event builder.
pub mod ixn;
/// Rotation event builder.
pub mod rot;
/// Witness-set validation shared by the establishment-event builders.
mod witness;

pub use dip::DelegatedInceptionBuilder;
pub use drt::DelegatedRotationBuilder;
pub use icp::InceptionBuilder;
pub use ixn::InteractionBuilder;
pub use rot::RotationBuilder;
