//! Type-state builders for KERI event construction.
//!
//! Builders enforce required fields at compile time and apply smart defaults
//! matching keripy's `incept()`, `rotate()`, `interact()`, `delcept()`, and
//! `deltate()` functions.

#[cfg(test)]
use alloc::borrow::Cow;
#[cfg(all(feature = "alloc", test))]
use alloc::vec;

use crate::error::SerderError;
#[cfg(test)]
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::DigestCode;
#[cfg(test)]
use cesr::core::matter::code::VerKeyCode;
#[cfg(test)]
use cesr::core::primitives::Prefixer;
use cesr::core::primitives::Saider;
use keri_events::SigningThreshold;

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

/// Key-configuration accumulation and validation shared by the
/// establishment-event builders.
mod establishment;
/// Witness-set validation shared by the establishment-event builders.
mod witness;

pub use dip::DelegatedInceptionBuilder;
pub use drt::DelegatedRotationBuilder;
pub use icp::InceptionBuilder;
pub use ixn::InteractionBuilder;
pub use rot::RotationBuilder;

/// Marker trait for the type-state pattern used by the event builders.
pub trait EventBuilderState {}

/// Checks a signing threshold well-formed against its key count — the one
/// routine shared by the establishment builders' write path and the
/// deserialize read path (spine phase 3 validation parity).
pub(crate) fn validate_threshold(
    threshold: &SigningThreshold,
    key_count: usize,
    field: &'static str,
) -> Result<(), SerderError> {
    threshold
        .check_well_formed(key_count)
        .map_err(|source| SerderError::SigningThresholdOutOfRange { field, source })
}

/// A placeholder [`Saider`] under `code`, sized correctly for any digest
/// code. Its value is never emitted — the writer dummies the SAID slot and
/// backpatches the computed digest — only its code steers the computation.
pub(crate) fn dummy_saider(code: DigestCode) -> Result<Saider<'static>, SerderError> {
    Saider::digest(code, &[]).map_err(SerderError::from)
}

#[cfg(test)]
pub(crate) fn dummy_prefixer() -> Result<Prefixer<'static>, SerderError> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
        .map_err(|e| SerderError::PlaceholderPrimitive { source: e.into() })?
        .build()
        .map_err(|e| SerderError::PlaceholderPrimitive { source: e })
}
