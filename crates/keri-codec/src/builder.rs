//! Type-state builders for KERI event construction.
//!
//! Builders enforce required fields at compile time and apply smart defaults
//! matching keripy's `incept()`, `rotate()`, `interact()`, `delcept()`, and
//! `deltate()` functions.

#[cfg(test)]
use alloc::borrow::Cow;
#[cfg(all(feature = "alloc", test))]
use alloc::vec;

#[cfg(test)]
use crate::error::InternalError;
use crate::error::{BuilderError, SaidError};
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
pub(crate) mod dip;
/// Delegated rotation event builder.
pub(crate) mod drt;
/// Inception event builder.
pub(crate) mod icp;
/// Interaction event builder.
pub(crate) mod ixn;
/// Rotation event builder.
pub(crate) mod rot;

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

mod sealed {
    /// Private supertrait sealing [`EventBuilderState`]: only this crate's
    /// builder state types can name it, so the marker cannot be implemented
    /// downstream.
    pub trait Sealed {}
}

/// Marker trait for the type-state pattern used by the event builders.
///
/// Sealed via [`sealed::Sealed`] — the set of states is closed to this crate.
pub trait EventBuilderState: sealed::Sealed {}

impl<S: sealed::Sealed> EventBuilderState for S {}

/// Checks a signing threshold well-formed against its key count — the one
/// routine shared by the establishment builders' write path and the
/// deserialize read path (spine phase 3 validation parity).
pub(crate) fn validate_threshold(
    threshold: &SigningThreshold,
    key_count: usize,
    field: &'static str,
) -> Result<(), BuilderError> {
    threshold
        .check_well_formed(key_count)
        .map_err(|source| BuilderError::SigningThresholdOutOfRange { field, source })
}

/// A placeholder [`Saider`] under `code`, sized correctly for any digest
/// code. Its value is never emitted — the writer dummies the SAID slot and
/// backpatches the computed digest — only its code steers the computation.
pub(crate) fn dummy_saider(code: DigestCode) -> Result<Saider<'static>, SaidError> {
    Saider::digest(code, &[]).map_err(SaidError::from)
}

#[cfg(test)]
pub(crate) fn dummy_prefixer() -> Result<Prefixer<'static>, InternalError> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
        .map_err(|e| InternalError::PlaceholderPrimitive { source: e.into() })?
        .build()
        .map_err(|e| InternalError::PlaceholderPrimitive { source: e })
}
