//! Rotation (`rot` / `drt`) fold step.
use cesr::core::primitives::Siger;
use cesr::keri::{KeriEvent, RotationEvent};

use super::Accepted;
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

/// Validate a rotation (or delegated-rotation) event against the prior state.
///
/// STUB: the real rotation rules land in Phase 6.
///
/// # Errors
///
/// Always returns [`InvalidEvent`](RejectionReason::InvalidEvent) until Phase 6.
pub(super) const fn validate<'a>(
    _state: &KeyState<'_>,
    _event: &'a KeriEvent,
    _sigs: &[Siger<'_>],
    _wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    Err(Rejection::new(RejectionReason::InvalidEvent))
}

/// Fold a rotation event into the next [`KeyState`].
///
/// STUB: the real key-rotation fold lands in Phase 6. For now the prior state is
/// carried forward unchanged.
#[must_use]
pub(super) fn apply<'a>(
    prior: &KeyState<'a>,
    _event: &'a RotationEvent,
    _accepted: &Accepted<'a>,
) -> KeyState<'a> {
    prior.clone()
}
