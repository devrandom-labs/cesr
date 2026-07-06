//! Rotation (`rot` / `drt`) fold step.
use cesr::core::primitives::Siger;
use cesr::keri::KeriEvent;

use super::Accepted;
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

/// Validate a rotation (or delegated-rotation) event against the prior state.
///
/// STUB: the real rotation rules land in Phase 6, where this will return an
/// `Accepted::Rotation` carrying the prior state; `apply` is added alongside it.
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
