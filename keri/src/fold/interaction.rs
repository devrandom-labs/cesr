//! Interaction (`ixn`) fold step.
use cesr::core::primitives::Siger;
use cesr::keri::KeriEvent;

use super::Accepted;
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

/// Validate an interaction event against the prior state.
///
/// STUB: the real interaction rules land in Phase 5, where this will return an
/// `Accepted::Interaction` carrying the prior state; `apply` is added alongside
/// it.
///
/// # Errors
///
/// Always returns [`InvalidEvent`](RejectionReason::InvalidEvent) until Phase 5.
pub(super) const fn validate<'a>(
    _state: &KeyState<'_>,
    _event: &'a KeriEvent,
    _sigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    Err(Rejection::new(RejectionReason::InvalidEvent))
}
