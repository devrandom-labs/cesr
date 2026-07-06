//! Interaction (`ixn`) fold step.
use cesr::core::primitives::Siger;
use cesr::keri::{InteractionEvent, KeriEvent};

use super::Accepted;
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

/// Validate an interaction event against the prior state.
///
/// STUB: the real interaction rules land in Phase 5.
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

/// Fold an interaction event into the next [`KeyState`].
///
/// STUB: the real interaction fold lands in Phase 5. Interaction events never
/// change key state, so the prior state is carried forward unchanged.
#[must_use]
pub(super) fn apply<'a>(
    prior: &KeyState<'a>,
    _event: &'a InteractionEvent,
    _accepted: &Accepted<'a>,
) -> KeyState<'a> {
    prior.clone()
}
