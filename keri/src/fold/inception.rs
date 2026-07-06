//! Inception (`icp` / `dip`) fold step.
use cesr::core::primitives::Siger;
use cesr::keri::{Identifier, InceptionEvent, KeriEvent};

use super::{Accepted, stub_state};
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

/// Validate a genesis (inception or delegated-inception) event.
///
/// STUB: the real structural rules land in Task 4.3.
///
/// # Errors
///
/// Always returns [`InvalidEvent`](RejectionReason::InvalidEvent) until Task 4.3.
pub(super) const fn validate<'a>(
    _event: &'a KeriEvent,
    _sigs: &[Siger<'_>],
    _wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    Err(Rejection::new(RejectionReason::InvalidEvent))
}

/// Build the genesis [`KeyState`] from an accepted inception event.
///
/// STUB: the real genesis construction lands in Task 4.4.
#[must_use]
pub(super) fn apply<'a>(
    _icp: &'a InceptionEvent,
    _delegator: Option<&'a Identifier<'a>>,
    accepted: &Accepted<'a>,
) -> KeyState<'a> {
    stub_state(accepted)
}
