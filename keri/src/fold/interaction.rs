//! Interaction (`ixn`) fold step.
use alloc::boxed::Box;

use cesr::core::primitives::{Seqner, Siger};
use cesr::keri::{Ilk, InteractionEvent, KeriEvent};

use super::Accepted;
use super::rules::{check_next_sn, verify_signing};
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

/// Narrow a `KeriEvent` to its inner [`InteractionEvent`].
///
/// The fold's dispatch only routes the interaction ilk here, so the fallback arm
/// is unreachable in practice — but it returns an error rather than panicking.
const fn narrow(event: &KeriEvent) -> Result<&InteractionEvent, Rejection> {
    match event {
        KeriEvent::Interaction(e) => Ok(e),
        _ => Err(Rejection::new(RejectionReason::InvalidEvent)),
    }
}

/// Validate an interaction event against the prior state (keripy `eventing.py`,
/// interaction path). Signatures are read for their indices only.
///
/// # Errors
///
/// Returns a [`Rejection`] when the prior state is establishment-only (which
/// forbids interactions), when the sequence number is not exactly one past the
/// prior state ([`OutOfOrder`](RejectionReason::OutOfOrder)), when the prior-event
/// digest does not match the state's latest SAID
/// ([`PriorDigestMismatch`](RejectionReason::PriorDigestMismatch)), when a signer
/// index is out of range, or when the signing threshold is unmet
/// ([`MissingSignatures`](RejectionReason::MissingSignatures)).
pub(super) fn validate<'a>(
    prior: &KeyState,
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    let ixn = narrow(event)?;
    if prior.is_establishment_only() {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    check_next_sn(prior.sn().value(), ixn.sn().value())?;
    if ixn.prior_event_said().raw() != prior.latest_said().raw() {
        return Err(Rejection::new(RejectionReason::PriorDigestMismatch));
    }
    verify_signing(prior.threshold(), prior.keys().len(), sigs)?;
    Ok(Accepted::Interaction {
        event: ixn,
        prior: Box::new(prior.clone()),
    })
}

/// Fold an accepted interaction into the next [`KeyState`].
///
/// An interaction changes only the sequence number, latest SAID, and latest ilk;
/// keys, thresholds, next-key commitment, witnesses, config, delegator,
/// transferability, and the last-establishment pointer all carry over unchanged.
#[must_use]
pub(super) fn apply(prior: Box<KeyState>, ixn: &InteractionEvent) -> KeyState {
    let mut next = *prior;
    next.sn = Seqner::new(ixn.sn().value());
    next.latest_said = ixn.said().clone().into_static();
    next.latest_ilk = Ilk::Ixn;
    next
}
