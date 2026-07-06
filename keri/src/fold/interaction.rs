//! Interaction (`ixn`) fold step.
use alloc::boxed::Box;

use cesr::core::primitives::{Seqner, Siger};
use cesr::keri::{Ilk, InteractionEvent, KeriEvent};

use super::{Accepted, signed_indices};
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;
use crate::threshold::satisfied_by;

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

/// An interaction's sequence number must be exactly one past the prior state's.
const fn check_sn(prior: &KeyState, ixn: &InteractionEvent) -> Result<(), Rejection> {
    let Some(expected) = prior.sn().value().checked_add(1) else {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    };
    let actual = ixn.sn().value();
    if actual != expected {
        return Err(Rejection::sn(RejectionReason::OutOfOrder, expected, actual));
    }
    Ok(())
}

/// Every signer index must address an existing key, and the signed set must
/// satisfy the prior state's signing threshold.
fn check_signatures(prior: &KeyState, sigs: &[Siger<'_>]) -> Result<(), Rejection> {
    let key_count = prior.keys().len();
    for sig in sigs {
        let Ok(index) = usize::try_from(sig.index()) else {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        };
        if index >= key_count {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
    }
    if !satisfied_by(prior.threshold(), &signed_indices(sigs)) {
        return Err(Rejection::new(RejectionReason::MissingSignatures));
    }
    Ok(())
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
    check_sn(prior, ixn)?;
    if ixn.prior_event_said().raw() != prior.latest_said().raw() {
        return Err(Rejection::new(RejectionReason::PriorDigestMismatch));
    }
    check_signatures(prior, sigs)?;
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
