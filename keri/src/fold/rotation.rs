//! Rotation (`rot` / `drt`) fold step.
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;

use cesr::core::primitives::{Diger, Prefixer, Seqner, Siger, Verfer};
use cesr::crypto::digest;
use cesr::keri::{Ilk, KeriEvent, RotationEvent};

use super::Accepted;
use super::rules::{check_established_threshold, check_next_sn, verify_signing};
use crate::error::{Rejection, RejectionReason};
use crate::state::{EstablishmentRef, KeyState};
use crate::threshold::satisfied_by;

/// Narrow a `KeriEvent` to its inner [`RotationEvent`].
///
/// The fold's dispatch routes only the plain rotation ilk (`rot`) here —
/// delegated rotations (`drt`) are rejected upstream (K4 scope) — so the
/// fallback arm is unreachable in practice, but it returns an error rather than
/// panicking.
const fn narrow(event: &KeriEvent) -> Result<&RotationEvent, Rejection> {
    match event {
        KeriEvent::Rotation(e) => Ok(e),
        _ => Err(Rejection::new(RejectionReason::InvalidEvent)),
    }
}

/// The rotation's prior-event digest must match the state's latest SAID.
fn check_prior_digest(prior: &KeyState, rot: &RotationEvent) -> Result<(), Rejection> {
    if rot.prior_event_said().raw() != prior.latest_said().raw() {
        return Err(Rejection::new(RejectionReason::PriorDigestMismatch));
    }
    Ok(())
}

/// Each revealed key must hash to the positionally-corresponding committed
/// digest. Returns `Ok(false)` on mismatch, `Err` only if the digest primitive
/// itself fails to build — the check fails **closed** either way.
fn commitment_holds(revealed: &[Verfer<'_>], committed: &[Diger<'_>]) -> Result<bool, Rejection> {
    if revealed.len() != committed.len() {
        return Ok(false);
    }
    for (v, d) in revealed.iter().zip(committed.iter()) {
        let got = digest(*d.code(), &v.to_qb64b())
            .map_err(|_| Rejection::new(RejectionReason::NextKeyCommitmentMismatch))?;
        if got.raw() != d.raw() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The revealed keys must satisfy the prior next-key commitment: they must hash
/// to the committed digests (positional, full-rotation form) and the revealed
/// set must satisfy the prior next-key threshold.
fn check_next_commitment(prior: &KeyState, rot: &RotationEvent) -> Result<(), Rejection> {
    if !commitment_holds(rot.keys(), prior.next_keys())? {
        return Err(Rejection::new(RejectionReason::NextKeyCommitmentMismatch));
    }
    let Ok(n) = u32::try_from(rot.keys().len()) else {
        return Err(Rejection::new(RejectionReason::NextKeyCommitmentMismatch));
    };
    if !satisfied_by(prior.next_threshold(), 0..n) {
        return Err(Rejection::new(RejectionReason::NextKeyCommitmentMismatch));
    }
    Ok(())
}

/// Compute the post-rotation witness set: every removal must be a current
/// witness, every addition must not already be present after removals, and the
/// new witness threshold must not exceed the resolved count.
fn resolve_witnesses<'a>(
    prior: &KeyState,
    rot: &'a RotationEvent,
) -> Result<Vec<Prefixer<'a>>, Rejection> {
    let removals = rot.witness_removals();
    let additions = rot.witness_additions();
    for r in removals {
        if !prior.witnesses().iter().any(|w| w == r) {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
        // keripy requires cuts and adds to be disjoint; an overlapping prefix
        // would otherwise be removed then silently re-added (a no-op "keep").
        if additions.iter().any(|a| a == r) {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
    }
    let mut resolved: Vec<Prefixer<'a>> = prior
        .witnesses()
        .iter()
        .filter(|w| !removals.iter().any(|r| r == *w))
        .cloned()
        .collect();
    for a in additions {
        if resolved.iter().any(|w| w == a) {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
        resolved.push(a.clone());
    }
    let Ok(resolved_len) = u32::try_from(resolved.len()) else {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    };
    if rot.witness_threshold() > resolved_len {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    Ok(resolved)
}

/// Validate a rotation (`rot`) event against the prior state (keripy
/// `eventing.py`, rotation path). Signatures are read for their indices only.
/// Delegated rotations (`drt`) are rejected upstream (K4 scope) and never reach
/// here.
///
/// The next-key commitment is the security-critical check: the revealed keys
/// must hash to the digests the prior establishment event committed to, and the
/// revealed set must satisfy the prior next-key threshold. This is the strict
/// full-rotation form (revealed count equals committed count, positional match);
/// keripy also supports partial rotation, which is a follow-up.
///
/// # Errors
///
/// Returns a [`Rejection`] when the sequence number is not exactly one past the
/// prior state ([`OutOfOrder`](RejectionReason::OutOfOrder)), when the
/// prior-event digest does not match
/// ([`PriorDigestMismatch`](RejectionReason::PriorDigestMismatch)), when the new
/// key set is empty or ill-thresholded, when the revealed keys do not satisfy the
/// prior commitment
/// ([`NextKeyCommitmentMismatch`](RejectionReason::NextKeyCommitmentMismatch)),
/// when a witness cut/add or the witness threshold is invalid, or when the new
/// signing threshold is unmet
/// ([`MissingSignatures`](RejectionReason::MissingSignatures)).
pub(super) fn validate<'a>(
    prior: &KeyState,
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
    _wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    let rot = narrow(event)?;
    check_next_sn(prior.sn().value(), rot.sn().value())?;
    check_prior_digest(prior, rot)?;
    check_established_threshold(rot.keys(), rot.threshold())?;
    check_next_commitment(prior, rot)?;
    let resolved = resolve_witnesses(prior, rot)?;
    verify_signing(rot.threshold(), rot.keys().len(), sigs)?;
    Ok(Accepted::Rotation {
        event: rot,
        prior: Box::new(prior.clone()),
        resolved_witnesses: Cow::Owned(resolved),
    })
}

/// Fold an accepted rotation into the next [`KeyState`].
///
/// A rotation is an establishment event: it rolls the current keys, thresholds,
/// next-key commitment, and witnesses forward, and advances the
/// last-establishment pointer. Config, delegator, and transferability carry over
/// from the prior state.
#[must_use]
pub(super) fn apply(
    prior: Box<KeyState>,
    rot: &RotationEvent,
    resolved_witnesses: &[Prefixer<'_>],
) -> KeyState {
    let mut next = *prior;
    next.sn = Seqner::new(rot.sn().value());
    next.latest_said = rot.said().clone().into_static();
    next.latest_ilk = Ilk::Rot;
    next.keys = rot.keys().iter().map(|k| k.clone().into_static()).collect();
    next.threshold = rot.threshold().clone();
    next.next_keys = rot
        .next_keys()
        .iter()
        .map(|d| d.clone().into_static())
        .collect();
    next.next_threshold = rot.next_threshold().clone();
    next.witnesses = resolved_witnesses
        .iter()
        .map(|w| w.clone().into_static())
        .collect();
    next.witness_threshold = rot.witness_threshold();
    next.last_est = EstablishmentRef {
        sn: Seqner::new(rot.sn().value()),
        said: rot.said().clone().into_static(),
    };
    next
}
