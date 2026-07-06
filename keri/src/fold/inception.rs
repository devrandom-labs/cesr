//! Inception (`icp` / `dip`) fold step.
use alloc::borrow::Cow;

use cesr::core::primitives::{Prefixer, Seqner, Siger};
use cesr::keri::{Identifier, Ilk, InceptionEvent, KeriEvent};

use super::Accepted;
use super::rules::{check_established_threshold, verify_signing};
use crate::error::{Rejection, RejectionReason};
use crate::state::{EstablishmentRef, KeyState};

/// Narrow a genesis event to its inner [`InceptionEvent`].
///
/// The fold's dispatch routes only the plain inception ilk (`icp`) here —
/// delegated inceptions (`dip`) are rejected upstream (K4 scope) — so the
/// fallback arm is unreachable in practice, but it returns an error rather than
/// panicking.
const fn narrow(event: &KeriEvent) -> Result<&InceptionEvent, Rejection> {
    match event {
        KeriEvent::Inception(e) => Ok(e),
        _ => Err(Rejection::new(RejectionReason::InvalidEvent)),
    }
}

/// An inception must carry sequence number 0.
const fn check_sn(icp: &InceptionEvent) -> Result<(), Rejection> {
    let sn = icp.sn().value();
    if sn != 0 {
        return Err(Rejection::sn(RejectionReason::InvalidEvent, 0, sn));
    }
    Ok(())
}

/// Transferability must agree with the pre-rotation commitment: a
/// non-transferable prefix commits to no next keys; a self-addressing (always
/// transferable) prefix must commit to at least one. Returns the decided
/// transferability so the caller can carry it rather than recompute it.
fn check_transferability(icp: &InceptionEvent) -> Result<bool, Rejection> {
    let transferable = match icp.prefix() {
        Identifier::Basic(prefixer) => prefixer.code().is_transferable(),
        Identifier::SelfAddressing(_) => true,
    };
    let next_empty = icp.next_keys().is_empty();
    if !transferable && !next_empty {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    if matches!(icp.prefix(), Identifier::SelfAddressing(_)) && next_empty {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    Ok(transferable)
}

/// The witness threshold (TOAD) must not exceed the number of witnesses.
fn check_witnesses(icp: &InceptionEvent) -> Result<(), Rejection> {
    let toad = u128::from(icp.witness_threshold());
    let Ok(witness_count) = u128::try_from(icp.witnesses().len()) else {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    };
    if toad > witness_count {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    Ok(())
}

/// Validate a genesis (inception or delegated-inception) event against KERI's
/// structural rules and the signing-threshold arithmetic (keripy `eventing.py`
/// `incept`/`delegate` validation). Signatures are read for their indices only.
///
/// # Errors
///
/// Returns a [`Rejection`] for a non-zero sequence number, an empty or
/// ill-thresholded key set, a transferability/next-key mismatch, an oversize
/// witness threshold, an out-of-range signer index, or an unmet signing
/// threshold ([`MissingSignatures`](RejectionReason::MissingSignatures)).
pub(super) fn validate<'a>(
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
    _wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    let icp = narrow(event)?;
    check_sn(icp)?;
    check_established_threshold(icp.keys(), icp.threshold())?;
    let transferable = check_transferability(icp)?;
    check_witnesses(icp)?;
    verify_signing(icp.threshold(), icp.keys().len(), sigs)?;
    Ok(Accepted::Inception {
        event: icp,
        resolved_witnesses: Cow::Owned(icp.witnesses().to_vec()),
        transferable,
    })
}

/// Build the genesis [`KeyState`] from an accepted inception event.
///
/// `resolved_witnesses` is the witness set the caller resolved for this event;
/// every other field is read from the inception event. Sequence number and
/// last-establishment pointer are both fixed at the genesis (sn 0). The
/// delegator is always `None` here: delegated inceptions (`dip`) are rejected
/// upstream (K4 scope), and K4 will populate `KeyState.delegator` when it lands.
#[must_use]
pub(super) fn apply(
    icp: &InceptionEvent,
    resolved_witnesses: &[Prefixer<'_>],
    transferable: bool,
) -> KeyState {
    KeyState {
        prefix: icp.prefix().clone().into_static(),
        sn: Seqner::new(0),
        latest_said: icp.said().clone().into_static(),
        latest_ilk: Ilk::Icp,
        keys: icp.keys().iter().map(|k| k.clone().into_static()).collect(),
        threshold: icp.threshold().clone(),
        next_keys: icp
            .next_keys()
            .iter()
            .map(|d| d.clone().into_static())
            .collect(),
        next_threshold: icp.next_threshold().clone(),
        witnesses: resolved_witnesses
            .iter()
            .map(|w| w.clone().into_static())
            .collect(),
        witness_threshold: icp.witness_threshold(),
        config: icp.config().to_vec(),
        delegator: None,
        transferable,
        last_est: EstablishmentRef {
            sn: Seqner::new(0),
            said: icp.said().clone().into_static(),
        },
    }
}
