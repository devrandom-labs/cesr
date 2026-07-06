//! Inception (`icp` / `dip`) fold step.
use alloc::borrow::Cow;

use cesr::core::primitives::{Siger, Tholder};
use cesr::keri::{Identifier, InceptionEvent, KeriEvent};

use super::{Accepted, signed_indices, stub_state};
use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;
use crate::threshold::satisfied_by;

/// Narrow a genesis event to its inner [`InceptionEvent`].
///
/// The fold's dispatch only routes inception ilks here, so the fallback arm is
/// unreachable in practice — but it returns an error rather than panicking.
const fn narrow(event: &KeriEvent) -> Result<&InceptionEvent, Rejection> {
    match event {
        KeriEvent::Inception(e) => Ok(e),
        KeriEvent::DelegatedInception(e) => Ok(e.inception()),
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

/// Keys must be non-empty and a simple threshold must lie in `1..=keys.len()`.
fn check_keys_and_threshold(icp: &InceptionEvent) -> Result<(), Rejection> {
    let keys = icp.keys();
    if keys.is_empty() {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    if let Tholder::Simple(threshold) = icp.threshold() {
        let Ok(required) = usize::try_from(*threshold) else {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        };
        if !(1..=keys.len()).contains(&required) {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
    }
    Ok(())
}

/// Transferability must agree with the pre-rotation commitment: a
/// non-transferable prefix commits to no next keys; a self-addressing (always
/// transferable) prefix must commit to at least one.
fn check_transferability(icp: &InceptionEvent) -> Result<(), Rejection> {
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
    Ok(())
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

/// Every signer index must address an existing key, and the signed set must
/// satisfy the signing threshold.
fn check_signatures(icp: &InceptionEvent, sigs: &[Siger<'_>]) -> Result<(), Rejection> {
    let key_count = icp.keys().len();
    for sig in sigs {
        let Ok(index) = usize::try_from(sig.index()) else {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        };
        if index >= key_count {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
    }
    if !satisfied_by(icp.threshold(), &signed_indices(sigs)) {
        return Err(Rejection::new(RejectionReason::MissingSignatures));
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
    check_keys_and_threshold(icp)?;
    check_transferability(icp)?;
    check_witnesses(icp)?;
    check_signatures(icp, sigs)?;
    Ok(Accepted {
        event,
        resolved_witnesses: Cow::Owned(icp.witnesses().to_vec()),
    })
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
