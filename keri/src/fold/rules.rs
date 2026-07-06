//! Validation rules shared across the establishment/non-establishment ilks.
//!
//! These checks are security-relevant and were previously copy-pasted across the
//! inception, interaction, and rotation fold steps; centralising them here keeps
//! the read-path invariants from drifting apart between ilks.
use alloc::vec::Vec;

use cesr::core::primitives::{Siger, Tholder, Verfer};

use super::signed_indices;
use crate::error::{Rejection, RejectionReason};
use crate::threshold::satisfied_by;

/// An establishment event's key set must be non-empty and its signing threshold
/// well-formed: a simple threshold in `1..=keys.len()`, or a weighted threshold
/// that is a non-empty list of non-empty clauses whose flattened weight count
/// does not exceed the key count.
pub(super) fn check_established_threshold(
    keys: &[Verfer<'_>],
    tholder: &Tholder,
) -> Result<(), Rejection> {
    if keys.is_empty() {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    match tholder {
        Tholder::Simple(threshold) => {
            let Ok(required) = usize::try_from(*threshold) else {
                return Err(Rejection::new(RejectionReason::InvalidEvent));
            };
            if !(1..=keys.len()).contains(&required) {
                return Err(Rejection::new(RejectionReason::InvalidEvent));
            }
        }
        Tholder::Weighted(clauses) => {
            // keripy `Tholder`: a weighted threshold is a non-empty list of
            // non-empty clauses, and its flattened weight count (`tholder.size`)
            // must not exceed the key count (`eventing.py`: reject when
            // `tholder.size > len(keys)`).
            let weight_count: usize = clauses.iter().map(Vec::len).sum();
            if clauses.is_empty() || clauses.iter().any(Vec::is_empty) || weight_count > keys.len() {
                return Err(Rejection::new(RejectionReason::InvalidEvent));
            }
        }
    }
    Ok(())
}

/// Every signer index must address an existing key, and the signed set must
/// satisfy `threshold`.
pub(super) fn verify_signing(
    threshold: &Tholder,
    key_count: usize,
    sigs: &[Siger<'_>],
) -> Result<(), Rejection> {
    for sig in sigs {
        let Ok(index) = usize::try_from(sig.index()) else {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        };
        if index >= key_count {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
    }
    if !satisfied_by(threshold, &signed_indices(sigs)) {
        return Err(Rejection::new(RejectionReason::MissingSignatures));
    }
    Ok(())
}

/// A non-genesis event's sequence number must be exactly one past the prior
/// state's. Superseding recovery (a sn at or below the current one) is out of
/// scope here and lands in K3.
pub(super) const fn check_next_sn(prior_sn: u128, actual: u128) -> Result<(), Rejection> {
    let Some(expected) = prior_sn.checked_add(1) else {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    };
    if actual != expected {
        return Err(Rejection::sn(RejectionReason::OutOfOrder, expected, actual));
    }
    Ok(())
}
