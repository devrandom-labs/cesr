//! The fold's domain vocabulary: the controlling [`Authority`] an event is
//! authenticated against, the pre-rotation [`Commitment`] a rotation opens, and the
//! [`Establishment`] trait that reads both off an establishment event.
//!
//! These make the key rule of the fold explicit: an establishment event is
//! self-certifying (authenticated against its *own* authority), while an
//! interaction is authenticated against the *current* state's authority.

use alloc::vec::Vec;

use cesr::core::primitives::{Diger, Siger, Verfer};
use cesr::crypto::verify_indexed;
use cesr::keri::{InceptionEvent, RotationEvent, SigningThreshold, SigningThresholdError};

use crate::error::Rejection;

/// Who may sign: the controlling keys and their signing threshold — the unit an
/// event is authenticated against.
#[derive(Debug, Clone, Copy)]
pub struct Authority<'e> {
    keys: &'e [Verfer<'static>],
    threshold: &'e SigningThreshold,
}

impl<'e> Authority<'e> {
    /// A borrowed view over a key set and its signing threshold.
    #[must_use]
    pub const fn new(keys: &'e [Verfer<'static>], threshold: &'e SigningThreshold) -> Self {
        Self { keys, threshold }
    }

    /// The threshold is well-formed for the key count (also rejects an empty set).
    ///
    /// # Errors
    ///
    /// Returns a [`SigningThresholdError`] if the threshold is malformed for the key count.
    pub fn well_formed(&self) -> Result<(), SigningThresholdError> {
        self.threshold.check_well_formed(self.keys.len())
    }

    /// `sigs` authenticate against this authority: each verifies against the key it
    /// indexes, and the verified set satisfies the threshold.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::UnverifiedSignature`] if a signature fails to verify or
    /// its index addresses no key, or [`Rejection::MissingSignatures`] if the
    /// verified set does not satisfy the threshold.
    pub fn verify(&self, bytes: &[u8], sigs: &[Siger<'_>]) -> Result<(), Rejection> {
        let indices = verify_indexed(self.keys, bytes, sigs).collect::<Result<Vec<_>, _>>()?;
        if self.threshold.satisfied_by(indices) {
            Ok(())
        } else {
            Err(Rejection::MissingSignatures)
        }
    }
}

/// The pre-rotation commitment to the *next* authority.
#[derive(Debug, Clone, Copy)]
pub struct Commitment<'e> {
    next_digests: &'e [Diger<'static>],
    next_threshold: &'e SigningThreshold,
}

impl<'e> Commitment<'e> {
    /// A borrowed view over a next-key digest set and its threshold.
    #[must_use]
    pub const fn new(
        next_digests: &'e [Diger<'static>],
        next_threshold: &'e SigningThreshold,
    ) -> Self {
        Self {
            next_digests,
            next_threshold,
        }
    }

    /// `revealed` opens this commitment: its keys hash to the committed digests
    /// positionally (full-rotation form) and its key count satisfies the next
    /// threshold.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::NextKeyCommitmentMismatch`] if the revealed keys do not
    /// match the committed digests or their count does not satisfy the threshold.
    pub fn opened_by(&self, revealed: &Authority<'_>) -> Result<(), Rejection> {
        let keys = revealed.keys;
        if keys.len() != self.next_digests.len() {
            return Err(Rejection::NextKeyCommitmentMismatch);
        }
        for (v, d) in keys.iter().zip(self.next_digests.iter()) {
            if !d.verify(&v.to_qb64b()) {
                return Err(Rejection::NextKeyCommitmentMismatch);
            }
        }
        let n = u32::try_from(keys.len()).map_err(|_| Rejection::NextKeyCommitmentMismatch)?;
        if self.next_threshold.satisfied_by(0..n) {
            Ok(())
        } else {
            Err(Rejection::NextKeyCommitmentMismatch)
        }
    }
}

/// An establishment event, viewed as the [`Authority`] it declares.
///
/// That authority is the one its own signatures are verified against —
/// establishment events are self-certifying. Implemented for the establishment
/// event types (`icp`, `rot`); delegated events are rejected before this applies.
pub trait Establishment {
    /// The authority this event declares.
    fn authority(&self) -> Authority<'_>;
}

impl Establishment for InceptionEvent {
    fn authority(&self) -> Authority<'_> {
        Authority::new(self.keys(), self.threshold())
    }
}

impl Establishment for RotationEvent {
    fn authority(&self) -> Authority<'_> {
        Authority::new(self.keys(), self.threshold())
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test fixtures construct known-good values with unwrap for clarity"
)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use cesr::core::indexer::code::IndexMode;
    use cesr::core::matter::code::VerKeyCode;
    use cesr::crypto::{Ed25519, KeyPair};

    /// `n` distinct keys, each signing `msg` at its own index.
    fn keyed(msg: &[u8], n: u32) -> (Vec<Verfer<'static>>, Vec<Siger<'static>>) {
        let mut keys = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..n {
            let kp = KeyPair::<Ed25519>::generate().unwrap();
            keys.push(kp.verfer(VerKeyCode::Ed25519).unwrap().into_static());
            sigs.push(kp.sign_indexed(msg, i, IndexMode::Both).unwrap());
        }
        (keys, sigs)
    }

    #[test]
    fn verify_accepts_a_fully_signed_set() {
        let msg = b"event bytes";
        let (keys, sigs) = keyed(msg, 2);
        let th = SigningThreshold::Simple(2);
        assert!(Authority::new(&keys, &th).verify(msg, &sigs).is_ok());
    }

    #[test]
    fn verify_under_threshold_is_missing_signatures() {
        let msg = b"event bytes";
        let (keys, sigs) = keyed(msg, 2);
        let th = SigningThreshold::Simple(2);
        assert!(matches!(
            Authority::new(&keys, &th).verify(msg, &sigs[..1]),
            Err(Rejection::MissingSignatures)
        ));
    }

    #[test]
    fn verify_rejects_a_forged_signature() {
        let msg = b"event bytes";
        let (keys, _) = keyed(msg, 1);
        // A signature from an unrelated key presented at index 0.
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let forged = impostor.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let th = SigningThreshold::Simple(1);
        assert!(matches!(
            Authority::new(&keys, &th).verify(msg, &[forged]),
            Err(Rejection::UnverifiedSignature(_))
        ));
    }

    #[test]
    fn well_formed_rejects_threshold_exceeding_keys() {
        let (keys, _) = keyed(b"x", 2);
        let th = SigningThreshold::Simple(3);
        assert!(matches!(
            Authority::new(&keys, &th).well_formed(),
            Err(SigningThresholdError::ExceedsKeyCount { .. })
        ));
    }
}
