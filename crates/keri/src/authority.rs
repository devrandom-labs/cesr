//! The fold's domain vocabulary: the controlling [`Authority`] an event is
//! authenticated against, the pre-rotation [`Commitment`] a rotation opens, the
//! [`Witnessing`] agreement its receipts must satisfy, and the
//! [`Establishment`] trait that reads the authority off an establishment event.
//!
//! These make the key rule of the fold explicit: an establishment event is
//! self-certifying (authenticated against its *own* authority), while an
//! interaction is authenticated against the *current* state's authority.

use alloc::vec::Vec;

use cesr::core::primitives::{Diger, Prefixer, Siger, Verfer};
use cesr::crypto::verify_indexed;
use keri_events::{InceptionEvent, RotationEvent, SigningThreshold, SigningThresholdError, Toad};

use crate::error::Rejection;

/// Who may sign: the controlling keys and their signing threshold — the unit an
/// event is authenticated against.
#[derive(Debug, Clone, Copy)]
pub struct Authority<'e> {
    keys: &'e [Verfer<'e>],
    threshold: &'e SigningThreshold,
}

impl<'e> Authority<'e> {
    /// A borrowed view over a key set and its signing threshold.
    #[must_use]
    pub const fn new(keys: &'e [Verfer<'e>], threshold: &'e SigningThreshold) -> Self {
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
    next_digests: &'e [Diger<'e>],
    next_threshold: &'e SigningThreshold,
}

impl<'e> Commitment<'e> {
    /// A borrowed view over a next-key digest set and its threshold.
    #[must_use]
    pub const fn new(next_digests: &'e [Diger<'e>], next_threshold: &'e SigningThreshold) -> Self {
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

/// The witnessing agreement an event must carry: the governing witness set and
/// the threshold of accountable duplicity (TOAD) its receipts must satisfy.
///
/// The governing set is the event's *current* witness set — the declared `b`
/// list at inception, the post-cut/add resolved set for a rotation, and the
/// state's carried set for an interaction — exactly the `wits` keripy passes
/// into `Kever.valSigsWigsDel` (`eventing.py:1963` inception from
/// `Kever.incept`'s `self.wits = ked["b"]` at `eventing.py:2272`;
/// `eventing.py:2390` rotation from `wits = list((witset - cutset) | addset)`
/// at `eventing.py:2624`; `eventing.py:2459` interaction from the Kever
/// state). Witness prefixes are non-transferable, so each prefix IS the
/// verification key ([`Prefixer`] and [`Verfer`] are the same
/// `Matter<VerKeyCode>`), mirroring keripy's
/// `werfers = [Verfer(qb64=wit) for wit in wits]` (`eventing.py:2735`).
#[derive(Debug, Clone, Copy)]
pub struct Witnessing<'e> {
    witnesses: &'e [Prefixer<'e>],
    toad: Toad,
}

impl<'e> Witnessing<'e> {
    /// A borrowed view over a witness set and its agreement threshold.
    #[must_use]
    pub const fn new(witnesses: &'e [Prefixer<'e>], toad: Toad) -> Self {
        Self { witnesses, toad }
    }

    /// `wigs` witness this event: at least TOAD *distinct* witnesses have a
    /// receipt over `bytes` that verifies against the witness at its index.
    ///
    /// keripy semantics (pinned checkout, `src/keri/core/eventing.py`):
    /// each receipt is verified over the event's raw serialization against
    /// the witness its index selects (`verifySigs` at `eventing.py:2737`);
    /// a receipt whose index addresses no witness is *skipped*, not an error
    /// (`eventing.py:332-334`); duplicate receipts count once
    /// (`verifySigs` dedups by full signature qb64 at `eventing.py:325` —
    /// here as distinct verified indices, which also collapses the
    /// two-distinct-sigs-one-index shape strict Ed25519 verification cannot
    /// produce); a receipt that fails verification is likewise skipped and
    /// simply does not count. The TOAD is checked against the count of
    /// *valid* receipts (`len(windices) < toader.num`, `eventing.py:2788`).
    /// Where keripy escrows the event as partially witnessed
    /// (`escrowPWEvent` + `MissingWitnessSignatureError`,
    /// `eventing.py:2788-2799`), this pure fold returns a terminal
    /// [`Rejection::InsufficientWitnessReceipts`] and the consumer re-drives
    /// once more receipts arrive — the same pattern as
    /// [`Rejection::OutOfOrder`]. A TOAD of zero is vacuously satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::InsufficientWitnessReceipts`] if fewer than TOAD
    /// distinct witnesses have a valid receipt.
    pub fn receipted_by(&self, bytes: &[u8], wigs: &[Siger<'_>]) -> Result<(), Rejection> {
        let required = self.toad.value();
        if required == 0 {
            return Ok(());
        }
        let mut receipted: Vec<u32> = verify_indexed(self.witnesses, bytes, wigs)
            .filter_map(Result::ok)
            .collect();
        receipted.sort_unstable();
        receipted.dedup();
        let valid = receipted.len();
        if usize::try_from(required).is_ok_and(|r| valid >= r) {
            Ok(())
        } else {
            Err(Rejection::InsufficientWitnessReceipts { valid, required })
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

impl Establishment for InceptionEvent<'_> {
    fn authority(&self) -> Authority<'_> {
        Authority::new(self.keys(), self.threshold())
    }
}

impl Establishment for RotationEvent<'_> {
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
