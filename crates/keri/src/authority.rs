//! The fold's domain vocabulary: the controlling [`Authority`] an event is
//! authenticated against, the pre-rotation [`Commitment`] a rotation opens, the
//! [`Witnessing`] agreement its receipts must satisfy, and the
//! [`Establishment`] trait that reads the authority off an establishment event.
//!
//! These make the key rule of the fold explicit: an establishment event is
//! self-certifying (authenticated against its *own* authority), while an
//! interaction is authenticated against the *current* state's authority.

use alloc::vec::Vec;

use cesr::core::primitives::Siger;
use cesr::crypto::verify_indexed;
use keri_events::{
    BasicPrefix, Digest, InceptionEvent, RotationEvent, SigningThreshold, SigningThresholdError,
    Toad, VerifyingKey,
};

use crate::error::Rejection;

/// Who may sign: the controlling keys and their signing threshold — the unit an
/// event is authenticated against.
#[derive(Debug, Clone, Copy)]
pub struct Authority<'e> {
    keys: &'e [VerifyingKey<'e>],
    threshold: &'e SigningThreshold,
}

impl<'e> Authority<'e> {
    /// A borrowed view over a key set and its signing threshold.
    #[must_use]
    pub const fn new(keys: &'e [VerifyingKey<'e>], threshold: &'e SigningThreshold) -> Self {
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

    /// `sigs` authenticate against this authority: each is verified against the
    /// key its `index` selects, and the *valid subset* must satisfy the
    /// threshold.
    ///
    /// Filter semantics, matching keripy `verifySigs`
    /// (`src/keri/core/eventing.py:305-350`): a signature whose `index`
    /// addresses no key is *skipped* (L334-337), a signature that fails
    /// verification is *skipped* (L345-348), duplicates count once (keripy
    /// dedups by full signature qb64, L324-329 — here as distinct verified
    /// indices, which also collapses the two-distinct-sigs-one-index shape
    /// strict Ed25519 verification cannot produce), and the threshold is judged
    /// on the valid subset only. Skipping is never an error; only the final
    /// threshold check can fail.
    ///
    /// On success, returns a [`Verified`] witness carrying the valid subset.
    /// [`Commitment::opened_by`] requires this proof so it can count signatures
    /// as exposing prior-next keys without itself re-running signature
    /// verification.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::MissingSignatures`] if the valid subset does not
    /// satisfy the threshold; the carried `verified` counts distinct valid
    /// signature indices.
    pub fn verify<'s>(
        &self,
        bytes: &[u8],
        sigs: &'s [Siger<'s>],
    ) -> Result<Verified<'s>, Rejection> {
        // verify_indexed (cesr::crypto) takes a raw Verfer slice; the role
        // newtype only exists in keri-events, so the exact Matter each key
        // wraps is unwrapped here, at the crypto boundary, via `as_matter()`.
        let keys = self
            .keys
            .iter()
            .map(|k| k.as_matter().clone())
            .collect::<Vec<_>>();
        let (mut indices, valid): (Vec<u32>, Vec<&'s Siger<'s>>) =
            verify_indexed(&keys, bytes, sigs)
                .zip(sigs)
                .filter_map(|(result, sig)| result.ok().map(|index| (index, sig)))
                .unzip();
        indices.sort_unstable();
        indices.dedup();
        let verified = indices.len();
        if self.threshold.satisfied_by(indices) {
            Ok(Verified { sigs: valid })
        } else {
            Err(Rejection::MissingSignatures { verified })
        }
    }
}

/// Proof that a signature set verified against an [`Authority`]: the only
/// way to obtain one is [`Authority::verify`], so APIs taking `&Verified`
/// cannot receive unverified signatures.
///
/// Carries the valid subset of the provided signatures — each verified against
/// the key its index selects; invalid or out-of-range signatures were
/// filtered.
#[derive(Debug, Clone)]
pub struct Verified<'s> {
    sigs: Vec<&'s Siger<'s>>,
}

impl<'s> Verified<'s> {
    /// The valid signature subset this proof witnesses.
    #[must_use]
    pub fn sigs(&self) -> &[&'s Siger<'s>] {
        &self.sigs
    }
}

/// The pre-rotation commitment to the *next* authority.
#[derive(Debug, Clone, Copy)]
pub struct Commitment<'e> {
    next_digests: &'e [Digest<'e>],
    next_threshold: &'e SigningThreshold,
}

impl<'e> Commitment<'e> {
    /// A borrowed view over a next-key digest set and its threshold.
    #[must_use]
    pub const fn new(next_digests: &'e [Digest<'e>], next_threshold: &'e SigningThreshold) -> Self {
        Self {
            next_digests,
            next_threshold,
        }
    }

    /// `revealed` opens this commitment: the verified signatures select exposed
    /// prior-next keys by dual index, and the exposed set satisfies the prior
    /// next threshold.
    ///
    /// Spec anchors (`ToIP` KERI specification, line refs into its markdown source):
    /// - S1 (spec L174, L1387): the rotation must be signed by private keys
    ///   from the newly exposed pre-rotated keypairs satisfying the *prior next
    ///   threshold*; the new current key list must include a
    ///   threshold-satisficing subset of the prior next key list.
    /// - S2 (spec L1488): exposed pre-rotated keys must verify against their
    ///   pre-committed digests from the prior establishment event.
    /// - S3 (spec L1470, L1496-1498): partial rotation (some pre-rotated keys
    ///   held in reserve, unexposed) and augmented rotation (current list
    ///   contains new keys never pre-rotated) are both legal.
    /// - S4 (spec L1256): dual-index verification. A signature's `ondex`
    ///   selects the prior next *digest*; its `index` selects the exposed
    ///   public key in the current signing list; the digest is recomputed over
    ///   the exposed key's qb64 **under the committed digest's own code**
    ///   (crypto agility) and compared before the signature can count.
    /// - S5 (spec L1537, L1543 reserve examples): prior-next-threshold
    ///   satisfaction is measured over *signatures* from exposed keys, not
    ///   mere key presence.
    ///
    /// Skip semantics, matching keripy `Kever.exposeds`
    /// (`src/keri/core/eventing.py:2962-3007`, threshold call at L2875): a
    /// verified signature contributes nothing if its `ondex` is `None`, its
    /// `ondex` is out of range of the committed digest list, its `index` is
    /// out of range of the revealed current key list, or the digest does not
    /// match under the committed code. Skipping is never an error; only the final
    /// threshold check can fail.
    ///
    /// This module validates at its own boundary: even though `verified` was
    /// produced against *an* authority, the pairing with `revealed` is a
    /// call-site convention, so every `index` is guarded again with `.get()`.
    ///
    /// Divergence: keripy's numeric `_satisfy_numeric` (`coring.py:L4873`)
    /// counts duplicate ondices from duplicated current keys; this fold dedups
    /// them, which is conservative (over-rejects, never over-accepts). The
    /// K9 differential must account for it.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::PriorNextThresholdUnsatisfied`] if the exposed
    /// prior-next keys do not satisfy the prior next threshold.
    pub fn opened_by(
        &self,
        revealed: &Authority<'_>,
        verified: &Verified<'_>,
    ) -> Result<(), Rejection> {
        let mut exposed: Vec<u32> = verified
            .sigs()
            .iter()
            .filter_map(|sig| {
                let ondex = sig.ondex()?;
                let digest = self.next_digests.get(usize::try_from(ondex).ok()?)?;
                let key = revealed.keys.get(usize::try_from(sig.index()).ok()?)?;
                digest.verify(&key.to_qb64b()).then_some(ondex)
            })
            .collect();
        exposed.sort_unstable();
        exposed.dedup();
        let count = exposed.len();
        if self.next_threshold.satisfied_by(exposed) {
            Ok(())
        } else {
            Err(Rejection::PriorNextThresholdUnsatisfied { exposed: count })
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
/// verification key ([`BasicPrefix`] and [`VerifyingKey`] wrap the same
/// `Matter<VerKeyCode>`), mirroring keripy's
/// `werfers = [Verfer(qb64=wit) for wit in wits]` (`eventing.py:2735`).
#[derive(Debug, Clone, Copy)]
pub struct Witnessing<'e> {
    witnesses: &'e [BasicPrefix<'e>],
    toad: Toad,
}

impl<'e> Witnessing<'e> {
    /// A borrowed view over a witness set and its agreement threshold.
    #[must_use]
    pub const fn new(witnesses: &'e [BasicPrefix<'e>], toad: Toad) -> Self {
        Self { witnesses, toad }
    }

    /// The governing witness set (read by the K5 receipt judgments in
    /// [`crate::receipt`]).
    pub(crate) const fn witnesses(&self) -> &'e [BasicPrefix<'e>] {
        self.witnesses
    }

    /// The threshold of accountable duplicity (read by the K5 receipt
    /// judgments in [`crate::receipt`]).
    pub(crate) const fn toad(&self) -> Toad {
        self.toad
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
        // verify_indexed (cesr::crypto) takes a raw Verfer/Prefixer slice
        // (both `Matter<VerKeyCode>`); unwrap the role newtype here, at the
        // crypto boundary, via `as_matter()`.
        let witnesses = self
            .witnesses
            .iter()
            .map(|w| w.as_matter().clone())
            .collect::<Vec<_>>();
        let mut receipted: Vec<u32> = verify_indexed(&witnesses, bytes, wigs)
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
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::crypto::{Ed25519, KeyPair, digest};

    /// `n` distinct keys, each signing `msg` at its own index.
    fn keyed(msg: &[u8], n: u32) -> (Vec<VerifyingKey<'static>>, Vec<Siger<'static>>) {
        let mut keys = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..n {
            let kp = KeyPair::<Ed25519>::generate().unwrap();
            keys.push(VerifyingKey::from_matter(
                kp.verfer(VerKeyCode::Ed25519).unwrap().into_static(),
            ));
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
            Err(Rejection::MissingSignatures { verified: 1 })
        ));
    }

    #[test]
    fn forged_only_signature_set_is_missing_signatures_zero() {
        let msg = b"event bytes";
        let (keys, _) = keyed(msg, 1);
        // A signature from an unrelated key presented at index 0: filtered,
        // leaving zero valid signatures.
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let forged = impostor.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let th = SigningThreshold::Simple(1);
        assert!(matches!(
            Authority::new(&keys, &th).verify(msg, &[forged]),
            Err(Rejection::MissingSignatures { verified: 0 })
        ));
    }

    #[test]
    fn forged_extra_signature_is_filtered_not_fatal() {
        let msg = b"event bytes";
        let (keys, mut sigs) = keyed(msg, 2);
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        sigs.push(impostor.sign_indexed(msg, 0, IndexMode::Both).unwrap());
        let th = SigningThreshold::Simple(2);
        let verified = Authority::new(&keys, &th).verify(msg, &sigs).unwrap();
        assert_eq!(verified.sigs().len(), 2);
    }

    #[test]
    fn out_of_range_index_is_skipped() {
        let msg = b"event bytes";
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let keys = [VerifyingKey::from_matter(
            kp.verfer(VerKeyCode::Ed25519).unwrap().into_static(),
        )];
        let valid = kp.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let out_of_range = kp.sign_indexed(msg, 5, IndexMode::Both).unwrap();
        let th = SigningThreshold::Simple(1);
        let sigs = [valid, out_of_range];
        let verified = Authority::new(&keys, &th).verify(msg, &sigs).unwrap();
        assert_eq!(verified.sigs().len(), 1);
    }

    #[test]
    fn forged_below_threshold_reports_valid_count() {
        let msg = b"event bytes";
        let (keys, sigs) = keyed(msg, 2);
        let valid = sigs.into_iter().next().unwrap();
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let forged = impostor.sign_indexed(msg, 1, IndexMode::Both).unwrap();
        let th = SigningThreshold::Simple(2);
        assert!(matches!(
            Authority::new(&keys, &th).verify(msg, &[valid, forged]),
            Err(Rejection::MissingSignatures { verified: 1 })
        ));
    }

    #[test]
    fn duplicate_signature_counts_once() {
        let msg = b"event bytes";
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let other = KeyPair::<Ed25519>::generate().unwrap();
        let keys = [
            VerifyingKey::from_matter(kp.verfer(VerKeyCode::Ed25519).unwrap().into_static()),
            VerifyingKey::from_matter(other.verfer(VerKeyCode::Ed25519).unwrap().into_static()),
        ];
        // Ed25519 is deterministic: the same key over the same bytes at the
        // same index reproduces the identical signature.
        let first = kp.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let again = kp.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let th = SigningThreshold::Simple(2);
        assert!(matches!(
            Authority::new(&keys, &th).verify(msg, &[first, again]),
            Err(Rejection::MissingSignatures { verified: 1 })
        ));
    }

    #[test]
    fn opened_by_ignores_filtered_signatures() {
        let msg = b"rotation bytes";
        let rk = KeyPair::<Ed25519>::generate().unwrap();
        let revealed_key =
            VerifyingKey::from_matter(rk.verfer(VerKeyCode::Ed25519).unwrap().into_static());
        let committed =
            Digest::from_matter(digest(DigestCode::Blake3_256, &revealed_key.to_qb64b()).unwrap());
        let next_digests = [committed];
        let next_th = SigningThreshold::Simple(1);
        let commitment = Commitment::new(&next_digests, &next_th);
        let keys = [revealed_key];
        let th = SigningThreshold::Simple(1);
        let revealed = Authority::new(&keys, &th);
        // One valid exposing sig (index 0, ondex 0) plus a forged sig also
        // carrying ondex 0: the forged sig is filtered at verify, so only the
        // valid sig's ondex can count toward exposure.
        let exposing = rk.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let forged = impostor.sign_indexed(msg, 0, IndexMode::Both).unwrap();
        let sigs = [exposing, forged];
        let verified = revealed.verify(msg, &sigs).unwrap();
        assert_eq!(verified.sigs().len(), 1);
        assert!(commitment.opened_by(&revealed, &verified).is_ok());
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
