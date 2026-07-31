//! Out-of-band receipt validation as pure judgments (K5, #91).
//!
//! K1 verifies *inline* receipts during the fold
//! ([`Witnessing::receipted_by`]). This module judges receipts arriving
//! *after* acceptance — as their own `rct` messages (#82's
//! `ReceiptMessage`) — one at a time, against the host-asserted accepted
//! event ([`ReceiptedEvent`]). Accumulation is host stream state: the core
//! keeps no counters and no tables; the host collects distinct witness
//! receipts and asks for the TOAD verdict via [`Witnessing::accounted_by`].
//!
//! keripy conformance oracle (main `9161a705`): `Kevery.processReceipt`
//! (`src/keri/core/eventing.py:4481`). The three receipt shapes:
//!
//! - **Couples** (eventing.py:4534-4559): a non-transferable endorser's
//!   prefix IS the verification key, so signature checking itself is plain
//!   [`cesr::crypto::verify`] over the receipted event's bytes — no
//!   wrapper. If the endorser prefix is in the governing witness set, the
//!   couple promotes to an indexed witness receipt at that position
//!   ([`Witnessing::witness_index`], eventing.py:4553-4557); otherwise it
//!   is a non-witness endorsement (a watcher etc.) and trust is host
//!   policy.
//! - **Wigs** (eventing.py:4562-4587): an indexed witness receipt,
//!   verified over the event's bytes against the witness its index selects
//!   ([`Witnessing::receipt`]). Where the inline fold *skips* a bad wig in
//!   a batch, single-receipt judgment reports the failure — the host asked
//!   about THIS receipt.
//! - **Transferable groups** (eventing.py:4589-4652): the endorser's
//!   establishment event at the claimed sn is host-supplied evidence
//!   ([`ReceiptorEstablishment`]); its SAID must match the endorsement's
//!   coordinate, its keys verify the endorsement's signatures, and a
//!   signature index beyond the key count is an error, never a skip
//!   (eventing.py:4638-4640). keripy applies no threshold.
//!
//! Every judgment is sans-io: cross-KEL facts arrive as typed arguments
//! (the K4 [`DelegationEvidence`](crate::DelegationEvidence) precedent),
//! and failures classify via [`ReceiptError::disposition`].

use alloc::vec::Vec;

use cesr::core::primitives::{Number, Siger};
use cesr::crypto::{IndexedVerifyError, verify, verify_indexed};
use keri_events::{BasicPrefix, Identifier, Receipt, Said, VerifyingKey};

use crate::authority::Witnessing;
use crate::error::{Disposition, EvidenceKind};

/// The accepted event a receipt is judged against.
///
/// Host-constructed from the host's own stream state: that this event was
/// ACCEPTED at `(prefix, sn)` is host-asserted, and `signed_bytes` are the
/// exact serialized bytes every receipt signature signs (the same
/// provenance contract as [`Signed::signed_bytes`](crate::Signed)).
#[derive(Debug, Clone, Copy)]
pub struct ReceiptedEvent<'e> {
    /// Identifier prefix of the KEL holding the accepted event.
    pub prefix: &'e Identifier<'e>,
    /// Sequence number of the accepted event.
    pub sn: Number,
    /// SAID of the accepted event.
    pub said: &'e Said<'e>,
    /// The exact serialized bytes of the accepted event — what every
    /// receipt signature signs.
    pub signed_bytes: &'e [u8],
}

/// A transferable endorsement of a receipted event (keripy's `-F` group).
///
/// The parsed, borrowed view of one transferable receipt group: the
/// endorser's identifier, the claimed establishment coordinate `(sn, said)`
/// whose keys signed, and the indexed signatures over the receipted
/// event's bytes, indexed into that establishment event's key list.
#[derive(Debug, Clone, Copy)]
pub struct TransferableEndorsement<'e> {
    /// The endorser's identifier.
    pub receiptor: &'e Identifier<'e>,
    /// Sequence number of the endorser's establishment event.
    pub sn: Number,
    /// SAID of the endorser's establishment event.
    pub said: &'e Said<'e>,
    /// Indexed signatures over the receipted event's bytes, indexed into
    /// that establishment event's key list.
    pub sigs: &'e [Siger<'e>],
}

/// The receiptor's establishment event, as host-supplied evidence.
///
/// That the named event is ACCEPTED in the receiptor's KEL at the
/// endorsement's claimed sn is host-asserted — the same trust contract as
/// [`Signed::signed_bytes`](crate::Signed). The judgment checks the SAID
/// binding and verifies the endorsement's signatures against `keys`; it
/// never looks anything up.
#[derive(Debug, Clone, Copy)]
pub struct ReceiptorEstablishment<'e> {
    /// SAID of the receiptor's establishment event at the endorsement's
    /// claimed sn.
    pub said: &'e Said<'e>,
    /// That establishment event's signing keys.
    pub keys: &'e [VerifyingKey<'e>],
}

/// A position in a governing witness set, minted by the receipt judgments.
///
/// This is a *membership* witness, not a cryptographic proof:
/// [`Witnessing::witness_index`] mints one from set membership alone (the
/// couple's signature check is the separate [`cesr::crypto::verify`] call),
/// and [`Witnessing::accounted_by`] re-checks range defensively because a
/// minted value binds to *a* witness set, not necessarily the one being
/// judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WitnessIndex(u32);

impl WitnessIndex {
    /// The position in the witness set.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl ReceiptedEvent<'_> {
    /// The stale check: `receipt` must name exactly this event's
    /// `(prefix, sn, said)` coordinate.
    ///
    /// keripy `processReceipt` accepts a receipt only for the last-seen
    /// event at `(pre, sn)` — the body `d` must equal that event's SAID,
    /// else the receipt is dropped with a bare `ValidationError`
    /// (eventing.py:4526-4530). A receipt for an sn with no accepted event
    /// is keripy's unverified-receipt escrow (eventing.py:4705-4718); in
    /// the pure model the host simply has no accepted event to judge
    /// against, so no judgment is possible until one exists.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::Stale`] if any coordinate component differs.
    pub fn named_by(&self, receipt: &Receipt<'_>) -> Result<(), ReceiptError> {
        if receipt.prefix() != self.prefix
            || receipt.sn().value() != self.sn.value()
            || receipt.said() != self.said
        {
            return Err(ReceiptError::Stale {
                named_sn: receipt.sn().value(),
                accepted_sn: self.sn.value(),
            });
        }
        Ok(())
    }

    /// The transferable judgment: `endorsement` vouches for this event,
    /// its signatures verified against the receiptor's establishment keys.
    ///
    /// keripy `processReceipt`'s transferable-group arm
    /// (eventing.py:4589-4652), in keripy's order:
    ///
    /// 1. Missing establishment evidence →
    ///    [`ReceiptError::EvidenceRequired`] (keripy's escrow,
    ///    `UnverifiedTransferableReceiptError`, eventing.py:4604-4610).
    /// 2. The evidence's SAID differs from the endorsement's claimed
    ///    coordinate → [`ReceiptError::EstablishmentMismatch`]
    ///    (eventing.py:4613-4616).
    /// 3. The establishment event carries no keys →
    ///    [`ReceiptError::NoAuthorityKeys`] (eventing.py:4620-4624).
    /// 4. Any signature index beyond the key count →
    ///    [`ReceiptError::EndorsementIndexOutOfRange`]
    ///    (eventing.py:4638-4640 — an ERROR here, unlike wig skipping).
    /// 5. Every signature verifies over the receipted event's bytes against
    ///    the key its index selects; only verifying sigs count, and keripy
    ///    applies no threshold, so zero verifying sigs →
    ///    [`ReceiptError::NoVerifiedSignatures`], one or more → `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns the first [`ReceiptError`] rule violated, in the order above.
    pub fn endorsed_by(
        &self,
        endorsement: &TransferableEndorsement<'_>,
        receiptor: Option<&ReceiptorEstablishment<'_>>,
    ) -> Result<(), ReceiptError> {
        let establishment = receiptor.ok_or(ReceiptError::EvidenceRequired)?;
        if establishment.said != endorsement.said {
            return Err(ReceiptError::EstablishmentMismatch);
        }
        if establishment.keys.is_empty() {
            return Err(ReceiptError::NoAuthorityKeys);
        }
        for sig in endorsement.sigs {
            let index = sig.index();
            if !usize::try_from(index).is_ok_and(|i| i < establishment.keys.len()) {
                return Err(ReceiptError::EndorsementIndexOutOfRange {
                    index,
                    count: establishment.keys.len(),
                });
            }
        }
        // verify_indexed (cesr::crypto) takes a raw Verfer slice; the role
        // newtype only exists in keri-events, so each key's exact Matter is
        // unwrapped here, at the crypto boundary, via `as_matter()` — the
        // `Authority::verify` / `Witnessing::receipted_by` pattern.
        let keys = establishment
            .keys
            .iter()
            .map(|k| k.as_matter().clone())
            .collect::<Vec<_>>();
        let verified = verify_indexed(&keys, self.signed_bytes, endorsement.sigs)
            .filter_map(Result::ok)
            .count();
        if verified == 0 {
            return Err(ReceiptError::NoVerifiedSignatures);
        }
        Ok(())
    }
}

impl Witnessing<'_> {
    /// Judge ONE late witness receipt: `wig` verifies over `bytes` against
    /// the witness its index selects in the governing set, and the index is
    /// returned as a [`WitnessIndex`] for the host to accumulate.
    ///
    /// keripy's wig arm (eventing.py:4562-4587). Where the inline fold
    /// *skips* a bad wig inside a batch
    /// ([`receipted_by`](Self::receipted_by)), single-receipt judgment
    /// reports the failure — an out-of-range index or a failed
    /// verification is a verdict on THIS receipt, not a skip.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::Signature`] if the wig's index addresses no
    /// witness or the signature does not verify.
    pub fn receipt(&self, bytes: &[u8], wig: &Siger<'_>) -> Result<WitnessIndex, ReceiptError> {
        let index = wig.index();
        let witness = usize::try_from(index)
            .ok()
            .and_then(|i| self.witnesses().get(i))
            .ok_or_else(|| IndexedVerifyError::IndexOutOfRange {
                index,
                key_count: self.witnesses().len(),
            })?;
        // The prefix IS the verification key; unwrap the role newtype at
        // the crypto boundary via `as_matter()` (the `receipted_by`
        // pattern) and verify the single sig directly.
        verify(witness.as_matter(), bytes, wig).map_err(IndexedVerifyError::from)?;
        Ok(WitnessIndex(index))
    }

    /// The couple-promotion lookup: the position of `prefix` in the
    /// governing witness set, if it is a witness (eventing.py:4553-4557).
    ///
    /// The full couple recipe is two calls: first verify the endorsement
    /// signature over the receipted event's bytes with the couple's prefix
    /// as the key — plain [`cesr::crypto::verify`], no wrapper needed (the
    /// prefix IS the key, eventing.py:4541-4551) — then promote a
    /// verifying couple into the witness set with this lookup. `None` is
    /// the non-witness endorser case (a watcher etc.): the endorsement
    /// verified but binds to no witness position; whether it counts toward
    /// anything is host policy, not this judgment's.
    #[must_use]
    pub fn witness_index(&self, prefix: &BasicPrefix<'_>) -> Option<WitnessIndex> {
        self.witnesses()
            .iter()
            .position(|w| w == prefix)
            .and_then(|position| u32::try_from(position).ok())
            .map(WitnessIndex)
    }

    /// TOAD accounting over the host-accumulated set: at least TOAD
    /// *distinct* in-range witness positions are present.
    ///
    /// The set is host state — the host collects one [`WitnessIndex`] per
    /// accepted receipt (wig or promoted couple) and asks for the verdict
    /// here. Duplicates count once (sort + dedup, matching
    /// [`receipted_by`](Self::receipted_by)'s distinct-index semantics);
    /// positions beyond the witness count are dropped defensively — this
    /// module validates at its own boundary, because a [`WitnessIndex`]
    /// binds to *a* witness set, not necessarily this one. keripy checks
    /// `len(windices) < toader.num` (eventing.py:2907) and escrows
    /// partially-witnessed events (`escrowPWEvent` +
    /// `MissingWitnessSignatureError`, eventing.py:2908-2918); here the
    /// shortfall is [`ReceiptError::InsufficientReceipts`], whose
    /// disposition carries the same awaiting-evidence classification. A
    /// TOAD of zero is vacuously satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::InsufficientReceipts`] if fewer than TOAD
    /// distinct in-range positions are present.
    pub fn accounted_by<I>(&self, indices: I) -> Result<(), ReceiptError>
    where
        I: IntoIterator<Item = WitnessIndex>,
    {
        let required = self.toad().value();
        if required == 0 {
            return Ok(());
        }
        let mut positions: Vec<u32> = indices
            .into_iter()
            .map(WitnessIndex::value)
            .filter(|position| usize::try_from(*position).is_ok_and(|i| i < self.witnesses().len()))
            .collect();
        positions.sort_unstable();
        positions.dedup();
        let valid = positions.len();
        if usize::try_from(required).is_ok_and(|r| valid >= r) {
            Ok(())
        } else {
            Err(ReceiptError::InsufficientReceipts { valid, required })
        }
    }
}

/// Why a receipt judgment failed (K5).
///
/// The receipt domain's single verdict type — receipts are judged outside
/// the fold, so [`Rejection`](crate::Rejection) is not extended.
/// [`disposition`](Self::disposition) classifies every variant as
/// [`Terminal`](Disposition::Terminal) or
/// [`Awaiting`](Disposition::Awaiting) specific evidence — the K2 escrow
/// classification, applied to receipts. `#[non_exhaustive]` keeps
/// additions non-breaking for external matchers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The receipt names a different event than the accepted one it is
    /// judged against.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops a
    /// receipt whose body `d` is not the last-seen event's SAID at
    /// `(pre, sn)` with a bare `ValidationError` (eventing.py:4526-4530).
    #[error("receipt names sn {named_sn} but the accepted event is at sn {accepted_sn}")]
    Stale {
        /// Sequence number the receipt names.
        named_sn: u128,
        /// Sequence number of the accepted event.
        accepted_sn: u128,
    },

    /// The receipt's signature failed — either its index addresses no
    /// witness/key or the cryptographic check failed.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — the batch skip of
    /// the inline fold becomes a verdict when the host asks about THIS
    /// receipt; a bad wig is a keripy drop.
    #[error(transparent)]
    Signature(#[from] IndexedVerifyError),

    /// A transferable endorsement arrived without the receiptor's
    /// establishment event.
    ///
    /// Disposition:
    /// [`Awaiting(ReceiptorEstablishment)`](EvidenceKind::ReceiptorEstablishment)
    /// — keripy's unverified transferable-receipt escrow
    /// (`escrowTReceipts` + `UnverifiedTransferableReceiptError`,
    /// eventing.py:4604-4610). Re-drive
    /// [`ReceiptedEvent::endorsed_by`] with the evidence once the host's
    /// stream/query produces it.
    #[error("transferable endorsement requires the receiptor's establishment event")]
    EvidenceRequired,

    /// The receiptor's establishment event SAID differs from the
    /// endorsement's claimed coordinate.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops with
    /// a bare `ValidationError` (eventing.py:4613-4616).
    #[error("receiptor establishment SAID does not match the endorsement's coordinate")]
    EstablishmentMismatch,

    /// The receiptor's establishment event carries no signing keys.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops with
    /// a bare `ValidationError` (eventing.py:4620-4624).
    #[error("receiptor establishment event carries no signing keys")]
    NoAuthorityKeys,

    /// An endorsement signature's index addresses no key in the
    /// receiptor's establishment event.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops with
    /// a bare `ValidationError` (eventing.py:4638-4640); unlike wig
    /// handling, an out-of-range index here is an error, not a skip.
    #[error("endorsement signature index {index} out of range for {count} keys")]
    EndorsementIndexOutOfRange {
        /// The out-of-range index carried by the signature.
        index: u32,
        /// The number of keys available to address.
        count: usize,
    },

    /// No endorsement signature verified against the receiptor's
    /// establishment keys.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy stores
    /// only verifying sigs (eventing.py:4641-4652), so a group with none is
    /// empty evidence; keripy applies no threshold, so one verifying sig
    /// would have sufficed.
    #[error("no endorsement signature verified")]
    NoVerifiedSignatures,

    /// Fewer distinct witnesses than the TOAD requires have a valid
    /// receipt over the event.
    ///
    /// Disposition:
    /// [`Awaiting(WitnessReceipts)`](EvidenceKind::WitnessReceipts) —
    /// keripy's partially-witnessed escrow (`.pwes`, `escrowPWEvent` +
    /// `MissingWitnessSignatureError`, eventing.py:2907-2918). Re-drive
    /// when further witness receipts arrive.
    #[error("witness receipts below threshold: {valid} valid of {required} required")]
    InsufficientReceipts {
        /// Distinct witnesses whose receipt verified.
        valid: usize,
        /// The governing threshold of accountable duplicity (TOAD).
        required: u32,
    },
}

impl ReceiptError {
    /// Classify this failure: [`Terminal`](Disposition::Terminal) or
    /// [`Awaiting`](Disposition::Awaiting) specific evidence.
    ///
    /// Total over every variant with no wildcard arm (the K2
    /// [`Rejection::disposition`](crate::Rejection::disposition) pattern),
    /// so a new variant forces a decision here at compile time. The rule:
    /// **awaiting** iff more host-supplied evidence (the receiptor's
    /// establishment event, further witness receipts) can change the
    /// verdict on re-drive; **terminal** iff the verdict is a function of
    /// the receipt plus accepted state alone.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::Stale { .. }
            | Self::Signature(_)
            | Self::EstablishmentMismatch
            | Self::NoAuthorityKeys
            | Self::EndorsementIndexOutOfRange { .. }
            | Self::NoVerifiedSignatures => Disposition::Terminal,
            Self::EvidenceRequired => Disposition::Awaiting(EvidenceKind::ReceiptorEstablishment),
            Self::InsufficientReceipts { valid, required } => {
                Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                    valid: *valid,
                    required: *required,
                })
            }
        }
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
    use keri_events::Toad;

    /// `n` witness keypairs and their prefixes.
    fn witnesses(n: u32) -> (Vec<KeyPair<Ed25519>>, Vec<BasicPrefix<'static>>) {
        (0..n)
            .map(|_| {
                let kp = KeyPair::<Ed25519>::generate().unwrap();
                let prefix =
                    BasicPrefix::from_matter(kp.verfer(VerKeyCode::Ed25519).unwrap().into_static());
                (kp, prefix)
            })
            .unzip()
    }

    fn said_of(bytes: &[u8]) -> Said<'static> {
        Said::from_matter(digest(DigestCode::Blake3_256, bytes).unwrap())
    }

    /// A fixed accepted event the fixtures judge receipts against.
    fn event<'e>(
        prefix: &'e Identifier<'e>,
        said: &'e Said<'e>,
        bytes: &'e [u8],
    ) -> ReceiptedEvent<'e> {
        ReceiptedEvent {
            prefix,
            sn: Number::new(3),
            said,
            signed_bytes: bytes,
        }
    }

    #[test]
    fn named_by_accepts_the_matching_coordinate() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let receipt = Receipt::new(prefix.clone(), Number::new(3), said.clone());
        assert!(event.named_by(&receipt).is_ok());
    }

    #[test]
    fn named_by_rejects_a_stale_said() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let stale = Receipt::new(prefix.clone(), Number::new(3), said_of(b"other event"));
        assert!(matches!(
            event.named_by(&stale),
            Err(ReceiptError::Stale {
                named_sn: 3,
                accepted_sn: 3
            })
        ));
    }

    #[test]
    fn named_by_rejects_a_stale_sn() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let stale = Receipt::new(prefix.clone(), Number::new(4), said.clone());
        assert!(matches!(
            event.named_by(&stale),
            Err(ReceiptError::Stale {
                named_sn: 4,
                accepted_sn: 3
            })
        ));
    }

    #[test]
    fn named_by_rejects_a_stale_prefix() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let stale = Receipt::new(
            Identifier::SelfAddressing(said_of(b"other pre")),
            Number::new(3),
            said.clone(),
        );
        assert!(matches!(
            event.named_by(&stale),
            Err(ReceiptError::Stale {
                named_sn: 3,
                accepted_sn: 3
            })
        ));
    }

    #[test]
    fn wig_at_each_index_verifies_and_accounts() {
        let bytes = b"event bytes";
        let (keypairs, prefixes) = witnesses(3);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(3));
        let indices: Vec<WitnessIndex> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| {
                let index = u32::try_from(i).unwrap();
                let wig = kp
                    .sign_indexed(bytes, index, IndexMode::CurrentOnly)
                    .unwrap();
                witnessing.receipt(bytes, &wig).unwrap()
            })
            .collect();
        assert_eq!(
            indices.iter().map(|i| i.value()).collect::<Vec<_>>(),
            alloc::vec![0, 1, 2]
        );
        assert!(witnessing.accounted_by(indices).is_ok());
    }

    #[test]
    fn wig_index_out_of_range_is_a_signature_error() {
        let bytes = b"event bytes";
        let (keypairs, prefixes) = witnesses(3);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(1));
        let wig = keypairs[0]
            .sign_indexed(bytes, 5, IndexMode::CurrentOnly)
            .unwrap();
        assert!(matches!(
            witnessing.receipt(bytes, &wig),
            Err(ReceiptError::Signature(
                IndexedVerifyError::IndexOutOfRange {
                    index: 5,
                    key_count: 3
                }
            ))
        ));
    }

    #[test]
    fn forged_wig_is_a_signature_error() {
        let bytes = b"event bytes";
        let (_, prefixes) = witnesses(3);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(1));
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let forged = impostor
            .sign_indexed(bytes, 0, IndexMode::CurrentOnly)
            .unwrap();
        assert!(matches!(
            witnessing.receipt(bytes, &forged),
            Err(ReceiptError::Signature(IndexedVerifyError::Verification(_)))
        ));
    }

    #[test]
    fn couple_promotion_finds_the_witness_index() {
        let (_, prefixes) = witnesses(3);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(1));
        assert_eq!(
            witnessing
                .witness_index(&prefixes[1])
                .map(WitnessIndex::value),
            Some(1)
        );
    }

    #[test]
    fn witness_index_outside_the_set_is_none() {
        let (_, prefixes) = witnesses(3);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(1));
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let outsider =
            BasicPrefix::from_matter(impostor.verfer(VerKeyCode::Ed25519).unwrap().into_static());
        assert_eq!(witnessing.witness_index(&outsider), None);
    }

    #[test]
    fn duplicate_indices_account_once() {
        let (_, prefixes) = witnesses(3);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(2));
        let index = witnessing.witness_index(&prefixes[0]).unwrap();
        assert!(matches!(
            witnessing.accounted_by([index, index]),
            Err(ReceiptError::InsufficientReceipts {
                valid: 1,
                required: 2
            })
        ));
    }

    #[test]
    fn out_of_range_indices_are_dropped() {
        let (_, prefixes) = witnesses(2);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(1));
        let index = witnessing.witness_index(&prefixes[0]).unwrap();
        // A WitnessIndex minted against a LARGER witness set binds to that
        // set, not this one — the out-of-range position is dropped, and
        // the in-range one still satisfies the toad.
        assert!(witnessing.accounted_by([index, WitnessIndex(9)]).is_ok());
    }

    #[test]
    fn toad_zero_is_vacuously_satisfied() {
        let (_, prefixes) = witnesses(2);
        let witnessing = Witnessing::new(&prefixes, Toad::from_wire(0));
        assert!(witnessing.accounted_by([]).is_ok());
    }

    /// A transferable endorser: one keypair, its verifying key, the claimed
    /// establishment SAID, and its indexed signature over `bytes`.
    struct Endorser {
        keypair: KeyPair<Ed25519>,
        key: VerifyingKey<'static>,
        establishment_said: Said<'static>,
        sig: Siger<'static>,
    }

    fn endorser(bytes: &[u8]) -> Endorser {
        let keypair = KeyPair::<Ed25519>::generate().unwrap();
        let key =
            VerifyingKey::from_matter(keypair.verfer(VerKeyCode::Ed25519).unwrap().into_static());
        let establishment_said = said_of(b"endorser establishment");
        let sig = keypair.sign_indexed(bytes, 0, IndexMode::Both).unwrap();
        Endorser {
            keypair,
            key,
            establishment_said,
            sig,
        }
    }

    #[test]
    fn transferable_endorsement_verifies_with_matching_evidence() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let endorser = endorser(bytes);
        let receiptor = Identifier::SelfAddressing(said_of(b"endorser pre"));
        let sigs = [endorser.sig];
        let endorsement = TransferableEndorsement {
            receiptor: &receiptor,
            sn: Number::new(0),
            said: &endorser.establishment_said,
            sigs: &sigs,
        };
        let evidence = ReceiptorEstablishment {
            said: &endorser.establishment_said,
            keys: core::slice::from_ref(&endorser.key),
        };
        assert!(event.endorsed_by(&endorsement, Some(&evidence)).is_ok());
    }

    #[test]
    fn transferable_endorsement_without_evidence_awaits_it() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let endorser = endorser(bytes);
        let receiptor = Identifier::SelfAddressing(said_of(b"endorser pre"));
        let sigs = [endorser.sig];
        let endorsement = TransferableEndorsement {
            receiptor: &receiptor,
            sn: Number::new(0),
            said: &endorser.establishment_said,
            sigs: &sigs,
        };
        assert!(matches!(
            event.endorsed_by(&endorsement, None),
            Err(ReceiptError::EvidenceRequired)
        ));
    }

    #[test]
    fn establishment_said_mismatch_is_terminal() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let endorser = endorser(bytes);
        let receiptor = Identifier::SelfAddressing(said_of(b"endorser pre"));
        let sigs = [endorser.sig];
        let endorsement = TransferableEndorsement {
            receiptor: &receiptor,
            sn: Number::new(0),
            said: &endorser.establishment_said,
            sigs: &sigs,
        };
        let wrong = ReceiptorEstablishment {
            said: &said,
            keys: core::slice::from_ref(&endorser.key),
        };
        assert!(matches!(
            event.endorsed_by(&endorsement, Some(&wrong)),
            Err(ReceiptError::EstablishmentMismatch)
        ));
    }

    #[test]
    fn empty_establishment_keys_are_terminal() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let endorser = endorser(bytes);
        let receiptor = Identifier::SelfAddressing(said_of(b"endorser pre"));
        let sigs = [endorser.sig];
        let endorsement = TransferableEndorsement {
            receiptor: &receiptor,
            sn: Number::new(0),
            said: &endorser.establishment_said,
            sigs: &sigs,
        };
        let evidence = ReceiptorEstablishment {
            said: &endorser.establishment_said,
            keys: &[],
        };
        assert!(matches!(
            event.endorsed_by(&endorsement, Some(&evidence)),
            Err(ReceiptError::NoAuthorityKeys)
        ));
    }

    #[test]
    fn endorsement_index_out_of_range_is_terminal() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let endorser = endorser(bytes);
        let receiptor = Identifier::SelfAddressing(said_of(b"endorser pre"));
        let out_of_range = endorser
            .keypair
            .sign_indexed(bytes, 1, IndexMode::Both)
            .unwrap();
        let sigs = [out_of_range];
        let endorsement = TransferableEndorsement {
            receiptor: &receiptor,
            sn: Number::new(0),
            said: &endorser.establishment_said,
            sigs: &sigs,
        };
        let evidence = ReceiptorEstablishment {
            said: &endorser.establishment_said,
            keys: core::slice::from_ref(&endorser.key),
        };
        assert!(matches!(
            event.endorsed_by(&endorsement, Some(&evidence)),
            Err(ReceiptError::EndorsementIndexOutOfRange { index: 1, count: 1 })
        ));
    }

    #[test]
    fn forged_transferable_sigs_are_no_verified_signatures() {
        let prefix = Identifier::SelfAddressing(said_of(b"pre"));
        let said = said_of(b"event");
        let bytes = b"event bytes";
        let event = event(&prefix, &said, bytes);
        let endorser = endorser(bytes);
        let receiptor = Identifier::SelfAddressing(said_of(b"endorser pre"));
        // A signature from an unrelated key presented at index 0: it does
        // not verify against the endorser's key, so zero sigs count.
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let forged = impostor.sign_indexed(bytes, 0, IndexMode::Both).unwrap();
        let sigs = [forged];
        let endorsement = TransferableEndorsement {
            receiptor: &receiptor,
            sn: Number::new(0),
            said: &endorser.establishment_said,
            sigs: &sigs,
        };
        let evidence = ReceiptorEstablishment {
            said: &endorser.establishment_said,
            keys: core::slice::from_ref(&endorser.key),
        };
        assert!(matches!(
            event.endorsed_by(&endorsement, Some(&evidence)),
            Err(ReceiptError::NoVerifiedSignatures)
        ));
    }

    #[test]
    fn disposition_of_every_variant() {
        assert_eq!(
            ReceiptError::Stale {
                named_sn: 4,
                accepted_sn: 3
            }
            .disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            ReceiptError::from(IndexedVerifyError::IndexOutOfRange {
                index: 5,
                key_count: 3,
            })
            .disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            ReceiptError::EvidenceRequired.disposition(),
            Disposition::Awaiting(EvidenceKind::ReceiptorEstablishment)
        );
        assert_eq!(
            ReceiptError::EstablishmentMismatch.disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            ReceiptError::NoAuthorityKeys.disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            ReceiptError::EndorsementIndexOutOfRange { index: 1, count: 1 }.disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            ReceiptError::NoVerifiedSignatures.disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            ReceiptError::InsufficientReceipts {
                valid: 1,
                required: 2
            }
            .disposition(),
            Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                valid: 1,
                required: 2
            })
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "property fixtures construct known-good values with unwrap for clarity"
)]
mod properties {
    use super::*;
    use alloc::borrow::Cow;
    use alloc::vec;
    use alloc::vec::Vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::VerKeyCode;
    use keri_events::Toad;
    use proptest::prelude::*;

    /// `n` dummy witness prefixes — accounting judges positions, not
    /// crypto, so the raw bytes need only be distinct.
    fn dummy_witnesses(n: usize) -> Vec<BasicPrefix<'static>> {
        (0..n)
            .map(|i| {
                BasicPrefix::from_matter(
                    MatterBuilder::new()
                        .with_code(VerKeyCode::Ed25519)
                        .with_raw(Cow::<[u8]>::Owned(vec![u8::try_from(i).unwrap(); 32]))
                        .unwrap()
                        .build()
                        .unwrap(),
                )
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// TOAD accounting is exactly "distinct in-range count >= toad":
        /// toad drawn from the boundary set {0, 1, n, n+1} over witness
        /// counts 1..=8, with an arbitrary subset of valid indices and an
        /// optional out-of-range index that must not count (issue #91
        /// acceptance boundaries).
        #[test]
        fn toad_accounting_is_distinct_in_range_count(
            n in 1..=8usize,
            toad_pick in 0..4usize,
            mask in any::<u8>(),
            with_out_of_range in any::<bool>(),
        ) {
            let count32 = u32::try_from(n).unwrap();
            let toad = [0, 1, count32, count32 + 1][toad_pick];
            let prefixes = dummy_witnesses(n);
            let witnessing = Witnessing::new(&prefixes, Toad::from_wire(toad));
            let mut indices: Vec<WitnessIndex> = (0..n)
                .filter(|i| mask & (1u8 << i) != 0)
                .map(|i| WitnessIndex(u32::try_from(i).unwrap()))
                .collect();
            if with_out_of_range {
                indices.push(WitnessIndex(count32 + 5));
            }
            let distinct_in_range = (0..n).filter(|i| mask & (1u8 << i) != 0).count();
            let expected_ok = distinct_in_range >= usize::try_from(toad).unwrap();
            let result = witnessing.accounted_by(indices);
            if expected_ok {
                prop_assert!(result.is_ok());
            } else {
                match result {
                    Err(ReceiptError::InsufficientReceipts { valid, required }) => {
                        prop_assert_eq!(valid, distinct_in_range);
                        prop_assert_eq!(required, toad);
                    }
                    other => prop_assert!(false, "expected InsufficientReceipts, got {other:?}"),
                }
            }
        }
    }
}
