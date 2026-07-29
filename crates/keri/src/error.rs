//! Validation verdict types for the key-state fold.
use cesr::crypto::IndexedVerifyError;
use keri_events::SigningThresholdError;

/// Why an event was not accepted by the fold.
///
/// The fold's single verdict type. Variants that wrap a cesr or keri sub-error
/// carry it directly, so the precise cause survives (`?` lifts each source in via
/// [`From`]). [`disposition`](Self::disposition) classifies every variant as
/// [`Terminal`](Disposition::Terminal) or [`Awaiting`](Disposition::Awaiting)
/// specific evidence — the K2 escrow verdict.
/// `#[non_exhaustive]` keeps additions non-breaking for external matchers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// Sequence number is not the expected next sn.
    ///
    /// Disposition: gap (`actual > expected`) is
    /// [`Awaiting(PriorEvents)`](EvidenceKind::PriorEvents) — keripy's
    /// out-of-order escrow (`.ooes`, `OutOfOrderError`); re-drive when the
    /// missing prior events arrive. Stale (`actual < expected`) is
    /// [`Terminal`](Disposition::Terminal): the prior event already exists,
    /// keripy routes it to duplicity / superseding recovery — K3.
    #[error("out of order: expected sn {expected}, got {actual}")]
    OutOfOrder {
        /// The sn the fold expected next.
        expected: u128,
        /// The sn the event actually carried.
        actual: u128,
    },

    /// Prior-event digest does not match the current state's latest SAID.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal). Fires at the
    /// in-order sn, where keripy raises a bare `ValidationError` (drop).
    /// keripy's likely-duplicitous escrow (`.ldes`) concerns a *different*
    /// situation — a second event at an already-accepted sn — which is K3's
    /// duplicity verdict, not this rejection.
    #[error("prior-event digest does not match current state")]
    PriorDigestMismatch,

    /// The verified signatures do not satisfy the signing threshold.
    ///
    /// `verified` is the number of signatures that verified against a current
    /// key. Under [`Authority::verify`](crate::Authority::verify)'s
    /// abort-on-bad-signature semantics every *provided* signature verified
    /// when this fires, so `verified == 0` means the attached signature set
    /// was empty.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) when `verified == 0`
    /// (KERI spec: a message without at least one verifiable controller
    /// signature MUST be dropped, not escrowed — `DDoS` guard);
    /// [`Awaiting(Signatures)`](EvidenceKind::Signatures) when `verified >= 1`
    /// (spec SHOULD-escrow; keripy `.pses` via `escrowPSEvent` +
    /// `MissingSignatureError`). Re-drive trigger: more controller signatures
    /// for the same event version arrive.
    #[error("signing threshold not satisfied: {verified} verified signature(s)")]
    MissingSignatures {
        /// How many signatures verified against a current key.
        verified: usize,
    },

    /// A controller signature did not verify, or its index addressed no key.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — re-driving the
    /// same event re-checks the same signatures. Divergence (D1, see the K2
    /// design doc): keripy *filters* unverifiable signatures and judges the
    /// valid subset, so it never rejects solely for a bad attached signature;
    /// this fold aborts on the first one. Tracked with #132/#133; K9
    /// differential must account for it.
    #[error(transparent)]
    UnverifiedSignature(#[from] IndexedVerifyError),

    /// The event's signing threshold is not well-formed for its key set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy raises a
    /// bare `ValidationError` (drop) for an invalid sith.
    #[error(transparent)]
    MalformedThreshold(#[from] SigningThresholdError),

    /// A rotation's revealed keys do not match the prior next-key commitment.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — the event's own
    /// key list contradicts the commitment, so no evidence can cure it.
    /// Divergence (D2, see the K2 design doc): keripy has no positional
    /// check; its analog outcome is partially-signed escrow (`.pses`) under
    /// ondex semantics. Revisited by #132; K9 differential must account for
    /// it.
    #[error("revealed keys do not match prior next-key commitment")]
    NextKeyCommitmentMismatch,

    /// A rotation's witness cut/add deltas are inconsistent.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy's backer
    /// derivation raises a bare `ValidationError` (drop) for every cut/add
    /// algebra violation.
    #[error(transparent)]
    WitnessSet(#[from] WitnessSetError),

    /// The witness threshold (`TOAD`) is out of bounds for the witness set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops
    /// out-of-bounds toads with a bare `ValidationError`.
    #[error("witness threshold {toad} exceeds {count} witnesses")]
    WitnessThresholdExceeded {
        /// The declared threshold of accountable duplicity.
        toad: u32,
        /// The number of witnesses available.
        count: usize,
    },

    /// Fewer distinct witnesses than the `TOAD` requires have a valid receipt
    /// over the event.
    ///
    /// Disposition:
    /// [`Awaiting(WitnessReceipts)`](EvidenceKind::WitnessReceipts) —
    /// keripy's partially-witnessed escrow (`.pwes`, `escrowPWEvent` +
    /// `MissingWitnessSignatureError`). Re-drive when further witness
    /// receipts arrive.
    #[error("witness receipts below threshold: {valid} valid of {required} required")]
    InsufficientWitnessReceipts {
        /// Distinct witnesses whose receipt verified.
        valid: usize,
        /// The governing threshold of accountable duplicity (TOAD).
        required: u32,
    },

    /// The inception violates a transferability / next-key commitment rule.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — inception content
    /// is self-contradictory. keripy drops a non-transferable inception that
    /// commits next keys; the self-addressing-without-next-keys rule is
    /// deliberately stricter than keripy, which accepts such an inception as
    /// an abandoned identifier (divergence D3, see the K2 design doc).
    #[error(transparent)]
    Transferability(#[from] TransferabilityError),

    /// A delegated inception/rotation (`dip`/`drt`). Delegated-event folding —
    /// which requires verifying the delegator's authorizing seal — is deferred
    /// to K4 (delegation); K1 rejects these rather than accept them unverified.
    ///
    /// Disposition:
    /// [`Awaiting(DelegationEvidence)`](EvidenceKind::DelegationEvidence) —
    /// keripy's delegated escrows (`.pdes`/`.udes`). Re-drive once K4's
    /// verification path lands and the delegator's evidence is available.
    #[error("delegated events are not yet supported (K4)")]
    DelegationUnsupported,

    /// The event violates a structural rule (shape, arity, message type
    /// placement, ranges).
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — the KERI spec
    /// requires config-trait violations to be invalidated ("MUST … drop"),
    /// and the remaining shape/arity/range violations are functions of the
    /// event's own content.
    #[error(transparent)]
    Structural(#[from] StructuralError),
}

/// What a host should do with a rejected event.
///
/// Escrow as a pure classification: `keri-rs` owes only the verdict on the
/// fold's [`Rejection`] — parking, retry scheduling, timeouts, and storage
/// are entirely the host's (an event-sourced host records "awaiting X" as its
/// own state and re-drives the event when X arrives). Both enums here are
/// deliberately exhaustive: a new evidence kind (K4 delegation, K5 receipt
/// evidence) must be a compile error in hosts, not a silently-parked event
/// that never re-drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Never acceptable — drop or report. (Duplicity routing detail is K3.)
    Terminal,
    /// Acceptable the moment this evidence arrives — park and re-drive.
    Awaiting(EvidenceKind),
}

/// The specific evidence whose arrival makes a parked event acceptable.
///
/// Each variant names the keripy escrow whose *outcome* it reproduces
/// (semantics, not tables — see the K2 design doc for line-anchored
/// evidence). Receipt evidence for transferable receiptors is K5 and will be
/// added as a deliberate breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// The KEL events between the accepted head and `expected_sn`.
    /// keripy `.ooes` (out-of-order escrow). Re-drive when the prior
    /// event(s) arrive and fold in order.
    PriorEvents {
        /// The sequence number the fold expected next.
        expected_sn: u128,
    },
    /// More controller signatures for the same event version.
    /// keripy `.pses` (partially-signed escrow). Re-drive when new
    /// signatures arrive, attached to the event or to a receipt of it.
    Signatures,
    /// More witness receipts over the event. keripy `.pwes` (partially
    /// witnessed escrow). Re-drive when further receipts arrive.
    WitnessReceipts {
        /// Distinct witnesses whose receipt verified.
        valid: usize,
        /// The governing threshold of accountable duplicity (`TOAD`).
        required: u32,
    },
    /// The delegator's authorizing evidence for a delegated event.
    /// keripy `.pdes`/`.udes` (partially/unverified delegated escrow).
    /// K4 builds the verification path; re-drive when it lands and the
    /// delegator's seal is available.
    DelegationEvidence,
}

impl Rejection {
    /// Classify this rejection: [`Terminal`](Disposition::Terminal) or
    /// [`Awaiting`](Disposition::Awaiting) specific evidence.
    ///
    /// Total over every variant with no wildcard arm, so a new [`Rejection`]
    /// variant forces a decision here at compile time. The rule: **awaiting**
    /// iff more host-supplied evidence (prior events, signatures, receipts,
    /// delegator approval) can change the verdict on re-drive; **terminal**
    /// iff the verdict is a function of the event's own content plus accepted
    /// state alone, so re-driving the same event can never succeed.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::PriorDigestMismatch
            | Self::UnverifiedSignature(_)
            | Self::MalformedThreshold(_)
            | Self::NextKeyCommitmentMismatch
            | Self::WitnessSet(_)
            | Self::WitnessThresholdExceeded { .. }
            | Self::Transferability(_)
            | Self::Structural(_)
            | Self::MissingSignatures { verified: 0 } => Disposition::Terminal,
            Self::OutOfOrder { expected, actual } => {
                if *actual > *expected {
                    Disposition::Awaiting(EvidenceKind::PriorEvents {
                        expected_sn: *expected,
                    })
                } else {
                    // Stale: the "missing prior" already exists, so no
                    // evidence arrival can cure it. keripy routes sn <= sno
                    // to the duplicity / superseding-recovery path — K3.
                    Disposition::Terminal
                }
            }
            Self::MissingSignatures { .. } => {
                Disposition::Awaiting(EvidenceKind::Signatures)
            }
            Self::InsufficientWitnessReceipts { valid, required } => {
                Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                    valid: *valid,
                    required: *required,
                })
            }
            Self::DelegationUnsupported => {
                Disposition::Awaiting(EvidenceKind::DelegationEvidence)
            }
        }
    }
}

/// Witness cut/add algebra failures during a rotation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WitnessSetError {
    /// A witness removal names a prefix that is not a current witness.
    #[error("witness removal names a prefix that is not a current witness")]
    RemovalNotCurrent,
    /// A prefix appears in both the witness cut and add sets.
    #[error("a prefix appears in both the witness cut and add sets")]
    CutAddOverlap,
    /// A witness addition names a prefix already in the set.
    #[error("witness addition names a prefix already in the set")]
    AdditionAlreadyPresent,
}

/// Transferability / next-key commitment rule violations at inception.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransferabilityError {
    /// A non-transferable prefix must not commit to next keys.
    #[error("a non-transferable prefix must not commit to next keys")]
    NonTransferableCommitsNextKeys,
    /// A self-addressing prefix must commit to at least one next key.
    #[error("a self-addressing prefix must commit to at least one next key")]
    SelfAddressingWithoutNextKeys,
}

/// Structural rule violations — event shape, arity, and range guards.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StructuralError {
    /// `incept` was called on a non-inception event.
    #[error("incept called on a non-inception event")]
    NotInception,
    /// A genesis event carried a non-zero sequence number.
    #[error("genesis event has non-zero sequence number {sn}")]
    NonZeroGenesisSn {
        /// The offending sequence number.
        sn: u128,
    },
    /// A second inception event cannot advance an existing state.
    #[error("a second inception event cannot advance state")]
    DuplicateInception,
    /// An interaction event under the establishment-only config trait.
    #[error("an interaction is not allowed under the establishment-only config")]
    InteractionOnEstablishmentOnly,
    /// `prior_sn + 1` overflowed `u128`.
    #[error("sequence number overflowed")]
    SequenceNumberOverflow,
    /// A witness count exceeded the addressable range (defensive guard).
    #[error("witness count exceeds addressable range")]
    WitnessCountOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    use cesr::crypto::{SignatureError, VerificationError};

    #[test]
    fn out_of_order_carries_sn_context() {
        let r = Rejection::OutOfOrder {
            expected: 1,
            actual: 4,
        };
        assert!(matches!(
            r,
            Rejection::OutOfOrder {
                expected: 1,
                actual: 4
            }
        ));
    }

    #[test]
    fn index_out_of_range_maps_to_unverified_signature() {
        let r = Rejection::from(IndexedVerifyError::IndexOutOfRange {
            index: 5,
            key_count: 2,
        });
        assert!(matches!(
            r,
            Rejection::UnverifiedSignature(IndexedVerifyError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn verification_failure_maps_to_unverified_signature() {
        let r = Rejection::from(IndexedVerifyError::Verification(
            VerificationError::Signature(SignatureError::Invalid),
        ));
        assert!(matches!(
            r,
            Rejection::UnverifiedSignature(IndexedVerifyError::Verification(_))
        ));
    }

    #[test]
    fn threshold_error_maps_to_malformed_threshold() {
        let r = Rejection::from(SigningThresholdError::BelowMinimum);
        assert!(matches!(
            r,
            Rejection::MalformedThreshold(SigningThresholdError::BelowMinimum)
        ));
    }

    #[test]
    fn witness_set_error_maps_to_witness_set() {
        let r = Rejection::from(WitnessSetError::RemovalNotCurrent);
        assert!(matches!(
            r,
            Rejection::WitnessSet(WitnessSetError::RemovalNotCurrent)
        ));
    }

    #[test]
    fn transferability_error_maps_to_transferability() {
        let r = Rejection::from(TransferabilityError::SelfAddressingWithoutNextKeys);
        assert!(matches!(
            r,
            Rejection::Transferability(TransferabilityError::SelfAddressingWithoutNextKeys)
        ));
    }

    #[test]
    fn structural_error_maps_to_structural() {
        let r = Rejection::from(StructuralError::DuplicateInception);
        assert!(matches!(
            r,
            Rejection::Structural(StructuralError::DuplicateInception)
        ));
    }

    #[test]
    fn out_of_order_gap_awaits_prior_events() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 7,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 3 })
        );
    }

    #[test]
    fn out_of_order_stale_is_terminal() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 2,
        };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn out_of_order_stale_at_u128_boundary_is_terminal() {
        let r = Rejection::OutOfOrder {
            expected: u128::MAX,
            actual: 0,
        };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn out_of_order_minimal_gap_awaits_prior_events() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 4,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 3 })
        );
    }

    #[test]
    fn zero_verified_signatures_is_terminal() {
        let r = Rejection::MissingSignatures { verified: 0 };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn one_verified_signature_below_threshold_awaits_signatures() {
        let r = Rejection::MissingSignatures { verified: 1 };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::Signatures)
        );
    }

    #[test]
    fn insufficient_witness_receipts_awaits_receipts() {
        let r = Rejection::InsufficientWitnessReceipts {
            valid: 1,
            required: 3,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                valid: 1,
                required: 3
            })
        );
    }

    #[test]
    fn delegation_unsupported_awaits_delegation_evidence() {
        let r = Rejection::DelegationUnsupported;
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn prior_digest_mismatch_is_terminal() {
        assert_eq!(Rejection::PriorDigestMismatch.disposition(), Disposition::Terminal);
    }

    #[test]
    fn unverified_signature_is_terminal() {
        let r = Rejection::from(IndexedVerifyError::IndexOutOfRange {
            index: 5,
            key_count: 2,
        });
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn malformed_threshold_is_terminal() {
        let r = Rejection::from(SigningThresholdError::BelowMinimum);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn next_key_commitment_mismatch_is_terminal() {
        assert_eq!(
            Rejection::NextKeyCommitmentMismatch.disposition(),
            Disposition::Terminal
        );
    }

    #[test]
    fn witness_set_error_is_terminal() {
        let r = Rejection::from(WitnessSetError::RemovalNotCurrent);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn witness_threshold_exceeded_is_terminal() {
        let r = Rejection::WitnessThresholdExceeded { toad: 3, count: 2 };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn transferability_error_is_terminal() {
        let r = Rejection::from(TransferabilityError::NonTransferableCommitsNextKeys);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn structural_error_is_terminal() {
        let r = Rejection::from(StructuralError::DuplicateInception);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }
}
