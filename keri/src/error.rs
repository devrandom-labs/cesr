//! Validation verdict types for the key-state fold.
use cesr::core::primitives::ThresholdError;
use cesr::crypto::IndexedVerifyError;

/// Why an event was not accepted by the fold.
///
/// The fold's single verdict type. Variants that wrap a cesr or keri sub-error
/// carry it directly, so the precise cause survives (`?` lifts each source in via
/// [`From`]). **Taxonomy still evolving — K2 expands escrow routing.**
/// `#[non_exhaustive]` keeps additions non-breaking for external matchers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// Sequence number is ahead of the expected next sn (a gap). K2 → out-of-order escrow.
    #[error("out of order: expected sn {expected}, got {actual}")]
    OutOfOrder {
        /// The sn the fold expected next.
        expected: u128,
        /// The sn the event actually carried.
        actual: u128,
    },

    /// Prior-event digest does not match the current state's latest SAID. K3 → duplicity.
    #[error("prior-event digest does not match current state")]
    PriorDigestMismatch,

    /// The provided signatures do not satisfy the signing threshold. K2 → partially-signed escrow.
    #[error("signing threshold not satisfied")]
    MissingSignatures,

    /// A controller signature did not verify, or its index addressed no key.
    #[error(transparent)]
    UnverifiedSignature(#[from] IndexedVerifyError),

    /// The event's signing threshold is not well-formed for its key set.
    #[error(transparent)]
    MalformedThreshold(#[from] ThresholdError),

    /// A rotation's revealed keys do not match the prior next-key commitment.
    #[error("revealed keys do not match prior next-key commitment")]
    NextKeyCommitmentMismatch,

    /// A rotation's witness cut/add deltas are inconsistent.
    #[error(transparent)]
    WitnessSet(#[from] WitnessSetError),

    /// The witness threshold (TOAD) exceeds the number of witnesses.
    #[error("witness threshold {toad} exceeds {count} witnesses")]
    WitnessThresholdExceeded {
        /// The declared threshold of accountable duplicity.
        toad: u32,
        /// The number of witnesses available.
        count: usize,
    },

    /// The inception violates a transferability / next-key commitment rule.
    #[error(transparent)]
    Transferability(#[from] TransferabilityError),

    /// A delegated inception/rotation (`dip`/`drt`). Delegated-event folding —
    /// which requires verifying the delegator's authorizing seal — is deferred to
    /// K4 (delegation); K1 rejects these rather than accept them unverified.
    #[error("delegated events are not yet supported (K4)")]
    DelegationUnsupported,

    /// The event violates a structural rule (shape, arity, ilk placement, ranges).
    #[error(transparent)]
    Structural(#[from] StructuralError),
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
        let r = Rejection::from(ThresholdError::BelowMinimum);
        assert!(matches!(
            r,
            Rejection::MalformedThreshold(ThresholdError::BelowMinimum)
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
}
