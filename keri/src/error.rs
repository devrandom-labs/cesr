//! Validation verdict types for the key-state fold.
use core::fmt;

/// Why an event was not accepted. **Placeholder taxonomy — K2 expands this**
/// into the full escrow routing. `#[non_exhaustive]` keeps additions non-breaking
/// for external matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// Sequence number is ahead of the expected next sn (a gap). K2 → out-of-order escrow.
    OutOfOrder,
    /// Prior-event digest does not match the current state's latest SAID. K3 → duplicity.
    PriorDigestMismatch,
    /// Signing threshold not satisfied by the provided signatures. K2 → partially-signed escrow.
    MissingSignatures,
    /// A controller signature failed cryptographic verification against its
    /// resolved signer key.
    InvalidSignature,
    /// A structural KERI rule was violated (arity, transferability, ilk placement, ranges).
    InvalidEvent,
    /// Rotation's revealed keys do not match the prior next-key commitment.
    NextKeyCommitmentMismatch,
    /// A delegated inception/rotation (`dip`/`drt`). Delegated-event folding —
    /// which requires verifying the delegator's authorizing seal — is deferred to
    /// K4 (delegation); K1 rejects these rather than accept them unverified.
    DelegationUnsupported,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OutOfOrder => "event sequence number is out of order",
            Self::PriorDigestMismatch => "prior-event digest does not match current state",
            Self::MissingSignatures => "signing threshold not satisfied",
            Self::InvalidSignature => "controller signature failed verification",
            Self::InvalidEvent => "event violates a structural KERI rule",
            Self::NextKeyCommitmentMismatch => {
                "revealed keys do not match prior next-key commitment"
            }
            Self::DelegationUnsupported => "delegated events are not yet supported (K4)",
        };
        f.write_str(s)
    }
}

/// A validation rejection: the reason plus optional diagnostic context.
#[derive(Debug, Clone, thiserror::Error)]
#[error("event rejected: {reason}")]
pub struct Rejection {
    /// The failure domain.
    pub reason: RejectionReason,
    /// Expected sequence number, when the failure is sequence-related.
    pub expected_sn: Option<u128>,
    /// Actual sequence number carried by the event, when relevant.
    pub actual_sn: Option<u128>,
}

impl Rejection {
    /// A rejection carrying only a reason (no sn context).
    #[must_use]
    pub const fn new(reason: RejectionReason) -> Self {
        Self {
            reason,
            expected_sn: None,
            actual_sn: None,
        }
    }

    /// A sequence-related rejection carrying expected/actual sn.
    #[must_use]
    pub const fn sn(reason: RejectionReason, expected: u128, actual: u128) -> Self {
        Self {
            reason,
            expected_sn: Some(expected),
            actual_sn: Some(actual),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_carries_reason_and_context() {
        let r = Rejection::sn(RejectionReason::OutOfOrder, 1, 4);
        assert_eq!(r.reason, RejectionReason::OutOfOrder);
        assert_eq!(r.expected_sn, Some(1));
        assert_eq!(r.actual_sn, Some(4));
    }
}
