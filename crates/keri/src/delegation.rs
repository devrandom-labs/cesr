//! Delegation validation over typed evidence (K4, #90).
//!
//! The acceptance checks for delegated establishment events, every
//! cross-KEL fact supplied by the host as an argument. The delegator's KEL
//! is the host's stream. The host folds it, locates the anchoring event,
//! and hands both to the fold as [`DelegationEvidence`];
//! the core checks bindings by digest and never walks anything. Spec
//! (kswg-keri-specification, §Cooperative Delegation): *"A Validator MUST
//! be given or find the delegating seal in the delegator's KEL before the
//! event may be accepted as valid"* — this module is the "be given" arm.
//!
//! keripy conformance (main `9161a705`): `Kever.validateDelegation`
//! eventing.py:3009-3416 — the acceptance path. Its recursive climb
//! (3418-3492) is the superseding cascade, which K3 models as the
//! host-supplied [`DelegationContest`](crate::DelegationContest) slice;
//! acceptance itself needs exactly one delegating event.
use keri_events::{ConfigTrait, Identifier, KeriEvent};

use crate::error::DelegationError;
use crate::state::KeyState;

/// Everything the fold needs from the delegator's side. That
/// `delegating_event` is ACCEPTED in the delegator's KEL is host-asserted —
/// the same trust contract as [`Signed::signed_bytes`](crate::Signed).
pub struct AnchoredDelegation<'e> {
    /// The delegator's current key state (the host folds the delegator's
    /// stream; keripy's `dkever`).
    pub delegator: &'e KeyState<'e>,
    /// The accepted event in the delegator's KEL carrying the anchoring
    /// event-seal of the delegated event (a rotation or an interaction).
    pub delegating_event: &'e KeriEvent<'e>,
}

/// Delegation evidence, supplied fat-command style alongside the delegated
/// event to [`KeyState::incept_delegated`] and [`KeyState::ingest_delegated`].
pub enum DelegationEvidence<'e> {
    /// The spec path: the delegating seal is anchored in the delegator's
    /// KEL.
    Anchored(AnchoredDelegation<'e>),
    /// Host policy accepts without an anchor (keripy's
    /// `locallyOwned`/`locallyMembered`/`locallyWitnessed` controller and
    /// witness roles — eventing.py:3281-3284; not in the spec, which is
    /// validator-role). Signatures, thresholds, and witnessing are still
    /// enforced; only the seal/delegator checks are skipped. The host
    /// decides WHEN to assert this — the fold never does.
    HostAccepted,
}

impl DelegationEvidence<'_> {
    /// Check that this evidence authorizes `delegated` under
    /// `expected_delegator` — the K4 acceptance rules, in keripy's order:
    /// delegator identity, do-not-delegate, seal binding. All checks are
    /// digest comparisons; [`HostAccepted`](Self::HostAccepted) skips them
    /// by construction.
    ///
    /// # Errors
    ///
    /// Returns the first [`DelegationError`] rule violated.
    pub fn authorizes(
        &self,
        delegated: &KeriEvent<'_>,
        expected_delegator: &Identifier<'_>,
    ) -> Result<(), DelegationError> {
        let Self::Anchored(anchor) = self else {
            return Ok(());
        };
        if anchor.delegator.prefix() != expected_delegator
            || anchor.delegating_event.prefix() != anchor.delegator.prefix()
        {
            return Err(DelegationError::DelegatorMismatch);
        }
        if anchor
            .delegator
            .config()
            .iter()
            .any(|c| matches!(c, ConfigTrait::DoNotDelegate))
        {
            return Err(DelegationError::Denied);
        }
        if anchor.delegating_event.anchor_position(delegated).is_none() {
            return Err(DelegationError::SealNotFound);
        }
        Ok(())
    }
}
