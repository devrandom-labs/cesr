//! Computed key state for a KERI identifier, and the transitions that advance it.
//!
//! [`KeyState`] is the running snapshot of an identifier's cryptographic control,
//! derived by folding its verified KEL. It borrows from the parsed events the
//! caller keeps alive (`'e`): the current keys, next-key commitment, prefix, and
//! config are slice/reference borrows into those events, never re-materialized.
//! Only the witness set — which a rotation recomputes from cut/add deltas — is
//! owned, and even then only when it actually changes.
//!
//! The only way to obtain a first state is [`KeyState::incept`] (the seed); the
//! only way to advance one is [`KeyState::ingest`] (the step). Verification lives
//! inside the step — the keys that verify an event are resolved from the state
//! itself for interactions and from the event for establishment events — so an
//! unverifiable event can never advance the state. The caller drives the
//! transitions over its own iterator or stream; `keri` does no I/O:
//!
//! ```ignore
//! let seed = KeyState::incept(&genesis)?;
//! let latest = rest.iter().try_fold(seed, |state, ev| state.ingest(ev))?;
//! ```
use alloc::borrow::Cow;
use alloc::vec::Vec;

use cesr::core::primitives::{Diger, Prefixer, Saider, Siger, Verfer};
use cesr::keri::{
    ConfigTrait, Identifier, Ilk, InceptionEvent, InteractionEvent, KeriEvent, RotationEvent,
    SequenceNumber, SigningThreshold,
};

use crate::authority::{Authority, Commitment, Establishment};
use crate::error::{Rejection, StructuralError, TransferabilityError, WitnessSetError};

/// Whether an identifier's controlling keys can be rotated.
///
/// Decided at inception from the prefix — a basic non-transferable key code
/// yields [`NonTransferable`](Transferability::NonTransferable); a transferable
/// or self-addressing prefix yields [`Transferable`](Transferability::Transferable)
/// — and carried forward through the KEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transferability {
    /// The identifier commits to next keys and can rotate.
    Transferable,
    /// The identifier is ephemeral: it commits to no next keys and cannot rotate.
    NonTransferable,
}

/// `(sn, said)` of the last establishment event (keripy `lastEst`). The SAID
/// borrows the establishment event it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentRef<'e> {
    /// Sequence number of the last establishment event.
    pub sn: SequenceNumber,
    /// SAID of the last establishment event.
    pub said: &'e Saider<'static>,
}

/// An already-parsed KERI event paired with the exact bytes it was parsed from
/// and its indexed signatures.
///
/// `signed_bytes` are the serialized event bytes the signatures were produced
/// over — the caller obtained them while parsing (via `cesr::stream`/`serder`), so
/// carrying a borrow here keeps the transition zero-copy and lets `keri` verify
/// signatures without a serializer of its own. The contract is that `signed_bytes`
/// are the bytes `event` was parsed from; a mismatch makes every signature fail to
/// verify and the event is rejected.
pub struct Signed<'e> {
    /// The parsed event to fold.
    pub event: &'e KeriEvent<'static>,
    /// The serialized bytes the signatures are computed over.
    pub signed_bytes: &'e [u8],
    /// Indexed controller signatures over `signed_bytes`.
    pub sigs: Vec<Siger<'e>>,
    /// Indexed witness receipts over `signed_bytes`.
    pub wigs: Vec<Siger<'e>>,
}

/// Computed key state, borrowing from the events it was folded from (`'e`).
#[derive(Debug, Clone)]
pub struct KeyState<'e> {
    prefix: &'e Identifier<'static>,
    sn: SequenceNumber,
    latest_said: &'e Saider<'static>,
    latest_ilk: Ilk,
    keys: &'e [Verfer<'static>],
    threshold: &'e SigningThreshold,
    next_keys: &'e [Diger<'static>],
    next_threshold: &'e SigningThreshold,
    witnesses: Cow<'e, [Prefixer<'static>]>,
    witness_threshold: u32,
    config: &'e [ConfigTrait],
    delegator: Option<&'e Prefixer<'static>>,
    transferability: Transferability,
    last_est: EstablishmentRef<'e>,
}

impl<'e> KeyState<'e> {
    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &'e Identifier<'static> {
        self.prefix
    }
    /// Sequence number of the latest applied event.
    #[must_use]
    pub const fn sn(&self) -> &SequenceNumber {
        &self.sn
    }
    /// SAID of the latest applied event.
    #[must_use]
    pub const fn latest_said(&self) -> &'e Saider<'static> {
        self.latest_said
    }
    /// Ilk of the latest applied event.
    #[must_use]
    pub const fn latest_ilk(&self) -> Ilk {
        self.latest_ilk
    }
    /// Current signing keys.
    #[must_use]
    pub const fn keys(&self) -> &'e [Verfer<'static>] {
        self.keys
    }
    /// Current signing threshold.
    #[must_use]
    pub const fn threshold(&self) -> &'e SigningThreshold {
        self.threshold
    }
    /// Committed next-key digests.
    #[must_use]
    pub const fn next_keys(&self) -> &'e [Diger<'static>] {
        self.next_keys
    }
    /// Threshold for the next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &'e SigningThreshold {
        self.next_threshold
    }
    /// Current witness prefixes.
    #[must_use]
    pub fn witnesses(&self) -> &[Prefixer<'static>] {
        &self.witnesses
    }
    /// Witness threshold (TOAD).
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }
    /// Configuration traits in effect.
    #[must_use]
    pub const fn config(&self) -> &'e [ConfigTrait] {
        self.config
    }
    /// Delegator prefix, if this identifier is delegated.
    #[must_use]
    pub const fn delegator(&self) -> Option<&'e Prefixer<'static>> {
        self.delegator
    }
    /// The identifier's transferability (rotatability).
    #[must_use]
    pub const fn transferability(&self) -> Transferability {
        self.transferability
    }
    /// `true` if the identifier can be rotated.
    #[must_use]
    pub const fn is_transferable(&self) -> bool {
        matches!(self.transferability, Transferability::Transferable)
    }
    /// `(sn, said)` of the last establishment event.
    #[must_use]
    pub const fn last_establishment(&self) -> &EstablishmentRef<'e> {
        &self.last_est
    }
    /// `true` if this state has the `EstOnly` config trait.
    #[must_use]
    pub fn is_establishment_only(&self) -> bool {
        self.config
            .iter()
            .any(|c| matches!(c, ConfigTrait::EstOnly))
    }

    // ── Lifecycle: the only ways to obtain and advance a KeyState ──────────

    /// Seed the fold from a genesis (inception) event.
    ///
    /// Validates the genesis structural rules, verifies the controller signatures
    /// against the event's own declared keys (a genesis is self-certifying), and
    /// borrows the first [`KeyState`] from the event.
    ///
    /// # Errors
    ///
    /// Returns a [`Rejection`] if the event is not a plain inception, carries a
    /// non-zero sequence number, has an empty or ill-formed key set, violates the
    /// transferability/next-key rule, over-specifies its witness threshold, or
    /// fails signature verification.
    pub fn incept(signed: &Signed<'e>) -> Result<Self, Rejection> {
        let KeriEvent::Inception(icp) = signed.event else {
            return Err(StructuralError::NotInception.into());
        };
        let sn = icp.sn().value();
        if sn != 0 {
            return Err(StructuralError::NonZeroGenesisSn { sn }.into());
        }
        // authenticate: a genesis is self-certifying against its own declared authority
        icp.authority().well_formed()?;
        icp.authority().verify(signed.signed_bytes, &signed.sigs)?;
        // establishment rules: transferability/next-key and witness threshold
        let transferability = decide_transferability(icp)?;
        check_witness_threshold(icp.witnesses().len(), icp.witness_threshold().value())?;
        // apply
        Ok(Self::seed(icp, transferability))
    }

    /// Build the genesis key state from an inception event: it seeds the invariant
    /// fields (`prefix`, `transferability`, `config`, `delegator`) that later
    /// establishment events carry forward.
    fn seed(icp: &'e InceptionEvent<'static>, transferability: Transferability) -> Self {
        Self {
            prefix: icp.prefix(),
            sn: SequenceNumber::new(0),
            latest_said: icp.said(),
            latest_ilk: Ilk::Icp,
            keys: icp.keys(),
            threshold: icp.threshold(),
            next_keys: icp.next_keys(),
            next_threshold: icp.next_threshold(),
            witnesses: Cow::Borrowed(icp.witnesses()),
            witness_threshold: icp.witness_threshold().value(),
            config: icp.config(),
            delegator: None,
            transferability,
            last_est: EstablishmentRef {
                sn: SequenceNumber::new(0),
                said: icp.said(),
            },
        }
    }

    /// Fold one signed event onto this state, returning the next state.
    ///
    /// Consumes `self`: the carried-over borrows move into the next state, so
    /// nothing is re-materialized. Delegated events are rejected (K4 scope), a
    /// second inception is invalid, and rotations and interactions transition.
    ///
    /// # Errors
    ///
    /// Returns a [`Rejection`] describing the first structural, threshold,
    /// commitment, or signature rule the event violates.
    pub fn ingest(self, signed: &Signed<'e>) -> Result<Self, Rejection> {
        match signed.event {
            KeriEvent::DelegatedInception(_) | KeriEvent::DelegatedRotation(_) => {
                Err(Rejection::DelegationUnsupported)
            }
            KeriEvent::Inception(_) => Err(StructuralError::DuplicateInception.into()),
            KeriEvent::Rotation(rot) => self.rotate(rot, signed),
            KeriEvent::Interaction(ixn) => self.interact(ixn, signed),
        }
    }

    /// Transition on a rotation: the revealed keys must satisfy the prior next-key
    /// commitment and the signatures, then the keys, thresholds, and commitment
    /// roll forward while the prefix, config, and delegator carry over.
    fn rotate(
        self,
        rot: &'e RotationEvent<'static>,
        signed: &Signed<'e>,
    ) -> Result<Self, Rejection> {
        // authorize succession: chains onto state, and the revealed keys open the
        // prior next-key commitment
        self.check_chains_onto(rot.sn().value(), rot.prior_event_said())?;
        self.commitment().opened_by(&rot.authority())?;
        // authenticate: a rotation is self-certifying against its revealed authority
        rot.authority().well_formed()?;
        rot.authority().verify(signed.signed_bytes, &signed.sigs)?;
        // apply
        let witnesses = resolve_witnesses(&self, rot)?;
        check_witness_threshold(witnesses.len(), rot.witness_threshold().value())?;
        Ok(self.rotated(rot, witnesses))
    }

    /// Roll the establishment state forward onto a rotation: keys, thresholds, the
    /// next-key commitment, and the resolved witness set advance while the prefix,
    /// config, transferability, and delegator carry over via `..self`.
    fn rotated(self, rot: &'e RotationEvent<'static>, witnesses: Vec<Prefixer<'static>>) -> Self {
        let sn = rot.sn().value();
        Self {
            sn: SequenceNumber::new(sn),
            latest_said: rot.said(),
            latest_ilk: Ilk::Rot,
            keys: rot.keys(),
            threshold: rot.threshold(),
            next_keys: rot.next_keys(),
            next_threshold: rot.next_threshold(),
            witnesses: Cow::Owned(witnesses),
            witness_threshold: rot.witness_threshold().value(),
            last_est: EstablishmentRef {
                sn: SequenceNumber::new(sn),
                said: rot.said(),
            },
            ..self
        }
    }

    /// Transition on an interaction: verify against this state's *current* authority
    /// (the recurrent edge), then advance the pointer without changing keys.
    fn interact(
        self,
        ixn: &'e InteractionEvent<'static>,
        signed: &Signed<'e>,
    ) -> Result<Self, Rejection> {
        self.reject_establishment_only()?;
        // authorize succession
        self.check_chains_onto(ixn.sn().value(), ixn.prior_event_said())?;
        // authenticate against the current authority (an interaction establishes nothing)
        self.authority().verify(signed.signed_bytes, &signed.sigs)?;
        // apply
        Ok(self.advanced(ixn))
    }

    /// Advance the pointer onto an interaction: sequence number, latest SAID, and
    /// ilk move; everything else carries over via `..self`.
    fn advanced(self, ixn: &'e InteractionEvent<'static>) -> Self {
        Self {
            sn: SequenceNumber::new(ixn.sn().value()),
            latest_said: ixn.said(),
            latest_ilk: Ilk::Ixn,
            ..self
        }
    }

    /// This state's current controlling authority.
    const fn authority(&self) -> Authority<'e> {
        Authority::new(self.keys, self.threshold)
    }

    /// This state's current commitment to the next authority.
    const fn commitment(&self) -> Commitment<'e> {
        Commitment::new(self.next_keys, self.next_threshold)
    }

    /// Reject an interaction when the identifier is configured establishment-only.
    fn reject_establishment_only(&self) -> Result<(), Rejection> {
        if self.is_establishment_only() {
            Err(StructuralError::InteractionOnEstablishmentOnly.into())
        } else {
            Ok(())
        }
    }

    /// A non-genesis event chains onto this state when its sequence number is the
    /// next in order and its prior-event digest matches this state's latest SAID.
    /// The recurrent edge shared by rotations and interactions.
    fn check_chains_onto(&self, sn: u128, prior_said: &Saider<'static>) -> Result<(), Rejection> {
        check_next_sn(self.sn.value(), sn)?;
        if prior_said != self.latest_said {
            return Err(Rejection::PriorDigestMismatch);
        }
        Ok(())
    }
}

// ── Validation rules ──────────────────────────────────────────────────────
// Private, named for the invariant each enforces, in the order the transitions
// apply them. Nothing outside this module can call them.

/// Resolve a rotation's post-transition witness set from its cut/add deltas: every
/// removal must be a current witness disjoint from the additions, and every addition
/// must be new. This is the one set the state owns, because it is computed from
/// deltas rather than read whole. The witness-threshold check is applied by the
/// caller against the resolved count.
fn resolve_witnesses(
    prior: &KeyState<'_>,
    rot: &RotationEvent<'static>,
) -> Result<Vec<Prefixer<'static>>, WitnessSetError> {
    let removals = rot.witness_removals();
    let additions = rot.witness_additions();
    for r in removals {
        if !prior.witnesses().iter().any(|w| w == r) {
            return Err(WitnessSetError::RemovalNotCurrent);
        }
        if additions.iter().any(|a| a == r) {
            return Err(WitnessSetError::CutAddOverlap);
        }
    }
    let mut resolved: Vec<Prefixer<'static>> = prior
        .witnesses()
        .iter()
        .filter(|w| !removals.iter().any(|r| r == *w))
        .map(|w| w.clone().into_static())
        .collect();
    for a in additions {
        if resolved.iter().any(|w| w == a) {
            return Err(WitnessSetError::AdditionAlreadyPresent);
        }
        resolved.push(a.clone().into_static());
    }
    Ok(resolved)
}

/// A non-genesis event's sequence number must be exactly one past the prior
/// state's.
const fn check_next_sn(prior_sn: u128, actual: u128) -> Result<(), Rejection> {
    let Some(expected) = prior_sn.checked_add(1) else {
        return Err(Rejection::Structural(
            StructuralError::SequenceNumberOverflow,
        ));
    };
    if actual != expected {
        return Err(Rejection::OutOfOrder { expected, actual });
    }
    Ok(())
}

/// Transferability must agree with the pre-rotation commitment: a non-transferable
/// prefix commits to no next keys; a self-addressing (always transferable) prefix
/// must commit to at least one.
fn decide_transferability(icp: &InceptionEvent) -> Result<Transferability, TransferabilityError> {
    let transferable = icp.prefix().is_transferable();
    let next_empty = icp.next_keys().is_empty();
    if !transferable && !next_empty {
        return Err(TransferabilityError::NonTransferableCommitsNextKeys);
    }
    if icp.prefix().as_saider().is_some() && next_empty {
        return Err(TransferabilityError::SelfAddressingWithoutNextKeys);
    }
    Ok(if transferable {
        Transferability::Transferable
    } else {
        Transferability::NonTransferable
    })
}

/// The witness threshold (TOAD) must not exceed the number of witnesses. Shared by
/// inception (declared witnesses) and rotation (resolved witnesses).
fn check_witness_threshold(witness_count: usize, toad: u32) -> Result<(), Rejection> {
    let count = u128::try_from(witness_count).map_err(|_| StructuralError::WitnessCountOverflow)?;
    if u128::from(toad) > count {
        return Err(Rejection::WitnessThresholdExceeded {
            toad,
            count: witness_count,
        });
    }
    Ok(())
}
