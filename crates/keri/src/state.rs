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

use cesr::core::primitives::{Number, Siger};
use keri_events::{
    BasicPrefix, ConfigTrait, Digest, Identifier, InceptionEvent, InteractionEvent, KeriEvent,
    MessageType, RotationEvent, Said, SigningThreshold, Toad, VerifyingKey,
};

use crate::authority::{Authority, Commitment, Establishment, Witnessing};
use crate::error::{Rejection, StructuralError, TransferabilityError, WitnessSetError};

/// Whether an identifier's controlling keys can be rotated.
///
/// Derived state, not a prefix-code echo (keripy `Kever.transferable`,
/// eventing.py:2166): `Transferable` iff the prefix code is transferable AND
/// the current next-key commitment is non-empty. Recomputed at every
/// establishment event — an empty-`n` inception is non-transferable at birth,
/// and an empty-`n` rotation abandons the identifier. A non-transferable
/// state admits no further events (spec: "no more key events").
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
    pub sn: Number,
    /// SAID of the last establishment event.
    pub said: &'e Said<'e>,
}

/// An already-parsed KERI event paired with the exact bytes it was parsed from
/// and its indexed signatures.
///
/// `signed_bytes` are the serialized event bytes the signatures were produced
/// over — the caller obtained them while parsing (via `cesr::stream`/`keri-codec`), so
/// carrying a borrow here keeps the transition zero-copy and lets `keri` verify
/// signatures without a serializer of its own. The contract is that `signed_bytes`
/// are the bytes `event` was parsed from; a mismatch makes every signature fail to
/// verify and the event is rejected.
pub struct Signed<'e> {
    /// The parsed event to fold.
    pub event: &'e KeriEvent<'e>,
    /// The serialized bytes the signatures are computed over.
    pub signed_bytes: &'e [u8],
    /// Indexed controller signatures over `signed_bytes`.
    pub sigs: Vec<Siger<'e>>,
    /// Indexed witness receipts over `signed_bytes`. Verified by the fold
    /// against the event's governing witness set: each index selects the
    /// witness whose non-transferable prefix is the verification key, and at
    /// least TOAD distinct witnesses must have a valid receipt (see
    /// [`Witnessing`](crate::Witnessing)).
    pub wigs: Vec<Siger<'e>>,
}

/// Computed key state, borrowing from the events it was folded from (`'e`).
#[derive(Debug, Clone)]
pub struct KeyState<'e> {
    prefix: &'e Identifier<'e>,
    sn: Number,
    latest_said: &'e Said<'e>,
    latest_message_type: MessageType,
    keys: &'e [VerifyingKey<'e>],
    threshold: &'e SigningThreshold,
    next_keys: &'e [Digest<'e>],
    next_threshold: &'e SigningThreshold,
    witnesses: Cow<'e, [BasicPrefix<'e>]>,
    witness_threshold: Toad,
    config: &'e [ConfigTrait],
    delegator: Option<&'e BasicPrefix<'e>>,
    transferability: Transferability,
    last_est: EstablishmentRef<'e>,
}

impl<'e> KeyState<'e> {
    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &'e Identifier<'e> {
        self.prefix
    }
    /// Sequence number of the latest applied event.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }
    /// SAID of the latest applied event.
    #[must_use]
    pub const fn latest_said(&self) -> &'e Said<'e> {
        self.latest_said
    }
    /// Message type of the latest applied event.
    #[must_use]
    pub const fn latest_message_type(&self) -> MessageType {
        self.latest_message_type
    }
    /// Current signing keys.
    #[must_use]
    pub const fn keys(&self) -> &'e [VerifyingKey<'e>] {
        self.keys
    }
    /// Current signing threshold.
    #[must_use]
    pub const fn threshold(&self) -> &'e SigningThreshold {
        self.threshold
    }
    /// Committed next-key digests.
    #[must_use]
    pub const fn next_keys(&self) -> &'e [Digest<'e>] {
        self.next_keys
    }
    /// Threshold for the next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &'e SigningThreshold {
        self.next_threshold
    }
    /// Current witness prefixes.
    #[must_use]
    pub fn witnesses(&self) -> &[BasicPrefix<'e>] {
        &self.witnesses
    }
    /// Witness agreement threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> Toad {
        self.witness_threshold
    }
    /// Configuration traits in effect.
    #[must_use]
    pub const fn config(&self) -> &'e [ConfigTrait] {
        self.config
    }
    /// Delegator prefix, if this identifier is delegated.
    #[must_use]
    pub const fn delegator(&self) -> Option<&'e BasicPrefix<'e>> {
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
    /// transferability/next-key rule, over-specifies its witness threshold,
    /// fails signature verification, or carries fewer valid witness receipts
    /// than its declared TOAD requires.
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
        // witnessing: the declared TOAD must be met by valid receipts over the
        // declared witness set (keripy: wits=self.wits from ked["b"],
        // eventing.py:1963/2272)
        Witnessing::new(icp.witnesses(), icp.witness_threshold())
            .receipted_by(signed.signed_bytes, &signed.wigs)?;
        // apply
        Ok(Self::seed(icp, transferability))
    }

    /// Build the genesis key state from an inception event: it seeds the invariant
    /// fields (`prefix`, `transferability`, `config`, `delegator`) that later
    /// establishment events carry forward.
    fn seed(icp: &'e InceptionEvent<'e>, transferability: Transferability) -> Self {
        Self {
            prefix: icp.prefix(),
            sn: Number::new(0),
            latest_said: icp.said(),
            latest_message_type: MessageType::Icp,
            keys: icp.keys(),
            threshold: icp.threshold(),
            next_keys: icp.next_keys(),
            next_threshold: icp.next_threshold(),
            witnesses: Cow::Borrowed(icp.witnesses()),
            witness_threshold: icp.witness_threshold(),
            config: icp.config(),
            delegator: None,
            transferability,
            last_est: EstablishmentRef {
                sn: Number::new(0),
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
    /// commitment, signature, or witness-receipt rule the event violates.
    /// Events on a non-transferable or abandoned state are rejected first
    /// ([`Rejection::NonTransferableState`]).
    pub fn ingest(self, signed: &Signed<'e>) -> Result<Self, Rejection> {
        if !self.is_transferable() {
            return Err(Rejection::NonTransferableState);
        }
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
    fn rotate(self, rot: &'e RotationEvent<'e>, signed: &Signed<'e>) -> Result<Self, Rejection> {
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
        // witnessing: receipts index into the POST-cut/add resolved set
        // (keripy: wits = list((witset - cutset) | addset), eventing.py:2624,
        // passed into valSigsWigsDel at eventing.py:2390)
        Witnessing::new(&witnesses, rot.witness_threshold())
            .receipted_by(signed.signed_bytes, &signed.wigs)?;
        Ok(self.rotated(rot, witnesses))
    }

    /// Roll the establishment state forward onto a rotation: keys, thresholds, the
    /// next-key commitment, and the resolved witness set advance while the prefix,
    /// config, transferability, and delegator carry over via `..self`.
    fn rotated(self, rot: &'e RotationEvent<'e>, witnesses: Vec<BasicPrefix<'e>>) -> Self {
        let sn = rot.sn().value();
        Self {
            sn: Number::new(sn),
            latest_said: rot.said(),
            latest_message_type: MessageType::Rot,
            keys: rot.keys(),
            threshold: rot.threshold(),
            next_keys: rot.next_keys(),
            next_threshold: rot.next_threshold(),
            witnesses: Cow::Owned(witnesses),
            witness_threshold: rot.witness_threshold(),
            last_est: EstablishmentRef {
                sn: Number::new(sn),
                said: rot.said(),
            },
            transferability: if rot.next_keys().is_empty() {
                Transferability::NonTransferable
            } else {
                self.transferability
            },
            ..self
        }
    }

    /// Transition on an interaction: verify against this state's *current* authority
    /// (the recurrent edge), then advance the pointer without changing keys.
    fn interact(
        self,
        ixn: &'e InteractionEvent<'e>,
        signed: &Signed<'e>,
    ) -> Result<Self, Rejection> {
        self.reject_establishment_only()?;
        // authorize succession
        self.check_chains_onto(ixn.sn().value(), ixn.prior_event_said())?;
        // authenticate against the current authority (an interaction establishes nothing)
        self.authority().verify(signed.signed_bytes, &signed.sigs)?;
        // witnessing: an interaction is receipted against the state's carried
        // witness set and TOAD (keripy: wits=self.wits, toader=self.toader in
        // the ixn branch of Kever.update, eventing.py:2452-2461)
        Witnessing::new(self.witnesses(), self.witness_threshold())
            .receipted_by(signed.signed_bytes, &signed.wigs)?;
        // apply
        Ok(self.advanced(ixn))
    }

    /// Advance the pointer onto an interaction: sequence number, latest SAID, and
    /// message type move; everything else carries over via `..self`.
    fn advanced(self, ixn: &'e InteractionEvent<'e>) -> Self {
        Self {
            sn: Number::new(ixn.sn().value()),
            latest_said: ixn.said(),
            latest_message_type: MessageType::Ixn,
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
    fn check_chains_onto(&self, sn: u128, prior_said: &Said<'_>) -> Result<(), Rejection> {
        check_next_sn(self.sn.value(), sn)?;
        if prior_said != self.latest_said {
            return Err(Rejection::PriorDigestMismatch);
        }
        Ok(())
    }
}

/// Owned snapshot of a [`KeyState`]: the storage-facing carrier.
///
/// The `PathBuf` to [`KeyState`]'s `&Path`: [`view`](Self::view) lends the
/// zero-copy working state back, and [`From<&KeyState>`] owns one out of a
/// fold result. `Send + Sync + 'static`, so an event-sourced host can hold it
/// as aggregate state. The trusted fold ([`genesis`](Self::genesis),
/// [`advance`](Self::advance)) rebuilds it from ACCEPTED events without
/// re-verifying — validation happened at decide time, in the K1 fold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStateSnapshot {
    prefix: Identifier<'static>,
    sn: Number,
    latest_said: Said<'static>,
    latest_message_type: MessageType,
    keys: Vec<VerifyingKey<'static>>,
    threshold: SigningThreshold,
    next_keys: Vec<Digest<'static>>,
    next_threshold: SigningThreshold,
    witnesses: Vec<BasicPrefix<'static>>,
    witness_threshold: Toad,
    config: Vec<ConfigTrait>,
    delegator: Option<BasicPrefix<'static>>,
    transferability: Transferability,
    last_est_sn: Number,
    last_est_said: Said<'static>,
}

impl KeyStateSnapshot {
    /// Lend the zero-copy working view: every borrow in the returned
    /// [`KeyState`] points into this snapshot's owned fields.
    #[must_use]
    pub fn view(&self) -> KeyState<'_> {
        KeyState {
            prefix: &self.prefix,
            sn: self.sn,
            latest_said: &self.latest_said,
            latest_message_type: self.latest_message_type,
            keys: &self.keys,
            threshold: &self.threshold,
            next_keys: &self.next_keys,
            next_threshold: &self.next_threshold,
            witnesses: Cow::Borrowed(self.witnesses.as_slice()),
            witness_threshold: self.witness_threshold,
            config: &self.config,
            delegator: self.delegator.as_ref(),
            transferability: self.transferability,
            last_est: EstablishmentRef {
                sn: self.last_est_sn,
                said: &self.last_est_said,
            },
        }
    }

    /// Trusted seed: fold an ACCEPTED inception event. Total and crypto-free —
    /// the K1 validating fold ([`KeyState::incept`]) already authenticated it
    /// at decide time. Transferability is derived from the prefix code and the
    /// next-key commitment; the transferability/next-key agreement rules were
    /// enforced at acceptance.
    #[must_use]
    pub fn genesis(icp: &InceptionEvent<'_>) -> Self {
        let transferability = if icp.prefix().is_transferable() && !icp.next_keys().is_empty() {
            Transferability::Transferable
        } else {
            Transferability::NonTransferable
        };
        Self {
            prefix: icp.prefix().clone().into_static(),
            sn: icp.sn(),
            latest_said: icp.said().clone().into_static(),
            latest_message_type: MessageType::Icp,
            keys: icp.keys().iter().map(|k| k.clone().into_static()).collect(),
            threshold: icp.threshold().clone(),
            next_keys: icp
                .next_keys()
                .iter()
                .map(|d| d.clone().into_static())
                .collect(),
            next_threshold: icp.next_threshold().clone(),
            witnesses: icp
                .witnesses()
                .iter()
                .map(|w| w.clone().into_static())
                .collect(),
            witness_threshold: icp.witness_threshold(),
            config: icp.config().to_vec(),
            delegator: None,
            transferability,
            last_est_sn: icp.sn(),
            last_est_said: icp.said().clone().into_static(),
        }
    }

    /// Trusted step: fold one ACCEPTED event. Total and crypto-free — the
    /// validating fold authenticated it at decide time; this fold only
    /// computes. On input no validating fold would ever accept, it stays
    /// deterministic (idempotent witness algebra, no checks) instead of
    /// panicking: garbage in, deterministic garbage out — store integrity is
    /// the hosting layer's invariant, not this fold's.
    #[must_use]
    pub fn advance(self, event: &KeriEvent<'_>) -> Self {
        match event {
            KeriEvent::Inception(icp) => Self::genesis(icp),
            // Delegation validation is K4 scope. A dip/drt in an accepted
            // stream cannot exist before K4 extends BOTH folds (the
            // validating fold rejects them); folding the underlying
            // establishment data keeps `advance` total and deterministic
            // meanwhile. K4 also carries the delegator (an `Identifier`,
            // which today's `KeyState.delegator: Option<&BasicPrefix>`
            // cannot hold — widening it is a K4 change).
            KeriEvent::DelegatedInception(dip) => {
                let mut next = Self::genesis(dip.inception());
                next.latest_message_type = MessageType::Dip;
                next
            }
            KeriEvent::Rotation(rot) => self.rolled(rot, MessageType::Rot),
            KeriEvent::DelegatedRotation(drt) => self.rolled(drt.rotation(), MessageType::Drt),
            KeriEvent::Interaction(ixn) => self.stepped(ixn),
        }
    }

    /// Roll establishment state onto a rotation, trusted: keys, thresholds,
    /// commitment, and the cut/add-resolved witness set advance; prefix,
    /// config, transferability, and delegator carry over.
    fn rolled(self, rot: &RotationEvent<'_>, message_type: MessageType) -> Self {
        Self {
            sn: rot.sn(),
            latest_said: rot.said().clone().into_static(),
            latest_message_type: message_type,
            keys: rot.keys().iter().map(|k| k.clone().into_static()).collect(),
            threshold: rot.threshold().clone(),
            next_keys: rot
                .next_keys()
                .iter()
                .map(|d| d.clone().into_static())
                .collect(),
            next_threshold: rot.next_threshold().clone(),
            witnesses: trusted_witnesses(
                &self.witnesses,
                rot.witness_removals(),
                rot.witness_additions(),
            ),
            witness_threshold: rot.witness_threshold(),
            last_est_sn: rot.sn(),
            last_est_said: rot.said().clone().into_static(),
            transferability: if rot.next_keys().is_empty() {
                Transferability::NonTransferable
            } else {
                self.transferability
            },
            ..self
        }
    }

    /// Advance the pointer onto an interaction, trusted: sn, latest SAID, and
    /// message type move; everything else carries over.
    fn stepped(self, ixn: &InteractionEvent<'_>) -> Self {
        Self {
            sn: ixn.sn(),
            latest_said: ixn.said().clone().into_static(),
            latest_message_type: MessageType::Ixn,
            ..self
        }
    }
}

impl From<&KeyState<'_>> for KeyStateSnapshot {
    fn from(state: &KeyState<'_>) -> Self {
        Self {
            prefix: state.prefix.clone().into_static(),
            sn: state.sn,
            latest_said: state.latest_said.clone().into_static(),
            latest_message_type: state.latest_message_type,
            keys: state.keys.iter().map(|k| k.clone().into_static()).collect(),
            threshold: state.threshold.clone(),
            next_keys: state
                .next_keys
                .iter()
                .map(|d| d.clone().into_static())
                .collect(),
            next_threshold: state.next_threshold.clone(),
            witnesses: state
                .witnesses
                .iter()
                .map(|w| w.clone().into_static())
                .collect(),
            witness_threshold: state.witness_threshold,
            config: state.config.to_vec(),
            delegator: state.delegator.map(|d| d.clone().into_static()),
            transferability: state.transferability,
            last_est_sn: state.last_est.sn,
            last_est_said: state.last_est.said.clone().into_static(),
        }
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
fn resolve_witnesses<'e>(
    prior: &KeyState<'e>,
    rot: &'e RotationEvent<'e>,
) -> Result<Vec<BasicPrefix<'e>>, WitnessSetError> {
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
    let mut resolved: Vec<BasicPrefix<'e>> = prior
        .witnesses()
        .iter()
        .filter(|w| !removals.iter().any(|r| r == *w))
        .cloned()
        .collect();
    for a in additions {
        if resolved.iter().any(|w| w == a) {
            return Err(WitnessSetError::AdditionAlreadyPresent);
        }
        resolved.push(a.clone());
    }
    Ok(resolved)
}

/// Trusted counterpart of [`resolve_witnesses`]: the same cut/add algebra as
/// idempotent set operations — cutting an absent prefix is a no-op, adding a
/// present prefix is a skip. On accepted rotations (where the validating fold
/// already rejected overlaps and unknown cuts) it computes the identical set;
/// on anything else it stays total and deterministic.
fn trusted_witnesses(
    current: &[BasicPrefix<'static>],
    removals: &[BasicPrefix<'_>],
    additions: &[BasicPrefix<'_>],
) -> Vec<BasicPrefix<'static>> {
    let mut resolved: Vec<BasicPrefix<'static>> = current
        .iter()
        .filter(|w| !removals.iter().any(|r| r == *w))
        .cloned()
        .collect();
    for a in additions {
        if !resolved.contains(a) {
            resolved.push(a.clone().into_static());
        }
    }
    resolved
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

/// Transferability must agree with the pre-rotation commitment: a
/// non-transferable prefix commits to no next keys. A transferable prefix
/// with an empty next-key list is accepted and deemed non-transferable at
/// birth (spec; keripy eventing.py:2166).
fn decide_transferability(icp: &InceptionEvent) -> Result<Transferability, TransferabilityError> {
    let transferable = icp.prefix().is_transferable();
    let next_empty = icp.next_keys().is_empty();
    if !transferable && !next_empty {
        return Err(TransferabilityError::NonTransferableCommitsNextKeys);
    }
    Ok(if transferable && !next_empty {
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

#[cfg(test)]
mod tests {
    use super::KeyStateSnapshot;

    /// The snapshot satisfies the owned-aggregate-state shape an event-sourced
    /// host requires (spec §5 constraint 1). Fails to compile if a borrowed
    /// field sneaks in.
    #[test]
    fn snapshot_is_send_sync_static() {
        fn probe<T: Send + Sync + core::fmt::Debug + Clone + 'static>() {}
        probe::<KeyStateSnapshot>();
    }
}
