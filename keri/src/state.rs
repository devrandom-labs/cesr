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

use cesr::core::primitives::{Diger, Prefixer, Saider, Seqner, Siger, Tholder, Verfer};
use cesr::crypto::verify_indexed;
use cesr::keri::{
    ConfigTrait, Identifier, Ilk, InceptionEvent, InteractionEvent, KeriEvent, RotationEvent,
};

use crate::error::{Rejection, RejectionReason};

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
    pub sn: Seqner,
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
    pub event: &'e KeriEvent,
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
    sn: Seqner,
    latest_said: &'e Saider<'static>,
    latest_ilk: Ilk,
    keys: &'e [Verfer<'static>],
    threshold: &'e Tholder,
    next_keys: &'e [Diger<'static>],
    next_threshold: &'e Tholder,
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
    pub const fn sn(&self) -> &Seqner {
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
    pub const fn threshold(&self) -> &'e Tholder {
        self.threshold
    }
    /// Committed next-key digests.
    #[must_use]
    pub const fn next_keys(&self) -> &'e [Diger<'static>] {
        self.next_keys
    }
    /// Threshold for the next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &'e Tholder {
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
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        };
        let sn = icp.sn().value();
        if sn != 0 {
            return Err(Rejection::sn(RejectionReason::InvalidEvent, 0, sn));
        }
        check_established_threshold(icp.keys(), icp.threshold())?;
        let transferability = decide_transferability(icp)?;
        check_witness_threshold(icp.witnesses().len(), icp.witness_threshold())?;
        verify_controller_sigs(
            icp.keys(),
            signed.signed_bytes,
            icp.threshold(),
            &signed.sigs,
        )?;
        Ok(Self {
            prefix: icp.prefix(),
            sn: Seqner::new(0),
            latest_said: icp.said(),
            latest_ilk: Ilk::Icp,
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
                sn: Seqner::new(0),
                said: icp.said(),
            },
        })
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
                Err(Rejection::new(RejectionReason::DelegationUnsupported))
            }
            KeriEvent::Inception(_) => Err(Rejection::new(RejectionReason::InvalidEvent)),
            KeriEvent::Rotation(rot) => self.rotate(rot, signed),
            KeriEvent::Interaction(ixn) => self.interact(ixn, signed),
        }
    }

    /// Transition on a rotation: the revealed keys must satisfy the prior next-key
    /// commitment and the signatures, then the keys, thresholds, and commitment
    /// roll forward while the prefix, config, and delegator carry over.
    fn rotate(self, rot: &'e RotationEvent, signed: &Signed<'e>) -> Result<Self, Rejection> {
        check_next_sn(self.sn.value(), rot.sn().value())?;
        if rot.prior_event_said() != self.latest_said {
            return Err(Rejection::new(RejectionReason::PriorDigestMismatch));
        }
        check_established_threshold(rot.keys(), rot.threshold())?;
        check_commitment(&self, rot)?;
        verify_controller_sigs(
            rot.keys(),
            signed.signed_bytes,
            rot.threshold(),
            &signed.sigs,
        )?;
        let witnesses = resolve_witnesses(&self, rot)?;
        let sn = rot.sn().value();
        Ok(Self {
            sn: Seqner::new(sn),
            latest_said: rot.said(),
            latest_ilk: Ilk::Rot,
            keys: rot.keys(),
            threshold: rot.threshold(),
            next_keys: rot.next_keys(),
            next_threshold: rot.next_threshold(),
            witnesses: Cow::Owned(witnesses),
            witness_threshold: rot.witness_threshold(),
            last_est: EstablishmentRef {
                sn: Seqner::new(sn),
                said: rot.said(),
            },
            ..self
        })
    }

    /// Transition on an interaction: verify against this state's *current* keys
    /// (the recurrent edge), then advance the pointer without changing keys.
    fn interact(self, ixn: &'e InteractionEvent, signed: &Signed<'e>) -> Result<Self, Rejection> {
        if self.is_establishment_only() {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
        check_next_sn(self.sn.value(), ixn.sn().value())?;
        if ixn.prior_event_said() != self.latest_said {
            return Err(Rejection::new(RejectionReason::PriorDigestMismatch));
        }
        verify_controller_sigs(self.keys, signed.signed_bytes, self.threshold, &signed.sigs)?;
        Ok(Self {
            sn: Seqner::new(ixn.sn().value()),
            latest_said: ixn.said(),
            latest_ilk: Ilk::Ixn,
            ..self
        })
    }
}

// ── Validation rules ──────────────────────────────────────────────────────
// Private, named for the invariant each enforces, in the order the transitions
// apply them. Nothing outside this module can call them.

/// Verify every controller signature against the key it addresses and confirm the
/// verified set satisfies `threshold`. Resolution + verification is one lazy
/// traversal via [`verify_indexed`]; an out-of-range index and a bad signature are
/// distinct cesr errors mapped to their respective rejections.
fn verify_controller_sigs(
    signers: &[Verfer<'_>],
    signed_bytes: &[u8],
    threshold: &Tholder,
    sigs: &[Siger<'_>],
) -> Result<(), Rejection> {
    let indices = verify_indexed(signers, signed_bytes, sigs).collect::<Result<Vec<_>, _>>()?;
    if threshold.satisfy(indices) {
        Ok(())
    } else {
        Err(Rejection::new(RejectionReason::MissingSignatures))
    }
}

/// A rotation's revealed keys must satisfy the prior next-key commitment: hash to
/// the committed digests (positional, full-rotation form) and satisfy the prior
/// next-key threshold.
fn check_commitment(prior: &KeyState<'_>, rot: &RotationEvent) -> Result<(), Rejection> {
    let revealed = rot.keys();
    let committed = prior.next_keys();
    if revealed.len() != committed.len() {
        return Err(Rejection::new(RejectionReason::NextKeyCommitmentMismatch));
    }
    for (v, d) in revealed.iter().zip(committed.iter()) {
        if !d.verify(&v.to_qb64b()) {
            return Err(Rejection::new(RejectionReason::NextKeyCommitmentMismatch));
        }
    }
    let n = u32::try_from(revealed.len())
        .map_err(|_| Rejection::new(RejectionReason::NextKeyCommitmentMismatch))?;
    if prior.next_threshold().satisfy(0..n) {
        Ok(())
    } else {
        Err(Rejection::new(RejectionReason::NextKeyCommitmentMismatch))
    }
}

/// Resolve a rotation's post-transition witness set: every removal must be a
/// current witness disjoint from the additions, every addition must be new, and
/// the new threshold must not exceed the resolved count. This is the one set the
/// state owns, because it is computed from cut/add deltas rather than read whole.
fn resolve_witnesses(
    prior: &KeyState<'_>,
    rot: &RotationEvent,
) -> Result<Vec<Prefixer<'static>>, Rejection> {
    let removals = rot.witness_removals();
    let additions = rot.witness_additions();
    for r in removals {
        if !prior.witnesses().iter().any(|w| w == r) || additions.iter().any(|a| a == r) {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
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
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
        resolved.push(a.clone().into_static());
    }
    let resolved_len =
        u32::try_from(resolved.len()).map_err(|_| Rejection::new(RejectionReason::InvalidEvent))?;
    if rot.witness_threshold() > resolved_len {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    Ok(resolved)
}

/// An establishment key set must be non-empty and its signing threshold
/// well-formed for the key count.
fn check_established_threshold(keys: &[Verfer<'_>], tholder: &Tholder) -> Result<(), Rejection> {
    if tholder.is_well_formed(keys.len()) {
        Ok(())
    } else {
        Err(Rejection::new(RejectionReason::InvalidEvent))
    }
}

/// A non-genesis event's sequence number must be exactly one past the prior
/// state's.
const fn check_next_sn(prior_sn: u128, actual: u128) -> Result<(), Rejection> {
    let Some(expected) = prior_sn.checked_add(1) else {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    };
    if actual != expected {
        return Err(Rejection::sn(RejectionReason::OutOfOrder, expected, actual));
    }
    Ok(())
}

/// Transferability must agree with the pre-rotation commitment: a non-transferable
/// prefix commits to no next keys; a self-addressing (always transferable) prefix
/// must commit to at least one.
fn decide_transferability(icp: &InceptionEvent) -> Result<Transferability, Rejection> {
    let transferable = icp.prefix().is_transferable();
    let next_empty = icp.next_keys().is_empty();
    if !transferable && !next_empty {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    if icp.prefix().as_saider().is_some() && next_empty {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    Ok(if transferable {
        Transferability::Transferable
    } else {
        Transferability::NonTransferable
    })
}

/// The witness threshold (TOAD) must not exceed the number of witnesses.
fn check_witness_threshold(witness_count: usize, toad: u32) -> Result<(), Rejection> {
    let count =
        u128::try_from(witness_count).map_err(|_| Rejection::new(RejectionReason::InvalidEvent))?;
    if u128::from(toad) > count {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    Ok(())
}
