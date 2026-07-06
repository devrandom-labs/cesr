//! The pure key-state fold — the decide/apply split at the heart of `keri`.
//!
//! [`validate`] is the fallible decision step: it applies KERI's structural
//! rules and threshold arithmetic over an **already cryptographically verified**
//! signer index-set, returning an [`Accepted`] receipt or a [`Rejection`]. It
//! performs **no** signature verification — reading only `Siger::index` — so the
//! caller MUST verify every signature upstream before handing events here. This
//! is a soundness requirement: the fold trusts the index-set it is given.
//!
//! [`apply`] is the infallible fold step: given an [`Accepted`] (which already
//! carries the narrowed event and, for transitions, the prior state), it
//! produces the next [`KeyState`].
//!
//! [`fold`] threads state across a sequence of [`SignedEvent`]s. The crate is
//! sans-io: the caller owns the event stream and its ordering.
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use cesr::core::primitives::{Prefixer, Siger};
use cesr::keri::{InceptionEvent, InteractionEvent, KeriEvent, RotationEvent};

use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

mod inception;
mod interaction;
mod rotation;
mod rules;

/// The key-list indices carried by `sigs`, in stream order (duplicates
/// preserved — [`satisfied_by`](crate::threshold::satisfied_by) deduplicates).
pub(crate) fn signed_indices(sigs: &[Siger<'_>]) -> Vec<u32> {
    sigs.iter().map(Siger::index).collect()
}

/// The receipt of a successful [`validate`].
///
/// Each variant carries the **already narrowed** inner event (and, for
/// transitions, the prior state), so [`apply`] never re-narrows a [`KeriEvent`]
/// nor fabricates a prior state. Only the fold constructs an `Accepted`: every
/// variant is `#[non_exhaustive]`, so downstream crates can neither build nor
/// exhaustively destructure it.
///
/// Phase 4 defines only the genesis variant; the K1 rotation/interaction phases
/// add `Rotation`/`Interaction` variants that carry the prior [`KeyState`], which
/// is why the enum is `#[non_exhaustive]`.
#[non_exhaustive]
pub enum Accepted<'a> {
    /// An accepted inception (genesis) — there is no prior state.
    #[non_exhaustive]
    Inception {
        /// The narrowed inception event (`icp`). Delegated inceptions (`dip`)
        /// are rejected upstream (K4 scope), so this is never a delegated event.
        event: &'a InceptionEvent,
        /// The witness set resolved for this event.
        resolved_witnesses: Cow<'a, [Prefixer<'a>]>,
        /// Whether the incepted identifier is transferable, decided once during
        /// validation and carried so `apply` need not recompute it.
        transferable: bool,
    },
    /// An accepted interaction — carries the prior state it folds onto.
    #[non_exhaustive]
    Interaction {
        /// The narrowed interaction event.
        event: &'a InteractionEvent,
        /// The key state this interaction folds onto (cloned at validation time).
        /// Boxed to keep `Accepted`'s variants size-balanced.
        prior: Box<KeyState>,
    },
    /// An accepted rotation — carries the prior state and the resolved witness set.
    #[non_exhaustive]
    Rotation {
        /// The narrowed rotation event (`rot`). Delegated rotations (`drt`) are
        /// rejected upstream (K4 scope), so this is never a delegated event.
        event: &'a RotationEvent,
        /// The state this rotation folds onto (cloned at validation time).
        /// Boxed to keep `Accepted`'s variants size-balanced.
        prior: Box<KeyState>,
        /// Witness set after applying removals then additions.
        resolved_witnesses: Cow<'a, [Prefixer<'a>]>,
    },
}

impl fmt::Debug for Accepted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inception {
                resolved_witnesses,
                transferable,
                ..
            } => f
                .debug_struct("Accepted::Inception")
                .field("resolved_witnesses", resolved_witnesses)
                .field("transferable", transferable)
                .finish_non_exhaustive(),
            Self::Interaction { prior, .. } => f
                .debug_struct("Accepted::Interaction")
                .field("prior_sn", &prior.sn().value())
                .finish_non_exhaustive(),
            Self::Rotation { prior, .. } => f
                .debug_struct("Accepted::Rotation")
                .field("prior_sn", &prior.sn().value())
                .finish_non_exhaustive(),
        }
    }
}

/// A KERI event paired with its signatures and witness receipts.
///
/// `sigs` are indexed controller signatures; `wigs` are indexed witness
/// receipts. Both MUST be cryptographically verified before folding — the fold
/// reads only their indices (see the module docs).
pub struct SignedEvent<'a> {
    /// The event being folded.
    pub event: &'a KeriEvent,
    /// Verified indexed controller signatures.
    pub sigs: Vec<Siger<'a>>,
    /// Verified indexed witness receipts.
    pub wigs: Vec<Siger<'a>>,
}

impl fmt::Debug for SignedEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedEvent")
            .field("ilk", &self.event.ilk())
            .field("sigs", &self.sigs)
            .field("wigs", &self.wigs)
            .finish()
    }
}

/// Decide whether `event` is acceptable against the current `state`.
///
/// Dispatches on `(state, event.ilk())`:
/// - any state + delegated inception/rotation (`dip`/`drt`) → rejected as
///   [`DelegationUnsupported`](RejectionReason::DelegationUnsupported): folding
///   a delegated event requires verifying the delegator's authorizing seal,
///   which is K4 (delegation) scope;
/// - no state + inception → genesis validation;
/// - no state + anything else → out-of-order (missing inception);
/// - state + rotation → rotation validation;
/// - state + interaction → interaction validation;
/// - state + inception → invalid (duplicate inception).
///
/// `sigs`/`wigs` must be cryptographically verified upstream; only their indices
/// are read here.
///
/// # Errors
///
/// Returns a [`Rejection`] describing the first structural or threshold rule the
/// event violates.
pub fn validate<'a>(
    state: Option<&KeyState>,
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
    wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    match (state, event) {
        // Delegated events (`dip`/`drt`) require verifying the delegator's
        // authorizing seal against the delegator's KEL — that is K4 (delegation)
        // scope. K1 has neither the delegator's KEL nor escrow, so it fails
        // closed and rejects them regardless of prior state, rather than fold
        // them unverified.
        (_, KeriEvent::DelegatedInception(_) | KeriEvent::DelegatedRotation(_)) => {
            Err(Rejection::new(RejectionReason::DelegationUnsupported))
        }
        (None, KeriEvent::Inception(_)) => inception::validate(event, sigs, wigs),
        (None, _) => Err(Rejection::new(RejectionReason::OutOfOrder)),
        (Some(prior), KeriEvent::Rotation(_)) => rotation::validate(prior, event, sigs, wigs),
        (Some(prior), KeriEvent::Interaction(_)) => interaction::validate(prior, event, sigs),
        (Some(_), KeriEvent::Inception(_)) => Err(Rejection::new(RejectionReason::InvalidEvent)),
    }
}

/// Fold an [`Accepted`] event into the next [`KeyState`]. Infallible.
///
/// Each [`Accepted`] variant already carries its narrowed inner event (and, for
/// transitions, the prior state), so there is nothing to re-narrow and no
/// unreachable arm: an established event with no prior state is simply not
/// representable.
#[must_use]
pub fn apply(accepted: Accepted<'_>) -> KeyState {
    match accepted {
        Accepted::Inception {
            event,
            resolved_witnesses,
            transferable,
        } => inception::apply(event, &resolved_witnesses, transferable),
        Accepted::Interaction { event, prior } => interaction::apply(prior, event),
        Accepted::Rotation {
            event,
            prior,
            resolved_witnesses,
        } => rotation::apply(prior, event, &resolved_witnesses),
    }
}

/// Fold a sequence of [`SignedEvent`]s into a final [`KeyState`].
///
/// State is threaded left-to-right: each event is [`validate`]d against the
/// running state, then [`apply`]d. `initial` seeds the fold (`None` to begin from
/// a genesis event in the stream). The caller owns and orders the stream — `keri`
/// is sans-io.
///
/// # Errors
///
/// Returns the first [`Rejection`] produced by [`validate`], or an
/// [`InvalidEvent`](RejectionReason::InvalidEvent) rejection if the stream is
/// empty and no `initial` state was supplied.
pub fn fold<'a>(
    initial: Option<KeyState>,
    events: impl IntoIterator<Item = SignedEvent<'a>>,
) -> Result<KeyState, Rejection> {
    let mut state = initial;
    for signed in events {
        let accepted = validate(state.as_ref(), signed.event, &signed.sigs, &signed.wigs)?;
        let next = apply(accepted);
        state = Some(next);
    }
    state.ok_or_else(|| Rejection::new(RejectionReason::InvalidEvent))
}
