//! The pure key-state fold — the decide/apply split at the heart of `keri`.
//!
//! [`validate`] is the fallible decision step: it applies KERI's structural
//! rules and threshold arithmetic over an **already cryptographically verified**
//! signer index-set, returning an [`Accepted`] receipt or a [`Rejection`]. It
//! performs **no** signature verification — reading only `Siger::index` — so the
//! caller MUST verify every signature upstream before handing events here. This
//! is a soundness requirement: the fold trusts the index-set it is given.
//!
//! [`apply`] is the infallible fold step: given the prior state and an
//! [`Accepted`], it produces the next [`KeyState`].
//!
//! [`fold`] threads state across a sequence of [`SignedEvent`]s. The crate is
//! sans-io: the caller owns the event stream and its ordering.
use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use cesr::core::primitives::{Prefixer, Seqner, Siger, Tholder};
use cesr::keri::{Ilk, KeriEvent};

use crate::error::{Rejection, RejectionReason};
use crate::state::{EstablishmentRef, KeyState};

mod inception;
mod interaction;
mod rotation;

/// The key-list indices carried by `sigs`, in stream order (duplicates
/// preserved — [`satisfied_by`](crate::threshold::satisfied_by) deduplicates).
pub(crate) fn signed_indices(sigs: &[Siger<'_>]) -> Vec<u32> {
    sigs.iter().map(Siger::index).collect()
}

/// The receipt of a successful [`validate`]: the accepted event plus the witness
/// set resolved for it. Consumed by [`apply`] to produce the next [`KeyState`].
///
/// Fields are `pub(crate)`: only the fold constructs an `Accepted`.
pub struct Accepted<'a> {
    pub(crate) event: &'a KeriEvent,
    pub(crate) resolved_witnesses: Cow<'a, [Prefixer<'a>]>,
}

impl fmt::Debug for Accepted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("ilk", &self.event.ilk())
            .field("resolved_witnesses", &self.resolved_witnesses)
            .finish()
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
    state: Option<&KeyState<'_>>,
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
    wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    match (state, event) {
        (None, KeriEvent::Inception(_) | KeriEvent::DelegatedInception(_)) => {
            inception::validate(event, sigs, wigs)
        }
        (None, _) => Err(Rejection::new(RejectionReason::OutOfOrder)),
        (Some(prior), KeriEvent::Rotation(_) | KeriEvent::DelegatedRotation(_)) => {
            rotation::validate(prior, event, sigs, wigs)
        }
        (Some(prior), KeriEvent::Interaction(_)) => interaction::validate(prior, event, sigs),
        (Some(_), KeriEvent::Inception(_) | KeriEvent::DelegatedInception(_)) => {
            Err(Rejection::new(RejectionReason::InvalidEvent))
        }
    }
}

/// Fold an [`Accepted`] event into the next [`KeyState`]. Infallible.
///
/// Matches the event variant and dispatches the **already narrowed** inner event
/// to the per-ilk apply function, so no arm can be unreachable. `state` is the
/// prior key state — `None` only for a genesis (inception) event.
#[must_use]
pub fn apply<'a>(state: Option<&KeyState<'a>>, accepted: &Accepted<'a>) -> KeyState<'a> {
    match accepted.event {
        KeriEvent::Inception(icp) => inception::apply(icp, None, accepted),
        KeriEvent::DelegatedInception(dip) => {
            inception::apply(dip.inception(), Some(dip.delegator()), accepted)
        }
        KeriEvent::Rotation(rot) => {
            let Some(prior) = state else {
                return stub_state(accepted);
            };
            rotation::apply(prior, rot, accepted)
        }
        KeriEvent::DelegatedRotation(drt) => {
            let Some(prior) = state else {
                return stub_state(accepted);
            };
            rotation::apply(prior, drt.rotation(), accepted)
        }
        KeriEvent::Interaction(ixn) => {
            let Some(prior) = state else {
                return stub_state(accepted);
            };
            interaction::apply(prior, ixn, accepted)
        }
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
    initial: Option<KeyState<'a>>,
    events: impl IntoIterator<Item = SignedEvent<'a>>,
) -> Result<KeyState<'a>, Rejection> {
    let mut state = initial;
    for signed in events {
        let accepted = validate(state.as_ref(), signed.event, &signed.sigs, &signed.wigs)?;
        let next = apply(state.as_ref(), &accepted);
        state = Some(next);
    }
    state.ok_or_else(|| Rejection::new(RejectionReason::InvalidEvent))
}

/// Total, panic-free fallback for the (impossible) case of applying an
/// established event with no prior state. The fold's dispatch guarantees a prior
/// state is present for every non-genesis event, so this is never reached at
/// runtime — it exists only to keep [`apply`] infallible and exhaustive without
/// a `panic`/`unreachable`. Produces an empty placeholder carrying the event's
/// identity.
fn stub_state<'a>(accepted: &Accepted<'a>) -> KeyState<'a> {
    let (prefix, sn, said, ilk) = match accepted.event {
        KeriEvent::Inception(e) => (
            e.prefix().clone(),
            e.sn().value(),
            e.said().clone(),
            Ilk::Icp,
        ),
        KeriEvent::DelegatedInception(e) => {
            let inner = e.inception();
            (
                inner.prefix().clone(),
                inner.sn().value(),
                inner.said().clone(),
                Ilk::Dip,
            )
        }
        KeriEvent::Rotation(e) => (
            e.prefix().clone(),
            e.sn().value(),
            e.said().clone(),
            Ilk::Rot,
        ),
        KeriEvent::DelegatedRotation(e) => {
            let inner = e.rotation();
            (
                inner.prefix().clone(),
                inner.sn().value(),
                inner.said().clone(),
                Ilk::Drt,
            )
        }
        KeriEvent::Interaction(e) => (
            e.prefix().clone(),
            e.sn().value(),
            e.said().clone(),
            Ilk::Ixn,
        ),
    };
    KeyState {
        prefix,
        sn: Seqner::new(sn),
        latest_said: said.clone(),
        latest_ilk: ilk,
        keys: Cow::Owned(Vec::new()),
        threshold: Tholder::Simple(0),
        next_keys: Cow::Owned(Vec::new()),
        next_threshold: Tholder::Simple(0),
        witnesses: Cow::Owned(accepted.resolved_witnesses.to_vec()),
        witness_threshold: 0,
        config: Cow::Owned(Vec::new()),
        delegator: None,
        transferable: false,
        last_est: EstablishmentRef {
            sn: Seqner::new(sn),
            said,
        },
    }
}
