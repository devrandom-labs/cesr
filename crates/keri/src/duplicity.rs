//! Duplicity detection and superseding recovery: pure judgment on an event
//! that contests an already-occupied sequence number.
//!
//! The host owns the stream: it already knows what is recorded at `(pre, sn)`
//! and supplies it as evidence; the core classifies coordinates and recovery
//! priority. This judge receives parsed events without signatures. A
//! [`SameSnVerdict::Duplicitous`] result is a possible conflict to authenticate,
//! never durable proof that the candidate's controller signed it. On
//! [`SameSnVerdict::Supersedes`]
//! the host rewinds its stream to `sn - 1`, re-folds, and re-ingests the
//! incoming event through the validating fold ([`KeyState::ingest`]) — the
//! prior-digest check against the recorded `sn - 1` event and all
//! signature/commitment/witness validation happen there, never here.
//!
//! keripy conformance (main `9161a705`): the same-sn acceptance gate is
//! `Kevery.processEvent` (eventing.py:4396-4413, icp branch 4362-4392,
//! duplicate-vs-duplicitous 4447-4478); the drt-over-drt cascade is
//! `Kever.validateDelegation` (eventing.py:3413-3492). keripy walks its own
//! database (`fetchDelegatingEvent`) recursively; here the chain arrives as a
//! slice of [`DelegationContest`] pairs, so the climb is a bounded iteration
//! and an adversarial recursion bomb is unrepresentable.
use keri_events::{Identifier, KeriEvent, MessageType, Said};

use crate::state::KeyState;

/// Structural judgment on an event contesting an already-occupied sn.
///
/// No variant authenticates the incoming candidate. Hosts must validate its
/// signed bytes and signatures against the appropriate historical authority
/// before retaining or reporting a fork as proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSnVerdict<'a> {
    /// Same SAID as the recorded event — idempotent. The host may verify and
    /// log late-arriving signatures (keripy logs them; eventing.py:4449-4472).
    Duplicate,
    /// A recovery rule fired. The host rewinds to `sn - 1`, re-folds, and
    /// re-ingests the incoming event through the validating fold.
    Supersedes,
    /// Different SAID and no recovery rule applies — an unauthenticated
    /// conflict candidate. keripy escrows these for later duplicity reporting
    /// (`escrowLDEvent`); this verdict alone is not signed fork evidence.
    Duplicitous {
        /// SAID of the recorded event, for watcher reporting.
        recorded: &'a Said<'a>,
    },
    /// Cascade loss: same delegating event, and the challenger's seal does
    /// not come after the incumbent's (B2). An inferior recovery claim —
    /// keripy drops it with a bare `ValidationError` (eventing.py:3467-3475),
    /// not duplicity escrow. Drop quietly.
    Yields,
    /// The delegation-chain evidence ran out before a decision (keripy
    /// escrows as missing-delegation, eventing.py:3480-3489). Park and
    /// re-judge when deeper chain evidence arrives.
    Undecided,
}

/// One level of the drt-over-drt climb: the two delegating events whose
/// contest decides (or defers) the level below.
#[derive(Clone, Copy)]
pub struct DelegationContest<'a> {
    /// Delegating event on the recorded (incumbent) side.
    pub incumbent: &'a KeriEvent<'a>,
    /// Delegating event on the incoming (challenger) side.
    pub challenger: &'a KeriEvent<'a>,
}

/// Host-supplied evidence is inconsistent with the state or with itself.
/// Boundary validation — a typed error, never a verdict.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    /// The candidate belongs to a different identifier than this state.
    #[error("incoming contest event names a different identifier")]
    IncomingIdentifierMismatch,
    /// The purported accepted event belongs to a different identifier.
    #[error("recorded contest event names a different identifier")]
    RecordedIdentifierMismatch,
    /// At the state head, the host's recorded event differs from the accepted head.
    #[error("recorded contest event does not match the current state head")]
    RecordedHeadMismatch,
    /// The purported last establishment does not match the state's bookmark.
    #[error("recorded contest event does not match the last establishment")]
    RecordedEstablishmentMismatch,
    /// An event after the last establishment must be an interaction.
    #[error("recorded event after the last establishment is not an interaction")]
    RecordedPostEstablishmentKind,
    /// A delegating pair is not on the expected delegator KEL.
    #[error("delegating contest events at level {level} name inconsistent identifiers")]
    DelegatingIdentifierMismatch {
        /// Zero-based delegation-chain level.
        level: usize,
    },
    /// The proposed recovery event cannot advance this identifier's
    /// delegated or ordinary establishment chain, even after rewind.
    #[error("recovery event kind {event_kind:?} is incompatible with delegated={delegated} state")]
    IncompatibleEventKind {
        /// Incoming event kind.
        event_kind: MessageType,
        /// Whether the current identifier is delegated.
        delegated: bool,
    },
    /// The incoming event's sn is beyond the state head — not a same-sn
    /// contest at all (the fold's out-of-order path owns it).
    #[error("incoming sn {incoming_sn} is not stale for state at sn {state_sn}")]
    IncomingNotStale {
        /// The incoming event's sequence number.
        incoming_sn: u128,
        /// The state head's sequence number.
        state_sn: u128,
    },
    /// The recorded event is not at the incoming event's sn.
    #[error("recorded event sn {recorded_sn} does not match incoming sn {incoming_sn}")]
    RecordedSnMismatch {
        /// The incoming event's sequence number.
        incoming_sn: u128,
        /// The recorded event's sequence number.
        recorded_sn: u128,
    },
    /// A delegating event at this chain level carries no event-seal matching
    /// the `(i, s, d)` of the delegated event below it — the pair is not a
    /// delegation link. keripy assumes database linkage and would crash here
    /// (`nseals.index`, eventing.py:3459); host-supplied evidence gets a
    /// typed error instead.
    #[error("delegating event at chain level {level} carries no seal of its delegated event")]
    SealNotFound {
        /// Zero-based level in `delegation_chain` (0 = nearest the contest).
        level: usize,
    },
}

impl KeyState<'_> {
    /// Judge an incoming same-sn event against what the host has recorded.
    ///
    /// `recorded` is the accepted event at the incoming event's sn;
    /// `delegation_chain` carries the delegating-event pairs for the
    /// drt-over-drt cascade, ordered from the contest upward (empty for
    /// non-delegated contests). This compares event coordinates only: the
    /// incoming event has no signatures here, so a `Duplicitous` verdict
    /// must be authenticated against the appropriate historical key state
    /// before it can be retained or reported as fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] when the supplied evidence is inconsistent:
    /// the incoming event is not stale, the recorded event is at a different
    /// sn, the event kind cannot advance this identifier, or a chain pair is
    /// not seal-linked to the level below.
    pub fn judge_same_sn<'a>(
        &self,
        incoming: &KeriEvent<'_>,
        recorded: &'a KeriEvent<'a>,
        delegation_chain: &[DelegationContest<'_>],
    ) -> Result<SameSnVerdict<'a>, EvidenceError> {
        let incoming_sn = incoming.sn().value();
        let state_sn = self.sn().value();
        if incoming_sn > state_sn {
            return Err(EvidenceError::IncomingNotStale {
                incoming_sn,
                state_sn,
            });
        }
        let recorded_sn = recorded.sn().value();
        if recorded_sn != incoming_sn {
            return Err(EvidenceError::RecordedSnMismatch {
                incoming_sn,
                recorded_sn,
            });
        }
        if incoming.prefix() != self.prefix() {
            return Err(EvidenceError::IncomingIdentifierMismatch);
        }
        if recorded.prefix() != self.prefix() {
            return Err(EvidenceError::RecordedIdentifierMismatch);
        }
        if recorded_sn == state_sn
            && (recorded.said() != self.latest_said()
                || recorded.message_type() != self.latest_message_type())
        {
            return Err(EvidenceError::RecordedHeadMismatch);
        }
        let delegated = self.delegator().is_some();
        self.check_recorded_history(recorded, recorded_sn, delegated)?;
        if matches!(incoming, KeriEvent::Rotation(_)) && delegated
            || matches!(incoming, KeriEvent::DelegatedRotation(_)) && !delegated
        {
            return Err(EvidenceError::IncompatibleEventKind {
                event_kind: incoming.message_type(),
                delegated,
            });
        }
        let last_est_sn = self.last_establishment().sn.value();
        match incoming {
            // Inceptions and interactions supersede nothing (gate: only rot
            // and drt have recovery ranges; icp handled at eventing.py:4362).
            KeriEvent::Inception(_)
            | KeriEvent::DelegatedInception(_)
            | KeriEvent::Interaction(_) => Ok(said_verdict(incoming, recorded)),
            // rot recovery: lastEst.s < sn <= expected (eventing.py:4409).
            // The bound IS rule A1 (a rot never supersedes a rot: every sn
            // above lastEst.s holds an interaction) and implies A0.
            KeriEvent::Rotation(_) => {
                if last_est_sn < incoming_sn {
                    Ok(SameSnVerdict::Supersedes)
                } else {
                    Ok(said_verdict(incoming, recorded))
                }
            }
            // drt recovery: lastEst.s <= sn <= expected (eventing.py:4411) —
            // a drt may supersede the establishment event itself, so the
            // recorded event decides the branch.
            KeriEvent::DelegatedRotation(_) => {
                if last_est_sn <= incoming_sn {
                    match recorded {
                        KeriEvent::Interaction(_) => Ok(SameSnVerdict::Supersedes),
                        KeriEvent::DelegatedRotation(_) => {
                            let delegator = self.delegator().ok_or_else(|| {
                                EvidenceError::IncompatibleEventKind {
                                    event_kind: incoming.message_type(),
                                    delegated: false,
                                }
                            })?;
                            cascade(incoming, recorded, delegation_chain, delegator)
                        }
                        // A drt contesting a recorded icp/dip/rot has no
                        // keripy-sane path (a delegated identifier's
                        // establishment events are dip/drt): SAID-compare.
                        KeriEvent::Inception(_)
                        | KeriEvent::DelegatedInception(_)
                        | KeriEvent::Rotation(_) => Ok(said_verdict(incoming, recorded)),
                    }
                } else {
                    Ok(said_verdict(incoming, recorded))
                }
            }
        }
    }

    /// Bind host-supplied history to this state's establishment bookmark
    /// wherever the current state has enough information to check it.
    fn check_recorded_history(
        &self,
        recorded: &KeriEvent<'_>,
        recorded_sn: u128,
        delegated: bool,
    ) -> Result<(), EvidenceError> {
        let last_est = self.last_establishment();
        if recorded_sn == last_est.sn.value() {
            let expected_kind = match (delegated, recorded_sn == 0) {
                (false, true) => MessageType::Icp,
                (false, false) => MessageType::Rot,
                (true, true) => MessageType::Dip,
                (true, false) => MessageType::Drt,
            };
            if recorded.said() != last_est.said || recorded.message_type() != expected_kind {
                return Err(EvidenceError::RecordedEstablishmentMismatch);
            }
        } else if recorded_sn > last_est.sn.value() && recorded.message_type() != MessageType::Ixn {
            return Err(EvidenceError::RecordedPostEstablishmentKind);
        }
        Ok(())
    }
}

/// Same SAID → duplicate; different SAID with no recovery rule → duplicitous
/// (eventing.py:4448-4478).
fn said_verdict<'a>(incoming: &KeriEvent<'_>, recorded: &'a KeriEvent<'a>) -> SameSnVerdict<'a> {
    if incoming.said() == recorded.said() {
        SameSnVerdict::Duplicate
    } else {
        SameSnVerdict::Duplicitous {
            recorded: recorded.said(),
        }
    }
}

/// The drt-over-drt climb (`validateDelegation`, eventing.py:3413-3492),
/// with keripy's recursive database walk replaced by the host-supplied pair
/// slice. Every level is first proven to be a delegation link (seal lookup on
/// both sides — keripy gets this from its `aess` index by construction), then
/// judged: B1 later-delegating-sn wins; B3 delegating drt beats delegating
/// ixn; B2 same delegating event → later seal position wins, else the
/// challenger yields; anything else is a tie — climb. Chain exhausted →
/// undecided.
fn cascade<'a>(
    incoming: &KeriEvent<'_>,
    recorded: &'a KeriEvent<'a>,
    chain: &[DelegationContest<'_>],
    expected_delegator: &Identifier<'_>,
) -> Result<SameSnVerdict<'a>, EvidenceError> {
    let mut delegated_old: &KeriEvent<'_> = recorded;
    let mut delegated_new: &KeriEvent<'_> = incoming;
    for (level, contest) in chain.iter().enumerate() {
        if contest.incumbent.prefix() != contest.challenger.prefix()
            || (level == 0 && contest.incumbent.prefix() != expected_delegator)
        {
            return Err(EvidenceError::DelegatingIdentifierMismatch { level });
        }
        let challenger_pos = contest
            .challenger
            .anchor_position(delegated_new)
            .ok_or(EvidenceError::SealNotFound { level })?;
        let incumbent_pos = contest
            .incumbent
            .anchor_position(delegated_old)
            .ok_or(EvidenceError::SealNotFound { level })?;
        // B1 (eventing.py:3444): later delegating sn wins.
        if contest.challenger.sn().value() > contest.incumbent.sn().value() {
            return Ok(SameSnVerdict::Supersedes);
        }
        // B3 (eventing.py:3445-3446): delegating drt beats delegating ixn.
        if contest.challenger.message_type() == MessageType::Drt
            && contest.incumbent.message_type() == MessageType::Ixn
        {
            return Ok(SameSnVerdict::Supersedes);
        }
        // B2 (eventing.py:3450-3475): same delegating event — the later seal
        // position wins; otherwise the challenger's claim is inferior.
        if contest.challenger.said() == contest.incumbent.said() {
            return Ok(if challenger_pos > incumbent_pos {
                SameSnVerdict::Supersedes
            } else {
                SameSnVerdict::Yields
            });
        }
        // C (eventing.py:3477-3491): tie — climb one level. keripy climbs
        // without comparing sns further (even challenger.sn < incumbent.sn
        // climbs); mirrored deliberately for parity.
        delegated_old = contest.incumbent;
        delegated_new = contest.challenger;
    }
    Ok(SameSnVerdict::Undecided)
}
