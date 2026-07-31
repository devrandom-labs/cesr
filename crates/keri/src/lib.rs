//! `keri` — sans-IO KERI (Key Event Receipt Infrastructure) core, built on the
//! public API of the `cesr` crate. It exposes the key-state transition:
//! [`KeyState::incept`] seeds the fold from a genesis event and
//! [`KeyState::ingest`] folds one signed event onto a running state, returning the
//! next [`KeyState`] or a [`Rejection`]. The state borrows from the events the
//! caller keeps alive, so the transition allocates nothing but a recomputed
//! witness set. The caller owns the stream and its ordering — this crate does no
//! I/O — and drives the transition over its own iterator or stream with
//! `try_fold`.
//!
//! Verification lives **inside** the transition: the keys that verify an event are
//! resolved from the state itself for interactions (which carry no keys) and from
//! the event for establishment events, then every controller signature is
//! cryptographically verified before the state advances. Witness receipts are
//! verified too — each receipt against the witness its index selects in the
//! event's governing witness set, with at least TOAD distinct valid receipts
//! required ([`Witnessing`]).
//!
//! **Two folds, one domain.** The validating fold above runs at decide time —
//! an event is *proposed*, so it carries proof obligations (signatures,
//! commitment openings, receipts). [`KeyStateSnapshot`] is the owned,
//! `'static` dual for storage-facing hosts: [`KeyStateSnapshot::view`] lends
//! the zero-copy working state back, and the trusted fold
//! ([`KeyStateSnapshot::genesis`], [`KeyStateSnapshot::advance`]) replays
//! ACCEPTED events totally and crypto-free — validation never runs twice.
//! An event-sourced host keeps the snapshot as aggregate state, validates
//! proposals through [`KeyState::ingest`], and rehydrates with the trusted
//! fold. `keri` itself stores nothing and looks nothing up: evidence a rule
//! needs arrives as arguments (delegation and receipt evidence are K4/K5).
//!
//! **Sans-io by default; `wire` is the optional edge.** Per #128 the core takes
//! parsed borrowed values — never wire bytes — and the default features keep it
//! that way (no `keri-codec` in the dependency graph). Enabling the `wire`
//! feature adds one adapter at the edge: `Signed: From<&keri_codec::EventMessage>`,
//! so `EventMessage::parse` output feeds the fold directly and the
//! [`Signed::signed_bytes`] provenance contract is held by construction instead
//! of by convention.
//!
//! **Delegation is validated over typed evidence, never a walk.** The
//! delegator's KEL is the host's stream: the host folds it and supplies the
//! anchoring event plus the delegator's state as [`DelegationEvidence`];
//! [`KeyState::incept_delegated`] and [`KeyState::ingest_delegated`] check
//! the seal binding, delegator identity, and do-not-delegate rule by digest
//! comparison alone. A dip/drt reaching the plain entries parks as
//! [`Awaiting(DelegationEvidence)`](Disposition::Awaiting) until the host
//! re-drives it with evidence.
//!
//! **Escrow is a classification, not a subsystem.** For every [`Rejection`]
//! the fold owes exactly one extra bit of judgment:
//! [`Rejection::disposition`] says whether the event is
//! [`Terminal`](Disposition::Terminal) (never acceptable — drop) or
//! [`Awaiting`](Disposition::Awaiting) specific
//! [`EvidenceKind`] (park and re-drive when it arrives). Storage, timers,
//! and retry scheduling are the host's.
//!
//! **Receipts are judged one at a time; accumulation is host state.** A
//! receipt arriving after its event was accepted (its own `rct` message,
//! not an inline attachment) is judged against the host-asserted accepted
//! event as [`ReceiptedEvent`]: the stale check binds the receipt's
//! `(prefix, sn, said)` coordinate, a late witness receipt is judged by
//! [`Witnessing::receipt`], a non-transferable endorsement may promote
//! into the witness set via [`Witnessing::witness_index`], and a
//! transferable endorsement needs the receiptor's establishment event as
//! typed evidence ([`ReceiptedEvent::endorsed_by`]). The TOAD verdict runs
//! over the host-accumulated distinct witness set via
//! [`Witnessing::accounted_by`] — the core keeps no counters or tables —
//! and [`ReceiptError::disposition`] classifies every failure as terminal
//! or awaiting specific evidence.
//!
//! **Duplicity and superseding recovery are a judgment, not a lookup.** When
//! the fold rejects an event whose sn the KEL already occupies
//! ([`Disposition::Contested`]), the host supplies what it has recorded —
//! the event at that sn, plus delegating-event pairs for delegated contests —
//! and [`KeyState::judge_same_sn`] returns a [`SameSnVerdict`]: duplicate,
//! duplicitous, superseding recovery, an inferior claim, or undecided
//! pending deeper evidence. On `Supersedes` the host rewinds its own stream
//! and re-drives the validating fold; the core never stores or replays.
#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod authority;
/// Delegation validation over typed evidence.
pub mod delegation;
/// Duplicity detection and superseding recovery.
pub mod duplicity;
/// Validation verdict types.
pub mod error;
/// Out-of-band receipt validation as pure judgments (K5).
pub mod receipt;
/// Computed key state for a KERI identifier.
pub mod state;
#[cfg(feature = "wire")]
mod wire;

pub use authority::{Authority, Commitment, Establishment, Verified, Witnessing};
pub use delegation::{AnchoredDelegation, DelegationEvidence};
pub use duplicity::{DelegationContest, EvidenceError, SameSnVerdict};
pub use error::{
    DelegationError, Disposition, EvidenceKind, Rejection, StructuralError, TransferabilityError,
    WitnessSetError,
};
pub use receipt::{
    ReceiptError, ReceiptedEvent, ReceiptorEstablishment, TransferableEndorsement, WitnessIndex,
};
pub use state::{EstablishmentRef, KeyState, KeyStateSnapshot, Signed, Transferability};

#[cfg(test)]
mod tests {
    // Proves `keri` compiles against and links a real, PUBLIC `cesr` item (the same
    // path fuzz-common uses). Would fail to compile if the dependency were mis-wired
    // or if this reached a non-public path.
    use cesr::core::matter::builder::MatterBuilder;

    #[test]
    fn links_cesr_public_api() {
        // Empty input is not a valid qualified-base64 primitive: the public decoder
        // must return Err (and, per the parser contract, never panic).
        let empty: &[u8] = &[];
        assert!(MatterBuilder::new().from_qualified_base64(empty).is_err());
    }
}
