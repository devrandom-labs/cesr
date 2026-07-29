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
//! **Delegation authorization is deferred to K4.** Verifying a delegated event's
//! authorizing seal requires the delegator's KEL, which this crate does not have,
//! so delegated inceptions/rotations (`dip`/`drt`) are rejected
//! ([`DelegationUnsupported`](Rejection::DelegationUnsupported)) rather than
//! accepted unverified.
//!
//! **Escrow is a classification, not a subsystem.** For every [`Rejection`]
//! the fold owes exactly one extra bit of judgment:
//! [`Rejection::disposition`] says whether the event is
//! [`Terminal`](Disposition::Terminal) (never acceptable — drop) or
//! [`Awaiting`](Disposition::Awaiting) specific
//! [`EvidenceKind`] (park and re-drive when it arrives). Storage, timers,
//! and retry scheduling are the host's.
#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod authority;
/// Validation verdict types.
pub mod error;
/// Computed key state for a KERI identifier.
pub mod state;
#[cfg(feature = "wire")]
mod wire;

pub use authority::{Authority, Commitment, Establishment, Verified, Witnessing};
pub use error::{
    Disposition, EvidenceKind, Rejection, StructuralError, TransferabilityError, WitnessSetError,
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
