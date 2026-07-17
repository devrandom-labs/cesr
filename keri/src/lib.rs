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
//! **Sans-io by default; `wire` is the optional edge.** Per #128 the core takes
//! parsed borrowed values — never wire bytes — and the default features keep it
//! that way (no `cesr/serder` in the dependency graph). Enabling the `wire`
//! feature adds one adapter at the edge: `Signed: From<&cesr::serder::EventMessage>`,
//! so `EventMessage::parse` output feeds the fold directly and the
//! [`Signed::signed_bytes`] provenance contract is held by construction instead
//! of by convention.
//!
//! **Delegation authorization is deferred to K4.** Verifying a delegated event's
//! authorizing seal requires the delegator's KEL, which this crate does not have,
//! so delegated inceptions/rotations (`dip`/`drt`) are rejected
//! ([`DelegationUnsupported`](Rejection::DelegationUnsupported)) rather than
//! accepted unverified.
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

pub use authority::{Authority, Commitment, Establishment, Witnessing};
pub use error::{Rejection, StructuralError, TransferabilityError, WitnessSetError};
pub use state::{EstablishmentRef, KeyState, Signed, Transferability};

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
