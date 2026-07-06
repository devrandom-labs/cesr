//! `keri` — sans-IO KERI (Key Event Receipt Infrastructure) core, built on the
//! public API of the `cesr` crate. It exposes the pure key-state fold: a
//! decide/apply split where [`validate`] turns a `(state, event, sigs, wigs)`
//! tuple into an [`Accepted`] receipt (or a [`Rejection`]), [`apply`] folds an
//! [`Accepted`] into the next [`KeyState`], and [`fold`] threads that fold across
//! an ordered event sequence. The caller owns the stream and its ordering — this
//! crate does no I/O.
//!
//! Two trust boundaries bound the fold and are the caller's responsibility:
//!
//! - **Signatures are verified upstream.** The fold reads only signature indices
//!   ([`Siger::index`](cesr::core::primitives::Siger::index)) — it performs no
//!   cryptographic verification. Every controller signature and witness receipt
//!   MUST be verified before its event is handed to the fold; folding an
//!   unverified signature is a caller soundness bug, not something the fold can
//!   detect.
//! - **Delegation authorization is deferred to K4.** Verifying a delegated
//!   event's authorizing seal requires the delegator's KEL, which this crate does
//!   not have, so delegated inceptions/rotations (`dip`/`drt`) are rejected
//!   ([`DelegationUnsupported`](RejectionReason::DelegationUnsupported)) rather
//!   than accepted unverified.
#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Validation verdict types.
pub mod error;
/// The pure key-state fold: `validate`, `apply`, `fold`.
pub mod fold;
/// Computed key state for a KERI identifier.
pub mod state;
/// Signing-threshold satisfaction over a signer index-set.
pub mod threshold;

pub use error::{Rejection, RejectionReason};
pub use fold::{Accepted, SignedEvent, apply, fold, validate};
pub use state::{EstablishmentRef, KeyState};

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
