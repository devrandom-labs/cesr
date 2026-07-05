//! `keri` — sans-IO KERI (Key Event Receipt Infrastructure) core, built on the
//! public API of the `cesr` crate. This is the K0 skeleton: infrastructure only,
//! no KERI types yet (those arrive in K1+). Its sole purpose today is to prove the
//! workspace + the `cesr` public-API dependency are wired correctly.
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
