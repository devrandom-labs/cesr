#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String};

use crate::core::matter::Matter;
use crate::core::primitives::{Cigar, Siger};
use crate::crypto::algo::Algorithm;

/// A CESR signature primitive that can be verified against a key pair's
/// algorithm.
///
/// Implemented by both the non-indexed [`Cigar`] and the indexed [`Siger`], so a
/// single generic `verify` covers both forms with compile-time dispatch — the
/// caller never branches on "indexed or not". The algorithm-ownership check
/// ([`belongs_to`](Signature::belongs_to)) is the one runtime seam, because a
/// signature parsed off the wire carries a dynamic code.
pub trait Signature {
    /// The raw signature bytes to verify.
    fn raw(&self) -> &[u8];

    /// Returns `true` if this signature's CESR code belongs to algorithm `A`.
    ///
    /// For a [`Cigar`] this compares against the algorithm's single signature
    /// code; for a [`Siger`] it accepts any of the algorithm's indexed-signature
    /// code variants (small/big, current/both).
    fn belongs_to<A: Algorithm>(&self) -> bool;

    /// The signature's CESR code rendered for diagnostics (error messages).
    fn code_name(&self) -> String;
}

impl Signature for Cigar<'_> {
    fn raw(&self) -> &[u8] {
        Matter::raw(self)
    }

    fn belongs_to<A: Algorithm>(&self) -> bool {
        *self.code() == A::SIGNATURE_CODE
    }

    fn code_name(&self) -> String {
        format!("{:?}", self.code())
    }
}

impl Signature for Siger<'_> {
    fn raw(&self) -> &[u8] {
        Siger::raw(self)
    }

    fn belongs_to<A: Algorithm>(&self) -> bool {
        A::owns_indexed(self.code())
    }

    fn code_name(&self) -> String {
        format!("{:?}", self.code())
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test assertions use unwrap for clarity"
)]
mod tests {
    use super::*;
    use crate::core::indexer::code::IndexMode;
    use crate::core::matter::code::VerKeyCode;
    use crate::crypto::algo::{Ed25519, Secp256k1, Secp256r1};
    use crate::crypto::keypair::KeyPair;

    #[test]
    fn cigar_belongs_only_to_its_own_algorithm() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let cigar = kp.sign(b"m").unwrap();
        assert!(Signature::belongs_to::<Ed25519>(&cigar));
        assert!(!Signature::belongs_to::<Secp256k1>(&cigar));
        assert!(!Signature::belongs_to::<Secp256r1>(&cigar));
    }

    #[test]
    fn siger_belongs_only_to_its_own_algorithm() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let siger = kp.sign_indexed(b"m", 7, IndexMode::Both).unwrap();
        assert!(Signature::belongs_to::<Secp256k1>(&siger));
        assert!(!Signature::belongs_to::<Ed25519>(&siger));
        assert!(!Signature::belongs_to::<Secp256r1>(&siger));
    }

    #[test]
    fn raw_and_code_name_delegate_to_the_primitive() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let cigar = kp.sign(b"m").unwrap();
        assert_eq!(Signature::raw(&cigar), Matter::raw(&cigar));
        assert_eq!(cigar.code_name(), "Ed25519Sig");

        let _ = kp.verfer(VerKeyCode::Ed25519).unwrap();
    }
}
