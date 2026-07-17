#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;
/// ISO-8601 datetime primitive encoded as CESR Matter.
pub mod dater;
/// Unsigned integer primitive with automatic CESR code selection.
pub mod number;
/// Sequence number primitive wrapping [`Number`].
pub mod seqner;
/// Indexed signature primitive with optional verfer attachment.
pub mod siger;
use crate::core::matter::code::{
    DigestCode, LabelerCode, NoncerCode, SeedCode, SignatureCode, TexterCode, VerKeyCode,
    VerserCode,
};
use crate::core::matter::matter::Matter;

pub use dater::Dater;
pub use number::Number;
pub use seqner::Seqner;
pub use siger::Siger;

/// Verification key — can verify signatures
pub type Verfer<'a> = Matter<'a, VerKeyCode>;

/// Digest — holds a hash value
pub type Diger<'a> = Matter<'a, DigestCode>;

/// Signing key seed — can produce signatures (actual crypto in cesr-crypto)
pub type Signer<'a> = Matter<'a, SeedCode>;

/// Non-indexed signature
pub type Cigar<'a> = Matter<'a, SignatureCode>;

/// Self-addressing identifier (SAID) — a digest used as a content identifier
pub type Saider<'a> = Matter<'a, DigestCode>;

/// AID prefix — a verification key used as an autonomic identifier
pub type Prefixer<'a> = Matter<'a, VerKeyCode>;

/// Version primitive — encodes protocol/genus version info
pub type Verser<'a> = Matter<'a, VerserCode>;

/// Nonce/UUID primitive — salt, digest, or empty
pub type Noncer<'a> = Matter<'a, NoncerCode>;

/// Label primitive — field name or tag
pub type Labeler<'a> = Matter<'a, LabelerCode>;

/// Text primitive — variable-length byte string
pub type Texter<'a> = Matter<'a, TexterCode>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use alloc::borrow::Cow;

    #[test]
    fn verfer_is_matter_with_verkey_code() {
        let code = VerKeyCode::Ed25519;
        let raw = vec![0u8; 32];
        let verfer: Verfer<'_> =
            crate::core::matter::matter::Matter::new(code, Cow::Owned(raw), Cow::from(""));
        assert_eq!(*verfer.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn saider_is_matter_with_digest_code() {
        let code = DigestCode::Blake3_256;
        let raw = vec![0u8; 32];
        let saider: Saider<'_> =
            crate::core::matter::matter::Matter::new(code, Cow::Owned(raw), Cow::from(""));
        assert_eq!(*saider.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn prefixer_is_matter_with_verkey_code() {
        let code = VerKeyCode::Ed25519;
        let raw = vec![0u8; 32];
        let prefixer: Prefixer<'_> =
            crate::core::matter::matter::Matter::new(code, Cow::Owned(raw), Cow::from(""));
        assert_eq!(*prefixer.code(), VerKeyCode::Ed25519);
    }
}
