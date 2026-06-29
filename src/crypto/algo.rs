use cesr_core::indexer::code::IndexedSigCode;
use cesr_core::matter::code::{SeedCode, SignatureCode, VerKeyCode};

mod private {
    pub trait Sealed {}
}

/// Sealed trait implemented by each supported algorithm marker type.
pub trait Algorithm: private::Sealed {
    /// CESR seed code for this algorithm's private key material.
    const SEED_CODE: SeedCode;
    /// CESR verification key code (transferable prefix).
    const VERKEY_CODE: VerKeyCode;
    /// CESR verification key code (non-transferable prefix).
    const VERKEY_CODE_N: VerKeyCode;
    /// CESR signature code for this algorithm.
    const SIGNATURE_CODE: SignatureCode;
    /// Indexed signature code for both current and prior next key indices.
    const IDX_BOTH: IndexedSigCode;
    /// Indexed signature code for the current key index only.
    const IDX_CRT: IndexedSigCode;
    /// Big-index variant of [`IDX_BOTH`](Algorithm::IDX_BOTH).
    const IDX_BOTH_BIG: IndexedSigCode;
    /// Big-index variant of [`IDX_CRT`](Algorithm::IDX_CRT).
    const IDX_CRT_BIG: IndexedSigCode;
    /// Byte length of the raw seed (private key) material.
    const SEED_SIZE: usize;
    /// Byte length of the raw public key material.
    const PUBLIC_KEY_SIZE: usize;
    /// Byte length of a raw signature produced by this algorithm.
    const SIGNATURE_SIZE: usize;
}

/// Algorithm marker for Ed25519 (RFC 8032).
pub struct Ed25519;
impl private::Sealed for Ed25519 {}
impl Algorithm for Ed25519 {
    const SEED_CODE: SeedCode = SeedCode::Ed25519Seed;
    const VERKEY_CODE: VerKeyCode = VerKeyCode::Ed25519;
    const VERKEY_CODE_N: VerKeyCode = VerKeyCode::Ed25519N;
    const SIGNATURE_CODE: SignatureCode = SignatureCode::Ed25519Sig;
    const IDX_BOTH: IndexedSigCode = IndexedSigCode::Ed25519;
    const IDX_CRT: IndexedSigCode = IndexedSigCode::Ed25519Crt;
    const IDX_BOTH_BIG: IndexedSigCode = IndexedSigCode::Ed25519Big;
    const IDX_CRT_BIG: IndexedSigCode = IndexedSigCode::Ed25519BigCrt;
    const SEED_SIZE: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 32;
    const SIGNATURE_SIZE: usize = 64;
}

/// Algorithm marker for ECDSA over secp256k1 (used in Bitcoin/Ethereum).
pub struct Secp256k1;
impl private::Sealed for Secp256k1 {}
impl Algorithm for Secp256k1 {
    const SEED_CODE: SeedCode = SeedCode::ECDSA256k1Seed;
    const VERKEY_CODE: VerKeyCode = VerKeyCode::ECDSA256k1;
    const VERKEY_CODE_N: VerKeyCode = VerKeyCode::ECDSA256k1N;
    const SIGNATURE_CODE: SignatureCode = SignatureCode::ECDSA256k1Sig;
    const IDX_BOTH: IndexedSigCode = IndexedSigCode::ECDSA256k1;
    const IDX_CRT: IndexedSigCode = IndexedSigCode::ECDSA256k1Crt;
    const IDX_BOTH_BIG: IndexedSigCode = IndexedSigCode::ECDSA256k1Big;
    const IDX_CRT_BIG: IndexedSigCode = IndexedSigCode::ECDSA256k1BigCrt;
    const SEED_SIZE: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 33;
    const SIGNATURE_SIZE: usize = 64;
}

/// Algorithm marker for ECDSA over secp256r1 / NIST P-256.
pub struct Secp256r1;
impl private::Sealed for Secp256r1 {}
impl Algorithm for Secp256r1 {
    const SEED_CODE: SeedCode = SeedCode::ECDSA256r1Seed;
    const VERKEY_CODE: VerKeyCode = VerKeyCode::ECDSA256r1;
    const VERKEY_CODE_N: VerKeyCode = VerKeyCode::ECDSA256r1N;
    const SIGNATURE_CODE: SignatureCode = SignatureCode::ECDSA256r1Sig;
    const IDX_BOTH: IndexedSigCode = IndexedSigCode::ECDSA256r1;
    const IDX_CRT: IndexedSigCode = IndexedSigCode::ECDSA256r1Crt;
    const IDX_BOTH_BIG: IndexedSigCode = IndexedSigCode::ECDSA256r1Big;
    const IDX_CRT_BIG: IndexedSigCode = IndexedSigCode::ECDSA256r1BigCrt;
    const SEED_SIZE: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 33;
    const SIGNATURE_SIZE: usize = 64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr_core::indexer::code::IndexedSigCode;
    use cesr_core::matter::code::{SeedCode, SignatureCode, VerKeyCode};

    #[test]
    fn ed25519_constants() {
        assert_eq!(Ed25519::SEED_CODE, SeedCode::Ed25519Seed);
        assert_eq!(Ed25519::VERKEY_CODE, VerKeyCode::Ed25519);
        assert_eq!(Ed25519::VERKEY_CODE_N, VerKeyCode::Ed25519N);
        assert_eq!(Ed25519::SIGNATURE_CODE, SignatureCode::Ed25519Sig);
        assert_eq!(Ed25519::SEED_SIZE, 32);
        assert_eq!(Ed25519::PUBLIC_KEY_SIZE, 32);
        assert_eq!(Ed25519::SIGNATURE_SIZE, 64);
    }

    #[test]
    fn secp256k1_constants() {
        assert_eq!(Secp256k1::SEED_CODE, SeedCode::ECDSA256k1Seed);
        assert_eq!(Secp256k1::VERKEY_CODE, VerKeyCode::ECDSA256k1);
        assert_eq!(Secp256k1::VERKEY_CODE_N, VerKeyCode::ECDSA256k1N);
        assert_eq!(Secp256k1::SIGNATURE_CODE, SignatureCode::ECDSA256k1Sig);
        assert_eq!(Secp256k1::SEED_SIZE, 32);
        assert_eq!(Secp256k1::PUBLIC_KEY_SIZE, 33);
        assert_eq!(Secp256k1::SIGNATURE_SIZE, 64);
    }

    #[test]
    fn secp256r1_constants() {
        assert_eq!(Secp256r1::SEED_CODE, SeedCode::ECDSA256r1Seed);
        assert_eq!(Secp256r1::VERKEY_CODE, VerKeyCode::ECDSA256r1);
        assert_eq!(Secp256r1::VERKEY_CODE_N, VerKeyCode::ECDSA256r1N);
        assert_eq!(Secp256r1::SIGNATURE_CODE, SignatureCode::ECDSA256r1Sig);
        assert_eq!(Secp256r1::SEED_SIZE, 32);
        assert_eq!(Secp256r1::PUBLIC_KEY_SIZE, 33);
        assert_eq!(Secp256r1::SIGNATURE_SIZE, 64);
    }

    #[test]
    fn ed25519_idx_constants() {
        assert_eq!(Ed25519::IDX_BOTH, IndexedSigCode::Ed25519);
        assert_eq!(Ed25519::IDX_CRT, IndexedSigCode::Ed25519Crt);
        assert_eq!(Ed25519::IDX_BOTH_BIG, IndexedSigCode::Ed25519Big);
        assert_eq!(Ed25519::IDX_CRT_BIG, IndexedSigCode::Ed25519BigCrt);
    }

    #[test]
    fn secp256k1_idx_constants() {
        assert_eq!(Secp256k1::IDX_BOTH, IndexedSigCode::ECDSA256k1);
        assert_eq!(Secp256k1::IDX_CRT, IndexedSigCode::ECDSA256k1Crt);
        assert_eq!(Secp256k1::IDX_BOTH_BIG, IndexedSigCode::ECDSA256k1Big);
        assert_eq!(Secp256k1::IDX_CRT_BIG, IndexedSigCode::ECDSA256k1BigCrt);
    }

    #[test]
    fn secp256r1_idx_constants() {
        assert_eq!(Secp256r1::IDX_BOTH, IndexedSigCode::ECDSA256r1);
        assert_eq!(Secp256r1::IDX_CRT, IndexedSigCode::ECDSA256r1Crt);
        assert_eq!(Secp256r1::IDX_BOTH_BIG, IndexedSigCode::ECDSA256r1Big);
        assert_eq!(Secp256r1::IDX_CRT_BIG, IndexedSigCode::ECDSA256r1BigCrt);
    }
}
