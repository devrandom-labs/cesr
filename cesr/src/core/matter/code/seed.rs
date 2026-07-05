use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use super::verkey::VerKeyCode;
use crate::core::matter::error::ValidationError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::ToString;

/// CESR codes for supported private key (seed) types.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SeedCode {
    /// Ed25519 32-byte private key seed.
    Ed25519Seed,
    /// secp256k1 (ECDSA) 32-byte private key seed.
    ECDSA256k1Seed,
    /// Ed448 56-byte private key seed.
    Ed448Seed,
    /// secp256r1 / P-256 (ECDSA) 32-byte private key seed.
    ECDSA256r1Seed,
}

impl SeedCode {
    /// Returns the corresponding [`VerKeyCode`] for the public key derived from this seed.
    #[must_use]
    pub const fn verkey_code(&self) -> VerKeyCode {
        match self {
            Self::Ed25519Seed => VerKeyCode::Ed25519,
            Self::ECDSA256k1Seed => VerKeyCode::ECDSA256k1,
            Self::Ed448Seed => VerKeyCode::Ed448,
            Self::ECDSA256r1Seed => VerKeyCode::ECDSA256r1,
        }
    }
}

impl Sealed for SeedCode {}

impl CesrCode for SeedCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Ed25519Seed => MatterCode::Ed25519Seed,
            Self::ECDSA256k1Seed => MatterCode::ECDSA256k1Seed,
            Self::Ed448Seed => MatterCode::Ed448Seed,
            Self::ECDSA256r1Seed => MatterCode::ECDSA256r1Seed,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519Seed => "A",
            Self::ECDSA256k1Seed => "J",
            Self::Ed448Seed => "K",
            Self::ECDSA256r1Seed => "Q",
        }
    }
}

impl TryFrom<MatterCode> for SeedCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Ed25519Seed => Ok(Self::Ed25519Seed),
            MatterCode::ECDSA256k1Seed => Ok(Self::ECDSA256k1Seed),
            MatterCode::Ed448Seed => Ok(Self::Ed448Seed),
            MatterCode::ECDSA256r1Seed => Ok(Self::ECDSA256r1Seed),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<SeedCode> for MatterCode {
    fn from(code: SeedCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::MatterCode;
    use crate::core::matter::code::VerKeyCode;

    #[test]
    fn seed_code_to_matter_code_roundtrip() {
        let codes = [
            (SeedCode::Ed25519Seed, MatterCode::Ed25519Seed),
            (SeedCode::ECDSA256k1Seed, MatterCode::ECDSA256k1Seed),
            (SeedCode::Ed448Seed, MatterCode::Ed448Seed),
            (SeedCode::ECDSA256r1Seed, MatterCode::ECDSA256r1Seed),
        ];
        for (sc, mc) in codes {
            assert_eq!(sc.to_matter_code(), mc);
            assert_eq!(SeedCode::try_from(mc).unwrap(), sc);
            assert_eq!(MatterCode::from(sc), mc);
        }
    }

    #[test]
    fn seed_code_rejects_non_seed() {
        assert!(SeedCode::try_from(MatterCode::Ed25519).is_err());
        assert!(SeedCode::try_from(MatterCode::Blake3_256).is_err());
        assert!(SeedCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn seed_code_as_str() {
        assert_eq!(SeedCode::Ed25519Seed.as_str(), "A");
        assert_eq!(SeedCode::ECDSA256k1Seed.as_str(), "J");
        assert_eq!(SeedCode::Ed448Seed.as_str(), "K");
        assert_eq!(SeedCode::ECDSA256r1Seed.as_str(), "Q");
    }

    #[test]
    fn seed_code_verkey_relationship() {
        assert_eq!(SeedCode::Ed25519Seed.verkey_code(), VerKeyCode::Ed25519);
        assert_eq!(
            SeedCode::ECDSA256k1Seed.verkey_code(),
            VerKeyCode::ECDSA256k1
        );
        assert_eq!(SeedCode::Ed448Seed.verkey_code(), VerKeyCode::Ed448);
        assert_eq!(
            SeedCode::ECDSA256r1Seed.verkey_code(),
            VerKeyCode::ECDSA256r1
        );
    }
}
