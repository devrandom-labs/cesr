use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::core::matter::error::ValidationError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::ToString;

/// CESR codes for supported cryptographic digest algorithms.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[allow(
    non_camel_case_types,
    reason = "digest algorithm names use underscores by convention"
)]
pub enum DigestCode {
    /// BLAKE3 with 256-bit (32-byte) output.
    Blake3_256,
    /// `BLAKE2b` with 256-bit (32-byte) output.
    Blake2b_256,
    /// BLAKE2s with 256-bit (32-byte) output.
    Blake2s_256,
    /// SHA-3 with 256-bit (32-byte) output.
    SHA3_256,
    /// SHA-2 (SHA-256) with 256-bit (32-byte) output.
    SHA2_256,
    /// BLAKE3 with 512-bit (64-byte) output.
    Blake3_512,
    /// `BLAKE2b` with 512-bit (64-byte) output.
    Blake2b_512,
    /// SHA-3 with 512-bit (64-byte) output.
    SHA3_512,
    /// SHA-2 (SHA-512) with 512-bit (64-byte) output.
    SHA2_512,
}

impl Sealed for DigestCode {}

impl CesrCode for DigestCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Blake3_256 => MatterCode::Blake3_256,
            Self::Blake2b_256 => MatterCode::Blake2b_256,
            Self::Blake2s_256 => MatterCode::Blake2s_256,
            Self::SHA3_256 => MatterCode::SHA3_256,
            Self::SHA2_256 => MatterCode::SHA2_256,
            Self::Blake3_512 => MatterCode::Blake3_512,
            Self::Blake2b_512 => MatterCode::Blake2b_512,
            Self::SHA3_512 => MatterCode::SHA3_512,
            Self::SHA2_512 => MatterCode::SHA2_512,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Blake3_256 => "E",
            Self::Blake2b_256 => "F",
            Self::Blake2s_256 => "G",
            Self::SHA3_256 => "H",
            Self::SHA2_256 => "I",
            Self::Blake3_512 => "0D",
            Self::Blake2b_512 => "0E",
            Self::SHA3_512 => "0F",
            Self::SHA2_512 => "0G",
        }
    }
}

impl TryFrom<MatterCode> for DigestCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Blake3_256 => Ok(Self::Blake3_256),
            MatterCode::Blake2b_256 => Ok(Self::Blake2b_256),
            MatterCode::Blake2s_256 => Ok(Self::Blake2s_256),
            MatterCode::SHA3_256 => Ok(Self::SHA3_256),
            MatterCode::SHA2_256 => Ok(Self::SHA2_256),
            MatterCode::Blake3_512 => Ok(Self::Blake3_512),
            MatterCode::Blake2b_512 => Ok(Self::Blake2b_512),
            MatterCode::SHA3_512 => Ok(Self::SHA3_512),
            MatterCode::SHA2_512 => Ok(Self::SHA2_512),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<DigestCode> for MatterCode {
    fn from(code: DigestCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::MatterCode;

    #[test]
    fn digest_code_to_matter_code_roundtrip() {
        let codes = [
            (DigestCode::Blake3_256, MatterCode::Blake3_256),
            (DigestCode::Blake2b_256, MatterCode::Blake2b_256),
            (DigestCode::Blake2s_256, MatterCode::Blake2s_256),
            (DigestCode::SHA3_256, MatterCode::SHA3_256),
            (DigestCode::SHA2_256, MatterCode::SHA2_256),
            (DigestCode::Blake3_512, MatterCode::Blake3_512),
            (DigestCode::Blake2b_512, MatterCode::Blake2b_512),
            (DigestCode::SHA3_512, MatterCode::SHA3_512),
            (DigestCode::SHA2_512, MatterCode::SHA2_512),
        ];
        for (dc, mc) in codes {
            assert_eq!(dc.to_matter_code(), mc);
            assert_eq!(DigestCode::try_from(mc).unwrap(), dc);
            assert_eq!(MatterCode::from(dc), mc);
        }
    }

    #[test]
    fn digest_code_rejects_non_digest() {
        assert!(DigestCode::try_from(MatterCode::Ed25519).is_err());
        assert!(DigestCode::try_from(MatterCode::Ed25519Seed).is_err());
        assert!(DigestCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn digest_code_as_str() {
        assert_eq!(DigestCode::Blake3_256.as_str(), "E");
        assert_eq!(DigestCode::SHA2_256.as_str(), "I");
        assert_eq!(DigestCode::Blake3_512.as_str(), "0D");
        assert_eq!(DigestCode::SHA2_512.as_str(), "0G");
    }
}
