use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::matter::error::ValidationError;

/// CESR codes for nonce/randomness primitives.
///
/// Combines digest codes, salt codes, and an empty-value code
/// for representing absent nonces.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[allow(
    non_camel_case_types,
    reason = "digest algorithm names use underscores by convention"
)]
pub enum NoncerCode {
    /// Empty value for absent nonces.
    Empty,
    /// Salt/nonce, 128 bits.
    Salt128,
    /// Salt/nonce, 256 bits.
    Salt256,
    /// BLAKE3, 256-bit.
    Blake3_256,
    /// `BLAKE2b`, 256-bit.
    Blake2b_256,
    /// BLAKE2s, 256-bit.
    Blake2s_256,
    /// SHA-3, 256-bit.
    SHA3_256,
    /// SHA-2, 256-bit.
    SHA2_256,
    /// BLAKE3, 512-bit.
    Blake3_512,
    /// `BLAKE2b`, 512-bit.
    Blake2b_512,
    /// SHA-3, 512-bit.
    SHA3_512,
    /// SHA-2, 512-bit.
    SHA2_512,
}

impl Sealed for NoncerCode {}

impl CesrCode for NoncerCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Empty => MatterCode::Empty,
            Self::Salt128 => MatterCode::Salt128,
            Self::Salt256 => MatterCode::Salt256,
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
            Self::Empty => "1AAP",
            Self::Salt128 => "0A",
            Self::Salt256 => "a",
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

impl TryFrom<MatterCode> for NoncerCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Empty => Ok(Self::Empty),
            MatterCode::Salt128 => Ok(Self::Salt128),
            MatterCode::Salt256 => Ok(Self::Salt256),
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

impl From<NoncerCode> for MatterCode {
    fn from(code: NoncerCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matter::code::MatterCode;

    #[test]
    fn noncer_code_to_matter_code_roundtrip() {
        let codes = [
            (NoncerCode::Empty, MatterCode::Empty),
            (NoncerCode::Salt128, MatterCode::Salt128),
            (NoncerCode::Salt256, MatterCode::Salt256),
            (NoncerCode::Blake3_256, MatterCode::Blake3_256),
            (NoncerCode::Blake2b_256, MatterCode::Blake2b_256),
            (NoncerCode::Blake2s_256, MatterCode::Blake2s_256),
            (NoncerCode::SHA3_256, MatterCode::SHA3_256),
            (NoncerCode::SHA2_256, MatterCode::SHA2_256),
            (NoncerCode::Blake3_512, MatterCode::Blake3_512),
            (NoncerCode::Blake2b_512, MatterCode::Blake2b_512),
            (NoncerCode::SHA3_512, MatterCode::SHA3_512),
            (NoncerCode::SHA2_512, MatterCode::SHA2_512),
        ];
        for (nc, mc) in codes {
            assert_eq!(nc.to_matter_code(), mc);
            assert_eq!(NoncerCode::try_from(mc).unwrap(), nc);
            assert_eq!(MatterCode::from(nc), mc);
        }
    }

    #[test]
    fn noncer_code_rejects_non_noncer() {
        assert!(NoncerCode::try_from(MatterCode::Ed25519).is_err());
        assert!(NoncerCode::try_from(MatterCode::Ed25519Seed).is_err());
        assert!(NoncerCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn noncer_code_as_str() {
        assert_eq!(NoncerCode::Empty.as_str(), "1AAP");
        assert_eq!(NoncerCode::Salt128.as_str(), "0A");
        assert_eq!(NoncerCode::Salt256.as_str(), "a");
        assert_eq!(NoncerCode::Blake3_256.as_str(), "E");
        assert_eq!(NoncerCode::SHA2_512.as_str(), "0G");
    }
}
