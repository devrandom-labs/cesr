#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{string::ToString,};
use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::core::matter::error::ValidationError;

/// CESR codes for supported digital signature algorithms.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SignatureCode {
    /// Ed25519 64-byte signature.
    Ed25519Sig,
    /// secp256k1 (ECDSA) 64-byte signature (r || s).
    ECDSA256k1Sig,
    /// secp256r1 / P-256 (ECDSA) 64-byte signature (r || s).
    ECDSA256r1Sig,
    /// Ed448 114-byte signature.
    Ed448Sig,
}

impl Sealed for SignatureCode {}

impl CesrCode for SignatureCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Ed25519Sig => MatterCode::Ed25519Sig,
            Self::ECDSA256k1Sig => MatterCode::ECDSA256k1Sig,
            Self::ECDSA256r1Sig => MatterCode::ECDSA256r1Sig,
            Self::Ed448Sig => MatterCode::Ed448Sig,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519Sig => "0B",
            Self::ECDSA256k1Sig => "0C",
            Self::ECDSA256r1Sig => "0I",
            Self::Ed448Sig => "1AAE",
        }
    }
}

impl TryFrom<MatterCode> for SignatureCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Ed25519Sig => Ok(Self::Ed25519Sig),
            MatterCode::ECDSA256k1Sig => Ok(Self::ECDSA256k1Sig),
            MatterCode::ECDSA256r1Sig => Ok(Self::ECDSA256r1Sig),
            MatterCode::Ed448Sig => Ok(Self::Ed448Sig),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<SignatureCode> for MatterCode {
    fn from(code: SignatureCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::MatterCode;

    #[test]
    fn signature_code_to_matter_code_roundtrip() {
        let codes = [
            (SignatureCode::Ed25519Sig, MatterCode::Ed25519Sig),
            (SignatureCode::ECDSA256k1Sig, MatterCode::ECDSA256k1Sig),
            (SignatureCode::ECDSA256r1Sig, MatterCode::ECDSA256r1Sig),
            (SignatureCode::Ed448Sig, MatterCode::Ed448Sig),
        ];
        for (sc, mc) in codes {
            assert_eq!(sc.to_matter_code(), mc);
            assert_eq!(SignatureCode::try_from(mc).unwrap(), sc);
            assert_eq!(MatterCode::from(sc), mc);
        }
    }

    #[test]
    fn signature_code_rejects_non_signature() {
        assert!(SignatureCode::try_from(MatterCode::Ed25519).is_err());
        assert!(SignatureCode::try_from(MatterCode::Blake3_256).is_err());
        assert!(SignatureCode::try_from(MatterCode::Ed25519Seed).is_err());
        assert!(SignatureCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn signature_code_as_str() {
        assert_eq!(SignatureCode::Ed25519Sig.as_str(), "0B");
        assert_eq!(SignatureCode::ECDSA256k1Sig.as_str(), "0C");
        assert_eq!(SignatureCode::ECDSA256r1Sig.as_str(), "0I");
        assert_eq!(SignatureCode::Ed448Sig.as_str(), "1AAE");
    }
}
