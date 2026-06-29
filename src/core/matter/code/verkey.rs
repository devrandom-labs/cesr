use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::matter::error::ValidationError;

/// CESR codes for verification (public) keys, both transferable and non-transferable.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum VerKeyCode {
    /// Ed25519 transferable (rotatable) public key.
    Ed25519,
    /// Ed25519 non-transferable (non-rotatable) public key.
    Ed25519N,
    /// secp256k1 (ECDSA) transferable compressed public key.
    ECDSA256k1,
    /// secp256k1 (ECDSA) non-transferable compressed public key.
    ECDSA256k1N,
    /// Ed448 transferable public key.
    Ed448,
    /// Ed448 non-transferable public key.
    Ed448N,
    /// secp256r1 / P-256 (ECDSA) transferable compressed public key.
    ECDSA256r1,
    /// secp256r1 / P-256 (ECDSA) non-transferable compressed public key.
    ECDSA256r1N,
}

impl VerKeyCode {
    /// Returns `true` if this key can be rotated (transferable prefix).
    #[must_use]
    pub const fn is_transferable(&self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::ECDSA256k1 | Self::Ed448 | Self::ECDSA256r1
        )
    }

    /// Returns `true` if this key cannot be rotated (non-transferable prefix).
    #[must_use]
    pub const fn is_non_transferable(&self) -> bool {
        !self.is_transferable()
    }
}

impl Sealed for VerKeyCode {}

impl CesrCode for VerKeyCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Ed25519 => MatterCode::Ed25519,
            Self::Ed25519N => MatterCode::Ed25519N,
            Self::ECDSA256k1 => MatterCode::ECDSA256k1,
            Self::ECDSA256k1N => MatterCode::ECDSA256k1N,
            Self::Ed448 => MatterCode::Ed448,
            Self::Ed448N => MatterCode::Ed448N,
            Self::ECDSA256r1 => MatterCode::ECDSA256r1,
            Self::ECDSA256r1N => MatterCode::ECDSA256r1N,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "D",
            Self::Ed25519N => "B",
            Self::ECDSA256k1 => "1AAB",
            Self::ECDSA256k1N => "1AAA",
            Self::Ed448 => "1AAD",
            Self::Ed448N => "1AAC",
            Self::ECDSA256r1 => "1AAJ",
            Self::ECDSA256r1N => "1AAI",
        }
    }
}

impl TryFrom<MatterCode> for VerKeyCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Ed25519 => Ok(Self::Ed25519),
            MatterCode::Ed25519N => Ok(Self::Ed25519N),
            MatterCode::ECDSA256k1 => Ok(Self::ECDSA256k1),
            MatterCode::ECDSA256k1N => Ok(Self::ECDSA256k1N),
            MatterCode::Ed448 => Ok(Self::Ed448),
            MatterCode::Ed448N => Ok(Self::Ed448N),
            MatterCode::ECDSA256r1 => Ok(Self::ECDSA256r1),
            MatterCode::ECDSA256r1N => Ok(Self::ECDSA256r1N),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<VerKeyCode> for MatterCode {
    fn from(code: VerKeyCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matter::code::MatterCode;

    #[test]
    fn verkey_code_to_matter_code_roundtrip() {
        let codes = [
            (VerKeyCode::Ed25519, MatterCode::Ed25519),
            (VerKeyCode::Ed25519N, MatterCode::Ed25519N),
            (VerKeyCode::ECDSA256k1, MatterCode::ECDSA256k1),
            (VerKeyCode::ECDSA256k1N, MatterCode::ECDSA256k1N),
            (VerKeyCode::Ed448, MatterCode::Ed448),
            (VerKeyCode::Ed448N, MatterCode::Ed448N),
            (VerKeyCode::ECDSA256r1, MatterCode::ECDSA256r1),
            (VerKeyCode::ECDSA256r1N, MatterCode::ECDSA256r1N),
        ];
        for (vk, mc) in codes {
            assert_eq!(vk.to_matter_code(), mc);
            assert_eq!(VerKeyCode::try_from(mc).unwrap(), vk);
            assert_eq!(MatterCode::from(vk), mc);
        }
    }

    #[test]
    fn verkey_code_rejects_non_verkey() {
        assert!(VerKeyCode::try_from(MatterCode::Blake3_256).is_err());
        assert!(VerKeyCode::try_from(MatterCode::Ed25519Seed).is_err());
        assert!(VerKeyCode::try_from(MatterCode::Ed25519Sig).is_err());
        assert!(VerKeyCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn verkey_code_transferability() {
        assert!(VerKeyCode::Ed25519.is_transferable());
        assert!(!VerKeyCode::Ed25519.is_non_transferable());
        assert!(!VerKeyCode::Ed25519N.is_transferable());
        assert!(VerKeyCode::Ed25519N.is_non_transferable());
    }

    #[test]
    fn verkey_code_as_str() {
        assert_eq!(VerKeyCode::Ed25519.as_str(), "D");
        assert_eq!(VerKeyCode::Ed25519N.as_str(), "B");
        assert_eq!(VerKeyCode::ECDSA256k1N.as_str(), "1AAA");
    }
}
