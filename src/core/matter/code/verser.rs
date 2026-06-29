use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::matter::error::ValidationError;

/// CESR codes for version/protocol encoding primitives.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum VerserCode {
    /// Tag7: 7 B64 chars for protocol-only version.
    Tag7,
    /// Tag10: 10 B64 chars for protocol + genus version.
    Tag10,
}

impl Sealed for VerserCode {}

impl CesrCode for VerserCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Tag7 => MatterCode::Tag7,
            Self::Tag10 => MatterCode::Tag10,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Tag7 => "Y",
            Self::Tag10 => "0O",
        }
    }
}

impl TryFrom<MatterCode> for VerserCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Tag7 => Ok(Self::Tag7),
            MatterCode::Tag10 => Ok(Self::Tag10),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<VerserCode> for MatterCode {
    fn from(code: VerserCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matter::code::MatterCode;

    #[test]
    fn verser_code_to_matter_code_roundtrip() {
        let codes = [
            (VerserCode::Tag7, MatterCode::Tag7),
            (VerserCode::Tag10, MatterCode::Tag10),
        ];
        for (vc, mc) in codes {
            assert_eq!(vc.to_matter_code(), mc);
            assert_eq!(VerserCode::try_from(mc).unwrap(), vc);
            assert_eq!(MatterCode::from(vc), mc);
        }
    }

    #[test]
    fn verser_code_rejects_non_verser() {
        assert!(VerserCode::try_from(MatterCode::Ed25519).is_err());
        assert!(VerserCode::try_from(MatterCode::Blake3_256).is_err());
        assert!(VerserCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn verser_code_as_str() {
        assert_eq!(VerserCode::Tag7.as_str(), "Y");
        assert_eq!(VerserCode::Tag10.as_str(), "0O");
    }
}
