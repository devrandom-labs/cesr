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

/// CESR codes for variable-length byte string primitives.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[allow(
    non_camel_case_types,
    reason = "variable-size code names use underscores by convention"
)]
pub enum TexterCode {
    /// Variable-length byte string (lead 0).
    Bytes_L0,
    /// Variable-length byte string (lead 1).
    Bytes_L1,
    /// Variable-length byte string (lead 2).
    Bytes_L2,
    /// Variable-length big byte string (lead 0).
    BytesBig_L0,
    /// Variable-length big byte string (lead 1).
    BytesBig_L1,
    /// Variable-length big byte string (lead 2).
    BytesBig_L2,
}

impl Sealed for TexterCode {}

impl CesrCode for TexterCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Bytes_L0 => MatterCode::Bytes_L0,
            Self::Bytes_L1 => MatterCode::Bytes_L1,
            Self::Bytes_L2 => MatterCode::Bytes_L2,
            Self::BytesBig_L0 => MatterCode::BytesBig_L0,
            Self::BytesBig_L1 => MatterCode::BytesBig_L1,
            Self::BytesBig_L2 => MatterCode::BytesBig_L2,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Bytes_L0 => "4B",
            Self::Bytes_L1 => "5B",
            Self::Bytes_L2 => "6B",
            Self::BytesBig_L0 => "7AAB",
            Self::BytesBig_L1 => "8AAB",
            Self::BytesBig_L2 => "9AAB",
        }
    }
}

impl TryFrom<MatterCode> for TexterCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Bytes_L0 => Ok(Self::Bytes_L0),
            MatterCode::Bytes_L1 => Ok(Self::Bytes_L1),
            MatterCode::Bytes_L2 => Ok(Self::Bytes_L2),
            MatterCode::BytesBig_L0 => Ok(Self::BytesBig_L0),
            MatterCode::BytesBig_L1 => Ok(Self::BytesBig_L1),
            MatterCode::BytesBig_L2 => Ok(Self::BytesBig_L2),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<TexterCode> for MatterCode {
    fn from(code: TexterCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::MatterCode;

    #[test]
    fn texter_code_to_matter_code_roundtrip() {
        let codes = [
            (TexterCode::Bytes_L0, MatterCode::Bytes_L0),
            (TexterCode::Bytes_L1, MatterCode::Bytes_L1),
            (TexterCode::Bytes_L2, MatterCode::Bytes_L2),
            (TexterCode::BytesBig_L0, MatterCode::BytesBig_L0),
            (TexterCode::BytesBig_L1, MatterCode::BytesBig_L1),
            (TexterCode::BytesBig_L2, MatterCode::BytesBig_L2),
        ];
        for (tc, mc) in codes {
            assert_eq!(tc.to_matter_code(), mc);
            assert_eq!(TexterCode::try_from(mc).unwrap(), tc);
            assert_eq!(MatterCode::from(tc), mc);
        }
    }

    #[test]
    fn texter_code_rejects_non_texter() {
        assert!(TexterCode::try_from(MatterCode::Ed25519).is_err());
        assert!(TexterCode::try_from(MatterCode::Ed25519Seed).is_err());
        assert!(TexterCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn texter_code_as_str() {
        assert_eq!(TexterCode::Bytes_L0.as_str(), "4B");
        assert_eq!(TexterCode::Bytes_L2.as_str(), "6B");
        assert_eq!(TexterCode::BytesBig_L0.as_str(), "7AAB");
        assert_eq!(TexterCode::BytesBig_L2.as_str(), "9AAB");
    }
}
