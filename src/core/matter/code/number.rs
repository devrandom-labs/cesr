#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{string::ToString,};
use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::core::matter::error::ValidationError;

/// CESR codes for unsigned integer primitives, ordered from smallest to largest.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum NumberCode {
    /// 2-byte unsigned integer (`M`).
    Short,
    /// 4-byte unsigned integer (`0H`).
    Long,
    /// 5-byte unsigned integer (`R`).
    Tall,
    /// 8-byte unsigned integer (`N`).
    Big,
    /// 11-byte unsigned integer (`S`).
    Large,
    /// 14-byte unsigned integer (`T`).
    Great,
    /// 17-byte unsigned integer (`U`).
    Vast,
}

impl NumberCode {
    /// Maximum unsigned integer value this code can represent.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` for variable-size codes whose raw size
    /// cannot be determined.
    pub fn max_value(&self) -> Result<u128, ValidationError> {
        let raw_size = self.to_matter_code().raw_size()?;
        if raw_size >= 16 {
            Ok(u128::MAX)
        } else {
            Ok((1u128 << (raw_size * 8)) - 1)
        }
    }

    /// Pick the smallest `NumberCode` that can hold the given value.
    #[must_use]
    pub const fn for_value(value: u128) -> Self {
        match value {
            0..=0xFFFF => Self::Short,
            0x1_0000..=0xFFFF_FFFF => Self::Long,
            0x1_0000_0000..=0xFF_FFFF_FFFF => Self::Tall,
            0x100_0000_0000..=0xFFFF_FFFF_FFFF_FFFF => Self::Big,
            _ => Self::Vast,
        }
    }
}

impl Sealed for NumberCode {}

impl CesrCode for NumberCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Short => MatterCode::Short,
            Self::Long => MatterCode::Long,
            Self::Tall => MatterCode::Tall,
            Self::Big => MatterCode::Big,
            Self::Large => MatterCode::Large,
            Self::Great => MatterCode::Great,
            Self::Vast => MatterCode::Vast,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Short => "M",
            Self::Long => "0H",
            Self::Tall => "R",
            Self::Big => "N",
            Self::Large => "S",
            Self::Great => "T",
            Self::Vast => "U",
        }
    }
}

impl TryFrom<MatterCode> for NumberCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Short => Ok(Self::Short),
            MatterCode::Long => Ok(Self::Long),
            MatterCode::Tall => Ok(Self::Tall),
            MatterCode::Big => Ok(Self::Big),
            MatterCode::Large => Ok(Self::Large),
            MatterCode::Great => Ok(Self::Great),
            MatterCode::Vast => Ok(Self::Vast),
            _ => Err(ValidationError::UnknownMatterCode(code.to_string())),
        }
    }
}

impl From<NumberCode> for MatterCode {
    fn from(code: NumberCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::MatterCode;

    #[test]
    fn number_code_to_matter_code_roundtrip() {
        let codes = [
            (NumberCode::Short, MatterCode::Short),
            (NumberCode::Long, MatterCode::Long),
            (NumberCode::Tall, MatterCode::Tall),
            (NumberCode::Big, MatterCode::Big),
            (NumberCode::Large, MatterCode::Large),
            (NumberCode::Great, MatterCode::Great),
            (NumberCode::Vast, MatterCode::Vast),
        ];
        for (nc, mc) in codes {
            assert_eq!(nc.to_matter_code(), mc);
            assert_eq!(NumberCode::try_from(mc).unwrap(), nc);
            assert_eq!(MatterCode::from(nc), mc);
        }
    }

    #[test]
    fn number_code_rejects_non_number() {
        assert!(NumberCode::try_from(MatterCode::Ed25519).is_err());
        assert!(NumberCode::try_from(MatterCode::Blake3_256).is_err());
        assert!(NumberCode::try_from(MatterCode::Ed25519Seed).is_err());
    }

    #[test]
    fn number_code_as_str() {
        assert_eq!(NumberCode::Short.as_str(), "M");
        assert_eq!(NumberCode::Long.as_str(), "0H");
        assert_eq!(NumberCode::Big.as_str(), "N");
        assert_eq!(NumberCode::Vast.as_str(), "U");
    }

    #[test]
    fn number_code_max_value() {
        assert_eq!(NumberCode::Short.max_value().unwrap(), 0xFFFF);
        assert_eq!(NumberCode::Long.max_value().unwrap(), 0xFFFF_FFFF);
        assert_eq!(NumberCode::Big.max_value().unwrap(), 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn number_code_for_value() {
        assert_eq!(NumberCode::for_value(0), NumberCode::Short);
        assert_eq!(NumberCode::for_value(255), NumberCode::Short);
        assert_eq!(NumberCode::for_value(0xFFFF), NumberCode::Short);
        assert_eq!(NumberCode::for_value(0x1_0000), NumberCode::Long);
        assert_eq!(NumberCode::for_value(0xFFFF_FFFF), NumberCode::Long);
        assert_eq!(NumberCode::for_value(0x1_0000_0000), NumberCode::Tall);
        assert_eq!(NumberCode::for_value(0x1_0000_0000_0000), NumberCode::Big);
        assert_eq!(NumberCode::for_value(u128::from(u64::MAX)), NumberCode::Big);
        assert_eq!(NumberCode::for_value(u128::MAX), NumberCode::Vast);
    }
}
