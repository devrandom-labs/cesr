#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{string::ToString,};
use super::cesr_code::CesrCode;
use super::matter_code::MatterCode;
use super::sealed::Sealed;
use crate::core::matter::error::ValidationError;

/// CESR codes for auto-sized tags and labels used as field names.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[allow(
    non_camel_case_types,
    reason = "variable-size code names use underscores by convention"
)]
pub enum LabelerCode {
    /// Empty value.
    Empty,
    /// 1-char tag.
    Tag1,
    /// 2-char tag.
    Tag2,
    /// 3-char tag.
    Tag3,
    /// 4-char tag.
    Tag4,
    /// 5-char tag.
    Tag5,
    /// 6-char tag.
    Tag6,
    /// 7-char tag.
    Tag7,
    /// 8-char tag.
    Tag8,
    /// 9-char tag.
    Tag9,
    /// 10-char tag.
    Tag10,
    /// 11-char tag.
    Tag11,
    /// 1-byte label.
    Label1,
    /// 2-byte label.
    Label2,
    /// Variable-length Base64 string (lead 0).
    StrB64_L0,
    /// Variable-length Base64 string (lead 1).
    StrB64_L1,
    /// Variable-length Base64 string (lead 2).
    StrB64_L2,
    /// Variable-length big Base64 string (lead 0).
    StrB64Big_L0,
    /// Variable-length big Base64 string (lead 1).
    StrB64Big_L1,
    /// Variable-length big Base64 string (lead 2).
    StrB64Big_L2,
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

impl Sealed for LabelerCode {}

impl CesrCode for LabelerCode {
    fn to_matter_code(&self) -> MatterCode {
        match self {
            Self::Empty => MatterCode::Empty,
            Self::Tag1 => MatterCode::Tag1,
            Self::Tag2 => MatterCode::Tag2,
            Self::Tag3 => MatterCode::Tag3,
            Self::Tag4 => MatterCode::Tag4,
            Self::Tag5 => MatterCode::Tag5,
            Self::Tag6 => MatterCode::Tag6,
            Self::Tag7 => MatterCode::Tag7,
            Self::Tag8 => MatterCode::Tag8,
            Self::Tag9 => MatterCode::Tag9,
            Self::Tag10 => MatterCode::Tag10,
            Self::Tag11 => MatterCode::Tag11,
            Self::Label1 => MatterCode::Label1,
            Self::Label2 => MatterCode::Label2,
            Self::StrB64_L0 => MatterCode::StrB64_L0,
            Self::StrB64_L1 => MatterCode::StrB64_L1,
            Self::StrB64_L2 => MatterCode::StrB64_L2,
            Self::StrB64Big_L0 => MatterCode::StrB64Big_L0,
            Self::StrB64Big_L1 => MatterCode::StrB64Big_L1,
            Self::StrB64Big_L2 => MatterCode::StrB64Big_L2,
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
            Self::Empty => "1AAP",
            Self::Tag1 => "0J",
            Self::Tag2 => "0K",
            Self::Tag3 => "X",
            Self::Tag4 => "1AAF",
            Self::Tag5 => "0L",
            Self::Tag6 => "0M",
            Self::Tag7 => "Y",
            Self::Tag8 => "1AAN",
            Self::Tag9 => "0N",
            Self::Tag10 => "0O",
            Self::Tag11 => "Z",
            Self::Label1 => "V",
            Self::Label2 => "W",
            Self::StrB64_L0 => "4A",
            Self::StrB64_L1 => "5A",
            Self::StrB64_L2 => "6A",
            Self::StrB64Big_L0 => "7AAA",
            Self::StrB64Big_L1 => "8AAA",
            Self::StrB64Big_L2 => "9AAA",
            Self::Bytes_L0 => "4B",
            Self::Bytes_L1 => "5B",
            Self::Bytes_L2 => "6B",
            Self::BytesBig_L0 => "7AAB",
            Self::BytesBig_L1 => "8AAB",
            Self::BytesBig_L2 => "9AAB",
        }
    }
}

impl TryFrom<MatterCode> for LabelerCode {
    type Error = ValidationError;

    fn try_from(code: MatterCode) -> Result<Self, Self::Error> {
        match code {
            MatterCode::Empty => Ok(Self::Empty),
            MatterCode::Tag1 => Ok(Self::Tag1),
            MatterCode::Tag2 => Ok(Self::Tag2),
            MatterCode::Tag3 => Ok(Self::Tag3),
            MatterCode::Tag4 => Ok(Self::Tag4),
            MatterCode::Tag5 => Ok(Self::Tag5),
            MatterCode::Tag6 => Ok(Self::Tag6),
            MatterCode::Tag7 => Ok(Self::Tag7),
            MatterCode::Tag8 => Ok(Self::Tag8),
            MatterCode::Tag9 => Ok(Self::Tag9),
            MatterCode::Tag10 => Ok(Self::Tag10),
            MatterCode::Tag11 => Ok(Self::Tag11),
            MatterCode::Label1 => Ok(Self::Label1),
            MatterCode::Label2 => Ok(Self::Label2),
            MatterCode::StrB64_L0 => Ok(Self::StrB64_L0),
            MatterCode::StrB64_L1 => Ok(Self::StrB64_L1),
            MatterCode::StrB64_L2 => Ok(Self::StrB64_L2),
            MatterCode::StrB64Big_L0 => Ok(Self::StrB64Big_L0),
            MatterCode::StrB64Big_L1 => Ok(Self::StrB64Big_L1),
            MatterCode::StrB64Big_L2 => Ok(Self::StrB64Big_L2),
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

impl From<LabelerCode> for MatterCode {
    fn from(code: LabelerCode) -> Self {
        code.to_matter_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::MatterCode;

    #[test]
    fn labeler_code_to_matter_code_roundtrip() {
        let codes = [
            (LabelerCode::Empty, MatterCode::Empty),
            (LabelerCode::Tag1, MatterCode::Tag1),
            (LabelerCode::Tag2, MatterCode::Tag2),
            (LabelerCode::Tag3, MatterCode::Tag3),
            (LabelerCode::Tag4, MatterCode::Tag4),
            (LabelerCode::Tag5, MatterCode::Tag5),
            (LabelerCode::Tag6, MatterCode::Tag6),
            (LabelerCode::Tag7, MatterCode::Tag7),
            (LabelerCode::Tag8, MatterCode::Tag8),
            (LabelerCode::Tag9, MatterCode::Tag9),
            (LabelerCode::Tag10, MatterCode::Tag10),
            (LabelerCode::Tag11, MatterCode::Tag11),
            (LabelerCode::Label1, MatterCode::Label1),
            (LabelerCode::Label2, MatterCode::Label2),
            (LabelerCode::StrB64_L0, MatterCode::StrB64_L0),
            (LabelerCode::StrB64_L1, MatterCode::StrB64_L1),
            (LabelerCode::StrB64_L2, MatterCode::StrB64_L2),
            (LabelerCode::StrB64Big_L0, MatterCode::StrB64Big_L0),
            (LabelerCode::StrB64Big_L1, MatterCode::StrB64Big_L1),
            (LabelerCode::StrB64Big_L2, MatterCode::StrB64Big_L2),
            (LabelerCode::Bytes_L0, MatterCode::Bytes_L0),
            (LabelerCode::Bytes_L1, MatterCode::Bytes_L1),
            (LabelerCode::Bytes_L2, MatterCode::Bytes_L2),
            (LabelerCode::BytesBig_L0, MatterCode::BytesBig_L0),
            (LabelerCode::BytesBig_L1, MatterCode::BytesBig_L1),
            (LabelerCode::BytesBig_L2, MatterCode::BytesBig_L2),
        ];
        for (lc, mc) in codes {
            assert_eq!(lc.to_matter_code(), mc);
            assert_eq!(LabelerCode::try_from(mc).unwrap(), lc);
            assert_eq!(MatterCode::from(lc), mc);
        }
    }

    #[test]
    fn labeler_code_rejects_non_labeler() {
        assert!(LabelerCode::try_from(MatterCode::Ed25519).is_err());
        assert!(LabelerCode::try_from(MatterCode::Ed25519Seed).is_err());
        assert!(LabelerCode::try_from(MatterCode::Short).is_err());
    }

    #[test]
    fn labeler_code_as_str() {
        assert_eq!(LabelerCode::Empty.as_str(), "1AAP");
        assert_eq!(LabelerCode::Tag3.as_str(), "X");
        assert_eq!(LabelerCode::Tag7.as_str(), "Y");
        assert_eq!(LabelerCode::Label1.as_str(), "V");
        assert_eq!(LabelerCode::StrB64_L0.as_str(), "4A");
        assert_eq!(LabelerCode::Bytes_L0.as_str(), "4B");
        assert_eq!(LabelerCode::BytesBig_L2.as_str(), "9AAB");
    }
}
