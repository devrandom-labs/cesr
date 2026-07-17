#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String};
use thiserror::Error as ThisError;

/// Error returned when a hard code string is not a recognized counter code.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum CounterCodeError {
    /// The hard code string was not recognized.
    #[error("unknown counter code: '{0}'")]
    UnknownCode(String),
}

/// CESR V1.0 counter (group) codes, aligned with the keripy `CtrDex_1_0` table.
///
/// Each variant maps to a fixed CESR hard code string that begins with `'-'`.
/// Counter codes identify the type and count of the attached group that follows
/// in the CESR stream.
///
/// Size categories:
/// - Small codes (`-X`):   hs=2, ss=2, fs=4, max count = 4095
/// - Big codes (`--X`):    hs=3, ss=5, fs=8, max count = 1,073,741,823
/// - Genus (`-_AAA`):      hs=5, ss=3, fs=8
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CounterCodeV1 {
    /// `-A` — Controller indexed signatures (element count).
    ControllerIdxSigs,
    /// `-B` — Witness indexed signatures (element count).
    WitnessIdxSigs,
    /// `-C` — Non-transferable receipt couples (element count).
    NonTransReceiptCouples,
    /// `-D` — Transferable receipt quadruples (element count).
    TransReceiptQuadruples,
    /// `-E` — First-seen replay couples (element count).
    FirstSeenReplayCouples,
    /// `-F` — Transferable indexed sig groups (element count).
    TransIdxSigGroups,
    /// `-G` — Seal source couples (element count).
    SealSourceCouples,
    /// `-H` — Transferable last-event indexed sig groups (element count).
    TransLastIdxSigGroups,
    /// `-I` — Seal source triples (element count).
    SealSourceTriples,
    /// `-L` — Pathed material couples (element count).
    PathedMaterialCouples,
    /// `--L` — Big pathed material couples (element count).
    BigPathedMaterialCouples,
    /// `-T` — Generic group (quadlet count).
    GenericGroup,
    /// `--T` — Big generic group (quadlet count).
    BigGenericGroup,
    /// `-U` — Body with attachment group (quadlet count).
    BodyWithAttachmentGroup,
    /// `--U` — Big body with attachment group (quadlet count).
    BigBodyWithAttachmentGroup,
    /// `-V` — Attachment group (quadlet count).
    AttachmentGroup,
    /// `--V` — Big attachment group (quadlet count).
    BigAttachmentGroup,
    /// `-W` — Non-native body group (quadlet count).
    NonNativeBodyGroup,
    /// `--W` — Big non-native body group (quadlet count).
    BigNonNativeBodyGroup,
    /// `-Z` — ESSR payload group (quadlet count).
    ESSRPayloadGroup,
    /// `--Z` — Big ESSR payload group (quadlet count).
    BigESSRPayloadGroup,
    /// `-_AAA` — KERI/ACDC genus version marker.
    KERIACDCGenusVersion,
}

impl CounterCodeV1 {
    /// Returns the CESR wire code string for this variant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ControllerIdxSigs => "-A",
            Self::WitnessIdxSigs => "-B",
            Self::NonTransReceiptCouples => "-C",
            Self::TransReceiptQuadruples => "-D",
            Self::FirstSeenReplayCouples => "-E",
            Self::TransIdxSigGroups => "-F",
            Self::SealSourceCouples => "-G",
            Self::TransLastIdxSigGroups => "-H",
            Self::SealSourceTriples => "-I",
            Self::PathedMaterialCouples => "-L",
            Self::BigPathedMaterialCouples => "--L",
            Self::GenericGroup => "-T",
            Self::BigGenericGroup => "--T",
            Self::BodyWithAttachmentGroup => "-U",
            Self::BigBodyWithAttachmentGroup => "--U",
            Self::AttachmentGroup => "-V",
            Self::BigAttachmentGroup => "--V",
            Self::NonNativeBodyGroup => "-W",
            Self::BigNonNativeBodyGroup => "--W",
            Self::ESSRPayloadGroup => "-Z",
            Self::BigESSRPayloadGroup => "--Z",
            Self::KERIACDCGenusVersion => "-_AAA",
        }
    }

    /// Parses a hard code string back to the corresponding enum variant.
    ///
    /// # Errors
    /// Returns [`CounterCodeError::UnknownCode`] if the string is not a recognized V1 code.
    pub fn from_hard(hard: &str) -> Result<Self, CounterCodeError> {
        match hard {
            "-A" => Ok(Self::ControllerIdxSigs),
            "-B" => Ok(Self::WitnessIdxSigs),
            "-C" => Ok(Self::NonTransReceiptCouples),
            "-D" => Ok(Self::TransReceiptQuadruples),
            "-E" => Ok(Self::FirstSeenReplayCouples),
            "-F" => Ok(Self::TransIdxSigGroups),
            "-G" => Ok(Self::SealSourceCouples),
            "-H" => Ok(Self::TransLastIdxSigGroups),
            "-I" => Ok(Self::SealSourceTriples),
            "-L" => Ok(Self::PathedMaterialCouples),
            "--L" => Ok(Self::BigPathedMaterialCouples),
            "-T" => Ok(Self::GenericGroup),
            "--T" => Ok(Self::BigGenericGroup),
            "-U" => Ok(Self::BodyWithAttachmentGroup),
            "--U" => Ok(Self::BigBodyWithAttachmentGroup),
            "-V" => Ok(Self::AttachmentGroup),
            "--V" => Ok(Self::BigAttachmentGroup),
            "-W" => Ok(Self::NonNativeBodyGroup),
            "--W" => Ok(Self::BigNonNativeBodyGroup),
            "-Z" => Ok(Self::ESSRPayloadGroup),
            "--Z" => Ok(Self::BigESSRPayloadGroup),
            "-_AAA" => Ok(Self::KERIACDCGenusVersion),
            _ => Err(CounterCodeError::UnknownCode(hard.to_owned())),
        }
    }

    /// Hard-code length from the two lead bytes of a counter stream: `--` → 3
    /// (big), `-_` → 5 (genus/version), `-x` → 2. Shared V1/V2 grammar.
    ///
    /// # Errors
    /// [`CounterCodeError::UnknownCode`] if the lead bytes are not a counter
    /// (empty, single byte, or not starting with `'-'`).
    pub(crate) fn stream_hard_size(stream: &[u8]) -> Result<usize, CounterCodeError> {
        match stream {
            [b'-', b'-', ..] => Ok(3),
            [b'-', b'_', ..] => Ok(5),
            [b'-', _, ..] => Ok(2),
            _ => Err(CounterCodeError::UnknownCode(
                String::from_utf8_lossy(stream.get(..2).unwrap_or(stream)).into_owned(),
            )),
        }
    }

    /// Read a V1 counter code from a qb64 stream head (code only, no count).
    ///
    /// # Errors
    /// [`CounterCodeError`] if the lead bytes are not a counter or the code is
    /// unknown.
    pub fn from_base64_stream(stream: &[u8]) -> Result<Self, CounterCodeError> {
        let hs = Self::stream_hard_size(stream)?;
        let hard = stream
            .get(..hs)
            .and_then(|b| core::str::from_utf8(b).ok())
            .ok_or_else(|| {
                CounterCodeError::UnknownCode(
                    String::from_utf8_lossy(stream.get(..hs).unwrap_or(stream)).into_owned(),
                )
            })?;
        Self::from_hard(hard)
    }

    /// Returns the hard size (number of characters in the code prefix).
    #[must_use]
    pub const fn hard_size(&self) -> usize {
        match self {
            Self::BigPathedMaterialCouples
            | Self::BigGenericGroup
            | Self::BigBodyWithAttachmentGroup
            | Self::BigAttachmentGroup
            | Self::BigNonNativeBodyGroup
            | Self::BigESSRPayloadGroup => 3,
            Self::KERIACDCGenusVersion => 5,
            _ => 2,
        }
    }

    /// Returns the soft size (number of characters encoding the count).
    #[must_use]
    pub const fn soft_size(&self) -> usize {
        match self {
            Self::BigPathedMaterialCouples
            | Self::BigGenericGroup
            | Self::BigBodyWithAttachmentGroup
            | Self::BigAttachmentGroup
            | Self::BigNonNativeBodyGroup
            | Self::BigESSRPayloadGroup => 5,
            Self::KERIACDCGenusVersion => 3,
            _ => 2,
        }
    }

    /// Returns the full size of the counter frame in characters (hard + soft).
    #[must_use]
    pub const fn full_size(&self) -> usize {
        match self {
            Self::BigPathedMaterialCouples
            | Self::BigGenericGroup
            | Self::BigBodyWithAttachmentGroup
            | Self::BigAttachmentGroup
            | Self::BigNonNativeBodyGroup
            | Self::BigESSRPayloadGroup
            | Self::KERIACDCGenusVersion => 8,
            _ => 4,
        }
    }

    /// Returns the big variant of this code, if one exists.
    ///
    /// V1 only has big variants for quadlet-counted and `PathedMaterialCouples` codes.
    /// Element-counted codes (`-A` through `-I`) do not have big variants.
    /// Already-big codes and genus return `None`.
    #[must_use]
    pub const fn to_big(&self) -> Option<Self> {
        match self {
            Self::PathedMaterialCouples => Some(Self::BigPathedMaterialCouples),
            Self::GenericGroup => Some(Self::BigGenericGroup),
            Self::BodyWithAttachmentGroup => Some(Self::BigBodyWithAttachmentGroup),
            Self::AttachmentGroup => Some(Self::BigAttachmentGroup),
            Self::NonNativeBodyGroup => Some(Self::BigNonNativeBodyGroup),
            Self::ESSRPayloadGroup => Some(Self::BigESSRPayloadGroup),
            _ => None,
        }
    }

    /// Returns true if this is already a big code (hs=3).
    #[must_use]
    pub const fn is_big(&self) -> bool {
        self.hard_size() == 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(CounterCodeV1::ControllerIdxSigs, "-A")]
    #[case(CounterCodeV1::WitnessIdxSigs, "-B")]
    #[case(CounterCodeV1::NonTransReceiptCouples, "-C")]
    #[case(CounterCodeV1::TransReceiptQuadruples, "-D")]
    #[case(CounterCodeV1::FirstSeenReplayCouples, "-E")]
    #[case(CounterCodeV1::TransIdxSigGroups, "-F")]
    #[case(CounterCodeV1::SealSourceCouples, "-G")]
    #[case(CounterCodeV1::TransLastIdxSigGroups, "-H")]
    #[case(CounterCodeV1::SealSourceTriples, "-I")]
    #[case(CounterCodeV1::PathedMaterialCouples, "-L")]
    #[case(CounterCodeV1::BigPathedMaterialCouples, "--L")]
    #[case(CounterCodeV1::GenericGroup, "-T")]
    #[case(CounterCodeV1::BigGenericGroup, "--T")]
    #[case(CounterCodeV1::BodyWithAttachmentGroup, "-U")]
    #[case(CounterCodeV1::BigBodyWithAttachmentGroup, "--U")]
    #[case(CounterCodeV1::AttachmentGroup, "-V")]
    #[case(CounterCodeV1::BigAttachmentGroup, "--V")]
    #[case(CounterCodeV1::NonNativeBodyGroup, "-W")]
    #[case(CounterCodeV1::BigNonNativeBodyGroup, "--W")]
    #[case(CounterCodeV1::ESSRPayloadGroup, "-Z")]
    #[case(CounterCodeV1::BigESSRPayloadGroup, "--Z")]
    #[case(CounterCodeV1::KERIACDCGenusVersion, "-_AAA")]
    fn from_hard_roundtrip(#[case] code: CounterCodeV1, #[case] wire: &str) {
        assert_eq!(code.as_str(), wire);
        assert_eq!(CounterCodeV1::from_hard(wire).unwrap(), code);
        assert_eq!(CounterCodeV1::from_hard(code.as_str()).unwrap(), code);
    }

    #[rstest]
    #[case("-J")]
    #[case("-K")]
    #[case("-0V")]
    #[case("A")]
    #[case("")]
    fn from_hard_unknown(#[case] bad: &str) {
        assert!(CounterCodeV1::from_hard(bad).is_err());
        let err = CounterCodeV1::from_hard(bad).unwrap_err();
        assert_eq!(err, CounterCodeError::UnknownCode(bad.to_owned()));
    }

    #[rstest]
    #[case(CounterCodeV1::ControllerIdxSigs, 2, 2, 4)]
    #[case(CounterCodeV1::WitnessIdxSigs, 2, 2, 4)]
    #[case(CounterCodeV1::NonTransReceiptCouples, 2, 2, 4)]
    #[case(CounterCodeV1::TransReceiptQuadruples, 2, 2, 4)]
    #[case(CounterCodeV1::FirstSeenReplayCouples, 2, 2, 4)]
    #[case(CounterCodeV1::TransIdxSigGroups, 2, 2, 4)]
    #[case(CounterCodeV1::SealSourceCouples, 2, 2, 4)]
    #[case(CounterCodeV1::TransLastIdxSigGroups, 2, 2, 4)]
    #[case(CounterCodeV1::SealSourceTriples, 2, 2, 4)]
    #[case(CounterCodeV1::PathedMaterialCouples, 2, 2, 4)]
    #[case(CounterCodeV1::BigPathedMaterialCouples, 3, 5, 8)]
    #[case(CounterCodeV1::GenericGroup, 2, 2, 4)]
    #[case(CounterCodeV1::BigGenericGroup, 3, 5, 8)]
    #[case(CounterCodeV1::BodyWithAttachmentGroup, 2, 2, 4)]
    #[case(CounterCodeV1::BigBodyWithAttachmentGroup, 3, 5, 8)]
    #[case(CounterCodeV1::AttachmentGroup, 2, 2, 4)]
    #[case(CounterCodeV1::BigAttachmentGroup, 3, 5, 8)]
    #[case(CounterCodeV1::NonNativeBodyGroup, 2, 2, 4)]
    #[case(CounterCodeV1::BigNonNativeBodyGroup, 3, 5, 8)]
    #[case(CounterCodeV1::ESSRPayloadGroup, 2, 2, 4)]
    #[case(CounterCodeV1::BigESSRPayloadGroup, 3, 5, 8)]
    #[case(CounterCodeV1::KERIACDCGenusVersion, 5, 3, 8)]
    fn size_values(
        #[case] code: CounterCodeV1,
        #[case] hs: usize,
        #[case] ss: usize,
        #[case] fs: usize,
    ) {
        assert_eq!(code.hard_size(), hs);
        assert_eq!(code.soft_size(), ss);
        assert_eq!(code.full_size(), fs);
        assert_eq!(code.hard_size() + code.soft_size(), code.full_size());
    }

    #[test]
    fn counter_from_base64_stream() {
        assert_eq!(
            CounterCodeV1::from_base64_stream(b"-AAB").unwrap(),
            CounterCodeV1::ControllerIdxSigs
        );
        assert_eq!(
            CounterCodeV1::from_base64_stream(b"--LAAA").unwrap(),
            CounterCodeV1::BigPathedMaterialCouples
        );
        assert_eq!(
            CounterCodeV1::from_base64_stream(b"-_AAABAA").unwrap(),
            CounterCodeV1::KERIACDCGenusVersion
        );
        assert!(CounterCodeV1::from_base64_stream(b"").is_err());
        assert!(CounterCodeV1::from_base64_stream(b"-").is_err());
    }

    #[test]
    fn to_big_v1_promotable() {
        assert_eq!(
            CounterCodeV1::PathedMaterialCouples.to_big(),
            Some(CounterCodeV1::BigPathedMaterialCouples)
        );
        assert_eq!(
            CounterCodeV1::GenericGroup.to_big(),
            Some(CounterCodeV1::BigGenericGroup)
        );
        assert_eq!(
            CounterCodeV1::AttachmentGroup.to_big(),
            Some(CounterCodeV1::BigAttachmentGroup)
        );
        assert_eq!(
            CounterCodeV1::BodyWithAttachmentGroup.to_big(),
            Some(CounterCodeV1::BigBodyWithAttachmentGroup)
        );
        assert_eq!(
            CounterCodeV1::NonNativeBodyGroup.to_big(),
            Some(CounterCodeV1::BigNonNativeBodyGroup)
        );
        assert_eq!(
            CounterCodeV1::ESSRPayloadGroup.to_big(),
            Some(CounterCodeV1::BigESSRPayloadGroup)
        );
    }

    #[test]
    fn to_big_v1_not_promotable() {
        assert_eq!(CounterCodeV1::ControllerIdxSigs.to_big(), None);
        assert_eq!(CounterCodeV1::WitnessIdxSigs.to_big(), None);
        assert_eq!(CounterCodeV1::BigGenericGroup.to_big(), None);
        assert_eq!(CounterCodeV1::KERIACDCGenusVersion.to_big(), None);
    }

    #[test]
    fn is_big_v1() {
        assert!(!CounterCodeV1::GenericGroup.is_big());
        assert!(CounterCodeV1::BigGenericGroup.is_big());
        assert!(!CounterCodeV1::KERIACDCGenusVersion.is_big());
    }

    #[test]
    fn full_size_is_multiple_of_4() {
        let all_codes = [
            CounterCodeV1::ControllerIdxSigs,
            CounterCodeV1::WitnessIdxSigs,
            CounterCodeV1::NonTransReceiptCouples,
            CounterCodeV1::TransReceiptQuadruples,
            CounterCodeV1::FirstSeenReplayCouples,
            CounterCodeV1::TransIdxSigGroups,
            CounterCodeV1::SealSourceCouples,
            CounterCodeV1::TransLastIdxSigGroups,
            CounterCodeV1::SealSourceTriples,
            CounterCodeV1::PathedMaterialCouples,
            CounterCodeV1::BigPathedMaterialCouples,
            CounterCodeV1::GenericGroup,
            CounterCodeV1::BigGenericGroup,
            CounterCodeV1::BodyWithAttachmentGroup,
            CounterCodeV1::BigBodyWithAttachmentGroup,
            CounterCodeV1::AttachmentGroup,
            CounterCodeV1::BigAttachmentGroup,
            CounterCodeV1::NonNativeBodyGroup,
            CounterCodeV1::BigNonNativeBodyGroup,
            CounterCodeV1::ESSRPayloadGroup,
            CounterCodeV1::BigESSRPayloadGroup,
            CounterCodeV1::KERIACDCGenusVersion,
        ];
        for code in all_codes {
            assert_eq!(
                code.full_size() % 4,
                0,
                "{:?} full_size {} is not a multiple of 4",
                code,
                code.full_size()
            );
        }
    }
}
