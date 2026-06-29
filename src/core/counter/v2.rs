#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{borrow::ToOwned,};
use crate::core::counter::code::CounterCodeError;

/// CESR V2.0 counter (group) codes, aligned with the keripy `CtrDex_2_0` table.
///
/// V2.0 has 59 codes: 29 small (`-X`), 29 big (`--X`), and 1 genus (`-_AAA`).
/// Every small code has a corresponding big variant for counts exceeding 4095.
///
/// Size categories:
/// - Small codes (`-X`):   hs=2, ss=2, fs=4, max count = 4095
/// - Big codes (`--X`):    hs=3, ss=5, fs=8, max count = 1,073,741,823
/// - Genus (`-_AAA`):      hs=5, ss=3, fs=8
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CounterCodeV2 {
    /// `-A` — Generic group (quadlet count).
    GenericGroup,
    /// `--A` — Big generic group (quadlet count).
    BigGenericGroup,
    /// `-B` — Body with attachment group (quadlet count).
    BodyWithAttachmentGroup,
    /// `--B` — Big body with attachment group (quadlet count).
    BigBodyWithAttachmentGroup,
    /// `-C` — Attachment group (quadlet count).
    AttachmentGroup,
    /// `--C` — Big attachment group (quadlet count).
    BigAttachmentGroup,
    /// `-D` — Datagram segment group (quadlet count).
    DatagramSegmentGroup,
    /// `--D` — Big datagram segment group (quadlet count).
    BigDatagramSegmentGroup,
    /// `-E` — ESSR wrapper group (quadlet count).
    ESSRWrapperGroup,
    /// `--E` — Big ESSR wrapper group (quadlet count).
    BigESSRWrapperGroup,
    /// `-F` — Fixed body group (quadlet count).
    FixBodyGroup,
    /// `--F` — Big fixed body group (quadlet count).
    BigFixBodyGroup,
    /// `-G` — Map body group (quadlet count).
    MapBodyGroup,
    /// `--G` — Big map body group (quadlet count).
    BigMapBodyGroup,
    /// `-H` — Non-native body group (quadlet count).
    NonNativeBodyGroup,
    /// `--H` — Big non-native body group (quadlet count).
    BigNonNativeBodyGroup,
    /// `-I` — Generic map group (quadlet count).
    GenericMapGroup,
    /// `--I` — Big generic map group (quadlet count).
    BigGenericMapGroup,
    /// `-J` — Generic list group (quadlet count).
    GenericListGroup,
    /// `--J` — Big generic list group (quadlet count).
    BigGenericListGroup,
    /// `-K` — Controller indexed signatures (element count).
    ControllerIdxSigs,
    /// `--K` — Big controller indexed signatures (element count).
    BigControllerIdxSigs,
    /// `-L` — Witness indexed signatures (element count).
    WitnessIdxSigs,
    /// `--L` — Big witness indexed signatures (element count).
    BigWitnessIdxSigs,
    /// `-M` — Non-transferable receipt couples (element count).
    NonTransReceiptCouples,
    /// `--M` — Big non-transferable receipt couples (element count).
    BigNonTransReceiptCouples,
    /// `-N` — Transferable receipt quadruples (element count).
    TransReceiptQuadruples,
    /// `--N` — Big transferable receipt quadruples (element count).
    BigTransReceiptQuadruples,
    /// `-O` — First-seen replay couples (element count).
    FirstSeenReplayCouples,
    /// `--O` — Big first-seen replay couples (element count).
    BigFirstSeenReplayCouples,
    /// `-P` — Pathed material couples (element count).
    PathedMaterialCouples,
    /// `--P` — Big pathed material couples (element count).
    BigPathedMaterialCouples,
    /// `-Q` — Digest seal singles (element count).
    DigestSealSingles,
    /// `--Q` — Big digest seal singles (element count).
    BigDigestSealSingles,
    /// `-R` — Merkle root seal singles (element count).
    MerkleRootSealSingles,
    /// `--R` — Big Merkle root seal singles (element count).
    BigMerkleRootSealSingles,
    /// `-S` — Seal source couples (element count).
    SealSourceCouples,
    /// `--S` — Big seal source couples (element count).
    BigSealSourceCouples,
    /// `-T` — Seal source triples (element count).
    SealSourceTriples,
    /// `--T` — Big seal source triples (element count).
    BigSealSourceTriples,
    /// `-U` — Seal source last-event singles (element count).
    SealSourceLastSingles,
    /// `--U` — Big seal source last-event singles (element count).
    BigSealSourceLastSingles,
    /// `-V` — Backer registrar seal couples (element count).
    BackerRegistrarSealCouples,
    /// `--V` — Big backer registrar seal couples (element count).
    BigBackerRegistrarSealCouples,
    /// `-W` — Typed digest seal couples (element count).
    TypedDigestSealCouples,
    /// `--W` — Big typed digest seal couples (element count).
    BigTypedDigestSealCouples,
    /// `-X` — Transferable indexed sig groups (element count).
    TransIdxSigGroups,
    /// `--X` — Big transferable indexed sig groups (element count).
    BigTransIdxSigGroups,
    /// `-Y` — Transferable last-event indexed sig groups (element count).
    TransLastIdxSigGroups,
    /// `--Y` — Big transferable last-event indexed sig groups (element count).
    BigTransLastIdxSigGroups,
    /// `-Z` — ESSR payload group (quadlet count).
    ESSRPayloadGroup,
    /// `--Z` — Big ESSR payload group (quadlet count).
    BigESSRPayloadGroup,
    /// `-a` — Blinded state quadruples (element count).
    BlindedStateQuadruples,
    /// `--a` — Big blinded state quadruples (element count).
    BigBlindedStateQuadruples,
    /// `-b` — Bound state sextuples (element count).
    BoundStateSextuples,
    /// `--b` — Big bound state sextuples (element count).
    BigBoundStateSextuples,
    /// `-c` — Typed media quadruples (element count).
    TypedMediaQuadruples,
    /// `--c` — Big typed media quadruples (element count).
    BigTypedMediaQuadruples,
    /// `-_AAA` — KERI/ACDC genus version marker.
    KERIACDCGenusVersion,
}

impl CounterCodeV2 {
    /// Returns the CESR wire code string for this variant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GenericGroup => "-A",
            Self::BigGenericGroup => "--A",
            Self::BodyWithAttachmentGroup => "-B",
            Self::BigBodyWithAttachmentGroup => "--B",
            Self::AttachmentGroup => "-C",
            Self::BigAttachmentGroup => "--C",
            Self::DatagramSegmentGroup => "-D",
            Self::BigDatagramSegmentGroup => "--D",
            Self::ESSRWrapperGroup => "-E",
            Self::BigESSRWrapperGroup => "--E",
            Self::FixBodyGroup => "-F",
            Self::BigFixBodyGroup => "--F",
            Self::MapBodyGroup => "-G",
            Self::BigMapBodyGroup => "--G",
            Self::NonNativeBodyGroup => "-H",
            Self::BigNonNativeBodyGroup => "--H",
            Self::GenericMapGroup => "-I",
            Self::BigGenericMapGroup => "--I",
            Self::GenericListGroup => "-J",
            Self::BigGenericListGroup => "--J",
            Self::ControllerIdxSigs => "-K",
            Self::BigControllerIdxSigs => "--K",
            Self::WitnessIdxSigs => "-L",
            Self::BigWitnessIdxSigs => "--L",
            Self::NonTransReceiptCouples => "-M",
            Self::BigNonTransReceiptCouples => "--M",
            Self::TransReceiptQuadruples => "-N",
            Self::BigTransReceiptQuadruples => "--N",
            Self::FirstSeenReplayCouples => "-O",
            Self::BigFirstSeenReplayCouples => "--O",
            Self::PathedMaterialCouples => "-P",
            Self::BigPathedMaterialCouples => "--P",
            Self::DigestSealSingles => "-Q",
            Self::BigDigestSealSingles => "--Q",
            Self::MerkleRootSealSingles => "-R",
            Self::BigMerkleRootSealSingles => "--R",
            Self::SealSourceCouples => "-S",
            Self::BigSealSourceCouples => "--S",
            Self::SealSourceTriples => "-T",
            Self::BigSealSourceTriples => "--T",
            Self::SealSourceLastSingles => "-U",
            Self::BigSealSourceLastSingles => "--U",
            Self::BackerRegistrarSealCouples => "-V",
            Self::BigBackerRegistrarSealCouples => "--V",
            Self::TypedDigestSealCouples => "-W",
            Self::BigTypedDigestSealCouples => "--W",
            Self::TransIdxSigGroups => "-X",
            Self::BigTransIdxSigGroups => "--X",
            Self::TransLastIdxSigGroups => "-Y",
            Self::BigTransLastIdxSigGroups => "--Y",
            Self::ESSRPayloadGroup => "-Z",
            Self::BigESSRPayloadGroup => "--Z",
            Self::BlindedStateQuadruples => "-a",
            Self::BigBlindedStateQuadruples => "--a",
            Self::BoundStateSextuples => "-b",
            Self::BigBoundStateSextuples => "--b",
            Self::TypedMediaQuadruples => "-c",
            Self::BigTypedMediaQuadruples => "--c",
            Self::KERIACDCGenusVersion => "-_AAA",
        }
    }

    /// Parses a hard code string back to the corresponding enum variant.
    ///
    /// # Errors
    /// Returns [`CounterCodeError::UnknownCode`] if the string is not a recognized V2 code.
    pub fn from_hard(hard: &str) -> Result<Self, CounterCodeError> {
        match hard {
            "-A" => Ok(Self::GenericGroup),
            "--A" => Ok(Self::BigGenericGroup),
            "-B" => Ok(Self::BodyWithAttachmentGroup),
            "--B" => Ok(Self::BigBodyWithAttachmentGroup),
            "-C" => Ok(Self::AttachmentGroup),
            "--C" => Ok(Self::BigAttachmentGroup),
            "-D" => Ok(Self::DatagramSegmentGroup),
            "--D" => Ok(Self::BigDatagramSegmentGroup),
            "-E" => Ok(Self::ESSRWrapperGroup),
            "--E" => Ok(Self::BigESSRWrapperGroup),
            "-F" => Ok(Self::FixBodyGroup),
            "--F" => Ok(Self::BigFixBodyGroup),
            "-G" => Ok(Self::MapBodyGroup),
            "--G" => Ok(Self::BigMapBodyGroup),
            "-H" => Ok(Self::NonNativeBodyGroup),
            "--H" => Ok(Self::BigNonNativeBodyGroup),
            "-I" => Ok(Self::GenericMapGroup),
            "--I" => Ok(Self::BigGenericMapGroup),
            "-J" => Ok(Self::GenericListGroup),
            "--J" => Ok(Self::BigGenericListGroup),
            "-K" => Ok(Self::ControllerIdxSigs),
            "--K" => Ok(Self::BigControllerIdxSigs),
            "-L" => Ok(Self::WitnessIdxSigs),
            "--L" => Ok(Self::BigWitnessIdxSigs),
            "-M" => Ok(Self::NonTransReceiptCouples),
            "--M" => Ok(Self::BigNonTransReceiptCouples),
            "-N" => Ok(Self::TransReceiptQuadruples),
            "--N" => Ok(Self::BigTransReceiptQuadruples),
            "-O" => Ok(Self::FirstSeenReplayCouples),
            "--O" => Ok(Self::BigFirstSeenReplayCouples),
            "-P" => Ok(Self::PathedMaterialCouples),
            "--P" => Ok(Self::BigPathedMaterialCouples),
            "-Q" => Ok(Self::DigestSealSingles),
            "--Q" => Ok(Self::BigDigestSealSingles),
            "-R" => Ok(Self::MerkleRootSealSingles),
            "--R" => Ok(Self::BigMerkleRootSealSingles),
            "-S" => Ok(Self::SealSourceCouples),
            "--S" => Ok(Self::BigSealSourceCouples),
            "-T" => Ok(Self::SealSourceTriples),
            "--T" => Ok(Self::BigSealSourceTriples),
            "-U" => Ok(Self::SealSourceLastSingles),
            "--U" => Ok(Self::BigSealSourceLastSingles),
            "-V" => Ok(Self::BackerRegistrarSealCouples),
            "--V" => Ok(Self::BigBackerRegistrarSealCouples),
            "-W" => Ok(Self::TypedDigestSealCouples),
            "--W" => Ok(Self::BigTypedDigestSealCouples),
            "-X" => Ok(Self::TransIdxSigGroups),
            "--X" => Ok(Self::BigTransIdxSigGroups),
            "-Y" => Ok(Self::TransLastIdxSigGroups),
            "--Y" => Ok(Self::BigTransLastIdxSigGroups),
            "-Z" => Ok(Self::ESSRPayloadGroup),
            "--Z" => Ok(Self::BigESSRPayloadGroup),
            "-a" => Ok(Self::BlindedStateQuadruples),
            "--a" => Ok(Self::BigBlindedStateQuadruples),
            "-b" => Ok(Self::BoundStateSextuples),
            "--b" => Ok(Self::BigBoundStateSextuples),
            "-c" => Ok(Self::TypedMediaQuadruples),
            "--c" => Ok(Self::BigTypedMediaQuadruples),
            "-_AAA" => Ok(Self::KERIACDCGenusVersion),
            _ => Err(CounterCodeError::UnknownCode(hard.to_owned())),
        }
    }

    /// Returns the hard size (number of characters in the code prefix).
    #[must_use]
    pub const fn hard_size(&self) -> usize {
        match self {
            Self::BigGenericGroup
            | Self::BigBodyWithAttachmentGroup
            | Self::BigAttachmentGroup
            | Self::BigDatagramSegmentGroup
            | Self::BigESSRWrapperGroup
            | Self::BigFixBodyGroup
            | Self::BigMapBodyGroup
            | Self::BigNonNativeBodyGroup
            | Self::BigGenericMapGroup
            | Self::BigGenericListGroup
            | Self::BigControllerIdxSigs
            | Self::BigWitnessIdxSigs
            | Self::BigNonTransReceiptCouples
            | Self::BigTransReceiptQuadruples
            | Self::BigFirstSeenReplayCouples
            | Self::BigPathedMaterialCouples
            | Self::BigDigestSealSingles
            | Self::BigMerkleRootSealSingles
            | Self::BigSealSourceCouples
            | Self::BigSealSourceTriples
            | Self::BigSealSourceLastSingles
            | Self::BigBackerRegistrarSealCouples
            | Self::BigTypedDigestSealCouples
            | Self::BigTransIdxSigGroups
            | Self::BigTransLastIdxSigGroups
            | Self::BigESSRPayloadGroup
            | Self::BigBlindedStateQuadruples
            | Self::BigBoundStateSextuples
            | Self::BigTypedMediaQuadruples => 3,
            Self::KERIACDCGenusVersion => 5,
            _ => 2,
        }
    }

    /// Returns the soft size (number of characters encoding the count).
    #[must_use]
    pub const fn soft_size(&self) -> usize {
        match self {
            Self::BigGenericGroup
            | Self::BigBodyWithAttachmentGroup
            | Self::BigAttachmentGroup
            | Self::BigDatagramSegmentGroup
            | Self::BigESSRWrapperGroup
            | Self::BigFixBodyGroup
            | Self::BigMapBodyGroup
            | Self::BigNonNativeBodyGroup
            | Self::BigGenericMapGroup
            | Self::BigGenericListGroup
            | Self::BigControllerIdxSigs
            | Self::BigWitnessIdxSigs
            | Self::BigNonTransReceiptCouples
            | Self::BigTransReceiptQuadruples
            | Self::BigFirstSeenReplayCouples
            | Self::BigPathedMaterialCouples
            | Self::BigDigestSealSingles
            | Self::BigMerkleRootSealSingles
            | Self::BigSealSourceCouples
            | Self::BigSealSourceTriples
            | Self::BigSealSourceLastSingles
            | Self::BigBackerRegistrarSealCouples
            | Self::BigTypedDigestSealCouples
            | Self::BigTransIdxSigGroups
            | Self::BigTransLastIdxSigGroups
            | Self::BigESSRPayloadGroup
            | Self::BigBlindedStateQuadruples
            | Self::BigBoundStateSextuples
            | Self::BigTypedMediaQuadruples => 5,
            Self::KERIACDCGenusVersion => 3,
            _ => 2,
        }
    }

    /// Returns the full size of the counter frame in characters (hard + soft).
    #[must_use]
    pub const fn full_size(&self) -> usize {
        match self {
            Self::BigGenericGroup
            | Self::BigBodyWithAttachmentGroup
            | Self::BigAttachmentGroup
            | Self::BigDatagramSegmentGroup
            | Self::BigESSRWrapperGroup
            | Self::BigFixBodyGroup
            | Self::BigMapBodyGroup
            | Self::BigNonNativeBodyGroup
            | Self::BigGenericMapGroup
            | Self::BigGenericListGroup
            | Self::BigControllerIdxSigs
            | Self::BigWitnessIdxSigs
            | Self::BigNonTransReceiptCouples
            | Self::BigTransReceiptQuadruples
            | Self::BigFirstSeenReplayCouples
            | Self::BigPathedMaterialCouples
            | Self::BigDigestSealSingles
            | Self::BigMerkleRootSealSingles
            | Self::BigSealSourceCouples
            | Self::BigSealSourceTriples
            | Self::BigSealSourceLastSingles
            | Self::BigBackerRegistrarSealCouples
            | Self::BigTypedDigestSealCouples
            | Self::BigTransIdxSigGroups
            | Self::BigTransLastIdxSigGroups
            | Self::BigESSRPayloadGroup
            | Self::BigBlindedStateQuadruples
            | Self::BigBoundStateSextuples
            | Self::BigTypedMediaQuadruples
            | Self::KERIACDCGenusVersion => 8,
            _ => 4,
        }
    }

    /// Returns the big variant of this code, if one exists.
    ///
    /// V2 has big variants for all small codes. Returns `None` for
    /// already-big codes and genus.
    #[must_use]
    pub const fn to_big(&self) -> Option<Self> {
        match self {
            Self::GenericGroup => Some(Self::BigGenericGroup),
            Self::BodyWithAttachmentGroup => Some(Self::BigBodyWithAttachmentGroup),
            Self::AttachmentGroup => Some(Self::BigAttachmentGroup),
            Self::DatagramSegmentGroup => Some(Self::BigDatagramSegmentGroup),
            Self::ESSRWrapperGroup => Some(Self::BigESSRWrapperGroup),
            Self::FixBodyGroup => Some(Self::BigFixBodyGroup),
            Self::MapBodyGroup => Some(Self::BigMapBodyGroup),
            Self::NonNativeBodyGroup => Some(Self::BigNonNativeBodyGroup),
            Self::GenericMapGroup => Some(Self::BigGenericMapGroup),
            Self::GenericListGroup => Some(Self::BigGenericListGroup),
            Self::ControllerIdxSigs => Some(Self::BigControllerIdxSigs),
            Self::WitnessIdxSigs => Some(Self::BigWitnessIdxSigs),
            Self::NonTransReceiptCouples => Some(Self::BigNonTransReceiptCouples),
            Self::TransReceiptQuadruples => Some(Self::BigTransReceiptQuadruples),
            Self::FirstSeenReplayCouples => Some(Self::BigFirstSeenReplayCouples),
            Self::PathedMaterialCouples => Some(Self::BigPathedMaterialCouples),
            Self::DigestSealSingles => Some(Self::BigDigestSealSingles),
            Self::MerkleRootSealSingles => Some(Self::BigMerkleRootSealSingles),
            Self::SealSourceCouples => Some(Self::BigSealSourceCouples),
            Self::SealSourceTriples => Some(Self::BigSealSourceTriples),
            Self::SealSourceLastSingles => Some(Self::BigSealSourceLastSingles),
            Self::BackerRegistrarSealCouples => Some(Self::BigBackerRegistrarSealCouples),
            Self::TypedDigestSealCouples => Some(Self::BigTypedDigestSealCouples),
            Self::TransIdxSigGroups => Some(Self::BigTransIdxSigGroups),
            Self::TransLastIdxSigGroups => Some(Self::BigTransLastIdxSigGroups),
            Self::ESSRPayloadGroup => Some(Self::BigESSRPayloadGroup),
            Self::BlindedStateQuadruples => Some(Self::BigBlindedStateQuadruples),
            Self::BoundStateSextuples => Some(Self::BigBoundStateSextuples),
            Self::TypedMediaQuadruples => Some(Self::BigTypedMediaQuadruples),
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
    #[case(CounterCodeV2::GenericGroup, "-A")]
    #[case(CounterCodeV2::BigGenericGroup, "--A")]
    #[case(CounterCodeV2::BodyWithAttachmentGroup, "-B")]
    #[case(CounterCodeV2::BigBodyWithAttachmentGroup, "--B")]
    #[case(CounterCodeV2::AttachmentGroup, "-C")]
    #[case(CounterCodeV2::BigAttachmentGroup, "--C")]
    #[case(CounterCodeV2::DatagramSegmentGroup, "-D")]
    #[case(CounterCodeV2::BigDatagramSegmentGroup, "--D")]
    #[case(CounterCodeV2::ESSRWrapperGroup, "-E")]
    #[case(CounterCodeV2::BigESSRWrapperGroup, "--E")]
    #[case(CounterCodeV2::FixBodyGroup, "-F")]
    #[case(CounterCodeV2::BigFixBodyGroup, "--F")]
    #[case(CounterCodeV2::MapBodyGroup, "-G")]
    #[case(CounterCodeV2::BigMapBodyGroup, "--G")]
    #[case(CounterCodeV2::NonNativeBodyGroup, "-H")]
    #[case(CounterCodeV2::BigNonNativeBodyGroup, "--H")]
    #[case(CounterCodeV2::GenericMapGroup, "-I")]
    #[case(CounterCodeV2::BigGenericMapGroup, "--I")]
    #[case(CounterCodeV2::GenericListGroup, "-J")]
    #[case(CounterCodeV2::BigGenericListGroup, "--J")]
    #[case(CounterCodeV2::ControllerIdxSigs, "-K")]
    #[case(CounterCodeV2::BigControllerIdxSigs, "--K")]
    #[case(CounterCodeV2::WitnessIdxSigs, "-L")]
    #[case(CounterCodeV2::BigWitnessIdxSigs, "--L")]
    #[case(CounterCodeV2::NonTransReceiptCouples, "-M")]
    #[case(CounterCodeV2::BigNonTransReceiptCouples, "--M")]
    #[case(CounterCodeV2::TransReceiptQuadruples, "-N")]
    #[case(CounterCodeV2::BigTransReceiptQuadruples, "--N")]
    #[case(CounterCodeV2::FirstSeenReplayCouples, "-O")]
    #[case(CounterCodeV2::BigFirstSeenReplayCouples, "--O")]
    #[case(CounterCodeV2::PathedMaterialCouples, "-P")]
    #[case(CounterCodeV2::BigPathedMaterialCouples, "--P")]
    #[case(CounterCodeV2::DigestSealSingles, "-Q")]
    #[case(CounterCodeV2::BigDigestSealSingles, "--Q")]
    #[case(CounterCodeV2::MerkleRootSealSingles, "-R")]
    #[case(CounterCodeV2::BigMerkleRootSealSingles, "--R")]
    #[case(CounterCodeV2::SealSourceCouples, "-S")]
    #[case(CounterCodeV2::BigSealSourceCouples, "--S")]
    #[case(CounterCodeV2::SealSourceTriples, "-T")]
    #[case(CounterCodeV2::BigSealSourceTriples, "--T")]
    #[case(CounterCodeV2::SealSourceLastSingles, "-U")]
    #[case(CounterCodeV2::BigSealSourceLastSingles, "--U")]
    #[case(CounterCodeV2::BackerRegistrarSealCouples, "-V")]
    #[case(CounterCodeV2::BigBackerRegistrarSealCouples, "--V")]
    #[case(CounterCodeV2::TypedDigestSealCouples, "-W")]
    #[case(CounterCodeV2::BigTypedDigestSealCouples, "--W")]
    #[case(CounterCodeV2::TransIdxSigGroups, "-X")]
    #[case(CounterCodeV2::BigTransIdxSigGroups, "--X")]
    #[case(CounterCodeV2::TransLastIdxSigGroups, "-Y")]
    #[case(CounterCodeV2::BigTransLastIdxSigGroups, "--Y")]
    #[case(CounterCodeV2::ESSRPayloadGroup, "-Z")]
    #[case(CounterCodeV2::BigESSRPayloadGroup, "--Z")]
    #[case(CounterCodeV2::BlindedStateQuadruples, "-a")]
    #[case(CounterCodeV2::BigBlindedStateQuadruples, "--a")]
    #[case(CounterCodeV2::BoundStateSextuples, "-b")]
    #[case(CounterCodeV2::BigBoundStateSextuples, "--b")]
    #[case(CounterCodeV2::TypedMediaQuadruples, "-c")]
    #[case(CounterCodeV2::BigTypedMediaQuadruples, "--c")]
    #[case(CounterCodeV2::KERIACDCGenusVersion, "-_AAA")]
    fn from_hard_roundtrip(#[case] code: CounterCodeV2, #[case] wire: &str) {
        assert_eq!(code.as_str(), wire);
        assert_eq!(CounterCodeV2::from_hard(wire).unwrap(), code);
        assert_eq!(CounterCodeV2::from_hard(code.as_str()).unwrap(), code);
    }

    #[rstest]
    #[case("-0V")]
    #[case("A")]
    #[case("")]
    #[case("-d")]
    fn from_hard_unknown(#[case] bad: &str) {
        assert!(CounterCodeV2::from_hard(bad).is_err());
        let err = CounterCodeV2::from_hard(bad).unwrap_err();
        assert_eq!(err, CounterCodeError::UnknownCode(bad.to_owned()));
    }

    #[rstest]
    #[case(CounterCodeV2::GenericGroup, 2, 2, 4)]
    #[case(CounterCodeV2::BigGenericGroup, 3, 5, 8)]
    #[case(CounterCodeV2::ControllerIdxSigs, 2, 2, 4)]
    #[case(CounterCodeV2::BigControllerIdxSigs, 3, 5, 8)]
    #[case(CounterCodeV2::ESSRPayloadGroup, 2, 2, 4)]
    #[case(CounterCodeV2::BigESSRPayloadGroup, 3, 5, 8)]
    #[case(CounterCodeV2::BlindedStateQuadruples, 2, 2, 4)]
    #[case(CounterCodeV2::BigBlindedStateQuadruples, 3, 5, 8)]
    #[case(CounterCodeV2::TypedMediaQuadruples, 2, 2, 4)]
    #[case(CounterCodeV2::BigTypedMediaQuadruples, 3, 5, 8)]
    #[case(CounterCodeV2::KERIACDCGenusVersion, 5, 3, 8)]
    fn size_values(
        #[case] code: CounterCodeV2,
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
    fn to_big_v2_all_small_promotable() {
        let small_codes = [
            CounterCodeV2::GenericGroup,
            CounterCodeV2::BodyWithAttachmentGroup,
            CounterCodeV2::AttachmentGroup,
            CounterCodeV2::DatagramSegmentGroup,
            CounterCodeV2::ESSRWrapperGroup,
            CounterCodeV2::FixBodyGroup,
            CounterCodeV2::MapBodyGroup,
            CounterCodeV2::NonNativeBodyGroup,
            CounterCodeV2::GenericMapGroup,
            CounterCodeV2::GenericListGroup,
            CounterCodeV2::ControllerIdxSigs,
            CounterCodeV2::WitnessIdxSigs,
            CounterCodeV2::NonTransReceiptCouples,
            CounterCodeV2::TransReceiptQuadruples,
            CounterCodeV2::FirstSeenReplayCouples,
            CounterCodeV2::PathedMaterialCouples,
            CounterCodeV2::DigestSealSingles,
            CounterCodeV2::MerkleRootSealSingles,
            CounterCodeV2::SealSourceCouples,
            CounterCodeV2::SealSourceTriples,
            CounterCodeV2::SealSourceLastSingles,
            CounterCodeV2::BackerRegistrarSealCouples,
            CounterCodeV2::TypedDigestSealCouples,
            CounterCodeV2::TransIdxSigGroups,
            CounterCodeV2::TransLastIdxSigGroups,
            CounterCodeV2::ESSRPayloadGroup,
            CounterCodeV2::BlindedStateQuadruples,
            CounterCodeV2::BoundStateSextuples,
            CounterCodeV2::TypedMediaQuadruples,
        ];
        for code in small_codes {
            assert!(
                code.to_big().is_some(),
                "{code:?} should have a big variant"
            );
        }
    }

    #[test]
    fn to_big_v2_big_returns_none() {
        assert_eq!(CounterCodeV2::BigGenericGroup.to_big(), None);
        assert_eq!(CounterCodeV2::BigControllerIdxSigs.to_big(), None);
        assert_eq!(CounterCodeV2::KERIACDCGenusVersion.to_big(), None);
    }

    #[test]
    fn is_big_v2() {
        assert!(!CounterCodeV2::GenericGroup.is_big());
        assert!(CounterCodeV2::BigGenericGroup.is_big());
    }

    #[test]
    fn full_size_is_multiple_of_4() {
        let all_codes = [
            CounterCodeV2::GenericGroup,
            CounterCodeV2::BigGenericGroup,
            CounterCodeV2::BodyWithAttachmentGroup,
            CounterCodeV2::BigBodyWithAttachmentGroup,
            CounterCodeV2::AttachmentGroup,
            CounterCodeV2::BigAttachmentGroup,
            CounterCodeV2::DatagramSegmentGroup,
            CounterCodeV2::BigDatagramSegmentGroup,
            CounterCodeV2::ESSRWrapperGroup,
            CounterCodeV2::BigESSRWrapperGroup,
            CounterCodeV2::FixBodyGroup,
            CounterCodeV2::BigFixBodyGroup,
            CounterCodeV2::MapBodyGroup,
            CounterCodeV2::BigMapBodyGroup,
            CounterCodeV2::NonNativeBodyGroup,
            CounterCodeV2::BigNonNativeBodyGroup,
            CounterCodeV2::GenericMapGroup,
            CounterCodeV2::BigGenericMapGroup,
            CounterCodeV2::GenericListGroup,
            CounterCodeV2::BigGenericListGroup,
            CounterCodeV2::ControllerIdxSigs,
            CounterCodeV2::BigControllerIdxSigs,
            CounterCodeV2::WitnessIdxSigs,
            CounterCodeV2::BigWitnessIdxSigs,
            CounterCodeV2::NonTransReceiptCouples,
            CounterCodeV2::BigNonTransReceiptCouples,
            CounterCodeV2::TransReceiptQuadruples,
            CounterCodeV2::BigTransReceiptQuadruples,
            CounterCodeV2::FirstSeenReplayCouples,
            CounterCodeV2::BigFirstSeenReplayCouples,
            CounterCodeV2::PathedMaterialCouples,
            CounterCodeV2::BigPathedMaterialCouples,
            CounterCodeV2::DigestSealSingles,
            CounterCodeV2::BigDigestSealSingles,
            CounterCodeV2::MerkleRootSealSingles,
            CounterCodeV2::BigMerkleRootSealSingles,
            CounterCodeV2::SealSourceCouples,
            CounterCodeV2::BigSealSourceCouples,
            CounterCodeV2::SealSourceTriples,
            CounterCodeV2::BigSealSourceTriples,
            CounterCodeV2::SealSourceLastSingles,
            CounterCodeV2::BigSealSourceLastSingles,
            CounterCodeV2::BackerRegistrarSealCouples,
            CounterCodeV2::BigBackerRegistrarSealCouples,
            CounterCodeV2::TypedDigestSealCouples,
            CounterCodeV2::BigTypedDigestSealCouples,
            CounterCodeV2::TransIdxSigGroups,
            CounterCodeV2::BigTransIdxSigGroups,
            CounterCodeV2::TransLastIdxSigGroups,
            CounterCodeV2::BigTransLastIdxSigGroups,
            CounterCodeV2::ESSRPayloadGroup,
            CounterCodeV2::BigESSRPayloadGroup,
            CounterCodeV2::BlindedStateQuadruples,
            CounterCodeV2::BigBlindedStateQuadruples,
            CounterCodeV2::BoundStateSextuples,
            CounterCodeV2::BigBoundStateSextuples,
            CounterCodeV2::TypedMediaQuadruples,
            CounterCodeV2::BigTypedMediaQuadruples,
            CounterCodeV2::KERIACDCGenusVersion,
        ];
        assert_eq!(all_codes.len(), 59);
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
