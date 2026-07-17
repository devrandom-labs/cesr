//! The group families: one sealed kind per counter-code family.
//!
//! Each kind is an uninhabited marker enum that declares a family's wire
//! knowledge in one place — its counter code(s) and its element grammar
//! ([`GroupKind::element`] / [`GroupKind::skip`]) for element-counted
//! groups, or its counter code(s) alone ([`FrameKind`]) for quadlet-counted
//! framing groups. The public group types are aliases of the carriers:
//! `ControllerIdxSigs` is [`Group`]`<`[`ControllerIdxSig`]`>`,
//! `AttachmentGroup` is [`Frame`]`<`[`Attachment`]`>`, and so on.
//!
//! Group framing is deliberately more lenient than element typing: [`skip`]
//! sizes elements with the [`TextStream`] cursor's lenient `skip_matter`/
//! `skip_indexer` methods (any code of the right class), while [`element`]
//! narrows to the family's typed primitives.
//! A group whose payload holds well-formed primitives of an unexpected code
//! therefore frames successfully and fails typed on iteration — exactly the
//! behavior of the per-group parsers this module replaces.
//!
//! [`skip`]: GroupKind::skip
//! [`element`]: GroupKind::element

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec::Vec};
use bytes::Bytes;

use crate::error::ParseError;
use crate::parse::TextStream;
use cesr::core::counter::CounterCodeV1;
use cesr::core::counter::CounterCodeV2;
use cesr::core::matter::Matter;
use cesr::core::matter::code::MatterCode;
use cesr::core::primitives::Cigar;
use cesr::core::primitives::Diger;
use cesr::core::primitives::Labeler;
use cesr::core::primitives::Noncer;
use cesr::core::primitives::Number;
use cesr::core::primitives::Prefixer;
use cesr::core::primitives::Saider;
use cesr::core::primitives::Siger;
use cesr::core::primitives::Texter;
use cesr::core::primitives::Verser;
use cesr::core::version::CesrVersion;

use super::Frame;
use super::FrameKind;
use super::Group;
use super::GroupKind;
use super::V1FrameKind;
use super::V1GroupKind;
use super::private;

// ── Shared grammar helpers ───────────────────────────────────────────────

/// Size the nested controller-sig sub-group (counter + indexed signatures)
/// heading `input`, validating that the counter is the version's
/// `ControllerIdxSigs` code (`-A` in V1, `-K` in V2). The `outer_v1` /
/// `outer_v2` wire letters name the enclosing group in the error message.
fn skip_nested_controller_sigs(
    input: &[u8],
    version: CesrVersion,
    outer_v1: &str,
    outer_v2: &str,
) -> Result<usize, ParseError> {
    let mut ts = TextStream::new(input);
    ts.skip_counter()?;
    let sub_count = match version {
        CesrVersion::V1 => {
            let (code, sub_count) = TextStream::new(input).read_counter_v1()?;
            if code != CounterCodeV1::ControllerIdxSigs {
                return Err(ParseError::Malformed(format!(
                    "expected -A counter inside {outer_v1} group, got {}",
                    code.as_str()
                )));
            }
            sub_count
        }
        CesrVersion::V2 => {
            let (code, sub_count) = TextStream::new(input).read_counter_v2()?;
            if code != CounterCodeV2::ControllerIdxSigs {
                return Err(ParseError::Malformed(format!(
                    "expected -K counter inside {outer_v2} group (V2), got {}",
                    code.as_str()
                )));
            }
            sub_count
        }
    };
    for _ in 0..sub_count {
        ts.skip_indexer()?;
    }
    Ok(ts.offset())
}

/// Parse the nested controller-sig sub-group heading `input` into a
/// [`ControllerIdxSigs`], returning it with the bytes consumed. The counter
/// code is not re-validated here — framing ([`GroupKind::skip`]) already
/// validated it over the same span.
fn nested_controller_sigs(
    input: &[u8],
    version: CesrVersion,
) -> Result<(ControllerIdxSigs, usize), ParseError> {
    let mut ts = TextStream::new(input);
    ts.skip_counter()?;
    let counter_size = ts.offset();
    let sub_count = match version {
        CesrVersion::V1 => TextStream::new(input).read_counter_v1()?.1,
        CesrVersion::V2 => TextStream::new(input).read_counter_v2()?.1,
    };
    for _ in 0..sub_count {
        ts.skip_indexer()?;
    }
    let end = ts.offset();
    let raw = Bytes::copy_from_slice(&input[counter_size..end]);
    Ok((ControllerIdxSigs::new(raw, sub_count, version), end))
}

/// Encode indexed signatures into a group's backing bytes, deriving the
/// element count from the input so the count/raw invariant holds by
/// construction ([`Siger::to_qb64`] is infallible; the count conversion is
/// checked).
fn encode_sigers(sigers: &[Siger<'_>]) -> Result<(Bytes, u32), ParseError> {
    let count = u32::try_from(sigers.len()).map_err(|_| {
        ParseError::Malformed(format!(
            "indexed signature count {} exceeds the group count range",
            sigers.len()
        ))
    })?;
    let raw: Vec<u8> = sigers
        .iter()
        .flat_map(|siger| siger.to_qb64().into_bytes())
        .collect();
    Ok((Bytes::from(raw), count))
}

// ── Element-counted kinds, shared V1 + V2 ────────────────────────────────

/// One controller indexed signature (`-A`/`-K` element grammar).
pub enum ControllerIdxSig {}
impl private::Sealed for ControllerIdxSig {}
impl GroupKind for ControllerIdxSig {
    type Element = Siger<'static>;
    const CODE_V2: CounterCodeV2 = CounterCodeV2::ControllerIdxSigs;
    const NAME: &'static str = "ControllerIdxSigs";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let siger = ts.read_siger()?;
        Ok((siger, ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_indexer()?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for ControllerIdxSig {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::ControllerIdxSigs;
}

/// `-A` (V1) / `-K` (V2) — Controller indexed signatures.
pub type ControllerIdxSigs = Group<ControllerIdxSig>;

/// One witness indexed signature (`-B`/`-L` element grammar).
pub enum WitnessIdxSig {}
impl private::Sealed for WitnessIdxSig {}
impl GroupKind for WitnessIdxSig {
    type Element = Siger<'static>;
    const CODE_V2: CounterCodeV2 = CounterCodeV2::WitnessIdxSigs;
    const NAME: &'static str = "WitnessIdxSigs";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let siger = ts.read_siger()?;
        Ok((siger, ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_indexer()?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for WitnessIdxSig {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::WitnessIdxSigs;
}

/// `-B` (V1) / `-L` (V2) — Witness indexed signatures.
pub type WitnessIdxSigs = Group<WitnessIdxSig>;

/// One non-transferable receipt couple: (prefix, non-indexed signature).
pub enum NonTransReceiptCouple {}
impl private::Sealed for NonTransReceiptCouple {}
impl GroupKind for NonTransReceiptCouple {
    type Element = (Prefixer<'static>, Cigar<'static>);
    const CODE_V2: CounterCodeV2 = CounterCodeV2::NonTransReceiptCouples;
    const NAME: &'static str = "NonTransReceiptCouples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        let cigar = ts.read_cigar()?;
        Ok(((prefixer, cigar), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(2)?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for NonTransReceiptCouple {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::NonTransReceiptCouples;
}

/// `-C` (V1) / `-M` (V2) — Non-transferable receipt couples: (prefix, non-indexed signature)
pub type NonTransReceiptCouples = Group<NonTransReceiptCouple>;

/// One transferable receipt quadruple: (prefix, sequence number, SAID,
/// indexed signature).
pub enum TransReceiptQuadruple {}
impl private::Sealed for TransReceiptQuadruple {}
impl GroupKind for TransReceiptQuadruple {
    type Element = (
        Prefixer<'static>,
        Matter<'static, MatterCode>,
        Saider<'static>,
        Siger<'static>,
    );
    const CODE_V2: CounterCodeV2 = CounterCodeV2::TransReceiptQuadruples;
    const NAME: &'static str = "TransReceiptQuadruples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        let seqner = ts.read_matter()?;
        let saider = ts.read_saider()?;
        let siger = ts.read_siger()?;
        Ok(((prefixer, seqner, saider, siger), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(3)?;
        ts.skip_indexer()?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for TransReceiptQuadruple {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::TransReceiptQuadruples;
}

/// `-D` (V1) / `-N` (V2) — Transferable receipt quadruples: (prefix, sequence number, SAID, indexed sig)
pub type TransReceiptQuadruples = Group<TransReceiptQuadruple>;

/// One first-seen replay couple: (sequence number, datetime).
pub enum FirstSeenReplayCouple {}
impl private::Sealed for FirstSeenReplayCouple {}
impl GroupKind for FirstSeenReplayCouple {
    type Element = (Matter<'static, MatterCode>, Matter<'static, MatterCode>);
    const CODE_V2: CounterCodeV2 = CounterCodeV2::FirstSeenReplayCouples;
    const NAME: &'static str = "FirstSeenReplayCouples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let seqner = ts.read_matter()?;
        let dater = ts.read_matter()?;
        Ok(((seqner, dater), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(2)?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for FirstSeenReplayCouple {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::FirstSeenReplayCouples;
}

/// `-E` (V1) / `-O` (V2) — First-seen replay couples: (sequence number, datetime)
pub type FirstSeenReplayCouples = Group<FirstSeenReplayCouple>;

/// One transferable indexed-sig group element: (prefix, sequence number,
/// SAID, nested controller sigs).
pub enum TransIdxSigGroup {}
impl private::Sealed for TransIdxSigGroup {}
impl GroupKind for TransIdxSigGroup {
    type Element = (
        Prefixer<'static>,
        Matter<'static, MatterCode>,
        Saider<'static>,
        ControllerIdxSigs,
    );
    const CODE_V2: CounterCodeV2 = CounterCodeV2::TransIdxSigGroups;
    const NAME: &'static str = "TransIdxSigGroups";
    fn element(input: &[u8], version: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        let seqner = ts.read_matter()?;
        let saider = ts.read_saider()?;
        let head = ts.offset();
        let (sigs, nested) = nested_controller_sigs(ts.remaining(), version)?;
        let consumed = head
            .checked_add(nested)
            .ok_or_else(|| ParseError::Malformed("element span overflows the group".into()))?;
        Ok(((prefixer, seqner, saider, sigs), consumed))
    }
    fn skip(input: &[u8], version: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(3)?;
        let offset = ts.offset();
        let nested = skip_nested_controller_sigs(ts.remaining(), version, "-F", "-X")?;
        offset
            .checked_add(nested)
            .ok_or_else(|| ParseError::Malformed("element span overflows the group".into()))
    }
}
impl V1GroupKind for TransIdxSigGroup {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::TransIdxSigGroups;
}

/// `-F` (V1) / `-X` (V2) — Transferable indexed sig groups: (prefix, seqner, SAID, controller sigs)
pub type TransIdxSigGroups = Group<TransIdxSigGroup>;

/// One seal source couple: (sequence number, SAID).
pub enum SealSourceCouple {}
impl private::Sealed for SealSourceCouple {}
impl GroupKind for SealSourceCouple {
    type Element = (Matter<'static, MatterCode>, Saider<'static>);
    const CODE_V2: CounterCodeV2 = CounterCodeV2::SealSourceCouples;
    const NAME: &'static str = "SealSourceCouples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let seqner = ts.read_matter()?;
        let saider = ts.read_saider()?;
        Ok(((seqner, saider), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(2)?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for SealSourceCouple {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::SealSourceCouples;
}

/// `-G` (V1) / `-S` (V2) — Seal source couples: (sequence number, SAID)
pub type SealSourceCouples = Group<SealSourceCouple>;

/// One transferable last-event indexed-sig group element: (prefix, nested
/// controller sigs).
pub enum TransLastIdxSigGroup {}
impl private::Sealed for TransLastIdxSigGroup {}
impl GroupKind for TransLastIdxSigGroup {
    type Element = (Prefixer<'static>, ControllerIdxSigs);
    const CODE_V2: CounterCodeV2 = CounterCodeV2::TransLastIdxSigGroups;
    const NAME: &'static str = "TransLastIdxSigGroups";
    fn element(input: &[u8], version: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        let head = ts.offset();
        let (sigs, nested) = nested_controller_sigs(ts.remaining(), version)?;
        let consumed = head
            .checked_add(nested)
            .ok_or_else(|| ParseError::Malformed("element span overflows the group".into()))?;
        Ok(((prefixer, sigs), consumed))
    }
    fn skip(input: &[u8], version: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(1)?;
        let offset = ts.offset();
        let nested = skip_nested_controller_sigs(ts.remaining(), version, "-H", "-Y")?;
        offset
            .checked_add(nested)
            .ok_or_else(|| ParseError::Malformed("element span overflows the group".into()))
    }
}
impl V1GroupKind for TransLastIdxSigGroup {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::TransLastIdxSigGroups;
}

/// `-H` (V1) / `-Y` (V2) — Transferable last-event indexed sig groups: (prefix, controller sigs)
pub type TransLastIdxSigGroups = Group<TransLastIdxSigGroup>;

/// One seal source triple: (prefix, sequence number, SAID).
pub enum SealSourceTriple {}
impl private::Sealed for SealSourceTriple {}
impl GroupKind for SealSourceTriple {
    type Element = (
        Prefixer<'static>,
        Matter<'static, MatterCode>,
        Saider<'static>,
    );
    const CODE_V2: CounterCodeV2 = CounterCodeV2::SealSourceTriples;
    const NAME: &'static str = "SealSourceTriples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        let seqner = ts.read_matter()?;
        let saider = ts.read_saider()?;
        Ok(((prefixer, seqner, saider), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(3)?;
        Ok(ts.offset())
    }
}
impl V1GroupKind for SealSourceTriple {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::SealSourceTriples;
}

/// `-I` (V1) / `-T` (V2) — Seal source triples: (prefix, sequence number, SAID)
pub type SealSourceTriples = Group<SealSourceTriple>;

// ── Element-counted kinds, V2 only ───────────────────────────────────────

/// One digest seal single: (digest).
pub enum DigestSealSingle {}
impl private::Sealed for DigestSealSingle {}
impl GroupKind for DigestSealSingle {
    type Element = Diger<'static>;
    const CODE_V2: CounterCodeV2 = CounterCodeV2::DigestSealSingles;
    const NAME: &'static str = "DigestSealSingles";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let diger = ts.read_diger()?;
        Ok((diger, ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(1)?;
        Ok(ts.offset())
    }
}

/// `-Q` (V2 only) — Digest seal singles: (digest)
pub type DigestSealSingles = Group<DigestSealSingle>;

/// One Merkle root seal single: (digest).
pub enum MerkleRootSealSingle {}
impl private::Sealed for MerkleRootSealSingle {}
impl GroupKind for MerkleRootSealSingle {
    type Element = Diger<'static>;
    const CODE_V2: CounterCodeV2 = CounterCodeV2::MerkleRootSealSingles;
    const NAME: &'static str = "MerkleRootSealSingles";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let diger = ts.read_diger()?;
        Ok((diger, ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(1)?;
        Ok(ts.offset())
    }
}

/// `-R` (V2 only) — Merkle root seal singles: (digest)
pub type MerkleRootSealSingles = Group<MerkleRootSealSingle>;

/// One seal source last single: (prefix).
pub enum SealSourceLastSingle {}
impl private::Sealed for SealSourceLastSingle {}
impl GroupKind for SealSourceLastSingle {
    type Element = Prefixer<'static>;
    const CODE_V2: CounterCodeV2 = CounterCodeV2::SealSourceLastSingles;
    const NAME: &'static str = "SealSourceLastSingles";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        Ok((prefixer, ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(1)?;
        Ok(ts.offset())
    }
}

/// `-U` (V2 only) — Seal source last singles: (prefix)
pub type SealSourceLastSingles = Group<SealSourceLastSingle>;

/// One backer registrar seal couple: (prefix, digest).
pub enum BackerRegistrarSealCouple {}
impl private::Sealed for BackerRegistrarSealCouple {}
impl GroupKind for BackerRegistrarSealCouple {
    type Element = (Prefixer<'static>, Diger<'static>);
    const CODE_V2: CounterCodeV2 = CounterCodeV2::BackerRegistrarSealCouples;
    const NAME: &'static str = "BackerRegistrarSealCouples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let prefixer = ts.read_prefixer()?;
        let diger = ts.read_diger()?;
        Ok(((prefixer, diger), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(2)?;
        Ok(ts.offset())
    }
}

/// `-V` (V2 only) — Backer registrar seal couples: (prefix, digest)
pub type BackerRegistrarSealCouples = Group<BackerRegistrarSealCouple>;

/// One typed digest seal couple: (version, digest).
pub enum TypedDigestSealCouple {}
impl private::Sealed for TypedDigestSealCouple {}
impl GroupKind for TypedDigestSealCouple {
    type Element = (Verser<'static>, Diger<'static>);
    const CODE_V2: CounterCodeV2 = CounterCodeV2::TypedDigestSealCouples;
    const NAME: &'static str = "TypedDigestSealCouples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let verser = ts.read_verser()?;
        let diger = ts.read_diger()?;
        Ok(((verser, diger), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(2)?;
        Ok(ts.offset())
    }
}

/// `-W` (V2 only) — Typed digest seal couples: (version, digest)
pub type TypedDigestSealCouples = Group<TypedDigestSealCouple>;

/// One blinded state quadruple: (digest, nonce, nonce, label).
pub enum BlindedStateQuadruple {}
impl private::Sealed for BlindedStateQuadruple {}
impl GroupKind for BlindedStateQuadruple {
    type Element = (
        Diger<'static>,
        Noncer<'static>,
        Noncer<'static>,
        Labeler<'static>,
    );
    const CODE_V2: CounterCodeV2 = CounterCodeV2::BlindedStateQuadruples;
    const NAME: &'static str = "BlindedStateQuadruples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let diger = ts.read_diger()?;
        let noncer1 = ts.read_noncer()?;
        let noncer2 = ts.read_noncer()?;
        let labeler = ts.read_labeler()?;
        Ok(((diger, noncer1, noncer2, labeler), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(4)?;
        Ok(ts.offset())
    }
}

/// `-a` (V2 only) — Blinded state quadruples: (digest, nonce, nonce, label)
pub type BlindedStateQuadruples = Group<BlindedStateQuadruple>;

/// One bound state sextuple: (digest, nonce, nonce, label, number, nonce).
pub enum BoundStateSextuple {}
impl private::Sealed for BoundStateSextuple {}
impl GroupKind for BoundStateSextuple {
    type Element = (
        Diger<'static>,
        Noncer<'static>,
        Noncer<'static>,
        Labeler<'static>,
        Number,
        Noncer<'static>,
    );
    const CODE_V2: CounterCodeV2 = CounterCodeV2::BoundStateSextuples;
    const NAME: &'static str = "BoundStateSextuples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let diger = ts.read_diger()?;
        let noncer1 = ts.read_noncer()?;
        let noncer2 = ts.read_noncer()?;
        let labeler = ts.read_labeler()?;
        let number = ts.read_number()?;
        let noncer3 = ts.read_noncer()?;
        Ok((
            (diger, noncer1, noncer2, labeler, number, noncer3),
            ts.offset(),
        ))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(6)?;
        Ok(ts.offset())
    }
}

/// `-b` (V2 only) — Bound state sextuples: (digest, nonce, nonce, label, number, nonce)
pub type BoundStateSextuples = Group<BoundStateSextuple>;

/// One typed media quadruple: (digest, nonce, label, text).
pub enum TypedMediaQuadruple {}
impl private::Sealed for TypedMediaQuadruple {}
impl GroupKind for TypedMediaQuadruple {
    type Element = (
        Diger<'static>,
        Noncer<'static>,
        Labeler<'static>,
        Texter<'static>,
    );
    const CODE_V2: CounterCodeV2 = CounterCodeV2::TypedMediaQuadruples;
    const NAME: &'static str = "TypedMediaQuadruples";
    fn element(input: &[u8], _: CesrVersion) -> Result<(Self::Element, usize), ParseError> {
        let mut ts = TextStream::new(input);
        let diger = ts.read_diger()?;
        let noncer = ts.read_noncer()?;
        let labeler = ts.read_labeler()?;
        let texter = ts.read_texter()?;
        Ok(((diger, noncer, labeler, texter), ts.offset()))
    }
    fn skip(input: &[u8], _: CesrVersion) -> Result<usize, ParseError> {
        let mut ts = TextStream::new(input);
        ts.skip_matters(4)?;
        Ok(ts.offset())
    }
}

/// `-c` (V2 only) — Typed media quadruples: (digest, nonce, label, text)
pub type TypedMediaQuadruples = Group<TypedMediaQuadruple>;

// ── Public construction (the write spine) ────────────────────────────────

impl ControllerIdxSigs {
    /// Builds a controller indexed signature group from indexed signatures.
    ///
    /// The count is derived from the input — the count/raw invariant that a
    /// parsed group holds by framing is held here by construction. An empty
    /// slice yields a count-0 group: the CESR counter grammar admits count 0
    /// (keripy `counting.py:878` at the pin rejects only negative or
    /// over-capacity counts), though keripy's `messagize` never emits an
    /// empty group (`eventing.py:1605`) — `serder`'s
    /// `SerializedEvent::frame_v1` mirrors that omission.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Malformed`] if the signature count exceeds the
    /// group count range (`u32`).
    pub fn from_sigers(sigers: &[Siger<'_>]) -> Result<Self, ParseError> {
        let (raw, count) = encode_sigers(sigers)?;
        Ok(Self::new(raw, count, CesrVersion::V1))
    }
}

impl WitnessIdxSigs {
    /// Builds a witness indexed signature (receipt) group from indexed
    /// signatures.
    ///
    /// The count is derived from the input — see
    /// [`ControllerIdxSigs::from_sigers`] for the count-0 semantics, which
    /// are identical.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Malformed`] if the signature count exceeds the
    /// group count range (`u32`).
    pub fn from_sigers(sigers: &[Siger<'_>]) -> Result<Self, ParseError> {
        let (raw, count) = encode_sigers(sigers)?;
        Ok(Self::new(raw, count, CesrVersion::V1))
    }
}

// ── Quadlet-counted framing kinds, shared V1 + V2 ────────────────────────

/// Pathed material framing (`-L`/`-P`), counted in quadlets.
///
/// The payload is a Pather primitive plus arbitrary CESR material; keripy
/// treats this counter code as quadlet-counted, so this layer stores the
/// raw bytes without parsing the individual primitives.
pub enum PathedMaterial {}
impl private::Sealed for PathedMaterial {}
impl FrameKind for PathedMaterial {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::PathedMaterialCouples;
    const NAME: &'static str = "PathedMaterialCouples";
}
impl V1FrameKind for PathedMaterial {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::PathedMaterialCouples;
}

/// `-L` (V1) / `-P` (V2) — Pathed material (quadlet-counted raw bytes).
pub type PathedMaterialCouples = Frame<PathedMaterial>;

/// Attachment framing (`-V`/`-C`): the generic container for nested
/// attachment groups, counted in quadlets.
pub enum Attachment {}
impl private::Sealed for Attachment {}
impl FrameKind for Attachment {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::AttachmentGroup;
    const NAME: &'static str = "AttachmentGroup";
}
impl V1FrameKind for Attachment {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::AttachmentGroup;
}

/// `-V` (V1) / `-C` (V2) — Attachment group (generic container for nested groups, count in quadlets)
pub type AttachmentGroup = Frame<Attachment>;

/// Generic pipeline framing (`-T`/`-A`), counted in quadlets.
pub enum Generic {}
impl private::Sealed for Generic {}
impl FrameKind for Generic {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::GenericGroup;
    const NAME: &'static str = "GenericGroup";
}
impl V1FrameKind for Generic {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::GenericGroup;
}

/// `-T` (V1) / `-A` (V2) — Generic group (count in quadlets)
pub type GenericGroup = Frame<Generic>;

/// Body-with-attachment framing (`-U`/`-B`), counted in quadlets.
pub enum BodyWithAttachment {}
impl private::Sealed for BodyWithAttachment {}
impl FrameKind for BodyWithAttachment {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::BodyWithAttachmentGroup;
    const NAME: &'static str = "BodyWithAttachmentGroup";
}
impl V1FrameKind for BodyWithAttachment {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::BodyWithAttachmentGroup;
}

/// `-U` (V1) / `-B` (V2) — Body with attachment group (count in quadlets)
pub type BodyWithAttachmentGroup = Frame<BodyWithAttachment>;

/// Non-native body framing (`-W`/`-H`), counted in quadlets.
pub enum NonNativeBody {}
impl private::Sealed for NonNativeBody {}
impl FrameKind for NonNativeBody {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::NonNativeBodyGroup;
    const NAME: &'static str = "NonNativeBodyGroup";
}
impl V1FrameKind for NonNativeBody {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::NonNativeBodyGroup;
}

/// `-W` (V1) / `-H` (V2) — Non-native body group (count in quadlets)
pub type NonNativeBodyGroup = Frame<NonNativeBody>;

/// ESSR payload framing (`-Z`/`-Z`), counted in quadlets.
pub enum ESSRPayload {}
impl private::Sealed for ESSRPayload {}
impl FrameKind for ESSRPayload {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::ESSRPayloadGroup;
    const NAME: &'static str = "ESSRPayloadGroup";
}
impl V1FrameKind for ESSRPayload {
    const CODE_V1: CounterCodeV1 = CounterCodeV1::ESSRPayloadGroup;
}

/// `-Z` (V1) / `-Z` (V2) — ESSR payload group (count in quadlets)
pub type ESSRPayloadGroup = Frame<ESSRPayload>;

// ── Quadlet-counted framing kinds, V2 only ───────────────────────────────

/// Datagram segment framing (`-D`, V2 only), counted in quadlets.
pub enum DatagramSegment {}
impl private::Sealed for DatagramSegment {}
impl FrameKind for DatagramSegment {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::DatagramSegmentGroup;
    const NAME: &'static str = "DatagramSegmentGroup";
}

/// `-D` (V2 only) — Datagram segment group (count in quadlets)
pub type DatagramSegmentGroup = Frame<DatagramSegment>;

/// ESSR wrapper framing (`-E`, V2 only), counted in quadlets.
pub enum ESSRWrapper {}
impl private::Sealed for ESSRWrapper {}
impl FrameKind for ESSRWrapper {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::ESSRWrapperGroup;
    const NAME: &'static str = "ESSRWrapperGroup";
}

/// `-E` (V2 only) — ESSR wrapper group (count in quadlets)
pub type ESSRWrapperGroup = Frame<ESSRWrapper>;

/// Fixed body framing (`-F`, V2 only), counted in quadlets.
pub enum FixBody {}
impl private::Sealed for FixBody {}
impl FrameKind for FixBody {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::FixBodyGroup;
    const NAME: &'static str = "FixBodyGroup";
}

/// `-F` (V2 only) — Fixed body group (count in quadlets)
pub type FixBodyGroup = Frame<FixBody>;

/// Map body framing (`-G`, V2 only), counted in quadlets.
pub enum MapBody {}
impl private::Sealed for MapBody {}
impl FrameKind for MapBody {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::MapBodyGroup;
    const NAME: &'static str = "MapBodyGroup";
}

/// `-G` (V2 only) — Map body group (count in quadlets)
pub type MapBodyGroup = Frame<MapBody>;

/// Generic map framing (`-I`, V2 only), counted in quadlets.
pub enum GenericMap {}
impl private::Sealed for GenericMap {}
impl FrameKind for GenericMap {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::GenericMapGroup;
    const NAME: &'static str = "GenericMapGroup";
}

/// `-I` (V2 only) — Generic map group (count in quadlets)
pub type GenericMapGroup = Frame<GenericMap>;

/// Generic list framing (`-J`, V2 only), counted in quadlets.
pub enum GenericList {}
impl private::Sealed for GenericList {}
impl FrameKind for GenericList {
    const CODE_V2: CounterCodeV2 = CounterCodeV2::GenericListGroup;
    const NAME: &'static str = "GenericListGroup";
}

/// `-J` (V2 only) — Generic list group (count in quadlets)
pub type GenericListGroup = Frame<GenericList>;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use base64::{Engine, engine::general_purpose as b64};
    use bytes::BytesMut;
    use cesr::core::indexer::IndexerBuilder;
    use cesr::core::indexer::code::IndexedSigCode;
    use core::num::NonZeroUsize;

    use crate::version::CesrEncode;
    use crate::version::V1;

    // ── shared fixtures ──────────────────────────────────────────────────

    fn build_siger(index: u32, byte: u8) -> Siger<'static> {
        Siger::new(
            IndexerBuilder::new()
                .with_code(IndexedSigCode::Ed25519)
                .with_index(index)
                .unwrap()
                .with_raw(vec![byte; 64])
                .unwrap(),
        )
    }

    fn build_siger_qb64(index: u32) -> Vec<u8> {
        IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap()
            .to_qb64()
            .into_bytes()
    }

    fn build_ed25519_qb64() -> Vec<u8> {
        let raw = [0xAB_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_ed25519_sig_qb64() -> Vec<u8> {
        let raw = [0xAB_u8; 64];
        let ps = 2_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("0B{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_blake3_256_qb64() -> Vec<u8> {
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_tag7_verser_qb64() -> Vec<u8> {
        b"YAAAAAAA".to_vec()
    }

    fn build_tag3_labeler_qb64() -> Vec<u8> {
        b"XAAA".to_vec()
    }

    fn build_short_number_qb64() -> Vec<u8> {
        b"MAAF".to_vec()
    }

    fn build_texter_qb64() -> Vec<u8> {
        b"4BACW19uJT6H".to_vec()
    }

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = cesr::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    fn parse_v1<K: GroupKind>(input: &[u8], count: u32) -> (Group<K>, Bytes) {
        Group::parse(&Bytes::copy_from_slice(input), count, CesrVersion::V1).unwrap()
    }

    fn parse_v2<K: GroupKind>(input: &[u8], count: u32) -> (Group<K>, Bytes) {
        Group::parse(&Bytes::copy_from_slice(input), count, CesrVersion::V2).unwrap()
    }

    // ── ControllerIdxSig ─────────────────────────────────────────────────

    mod controller_idx_sig {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<ControllerIdxSig>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_siger() {
            let input = build_siger_qb64(0);
            let (group, rest) = parse_v1::<ControllerIdxSig>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(group.iter().next().unwrap().unwrap().index(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_sigers() {
            let mut input = Vec::new();
            for i in 0..3 {
                input.extend_from_slice(&build_siger_qb64(i));
            }
            let (group, rest) = parse_v1::<ControllerIdxSig>(&input, 3);
            assert_eq!(group.count(), 3);
            for (i, sig) in group.iter().enumerate() {
                assert_eq!(sig.unwrap().index(), u32::try_from(i).unwrap());
            }
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_siger_qb64(0);
            input.extend_from_slice(b"TRAILING");
            let (group, rest) = parse_v1::<ControllerIdxSig>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TRAILING"));
        }

        #[test]
        fn insufficient_data_errors() {
            let input = build_siger_qb64(0);
            let buf = Bytes::copy_from_slice(&input);
            let result = ControllerIdxSigs::parse(&buf, 2, CesrVersion::V1);
            assert!(result.is_err());
        }

        #[test]
        fn parse_slices_without_copying() {
            let input = build_siger_qb64(0);
            let parent = Bytes::copy_from_slice(&input);
            let parent_start = parent.as_ptr() as usize;
            let parent_end = parent_start + parent.len();

            let (group, _rest) = ControllerIdxSigs::parse(&parent, 1, CesrVersion::V1).unwrap();
            let raw_ptr = group.raw_bytes().as_ptr() as usize;

            // A slice points INTO the parent buffer; a copy would point to a fresh alloc.
            assert!(
                raw_ptr >= parent_start && raw_ptr < parent_end,
                "group raw must be a slice of the parent buffer, not a copy"
            );
        }
    }

    // ── WitnessIdxSig ────────────────────────────────────────────────────

    mod witness_idx_sig {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<WitnessIdxSig>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_siger() {
            let input = build_siger_qb64(0);
            let (group, rest) = parse_v1::<WitnessIdxSig>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(group.iter().next().unwrap().unwrap().index(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_sigers() {
            let mut input = Vec::new();
            for i in 0..2 {
                input.extend_from_slice(&build_siger_qb64(i));
            }
            let (group, rest) = parse_v1::<WitnessIdxSig>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_siger_qb64(0);
            input.extend_from_slice(b"TAIL");
            let (group, rest) = parse_v1::<WitnessIdxSig>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }
    }

    // ── NonTransReceiptCouple ────────────────────────────────────────────

    mod non_trans_receipt_couple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<NonTransReceiptCouple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_couple() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_sig_qb64());
            let (group, rest) = parse_v1::<NonTransReceiptCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_couples() {
            let mut input = Vec::new();
            for _ in 0..2 {
                input.extend_from_slice(&build_ed25519_qb64());
                input.extend_from_slice(&build_ed25519_sig_qb64());
            }
            let (group, rest) = parse_v1::<NonTransReceiptCouple>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_sig_qb64());
            input.extend_from_slice(b"EXTRA");
            let (group, rest) = parse_v1::<NonTransReceiptCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"EXTRA"));
        }

        #[test]
        fn parse_slices_without_copying() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_sig_qb64());
            let parent = Bytes::copy_from_slice(&input);
            let parent_start = parent.as_ptr() as usize;
            let parent_end = parent_start + parent.len();

            let (group, _rest) =
                NonTransReceiptCouples::parse(&parent, 1, CesrVersion::V1).unwrap();
            let raw_ptr = group.raw_bytes().as_ptr() as usize;

            assert!(
                raw_ptr >= parent_start && raw_ptr < parent_end,
                "NonTransReceiptCouples raw must be a slice of the parent buffer, not a copy"
            );
        }
    }

    // ── TransReceiptQuadruple ────────────────────────────────────────────

    mod trans_receipt_quadruple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<TransReceiptQuadruple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_quadruple() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_siger_qb64(0));
            let (group, rest) = parse_v1::<TransReceiptQuadruple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_siger_qb64(0));
            input.extend_from_slice(b"TAIL");
            let (group, rest) = parse_v1::<TransReceiptQuadruple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }
    }

    // ── FirstSeenReplayCouple ────────────────────────────────────────────

    mod first_seen_replay_couple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<FirstSeenReplayCouple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_couple() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            let (group, rest) = parse_v1::<FirstSeenReplayCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_couples() {
            let mut input = Vec::new();
            for _ in 0..2 {
                input.extend_from_slice(&build_ed25519_qb64());
                input.extend_from_slice(&build_ed25519_qb64());
            }
            let (group, rest) = parse_v1::<FirstSeenReplayCouple>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(b"REST");
            let (group, rest) = parse_v1::<FirstSeenReplayCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"REST"));
        }
    }

    // ── SealSourceCouple ─────────────────────────────────────────────────

    mod seal_source_couple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<SealSourceCouple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_couple() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_blake3_256_qb64());
            let (group, rest) = parse_v1::<SealSourceCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_couples() {
            let mut input = Vec::new();
            for _ in 0..3 {
                input.extend_from_slice(&build_ed25519_qb64());
                input.extend_from_slice(&build_blake3_256_qb64());
            }
            let (group, rest) = parse_v1::<SealSourceCouple>(&input, 3);
            assert_eq!(group.count(), 3);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(b"EXTRA");
            let (group, rest) = parse_v1::<SealSourceCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"EXTRA"));
        }
    }

    // ── SealSourceTriple ─────────────────────────────────────────────────

    mod seal_source_triple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<SealSourceTriple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_triple() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            let (group, rest) = parse_v1::<SealSourceTriple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_triples() {
            let mut input = Vec::new();
            for _ in 0..2 {
                input.extend_from_slice(&build_ed25519_qb64());
                input.extend_from_slice(&build_ed25519_qb64());
                input.extend_from_slice(&build_blake3_256_qb64());
            }
            let (group, rest) = parse_v1::<SealSourceTriple>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(b"TAIL");
            let (group, rest) = parse_v1::<SealSourceTriple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }
    }

    // ── TransIdxSigGroup ─────────────────────────────────────────────────

    mod trans_idx_sig_group {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<TransIdxSigGroup>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_group_with_two_sigs() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2));
            input.extend_from_slice(&build_siger_qb64(0));
            input.extend_from_slice(&build_siger_qb64(1));

            let (group, rest) = parse_v1::<TransIdxSigGroup>(&input, 1);
            assert_eq!(group.count(), 1);
            let elem = group.iter().next().unwrap().unwrap();
            assert_eq!(elem.3.count() as usize, 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1));
            input.extend_from_slice(&build_siger_qb64(0));
            input.extend_from_slice(b"TAIL");

            let (group, rest) = parse_v1::<TransIdxSigGroup>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }

        // The framing skip validates the nested counter code — a `-B`
        // (witness) counter inside a `-F` group is malformed, with the
        // enclosing group named in the message.
        #[test]
        fn wrong_nested_counter_code_is_rejected() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1));
            input.extend_from_slice(&build_siger_qb64(0));

            let err = TransIdxSigGroups::parse(&Bytes::copy_from_slice(&input), 1, CesrVersion::V1)
                .unwrap_err();
            let ParseError::Malformed(msg) = err else {
                panic!("expected Malformed, got {err:?}");
            };
            assert_eq!(&*msg, "expected -A counter inside -F group, got -B");
        }
    }

    // ── TransLastIdxSigGroup ─────────────────────────────────────────────

    mod trans_last_idx_sig_group {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v1::<TransLastIdxSigGroup>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_group_with_two_sigs() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2));
            input.extend_from_slice(&build_siger_qb64(0));
            input.extend_from_slice(&build_siger_qb64(1));

            let (group, rest) = parse_v1::<TransLastIdxSigGroup>(&input, 1);
            assert_eq!(group.count(), 1);
            let elem = group.iter().next().unwrap().unwrap();
            assert_eq!(elem.1.count() as usize, 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1));
            input.extend_from_slice(&build_siger_qb64(0));
            input.extend_from_slice(b"MORE");

            let (group, rest) = parse_v1::<TransLastIdxSigGroup>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"MORE"));
        }

        #[test]
        fn wrong_nested_counter_code_is_rejected() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1));
            input.extend_from_slice(&build_siger_qb64(0));

            let err =
                TransLastIdxSigGroups::parse(&Bytes::copy_from_slice(&input), 1, CesrVersion::V1)
                    .unwrap_err();
            let ParseError::Malformed(msg) = err else {
                panic!("expected Malformed, got {err:?}");
            };
            assert_eq!(&*msg, "expected -A counter inside -H group, got -B");
        }
    }

    // ── DigestSealSingle / MerkleRootSealSingle / SealSourceLastSingle ───

    mod digest_seal_single {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<DigestSealSingle>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_element() {
            let input = build_blake3_256_qb64();
            let (group, rest) = parse_v2::<DigestSealSingle>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_elements() {
            let mut input = Vec::new();
            for _ in 0..3 {
                input.extend_from_slice(&build_blake3_256_qb64());
            }
            let (group, rest) = parse_v2::<DigestSealSingle>(&input, 3);
            assert_eq!(group.count(), 3);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_blake3_256_qb64();
            input.extend_from_slice(b"TRAILING");
            let (group, rest) = parse_v2::<DigestSealSingle>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TRAILING"));
        }
    }

    mod merkle_root_seal_single {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<MerkleRootSealSingle>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_element() {
            let input = build_blake3_256_qb64();
            let (group, rest) = parse_v2::<MerkleRootSealSingle>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_elements() {
            let mut input = Vec::new();
            for _ in 0..3 {
                input.extend_from_slice(&build_blake3_256_qb64());
            }
            let (group, rest) = parse_v2::<MerkleRootSealSingle>(&input, 3);
            assert_eq!(group.count(), 3);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_blake3_256_qb64();
            input.extend_from_slice(b"TRAILING");
            let (group, rest) = parse_v2::<MerkleRootSealSingle>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TRAILING"));
        }
    }

    mod seal_source_last_single {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<SealSourceLastSingle>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_element() {
            let input = build_ed25519_qb64();
            let (group, rest) = parse_v2::<SealSourceLastSingle>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_elements() {
            let mut input = Vec::new();
            for _ in 0..3 {
                input.extend_from_slice(&build_ed25519_qb64());
            }
            let (group, rest) = parse_v2::<SealSourceLastSingle>(&input, 3);
            assert_eq!(group.count(), 3);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(b"TRAILING");
            let (group, rest) = parse_v2::<SealSourceLastSingle>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TRAILING"));
        }
    }

    // ── BackerRegistrarSealCouple / TypedDigestSealCouple ────────────────

    mod backer_registrar_seal_couple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<BackerRegistrarSealCouple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_couple() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_blake3_256_qb64());
            let (group, rest) = parse_v2::<BackerRegistrarSealCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_couples() {
            let mut input = Vec::new();
            for _ in 0..3 {
                input.extend_from_slice(&build_ed25519_qb64());
                input.extend_from_slice(&build_blake3_256_qb64());
            }
            let (group, rest) = parse_v2::<BackerRegistrarSealCouple>(&input, 3);
            assert_eq!(group.count(), 3);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_ed25519_qb64();
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(b"EXTRA");
            let (group, rest) = parse_v2::<BackerRegistrarSealCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"EXTRA"));
        }
    }

    mod typed_digest_seal_couple {
        use super::*;

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<TypedDigestSealCouple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_couple() {
            let mut input = build_tag7_verser_qb64();
            input.extend_from_slice(&build_blake3_256_qb64());
            let (group, rest) = parse_v2::<TypedDigestSealCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_three_couples() {
            let mut input = Vec::new();
            for _ in 0..3 {
                input.extend_from_slice(&build_tag7_verser_qb64());
                input.extend_from_slice(&build_blake3_256_qb64());
            }
            let (group, rest) = parse_v2::<TypedDigestSealCouple>(&input, 3);
            assert_eq!(group.count(), 3);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_tag7_verser_qb64();
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(b"EXTRA");
            let (group, rest) = parse_v2::<TypedDigestSealCouple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"EXTRA"));
        }
    }

    // ── BlindedStateQuadruple / BoundStateSextuple / TypedMediaQuadruple ─

    mod blinded_state_quadruple {
        use super::*;

        fn build_one_quadruple() -> Vec<u8> {
            let mut e = build_blake3_256_qb64();
            e.extend_from_slice(&build_blake3_256_qb64());
            e.extend_from_slice(&build_blake3_256_qb64());
            e.extend_from_slice(&build_tag3_labeler_qb64());
            e
        }

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<BlindedStateQuadruple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_quadruple() {
            let input = build_one_quadruple();
            let (group, rest) = parse_v2::<BlindedStateQuadruple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_quadruples() {
            let mut input = build_one_quadruple();
            input.extend_from_slice(&build_one_quadruple());
            let (group, rest) = parse_v2::<BlindedStateQuadruple>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_one_quadruple();
            input.extend_from_slice(b"TAIL");
            let (group, rest) = parse_v2::<BlindedStateQuadruple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }

        #[test]
        fn parse_slices_without_copying() {
            let input = build_one_quadruple();
            let parent = Bytes::copy_from_slice(&input);
            let parent_start = parent.as_ptr() as usize;
            let parent_end = parent_start + parent.len();

            let (group, _rest) =
                BlindedStateQuadruples::parse(&parent, 1, CesrVersion::V2).unwrap();
            let raw_ptr = group.raw_bytes().as_ptr() as usize;

            assert!(
                raw_ptr >= parent_start && raw_ptr < parent_end,
                "BlindedStateQuadruples raw must be a slice of the parent buffer, not a copy"
            );
        }
    }

    mod bound_state_sextuple {
        use super::*;

        fn build_one_sextuple() -> Vec<u8> {
            let mut e = build_blake3_256_qb64();
            e.extend_from_slice(&build_blake3_256_qb64());
            e.extend_from_slice(&build_blake3_256_qb64());
            e.extend_from_slice(&build_tag3_labeler_qb64());
            e.extend_from_slice(&build_short_number_qb64());
            e.extend_from_slice(&build_blake3_256_qb64());
            e
        }

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<BoundStateSextuple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_sextuple() {
            let input = build_one_sextuple();
            let (group, rest) = parse_v2::<BoundStateSextuple>(&input, 1);
            assert_eq!(group.count(), 1);
            let elem = group.iter().next().unwrap().unwrap();
            assert_eq!(elem.4.value(), 5);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_sextuples() {
            let mut input = build_one_sextuple();
            input.extend_from_slice(&build_one_sextuple());
            let (group, rest) = parse_v2::<BoundStateSextuple>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_one_sextuple();
            input.extend_from_slice(b"TAIL");
            let (group, rest) = parse_v2::<BoundStateSextuple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }
    }

    mod typed_media_quadruple {
        use super::*;

        fn build_one_quadruple() -> Vec<u8> {
            let mut e = build_blake3_256_qb64();
            e.extend_from_slice(&build_blake3_256_qb64());
            e.extend_from_slice(&build_tag3_labeler_qb64());
            e.extend_from_slice(&build_texter_qb64());
            e
        }

        #[test]
        fn parse_zero_elements() {
            let (group, rest) = parse_v2::<TypedMediaQuadruple>(&[], 0);
            assert_eq!(group.count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_one_quadruple() {
            let input = build_one_quadruple();
            let (group, rest) = parse_v2::<TypedMediaQuadruple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_two_quadruples() {
            let mut input = build_one_quadruple();
            input.extend_from_slice(&build_one_quadruple());
            let (group, rest) = parse_v2::<TypedMediaQuadruple>(&input, 2);
            assert_eq!(group.count(), 2);
            assert!(rest.is_empty());
        }

        #[test]
        fn trailing_bytes_preserved() {
            let mut input = build_one_quadruple();
            input.extend_from_slice(b"TAIL");
            let (group, rest) = parse_v2::<TypedMediaQuadruple>(&input, 1);
            assert_eq!(group.count(), 1);
            assert_eq!(rest, Bytes::from_static(b"TAIL"));
        }
    }

    // ── from_sigers (the write spine, phase 4) ───────────────────────────

    mod from_sigers {
        use super::*;
        use crate::group::CesrGroup;

        fn parse_roundtrip_controller(group: &ControllerIdxSigs) -> ControllerIdxSigs {
            let mut dst = BytesMut::new();
            CesrEncode::<V1>::encode_cesr(group, &mut dst).unwrap();
            let (parsed, rest) = CesrGroup::parse(&dst).unwrap();
            assert!(rest.is_empty());
            let CesrGroup::ControllerIdxSigs(g) = parsed else {
                panic!("expected ControllerIdxSigs, got {parsed:?}");
            };
            g
        }

        #[test]
        fn controller_from_sigers_roundtrips_through_parse() {
            let sigers = vec![build_siger(0, 0xAB), build_siger(1, 0xCD)];
            let group = ControllerIdxSigs::from_sigers(&sigers).unwrap();
            assert_eq!(group.count(), 2, "count is derived from the input");

            let reparsed = parse_roundtrip_controller(&group).into_vec().unwrap();
            let reparsed_qb64: Vec<String> = reparsed.iter().map(Siger::to_qb64).collect();
            let original_qb64: Vec<String> = sigers.iter().map(Siger::to_qb64).collect();
            assert_eq!(reparsed_qb64, original_qb64);
        }

        #[test]
        fn witness_from_sigers_roundtrips_through_parse() {
            let sigers = vec![build_siger(0, 0x11), build_siger(2, 0x22)];
            let group = WitnessIdxSigs::from_sigers(&sigers).unwrap();
            assert_eq!(group.count(), 2);

            let mut dst = BytesMut::new();
            CesrEncode::<V1>::encode_cesr(&group, &mut dst).unwrap();
            let (parsed, rest) = CesrGroup::parse(&dst).unwrap();
            assert!(rest.is_empty());
            let CesrGroup::WitnessIdxSigs(g) = parsed else {
                panic!("expected WitnessIdxSigs, got {parsed:?}");
            };
            let reparsed_qb64: Vec<String> =
                g.into_vec().unwrap().iter().map(Siger::to_qb64).collect();
            let original_qb64: Vec<String> = sigers.iter().map(Siger::to_qb64).collect();
            assert_eq!(reparsed_qb64, original_qb64);
        }

        #[test]
        fn from_sigers_empty_slice_yields_count_zero_group() {
            // The counter grammar admits count 0 (keripy counting.py:878 rejects
            // only negative/over-capacity counts); messagize simply never emits
            // an empty group (eventing.py:1605).
            let group = ControllerIdxSigs::from_sigers(&[]).unwrap();
            assert_eq!(group.count(), 0);
            assert!(group.raw_bytes().is_empty());
            assert!(
                parse_roundtrip_controller(&group)
                    .into_vec()
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn from_sigers_single_siger_boundary() {
            let sigers = vec![build_siger(0, 0x01)];
            let group = ControllerIdxSigs::from_sigers(&sigers).unwrap();
            assert_eq!(group.count(), 1);
            assert_eq!(group.raw_bytes(), sigers[0].to_qb64().as_bytes());
        }

        #[test]
        fn from_sigers_count_and_raw_stay_consistent_at_counter_capacity_boundary() {
            // 4095 is the V1 small-counter capacity (ss=2): the group itself is
            // constructible above it (V2 has a big controller-sig code), and the
            // count always equals the number of encoded elements.
            let siger = build_siger(0, 0x77);
            let sigers = vec![siger; 4096];
            let group = ControllerIdxSigs::from_sigers(&sigers).unwrap();
            assert_eq!(group.count(), 4096);
            assert_eq!(group.raw_bytes().len(), 4096 * 88);
        }
    }
}
