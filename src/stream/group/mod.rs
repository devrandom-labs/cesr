#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};
/// Lazy, streaming iterator over items in a CESR group.
pub mod iter;
/// CESR group type definitions.
pub mod types;

mod attachment_group;
mod backer_registrar_seal_couples;
mod blinded_state_quadruples;
mod bound_state_sextuples;
mod controller_idx_sigs;
mod digest_seal_singles;
mod first_seen_replay_couples;
mod merkle_root_seal_singles;
mod non_trans_receipt_couples;
mod quadlet_group;
mod seal_source_couples;
mod seal_source_last_singles;
mod seal_source_triples;
mod trans_idx_sig_groups;
mod trans_last_idx_sig_groups;
mod trans_receipt_quadruples;
mod typed_digest_seal_couples;
mod typed_media_quadruples;
mod witness_idx_sigs;

use crate::core::counter::CounterCodeV1;
use crate::core::counter::CounterCodeV2;

pub use quadlet_group::QuadletGroup;
pub use types::AttachmentGroup;
pub use types::BackerRegistrarSealCouples;
pub use types::BlindedStateQuadruples;
pub use types::BodyWithAttachmentGroup;
pub use types::BoundStateSextuples;
pub use types::CesrGroup;
pub use types::ControllerIdxSigs;
pub use types::DatagramSegmentGroup;
pub use types::DigestSealSingles;
pub use types::ESSRPayloadGroup;
pub use types::ESSRWrapperGroup;
pub use types::FirstSeenReplayCouples;
pub use types::FixBodyGroup;
pub use types::GenericGroup;
pub use types::GenericListGroup;
pub use types::GenericMapGroup;
pub use types::MapBodyGroup;
pub use types::MerkleRootSealSingles;
pub use types::NonNativeBodyGroup;
pub use types::NonTransReceiptCouples;
pub use types::PathedMaterialCouples;
pub use types::SealSourceCouples;
pub use types::SealSourceLastSingles;
pub use types::SealSourceTriples;
pub use types::TransIdxSigGroups;
pub use types::TransLastIdxSigGroups;
pub use types::TransReceiptQuadruples;
pub use types::TypedDigestSealCouples;
pub use types::TypedMediaQuadruples;
pub use types::WitnessIdxSigs;

use crate::stream::error::ParseError;
use crate::stream::parse::parse_counter;
use crate::stream::parse::parse_counter_v2;
use bytes::Bytes;

/// Parse one CESR attachment group (counter + elements) from the input.
///
/// Uses V1.0 counter codes. All parsed primitives are fully owned
/// (`'static`), so the returned group does not borrow from the input.
///
/// # Errors
///
/// Returns [`ParseError`] on malformed data, unknown codes, or insufficient bytes.
pub fn parse_group(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    parse_group_inner(input)
}

pub(crate) fn parse_group_inner(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    let buf = Bytes::copy_from_slice(input);
    let (group, rest) = parse_group_bytes(&buf)?;
    let consumed = input.len() - rest.len();
    Ok((group, &input[consumed..]))
}

fn dispatch_v1(
    code: CounterCodeV1,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    match code {
        CounterCodeV1::ControllerIdxSigs => {
            let (g, r) = controller_idx_sigs::parse(rest, count)?;
            Ok((CesrGroup::ControllerIdxSigs(g), r))
        }
        CounterCodeV1::WitnessIdxSigs => {
            let (g, r) = witness_idx_sigs::parse(rest, count)?;
            Ok((CesrGroup::WitnessIdxSigs(g), r))
        }
        CounterCodeV1::NonTransReceiptCouples => {
            let (g, r) = non_trans_receipt_couples::parse(rest, count)?;
            Ok((CesrGroup::NonTransReceiptCouples(g), r))
        }
        CounterCodeV1::TransReceiptQuadruples => {
            let (g, r) = trans_receipt_quadruples::parse(rest, count)?;
            Ok((CesrGroup::TransReceiptQuadruples(g), r))
        }
        CounterCodeV1::FirstSeenReplayCouples => {
            let (g, r) = first_seen_replay_couples::parse(rest, count)?;
            Ok((CesrGroup::FirstSeenReplayCouples(g), r))
        }
        CounterCodeV1::TransIdxSigGroups => {
            let (g, r) = trans_idx_sig_groups::parse(rest, count)?;
            Ok((CesrGroup::TransIdxSigGroups(g), r))
        }
        CounterCodeV1::SealSourceCouples => {
            let (g, r) = seal_source_couples::parse(rest, count)?;
            Ok((CesrGroup::SealSourceCouples(g), r))
        }
        CounterCodeV1::TransLastIdxSigGroups => {
            let (g, r) = trans_last_idx_sig_groups::parse(rest, count)?;
            Ok((CesrGroup::TransLastIdxSigGroups(g), r))
        }
        CounterCodeV1::SealSourceTriples => {
            let (g, r) = seal_source_triples::parse(rest, count)?;
            Ok((CesrGroup::SealSourceTriples(g), r))
        }
        CounterCodeV1::AttachmentGroup | CounterCodeV1::BigAttachmentGroup => {
            let (g, r) = attachment_group::parse(rest, count)?;
            Ok((CesrGroup::AttachmentGroup(g), r))
        }
        CounterCodeV1::GenericGroup | CounterCodeV1::BigGenericGroup => {
            let (qg, r) = quadlet_group::parse_quadlets(rest, count)?;
            Ok((CesrGroup::GenericGroup(GenericGroup(qg)), r))
        }
        CounterCodeV1::BodyWithAttachmentGroup | CounterCodeV1::BigBodyWithAttachmentGroup => {
            let (qg, r) = quadlet_group::parse_quadlets(rest, count)?;
            Ok((
                CesrGroup::BodyWithAttachmentGroup(BodyWithAttachmentGroup(qg)),
                r,
            ))
        }
        CounterCodeV1::NonNativeBodyGroup | CounterCodeV1::BigNonNativeBodyGroup => {
            let (qg, r) = quadlet_group::parse_quadlets(rest, count)?;
            Ok((CesrGroup::NonNativeBodyGroup(NonNativeBodyGroup(qg)), r))
        }
        CounterCodeV1::ESSRPayloadGroup | CounterCodeV1::BigESSRPayloadGroup => {
            let (qg, r) = quadlet_group::parse_quadlets(rest, count)?;
            Ok((CesrGroup::ESSRPayloadGroup(ESSRPayloadGroup(qg)), r))
        }
        CounterCodeV1::PathedMaterialCouples | CounterCodeV1::BigPathedMaterialCouples => {
            let (qg, r) = quadlet_group::parse_quadlets(rest, count)?;
            Ok((
                CesrGroup::PathedMaterialCouples(PathedMaterialCouples(qg)),
                r,
            ))
        }
        CounterCodeV1::KERIACDCGenusVersion => Err(ParseError::Malformed(
            "genus version codes are not attachment groups".into(),
        )),
    }
}

/// Zero-copy parsing core: slices `buf` for the counter and hands the element
/// region to the dispatch. Returns the remaining bytes as an O(1) `Bytes` slice.
pub(crate) fn parse_group_bytes(buf: &Bytes) -> Result<(CesrGroup, Bytes), ParseError> {
    let (code, count, after_counter) = parse_counter(buf)?;
    let consumed = buf.len() - after_counter.len();
    let elements = buf.slice(consumed..);
    dispatch_v1(code, count, &elements)
}

pub(crate) fn parse_group_bytes_v2(buf: &Bytes) -> Result<(CesrGroup, Bytes), ParseError> {
    let (code, count, after_counter) = parse_counter_v2(buf)?;
    let consumed = buf.len() - after_counter.len();
    let elements = buf.slice(consumed..);
    dispatch_v2(code, count, &elements)
}

/// An iterator that yields successive [`CesrGroup`]s from a byte stream.
///
/// All parsed groups are fully owned (`'static`). The attachment region is
/// copied into a shared [`Bytes`] buffer once, lazily, on the first call to
/// [`Iterator::next`]; every subsequent group is an O(1) slice of that
/// buffer rather than a fresh copy of the remaining input.
pub struct Groups<'a> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
}

impl Iterator for Groups<'_> {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Copy the attachment region into a shared Bytes exactly once; every group
        // is then an O(1) slice of it (no per-group copy).
        let buf = self
            .buf
            .get_or_insert_with(|| Bytes::copy_from_slice(self.input))
            .clone();
        if self.cursor >= buf.len() {
            return None;
        }
        let slice = buf.slice(self.cursor..);
        match parse_group_bytes(&slice) {
            Ok((group, rest)) => {
                self.cursor = buf.len() - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.cursor = buf.len();
                Some(Err(e))
            }
        }
    }
}

/// Create an iterator that parses successive CESR groups from the input.
#[must_use]
pub const fn groups(input: &[u8]) -> Groups<'_> {
    Groups {
        input,
        buf: None,
        cursor: 0,
    }
}

/// Parse one CESR attachment group using V2.0 counter codes.
///
/// V2.0 remaps wire letters but produces the same version-independent
/// `CesrGroup` variants for shared semantics.
///
/// # Errors
///
/// Returns [`ParseError`] on malformed data, unknown codes, or insufficient bytes.
pub fn parse_group_v2(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    parse_group_inner_v2(input)
}

pub(crate) fn parse_group_inner_v2(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    let buf = Bytes::copy_from_slice(input);
    let (group, rest) = parse_group_bytes_v2(&buf)?;
    let consumed = input.len() - rest.len();
    Ok((group, &input[consumed..]))
}

fn dispatch_v2(
    code: CounterCodeV2,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    match code {
        CounterCodeV2::ControllerIdxSigs | CounterCodeV2::BigControllerIdxSigs => {
            let (g, r) = controller_idx_sigs::parse(rest, count)?;
            Ok((CesrGroup::ControllerIdxSigs(g), r))
        }
        CounterCodeV2::WitnessIdxSigs | CounterCodeV2::BigWitnessIdxSigs => {
            let (g, r) = witness_idx_sigs::parse(rest, count)?;
            Ok((CesrGroup::WitnessIdxSigs(g), r))
        }
        CounterCodeV2::NonTransReceiptCouples | CounterCodeV2::BigNonTransReceiptCouples => {
            let (g, r) = non_trans_receipt_couples::parse(rest, count)?;
            Ok((CesrGroup::NonTransReceiptCouples(g), r))
        }
        CounterCodeV2::TransReceiptQuadruples | CounterCodeV2::BigTransReceiptQuadruples => {
            let (g, r) = trans_receipt_quadruples::parse(rest, count)?;
            Ok((CesrGroup::TransReceiptQuadruples(g), r))
        }
        CounterCodeV2::FirstSeenReplayCouples | CounterCodeV2::BigFirstSeenReplayCouples => {
            let (g, r) = first_seen_replay_couples::parse(rest, count)?;
            Ok((CesrGroup::FirstSeenReplayCouples(g), r))
        }
        CounterCodeV2::SealSourceCouples | CounterCodeV2::BigSealSourceCouples => {
            let (g, r) = seal_source_couples::parse(rest, count)?;
            Ok((CesrGroup::SealSourceCouples(g), r))
        }
        CounterCodeV2::SealSourceTriples | CounterCodeV2::BigSealSourceTriples => {
            let (g, r) = seal_source_triples::parse(rest, count)?;
            Ok((CesrGroup::SealSourceTriples(g), r))
        }
        CounterCodeV2::TransIdxSigGroups | CounterCodeV2::BigTransIdxSigGroups => {
            let (g, r) = trans_idx_sig_groups::parse_v2(rest, count)?;
            Ok((CesrGroup::TransIdxSigGroups(g), r))
        }
        CounterCodeV2::TransLastIdxSigGroups | CounterCodeV2::BigTransLastIdxSigGroups => {
            let (g, r) = trans_last_idx_sig_groups::parse_v2(rest, count)?;
            Ok((CesrGroup::TransLastIdxSigGroups(g), r))
        }
        _ => dispatch_v2_quadlets(code, count, rest),
    }
}

fn dispatch_v2_quadlets(
    code: CounterCodeV2,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    match code {
        CounterCodeV2::AttachmentGroup | CounterCodeV2::BigAttachmentGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::AttachmentGroup(AttachmentGroup(qg)), r))
        }
        CounterCodeV2::GenericGroup | CounterCodeV2::BigGenericGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::GenericGroup(GenericGroup(qg)), r))
        }
        CounterCodeV2::BodyWithAttachmentGroup | CounterCodeV2::BigBodyWithAttachmentGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((
                CesrGroup::BodyWithAttachmentGroup(BodyWithAttachmentGroup(qg)),
                r,
            ))
        }
        CounterCodeV2::NonNativeBodyGroup | CounterCodeV2::BigNonNativeBodyGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::NonNativeBodyGroup(NonNativeBodyGroup(qg)), r))
        }
        CounterCodeV2::ESSRPayloadGroup | CounterCodeV2::BigESSRPayloadGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::ESSRPayloadGroup(ESSRPayloadGroup(qg)), r))
        }
        CounterCodeV2::DatagramSegmentGroup | CounterCodeV2::BigDatagramSegmentGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::DatagramSegmentGroup(DatagramSegmentGroup(qg)), r))
        }
        CounterCodeV2::ESSRWrapperGroup | CounterCodeV2::BigESSRWrapperGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::ESSRWrapperGroup(ESSRWrapperGroup(qg)), r))
        }
        CounterCodeV2::FixBodyGroup | CounterCodeV2::BigFixBodyGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::FixBodyGroup(FixBodyGroup(qg)), r))
        }
        CounterCodeV2::MapBodyGroup | CounterCodeV2::BigMapBodyGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::MapBodyGroup(MapBodyGroup(qg)), r))
        }
        CounterCodeV2::GenericMapGroup | CounterCodeV2::BigGenericMapGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::GenericMapGroup(GenericMapGroup(qg)), r))
        }
        CounterCodeV2::GenericListGroup | CounterCodeV2::BigGenericListGroup => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((CesrGroup::GenericListGroup(GenericListGroup(qg)), r))
        }
        CounterCodeV2::PathedMaterialCouples | CounterCodeV2::BigPathedMaterialCouples => {
            let (qg, r) = quadlet_group::parse_quadlets_v2(rest, count)?;
            Ok((
                CesrGroup::PathedMaterialCouples(PathedMaterialCouples(qg)),
                r,
            ))
        }
        _ => dispatch_v2_special(code, count, rest),
    }
}

fn dispatch_v2_special(
    code: CounterCodeV2,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    match code {
        CounterCodeV2::DigestSealSingles | CounterCodeV2::BigDigestSealSingles => {
            let (g, r) = digest_seal_singles::parse(rest, count)?;
            Ok((CesrGroup::DigestSealSingles(g), r))
        }
        CounterCodeV2::MerkleRootSealSingles | CounterCodeV2::BigMerkleRootSealSingles => {
            let (g, r) = merkle_root_seal_singles::parse(rest, count)?;
            Ok((CesrGroup::MerkleRootSealSingles(g), r))
        }
        CounterCodeV2::SealSourceLastSingles | CounterCodeV2::BigSealSourceLastSingles => {
            let (g, r) = seal_source_last_singles::parse(rest, count)?;
            Ok((CesrGroup::SealSourceLastSingles(g), r))
        }
        CounterCodeV2::BackerRegistrarSealCouples
        | CounterCodeV2::BigBackerRegistrarSealCouples => {
            let (g, r) = backer_registrar_seal_couples::parse(rest, count)?;
            Ok((CesrGroup::BackerRegistrarSealCouples(g), r))
        }
        CounterCodeV2::TypedDigestSealCouples | CounterCodeV2::BigTypedDigestSealCouples => {
            let (g, r) = typed_digest_seal_couples::parse(rest, count)?;
            Ok((CesrGroup::TypedDigestSealCouples(g), r))
        }
        CounterCodeV2::BlindedStateQuadruples | CounterCodeV2::BigBlindedStateQuadruples => {
            let (g, r) = blinded_state_quadruples::parse(rest, count)?;
            Ok((CesrGroup::BlindedStateQuadruples(g), r))
        }
        CounterCodeV2::BoundStateSextuples | CounterCodeV2::BigBoundStateSextuples => {
            let (g, r) = bound_state_sextuples::parse(rest, count)?;
            Ok((CesrGroup::BoundStateSextuples(g), r))
        }
        CounterCodeV2::TypedMediaQuadruples | CounterCodeV2::BigTypedMediaQuadruples => {
            let (g, r) = typed_media_quadruples::parse(rest, count)?;
            Ok((CesrGroup::TypedMediaQuadruples(g), r))
        }
        CounterCodeV2::KERIACDCGenusVersion => Err(ParseError::Malformed(
            "genus version codes are not attachment groups".into(),
        )),
        _ => Err(ParseError::Malformed(format!(
            "unexpected V2 counter code {}",
            code.as_str()
        ))),
    }
}

/// An iterator that yields successive [`CesrGroup`]s from a V2.0 byte stream.
///
/// The attachment region is copied into a shared [`Bytes`] buffer once,
/// lazily, on the first call to [`Iterator::next`]; every subsequent group
/// is an O(1) slice of that buffer rather than a fresh copy of the
/// remaining input.
pub struct GroupsV2<'a> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
}

impl Iterator for GroupsV2<'_> {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Copy the attachment region into a shared Bytes exactly once; every group
        // is then an O(1) slice of it (no per-group copy).
        let buf = self
            .buf
            .get_or_insert_with(|| Bytes::copy_from_slice(self.input))
            .clone();
        if self.cursor >= buf.len() {
            return None;
        }
        let slice = buf.slice(self.cursor..);
        match parse_group_bytes_v2(&slice) {
            Ok((group, rest)) => {
                self.cursor = buf.len() - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.cursor = buf.len();
                Some(Err(e))
            }
        }
    }
}

/// Create an iterator that parses successive V2.0 CESR groups from the input.
#[must_use]
pub const fn groups_v2(input: &[u8]) -> GroupsV2<'_> {
    GroupsV2 {
        input,
        buf: None,
        cursor: 0,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::needless_collect,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use super::*;
    use crate::core::counter::CounterCodeV1;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use core::num::NonZeroUsize;

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

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    #[test]
    fn dispatch_controller_idx_sigs() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_witness_idx_sigs() {
        let mut input = build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::WitnessIdxSigs(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_attachment_group() {
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = inner.len() / 4;

        let mut input = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets as u32);
        input.extend_from_slice(&inner);
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_generic_group() {
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = inner.len() / 4;

        let mut input = build_counter_qb64(CounterCodeV1::GenericGroup, quadlets as u32);
        input.extend_from_slice(&inner);
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::GenericGroup(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_pathed_material_quadlet_counted() {
        // Build counter `-L` with count=2 (2 quadlets = 8 bytes) + 8 bytes payload
        let counter = build_counter_qb64(CounterCodeV1::PathedMaterialCouples, 2);
        let payload = b"ABCDEFGH"; // exactly 8 bytes = 2 quadlets
        let mut input = counter;
        input.extend_from_slice(payload);
        input.extend_from_slice(b"TRAILING");
        let (group, rest) = parse_group(&input).unwrap();
        match &group {
            CesrGroup::PathedMaterialCouples(pmc) => {
                assert_eq!(pmc.0.quadlet_count(), 2);
                assert_eq!(pmc.0.raw_bytes(), b"ABCDEFGH");
            }
            other => panic!("expected PathedMaterialCouples, got {other:?}"),
        }
        assert_eq!(rest, b"TRAILING");
    }

    #[test]
    fn dispatch_empty_input() {
        let result = parse_group(b"");
        assert!(result.is_err());
    }

    #[test]
    fn groups_iterator_multiple_groups() {
        let mut input = Vec::new();
        input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2));
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(&build_siger_qb64(1));
        input.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1));
        input.extend_from_slice(&build_siger_qb64(0));

        let results: Vec<_> = groups(&input).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(matches!(
            results[0].as_ref().unwrap(),
            CesrGroup::ControllerIdxSigs(_)
        ));
        assert!(matches!(
            results[1].as_ref().unwrap(),
            CesrGroup::WitnessIdxSigs(_)
        ));
    }

    #[test]
    fn groups_iterator_empty_input() {
        let results: Vec<_> = groups(b"").collect();
        assert!(results.is_empty());
    }

    #[test]
    fn groups_iterator_stops_on_error() {
        let input = b"INVALID";
        let results: Vec<_> = groups(input).collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn groups_iterator_copies_attachment_region_once() {
        let counter0 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        let sig0 = build_siger_qb64(0);
        let counter1 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        let sig1 = build_siger_qb64(1);

        let mut stream = Vec::new();
        stream.extend_from_slice(&counter0);
        stream.extend_from_slice(&sig0);
        stream.extend_from_slice(&counter1);
        stream.extend_from_slice(&sig1);

        let out: Vec<CesrGroup> = groups(&stream).collect::<Result<_, _>>().unwrap();
        assert_eq!(out.len(), 2);

        let raw0 = match &out[0] {
            CesrGroup::ControllerIdxSigs(g) => g.raw_bytes(),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        };
        let raw1 = match &out[1] {
            CesrGroup::ControllerIdxSigs(g) => g.raw_bytes(),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        };

        let p0 = raw0.as_ptr() as usize;
        let p1 = raw1.as_ptr() as usize;
        let g0_len = raw0.len();
        // group[1]'s own counter sits between group[0]'s payload and group[1]'s
        // payload, so the exact expected gap is that counter's length.
        let gap = counter1.len();

        // group[1]'s payload begins exactly `gap` bytes after group[0]'s payload
        // ends, within the SAME shared allocation — proving the iterator copied
        // the attachment region once and sliced it, rather than re-copying the
        // remaining input on every `next()` call.
        assert_eq!(
            p1,
            p0 + g0_len + gap,
            "groups must slice one shared buffer, not be copied separately"
        );
    }

    #[test]
    fn parse_group_trailing_bytes() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(b"EXTRA");
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert_eq!(rest, b"EXTRA");
    }

    #[test]
    fn pathed_material_couples_roundtrip() {
        use crate::stream::encode::encode_group_v1;

        // Build some payload bytes (must be multiple of 4)
        let payload = b"ABCDEFGHIJKLMNOP"; // 16 bytes = 4 quadlets
        let counter = build_counter_qb64(CounterCodeV1::PathedMaterialCouples, 4);
        let mut input = counter;
        input.extend_from_slice(payload);
        let (group, rest) = parse_group(&input).unwrap();
        assert!(rest.is_empty());

        // Roundtrip: encode and re-parse
        let encoded = encode_group_v1(&group).unwrap();
        let (reparsed, rest2) = parse_group(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::PathedMaterialCouples(a), CesrGroup::PathedMaterialCouples(b)) => {
                assert_eq!(a.0.raw_bytes(), b.0.raw_bytes());
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    // ── V2 seal group helpers ────────────────────────────────────────────

    fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    fn build_blake3_256_qb64() -> Vec<u8> {
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_ed25519_qb64() -> Vec<u8> {
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xAB_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    // ── V2 seal group dispatch tests ─────────────────────────────────────

    #[test]
    fn dispatch_v2_digest_seal_singles() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::DigestSealSingles, 1);
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::DigestSealSingles(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_merkle_root_seal_singles() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::MerkleRootSealSingles, 1);
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::MerkleRootSealSingles(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_seal_source_last_singles() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::SealSourceLastSingles, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::SealSourceLastSingles(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_backer_registrar_seal_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BackerRegistrarSealCouples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::BackerRegistrarSealCouples(_)));
        assert!(rest.is_empty());
    }

    // ── V2 seal group roundtrip tests ────────────────────────────────────

    #[test]
    fn digest_seal_singles_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::DigestSealSingles, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::DigestSealSingles(a), CesrGroup::DigestSealSingles(b)) => {
                assert_eq!(a.count(), b.count());
                for (da, db) in a.iter().zip(b.iter()) {
                    assert_eq!(da.unwrap().raw(), db.unwrap().raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn merkle_root_seal_singles_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::MerkleRootSealSingles, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::MerkleRootSealSingles(a), CesrGroup::MerkleRootSealSingles(b)) => {
                assert_eq!(a.count(), b.count());
                for (da, db) in a.iter().zip(b.iter()) {
                    assert_eq!(da.unwrap().raw(), db.unwrap().raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn seal_source_last_singles_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::SealSourceLastSingles, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_ed25519_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::SealSourceLastSingles(a), CesrGroup::SealSourceLastSingles(b)) => {
                assert_eq!(a.count(), b.count());
                for (pa, pb) in a.iter().zip(b.iter()) {
                    assert_eq!(pa.unwrap().raw(), pb.unwrap().raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn backer_registrar_seal_couples_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::BackerRegistrarSealCouples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (
                CesrGroup::BackerRegistrarSealCouples(a),
                CesrGroup::BackerRegistrarSealCouples(b),
            ) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (pa, da) = ea.unwrap();
                    let (pb, db) = eb.unwrap();
                    assert_eq!(pa.raw(), pb.raw());
                    assert_eq!(da.raw(), db.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    // ── Complex V2 seal group helpers ─────────────────────────────────────

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

    // ── Complex V2 seal group dispatch tests ──────────────────────────────

    #[test]
    fn dispatch_v2_typed_digest_seal_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedDigestSealCouples, 1);
        input.extend_from_slice(&build_tag7_verser_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::TypedDigestSealCouples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_blinded_state_quadruples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BlindedStateQuadruples, 1);
        input.extend_from_slice(&build_blake3_256_qb64()); // diger
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer1
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer2
        input.extend_from_slice(&build_tag3_labeler_qb64()); // labeler
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::BlindedStateQuadruples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_bound_state_sextuples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BoundStateSextuples, 1);
        input.extend_from_slice(&build_blake3_256_qb64()); // diger
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer1
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer2
        input.extend_from_slice(&build_tag3_labeler_qb64()); // labeler
        input.extend_from_slice(&build_short_number_qb64()); // number
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer3
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::BoundStateSextuples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_typed_media_quadruples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedMediaQuadruples, 1);
        input.extend_from_slice(&build_blake3_256_qb64()); // diger
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer
        input.extend_from_slice(&build_tag3_labeler_qb64()); // labeler
        input.extend_from_slice(&build_texter_qb64()); // texter
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::TypedMediaQuadruples(_)));
        assert!(rest.is_empty());
    }

    // ── Complex V2 seal group roundtrip tests ─────────────────────────────

    #[test]
    fn typed_digest_seal_couples_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedDigestSealCouples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_tag7_verser_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::TypedDigestSealCouples(a), CesrGroup::TypedDigestSealCouples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (va, da) = ea.unwrap();
                    let (vb, db) = eb.unwrap();
                    assert_eq!(va.soft(), vb.soft());
                    assert_eq!(da.raw(), db.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn blinded_state_quadruples_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::BlindedStateQuadruples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_tag3_labeler_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::BlindedStateQuadruples(a), CesrGroup::BlindedStateQuadruples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (da, n1a, n2a, la) = ea.unwrap();
                    let (db, n1b, n2b, lb) = eb.unwrap();
                    assert_eq!(da.raw(), db.raw());
                    assert_eq!(n1a.raw(), n1b.raw());
                    assert_eq!(n2a.raw(), n2b.raw());
                    assert_eq!(la.soft(), lb.soft());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn bound_state_sextuples_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::BoundStateSextuples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_tag3_labeler_qb64());
            input.extend_from_slice(&build_short_number_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::BoundStateSextuples(a), CesrGroup::BoundStateSextuples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (da, n1a, n2a, la, num_a, n3a) = ea.unwrap();
                    let (db, n1b, n2b, lb, num_b, n3b) = eb.unwrap();
                    assert_eq!(da.raw(), db.raw());
                    assert_eq!(n1a.raw(), n1b.raw());
                    assert_eq!(n2a.raw(), n2b.raw());
                    assert_eq!(la.soft(), lb.soft());
                    assert_eq!(num_a.value(), num_b.value());
                    assert_eq!(n3a.raw(), n3b.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn typed_media_quadruples_roundtrip_v2() {
        use crate::stream::encode::encode_group_v2;

        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedMediaQuadruples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_tag3_labeler_qb64());
            input.extend_from_slice(&build_texter_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::TypedMediaQuadruples(a), CesrGroup::TypedMediaQuadruples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (da, na, la, ta) = ea.unwrap();
                    let (db, nb, lb, tb) = eb.unwrap();
                    assert_eq!(da.raw(), db.raw());
                    assert_eq!(na.raw(), nb.raw());
                    assert_eq!(la.soft(), lb.soft());
                    assert_eq!(ta.raw(), tb.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn parse_group_bytes_matches_slice_path() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));

        let bytes = Bytes::copy_from_slice(&input);
        let (group, rest) = parse_group_bytes(&bytes).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(rest.is_empty());
    }
}
