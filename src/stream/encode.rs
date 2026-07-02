#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec, vec::Vec};
use core::num::NonZeroUsize;

use crate::b64::encode_int;
use crate::core::counter::CounterCodeV1;
use crate::core::counter::CounterCodeV2;
use crate::core::matter::Matter;
use crate::core::matter::code::CesrCode;
use crate::core::matter::sizage::SizeType;
use base64::Engine;
use base64::engine::general_purpose as b64;
use bytes::BytesMut;

use crate::stream::cold::ColdCode;
use crate::stream::error::ParseError;
use crate::stream::group::types::AttachmentGroup;
use crate::stream::group::types::BackerRegistrarSealCouples;
use crate::stream::group::types::BlindedStateQuadruples;
use crate::stream::group::types::BodyWithAttachmentGroup;
use crate::stream::group::types::BoundStateSextuples;
use crate::stream::group::types::CesrGroup;
use crate::stream::group::types::ControllerIdxSigs;
use crate::stream::group::types::DatagramSegmentGroup;
use crate::stream::group::types::DigestSealSingles;
use crate::stream::group::types::ESSRPayloadGroup;
use crate::stream::group::types::ESSRWrapperGroup;
use crate::stream::group::types::FirstSeenReplayCouples;
use crate::stream::group::types::FixBodyGroup;
use crate::stream::group::types::GenericGroup;
use crate::stream::group::types::GenericListGroup;
use crate::stream::group::types::GenericMapGroup;
use crate::stream::group::types::MapBodyGroup;
use crate::stream::group::types::MerkleRootSealSingles;
use crate::stream::group::types::NonNativeBodyGroup;
use crate::stream::group::types::NonTransReceiptCouples;
use crate::stream::group::types::PathedMaterialCouples;
use crate::stream::group::types::SealSourceCouples;
use crate::stream::group::types::SealSourceLastSingles;
use crate::stream::group::types::SealSourceTriples;
use crate::stream::group::types::TransIdxSigGroups;
use crate::stream::group::types::TransLastIdxSigGroups;
use crate::stream::group::types::TransReceiptQuadruples;
use crate::stream::group::types::TypedDigestSealCouples;
use crate::stream::group::types::TypedMediaQuadruples;
use crate::stream::group::types::WitnessIdxSigs;
use crate::stream::message::VersionStringV2;
use crate::stream::version::CesrEncode;
use crate::stream::version::V1;
use crate::stream::version::V2;
use crate::stream::version::Version;

fn encode_int_bytes(value: u64, width: usize) -> Vec<u8> {
    NonZeroUsize::new(width).map_or_else(Vec::new, |w| encode_int(value, w).into_bytes())
}

// ── Matter qb64 encoding helper ──────────────────────────────────────────

/// Encode a [`Matter`] primitive as its qualified Base64 (qb64) wire format.
///
/// This is the inverse of [`MatterBuilder::from_qualified_base64`]. It supports
/// all fixed-size and variable-size CESR codes.
///
/// The output buffer is allocated once at the final size `fs`; the Base64
/// payload is written straight into it via [`Engine::encode_slice`] at offset
/// `cs - ps`, then the header (code + soft field) is written over the first
/// `cs` bytes. This avoids the intermediate Base64 `String` and the padding
/// reallocation of the previous implementation.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if Base64 encoding fails or the encoded
/// length does not match the code's expected size `fs` — an internal invariant
/// break that would otherwise emit a silently truncated frame.
pub fn matter_to_qb64<C: CesrCode>(matter: &Matter<'_, C>) -> Result<Vec<u8>, ParseError> {
    let sizage = matter.code().get_sizage();
    let hs = sizage.hs();
    let ss = sizage.ss();
    let xs = sizage.xs();
    let ls = sizage.ls();
    let cs = hs + ss;
    let ps = cs % 4;

    let code_str = matter.code().as_str();
    let raw = matter.raw();

    let fs = match sizage.fs() {
        SizeType::Fixed(fixed) => usize::from(*fixed),
        SizeType::Small | SizeType::Large => {
            let raw_with_lead = raw.len() + ls;
            let quadlets = raw_with_lead.div_ceil(3);
            (quadlets * 4) + cs
        }
    };

    // Base64-encode `[ls+ps zero bytes] ++ raw`. The leading zero bytes realign
    // the payload to a 3-byte boundary; their Base64 image is `ps` pad chars
    // that land in the header region and are overwritten below.
    let pad_len = ls + ps;
    let mut padded = Vec::with_capacity(pad_len + raw.len());
    padded.resize(pad_len, 0);
    padded.extend_from_slice(raw);

    let mut out = vec![0u8; fs];
    let b64_start = cs - ps;
    let written = b64::URL_SAFE_NO_PAD
        .encode_slice(&padded, &mut out[b64_start..])
        .map_err(|err| ParseError::Malformed(format!("qb64 base64 encode failed: {err}")))?;
    if b64_start + written != fs {
        return Err(ParseError::Malformed(format!(
            "qb64 length mismatch for code {code_str}: expected {fs}, got {}",
            b64_start + written
        )));
    }

    out[..hs].copy_from_slice(code_str.as_bytes());
    if ss > 0 {
        out[hs..hs + xs].fill(b'_');
        out[hs + xs..cs].copy_from_slice(matter.soft().as_bytes());
    }
    Ok(out)
}

// ── Counter encoding ─────────────────────────────────────────────────────

/// Encode a V1 counter code + count as qb64 bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_counter_v1(code: CounterCodeV1, count: u32) -> Result<Vec<u8>, ParseError> {
    let hard = code.as_str();
    let ss = code.soft_size();
    let ss_nz = NonZeroUsize::new(ss)
        .ok_or_else(|| ParseError::Malformed(format!("counter code {hard} has zero soft size")))?;
    let soft = crate::b64::encode_int(count, ss_nz);
    Ok(format!("{hard}{soft}").into_bytes())
}

/// Encode a V2 counter code + count as qb64 bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_counter_v2(code: CounterCodeV2, count: u32) -> Result<Vec<u8>, ParseError> {
    let hard = code.as_str();
    let ss = code.soft_size();
    let ss_nz = NonZeroUsize::new(ss).ok_or_else(|| {
        ParseError::Malformed(format!("V2 counter code {hard} has zero soft size"))
    })?;
    let soft = crate::b64::encode_int(count, ss_nz);
    Ok(format!("{hard}{soft}").into_bytes())
}

// ── Counter auto-promotion ───────────────────────────────────────────────

/// Encode a counter, auto-promoting to big variant if count > 4095.
///
/// Small codes have ss=2 (max count 4095). When count exceeds this,
/// the code is promoted to its big variant (ss=5, max count 1,073,741,823).
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if count exceeds small limit and no
/// big variant exists for the code, or if count exceeds the big limit.
pub fn encode_counter_auto_v1(code: CounterCodeV1, count: u32) -> Result<Vec<u8>, ParseError> {
    if count > 4095 {
        if let Some(big) = code.to_big() {
            return encode_counter_v1(big, count);
        }
        return Err(ParseError::Malformed(format!(
            "count {count} exceeds small limit and no big variant for {}",
            code.as_str()
        )));
    }
    encode_counter_v1(code, count)
}

/// Encode a V2 counter, auto-promoting to big variant if count > 4095.
///
/// Same logic as [`encode_counter_auto_v1`] but for V2 counter codes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if count exceeds small limit and no
/// big variant exists for the code, or if count exceeds the big limit.
pub fn encode_counter_auto_v2(code: CounterCodeV2, count: u32) -> Result<Vec<u8>, ParseError> {
    if count > 4095 {
        if let Some(big) = code.to_big() {
            return encode_counter_v2(big, count);
        }
        return Err(ParseError::Malformed(format!(
            "count {count} exceeds small limit and no big variant for {}",
            code.as_str()
        )));
    }
    encode_counter_v2(code, count)
}

// ── Element-counted group encoding ───────────────────────────────────────
//
// These helpers delegate to `CesrEncode<V1>` — the trait is the single
// source of truth for encoding logic.

/// Encode controller indexed signatures as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_controller_idx_sigs_v1(group: &ControllerIdxSigs) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode witness indexed signatures as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_witness_idx_sigs_v1(group: &WitnessIdxSigs) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode non-transferable receipt couples as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_non_trans_receipt_couples_v1(
    group: &NonTransReceiptCouples,
) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode transferable receipt quadruples as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_trans_receipt_quadruples_v1(
    group: &TransReceiptQuadruples,
) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode first-seen replay couples as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_first_seen_replay_couples_v1(
    group: &FirstSeenReplayCouples,
) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode seal source couples as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_seal_source_couples_v1(group: &SealSourceCouples) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode seal source triples as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_seal_source_triples_v1(group: &SealSourceTriples) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode transferable indexed sig groups as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_trans_idx_sig_groups_v1(group: &TransIdxSigGroups) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

/// Encode transferable last-event indexed sig groups as V1 qb64.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count does not fit in the counter's soft field.
pub fn encode_trans_last_idx_sig_groups_v1(
    group: &TransLastIdxSigGroups,
) -> Result<Vec<u8>, ParseError> {
    encode_via_trait::<V1, _>(group)
}

fn encode_via_trait<V: Version, T: CesrEncode<V>>(group: &T) -> Result<Vec<u8>, ParseError> {
    let mut dst = BytesMut::new();
    group.encode_cesr(&mut dst)?;
    Ok(dst.to_vec())
}

// ── Quadlet-counted group encoding ───────────────────────────────────────

/// Encode an attachment group wrapping pre-encoded inner bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the byte count is not a multiple of 4
/// or the quadlet count does not fit in the counter's soft field.
pub fn encode_attachment_group_v1(inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    encode_quadlet_group_v1(CounterCodeV1::AttachmentGroup, inner_bytes)
}

/// Encode a generic group wrapping pre-encoded inner bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the byte count is not a multiple of 4
/// or the quadlet count does not fit in the counter's soft field.
pub fn encode_generic_group_v1(inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    encode_quadlet_group_v1(CounterCodeV1::GenericGroup, inner_bytes)
}

/// Encode a body-with-attachment group wrapping pre-encoded inner bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the byte count is not a multiple of 4
/// or the quadlet count does not fit in the counter's soft field.
pub fn encode_body_with_attachment_group_v1(inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    encode_quadlet_group_v1(CounterCodeV1::BodyWithAttachmentGroup, inner_bytes)
}

/// Encode a non-native body group wrapping pre-encoded inner bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the byte count is not a multiple of 4
/// or the quadlet count does not fit in the counter's soft field.
pub fn encode_non_native_body_group_v1(inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    encode_quadlet_group_v1(CounterCodeV1::NonNativeBodyGroup, inner_bytes)
}

/// Encode an ESSR payload group wrapping pre-encoded inner bytes.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the byte count is not a multiple of 4
/// or the quadlet count does not fit in the counter's soft field.
pub fn encode_essr_payload_group_v1(inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    encode_quadlet_group_v1(CounterCodeV1::ESSRPayloadGroup, inner_bytes)
}

fn encode_quadlet_group_v1(code: CounterCodeV1, inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    if !inner_bytes.len().is_multiple_of(4) {
        return Err(ParseError::Malformed(
            "quadlet group inner bytes must be a multiple of 4".into(),
        ));
    }
    let quadlets = u32::try_from(inner_bytes.len() / 4)
        .map_err(|_| ParseError::Malformed("too many quadlets".into()))?;
    let mut out = encode_counter_v1(code, quadlets)?;
    out.extend_from_slice(inner_bytes);
    Ok(out)
}

fn encode_quadlet_group_v2(code: CounterCodeV2, inner_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    if !inner_bytes.len().is_multiple_of(4) {
        return Err(ParseError::Malformed(
            "quadlet group inner bytes must be a multiple of 4".into(),
        ));
    }
    let quadlets = u32::try_from(inner_bytes.len() / 4)
        .map_err(|_| ParseError::Malformed("too many quadlets".into()))?;
    let mut out = encode_counter_v2(code, quadlets)?;
    out.extend_from_slice(inner_bytes);
    Ok(out)
}

// ── CesrGroup dispatch encoding ──────────────────────────────────────

/// Encode a [`CesrGroup`] using V1.0 counter codes.
///
/// Delegates to [`CesrEncode<V1>`] — the trait is the single source of truth
/// for encoding logic.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the group contains V2-only types that
/// have no V1 counter code, or if the count exceeds the counter capacity.
pub fn encode_group_v1(group: &CesrGroup) -> Result<Vec<u8>, ParseError> {
    let mut dst = BytesMut::new();
    CesrEncode::<V1>::encode_cesr(group, &mut dst)?;
    Ok(dst.to_vec())
}

/// Encode a [`CesrGroup`] using V2.0 counter codes.
///
/// Delegates to [`CesrEncode<V2>`] — the trait is the single source of truth
/// for encoding logic.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the count exceeds the counter capacity.
pub fn encode_group_v2(group: &CesrGroup) -> Result<Vec<u8>, ParseError> {
    let mut dst = BytesMut::new();
    CesrEncode::<V2>::encode_cesr(group, &mut dst)?;
    Ok(dst.to_vec())
}

// ── CesrEncode trait implementations ─────────────────────────────────

macro_rules! impl_encode_element {
    ($ty:ty, v1 = $v1:expr, v2 = $v2:expr) => {
        impl CesrEncode<V1> for $ty {
            fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
                let counter = encode_counter_v1($v1, self.count())?;
                dst.extend_from_slice(&counter);
                dst.extend_from_slice(self.raw_bytes());
                Ok(())
            }
        }
        impl CesrEncode<V2> for $ty {
            fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
                let counter = encode_counter_v2($v2, self.count())?;
                dst.extend_from_slice(&counter);
                dst.extend_from_slice(self.raw_bytes());
                Ok(())
            }
        }
    };
    ($ty:ty, v2 = $v2:expr) => {
        impl CesrEncode<V2> for $ty {
            fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
                let counter = encode_counter_v2($v2, self.count())?;
                dst.extend_from_slice(&counter);
                dst.extend_from_slice(self.raw_bytes());
                Ok(())
            }
        }
    };
}

macro_rules! impl_encode_quadlet {
    ($ty:ty, v1 = $v1:expr, v2 = $v2:expr) => {
        impl CesrEncode<V1> for $ty {
            fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
                let encoded = encode_quadlet_group_v1($v1, self.0.raw_bytes())?;
                dst.extend_from_slice(&encoded);
                Ok(())
            }
        }
        impl CesrEncode<V2> for $ty {
            fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
                let encoded = encode_quadlet_group_v2($v2, self.0.raw_bytes())?;
                dst.extend_from_slice(&encoded);
                Ok(())
            }
        }
    };
    ($ty:ty, v2 = $v2:expr) => {
        impl CesrEncode<V2> for $ty {
            fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
                let encoded = encode_quadlet_group_v2($v2, self.0.raw_bytes())?;
                dst.extend_from_slice(&encoded);
                Ok(())
            }
        }
    };
}

// Shared element-counted groups (V1 + V2)
impl_encode_element!(
    ControllerIdxSigs,
    v1 = CounterCodeV1::ControllerIdxSigs,
    v2 = CounterCodeV2::ControllerIdxSigs
);
impl_encode_element!(
    WitnessIdxSigs,
    v1 = CounterCodeV1::WitnessIdxSigs,
    v2 = CounterCodeV2::WitnessIdxSigs
);
impl_encode_element!(
    NonTransReceiptCouples,
    v1 = CounterCodeV1::NonTransReceiptCouples,
    v2 = CounterCodeV2::NonTransReceiptCouples
);
impl_encode_element!(
    TransReceiptQuadruples,
    v1 = CounterCodeV1::TransReceiptQuadruples,
    v2 = CounterCodeV2::TransReceiptQuadruples
);
impl_encode_element!(
    FirstSeenReplayCouples,
    v1 = CounterCodeV1::FirstSeenReplayCouples,
    v2 = CounterCodeV2::FirstSeenReplayCouples
);
impl_encode_element!(
    TransIdxSigGroups,
    v1 = CounterCodeV1::TransIdxSigGroups,
    v2 = CounterCodeV2::TransIdxSigGroups
);
impl_encode_element!(
    SealSourceCouples,
    v1 = CounterCodeV1::SealSourceCouples,
    v2 = CounterCodeV2::SealSourceCouples
);
impl_encode_element!(
    TransLastIdxSigGroups,
    v1 = CounterCodeV1::TransLastIdxSigGroups,
    v2 = CounterCodeV2::TransLastIdxSigGroups
);
impl_encode_element!(
    SealSourceTriples,
    v1 = CounterCodeV1::SealSourceTriples,
    v2 = CounterCodeV2::SealSourceTriples
);

// V2-only element-counted groups
impl_encode_element!(DigestSealSingles, v2 = CounterCodeV2::DigestSealSingles);
impl_encode_element!(
    MerkleRootSealSingles,
    v2 = CounterCodeV2::MerkleRootSealSingles
);
impl_encode_element!(
    SealSourceLastSingles,
    v2 = CounterCodeV2::SealSourceLastSingles
);
impl_encode_element!(
    BackerRegistrarSealCouples,
    v2 = CounterCodeV2::BackerRegistrarSealCouples
);
impl_encode_element!(
    TypedDigestSealCouples,
    v2 = CounterCodeV2::TypedDigestSealCouples
);
impl_encode_element!(
    BlindedStateQuadruples,
    v2 = CounterCodeV2::BlindedStateQuadruples
);
impl_encode_element!(BoundStateSextuples, v2 = CounterCodeV2::BoundStateSextuples);
impl_encode_element!(
    TypedMediaQuadruples,
    v2 = CounterCodeV2::TypedMediaQuadruples
);

// Shared quadlet-counted groups (V1 + V2)
impl_encode_quadlet!(
    PathedMaterialCouples,
    v1 = CounterCodeV1::PathedMaterialCouples,
    v2 = CounterCodeV2::PathedMaterialCouples
);
impl_encode_quadlet!(
    AttachmentGroup,
    v1 = CounterCodeV1::AttachmentGroup,
    v2 = CounterCodeV2::AttachmentGroup
);
impl_encode_quadlet!(
    GenericGroup,
    v1 = CounterCodeV1::GenericGroup,
    v2 = CounterCodeV2::GenericGroup
);
impl_encode_quadlet!(
    BodyWithAttachmentGroup,
    v1 = CounterCodeV1::BodyWithAttachmentGroup,
    v2 = CounterCodeV2::BodyWithAttachmentGroup
);
impl_encode_quadlet!(
    NonNativeBodyGroup,
    v1 = CounterCodeV1::NonNativeBodyGroup,
    v2 = CounterCodeV2::NonNativeBodyGroup
);
impl_encode_quadlet!(
    ESSRPayloadGroup,
    v1 = CounterCodeV1::ESSRPayloadGroup,
    v2 = CounterCodeV2::ESSRPayloadGroup
);

// V2-only quadlet-counted groups
impl_encode_quadlet!(
    DatagramSegmentGroup,
    v2 = CounterCodeV2::DatagramSegmentGroup
);
impl_encode_quadlet!(ESSRWrapperGroup, v2 = CounterCodeV2::ESSRWrapperGroup);
impl_encode_quadlet!(FixBodyGroup, v2 = CounterCodeV2::FixBodyGroup);
impl_encode_quadlet!(MapBodyGroup, v2 = CounterCodeV2::MapBodyGroup);
impl_encode_quadlet!(GenericMapGroup, v2 = CounterCodeV2::GenericMapGroup);
impl_encode_quadlet!(GenericListGroup, v2 = CounterCodeV2::GenericListGroup);

// CesrGroup enum — V2 handles all variants
impl CesrEncode<V2> for CesrGroup {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        match self {
            Self::ControllerIdxSigs(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::WitnessIdxSigs(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::NonTransReceiptCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TransReceiptQuadruples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::FirstSeenReplayCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TransIdxSigGroups(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::SealSourceCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TransLastIdxSigGroups(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::SealSourceTriples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::PathedMaterialCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::AttachmentGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::GenericGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BodyWithAttachmentGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::NonNativeBodyGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::ESSRPayloadGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::DatagramSegmentGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::ESSRWrapperGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::FixBodyGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::MapBodyGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::GenericMapGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::GenericListGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::DigestSealSingles(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::MerkleRootSealSingles(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::SealSourceLastSingles(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BackerRegistrarSealCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TypedDigestSealCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BlindedStateQuadruples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BoundStateSextuples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TypedMediaQuadruples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
        }
    }
}

// CesrGroup enum — V1 returns runtime error for V2-only variants
impl CesrEncode<V1> for CesrGroup {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        match self {
            Self::ControllerIdxSigs(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::WitnessIdxSigs(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::NonTransReceiptCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::TransReceiptQuadruples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::FirstSeenReplayCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::TransIdxSigGroups(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::SealSourceCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::TransLastIdxSigGroups(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::SealSourceTriples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::PathedMaterialCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::AttachmentGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::GenericGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::BodyWithAttachmentGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::NonNativeBodyGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::ESSRPayloadGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::DatagramSegmentGroup(_)
            | Self::ESSRWrapperGroup(_)
            | Self::FixBodyGroup(_)
            | Self::MapBodyGroup(_)
            | Self::GenericMapGroup(_)
            | Self::GenericListGroup(_)
            | Self::DigestSealSingles(_)
            | Self::MerkleRootSealSingles(_)
            | Self::SealSourceLastSingles(_)
            | Self::BackerRegistrarSealCouples(_)
            | Self::TypedDigestSealCouples(_)
            | Self::BlindedStateQuadruples(_)
            | Self::BoundStateSextuples(_)
            | Self::TypedMediaQuadruples(_) => Err(ParseError::Malformed(
                "V2-only group type cannot be encoded with V1 counters".into(),
            )),
        }
    }
}

// ── V2 version string encoding ───────────────────────────────────────

const fn kind_to_bytes(kind: ColdCode) -> &'static [u8; 4] {
    match kind {
        ColdCode::Json => b"JSON",
        ColdCode::Cbor => b"CBOR",
        ColdCode::MessagePack => b"MGPK",
        ColdCode::CesrBase64 | ColdCode::CesrBinary => b"CESR",
    }
}

/// Encode a [`VersionStringV2`] as a 19-byte CESR V2 version string.
///
/// Format: `PPPPpmMgmGKKKKssss.`
#[must_use]
pub fn encode_version_string_v2(vs: &VersionStringV2<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    out.extend_from_slice(vs.protocol.as_bytes());
    out.extend_from_slice(&encode_int_bytes(u64::from(vs.proto_major), 1));
    out.extend_from_slice(&encode_int_bytes(u64::from(vs.proto_minor), 2));
    out.extend_from_slice(&encode_int_bytes(u64::from(vs.genus_major), 1));
    out.extend_from_slice(&encode_int_bytes(u64::from(vs.genus_minor), 2));
    out.extend_from_slice(kind_to_bytes(vs.kind));
    out.extend_from_slice(&encode_int_bytes(u64::from(vs.size), 4));
    out.push(b'.');
    out
}

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

    #[test]
    fn encode_v1_controller_idx_sigs_count_2() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 2).unwrap();
        assert_eq!(&bytes, b"-AAC");
    }

    #[test]
    fn encode_v1_controller_idx_sigs_count_0() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 0).unwrap();
        assert_eq!(&bytes, b"-AAA");
    }

    #[test]
    fn encode_v1_controller_idx_sigs_count_1() {
        let bytes = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 1).unwrap();
        assert_eq!(&bytes, b"-AAB");
    }

    #[test]
    fn encode_v1_witness_idx_sigs() {
        let bytes = encode_counter_v1(CounterCodeV1::WitnessIdxSigs, 3).unwrap();
        assert_eq!(&bytes, b"-BAD");
    }

    #[test]
    fn encode_v1_attachment_group() {
        let bytes = encode_counter_v1(CounterCodeV1::AttachmentGroup, 23).unwrap();
        assert_eq!(&bytes, b"-VAX");
    }

    #[test]
    fn encode_v2_controller_idx_sigs_count_2() {
        let bytes = encode_counter_v2(CounterCodeV2::ControllerIdxSigs, 2).unwrap();
        assert_eq!(&bytes, b"-KAC");
    }

    #[test]
    fn encode_v2_attachment_group() {
        let bytes = encode_counter_v2(CounterCodeV2::AttachmentGroup, 23).unwrap();
        assert_eq!(&bytes, b"-CAX");
    }

    #[test]
    fn encode_v1_roundtrip() {
        use crate::stream::parse::parse_counter;

        let original_code = CounterCodeV1::SealSourceCouples;
        let original_count = 5_u32;
        let encoded = encode_counter_v1(original_code, original_count).unwrap();
        let (decoded_code, decoded_count, rest) = parse_counter(&encoded).unwrap();
        assert_eq!(decoded_code, original_code);
        assert_eq!(decoded_count, original_count);
        assert!(rest.is_empty());
    }

    #[test]
    fn encode_v2_roundtrip() {
        use crate::stream::parse::parse_counter_v2;

        let original_code = CounterCodeV2::SealSourceCouples;
        let original_count = 5_u32;
        let encoded = encode_counter_v2(original_code, original_count).unwrap();
        let (decoded_code, decoded_count, rest) = parse_counter_v2(&encoded).unwrap();
        assert_eq!(decoded_code, original_code);
        assert_eq!(decoded_count, original_count);
        assert!(rest.is_empty());
    }

    // ── Counter auto-promotion tests ──────────────────────────────────────

    #[test]
    fn auto_promote_v1_small_count_stays_small() {
        let result = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 100).unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.starts_with(b"-T"));
    }

    #[test]
    fn auto_promote_v1_large_count_promotes() {
        let result = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 8193).unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.starts_with(b"--T"));
    }

    #[test]
    fn auto_promote_v1_boundary() {
        let small = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 4095).unwrap();
        assert_eq!(small.len(), 4);
        let big = encode_counter_auto_v1(CounterCodeV1::GenericGroup, 4096).unwrap();
        assert_eq!(big.len(), 8);
    }

    #[test]
    fn auto_promote_v1_no_big_variant_errors() {
        let result = encode_counter_auto_v1(CounterCodeV1::ControllerIdxSigs, 5000);
        assert!(result.is_err());
    }

    #[test]
    fn auto_promote_v2_large_count_promotes() {
        let result = encode_counter_auto_v2(CounterCodeV2::ControllerIdxSigs, 8193).unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.starts_with(b"--K"));
    }

    #[test]
    fn auto_promote_v2_small_count_stays_small() {
        let result = encode_counter_auto_v2(CounterCodeV2::ControllerIdxSigs, 100).unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.starts_with(b"-K"));
    }

    // ── matter_to_qb64 tests ─────────────────────────────────────────────

    mod matter_qb64 {
        use super::*;
        use crate::core::matter::builder::MatterBuilder;

        #[test]
        fn ed25519_verkey_roundtrip() {
            let raw = [0xABu8; 32];
            let ps = 1_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            let expected = format!("D{}", &payload_b64[ps..]);

            let matter = MatterBuilder::new()
                .from_qualified_base64(expected.as_bytes())
                .unwrap();
            let encoded = matter_to_qb64(&matter).unwrap();
            assert_eq!(encoded, expected.as_bytes());
        }

        #[test]
        fn ed25519_sig_roundtrip() {
            let raw = [0xEFu8; 64];
            let ps = 2_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            let expected = format!("0B{}", &payload_b64[ps..]);

            let matter = MatterBuilder::new()
                .from_qualified_base64(expected.as_bytes())
                .unwrap();
            let encoded = matter_to_qb64(&matter).unwrap();
            assert_eq!(encoded, expected.as_bytes());
        }

        #[test]
        fn blake3_256_digest_roundtrip() {
            let raw = [0xCDu8; 32];
            let ps = 1_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            let expected = format!("E{}", &payload_b64[ps..]);

            let matter = MatterBuilder::new()
                .from_qualified_base64(expected.as_bytes())
                .unwrap();
            let encoded = matter_to_qb64(&matter).unwrap();
            assert_eq!(encoded, expected.as_bytes());
        }

        #[test]
        fn short_number_roundtrip() {
            let qb64 = b"MAAB";
            let matter = MatterBuilder::new()
                .from_qualified_base64(&qb64[..])
                .unwrap();
            let encoded = matter_to_qb64(&matter).unwrap();
            assert_eq!(&encoded, qb64);
        }

        #[test]
        fn narrow_and_encode_verkey() {
            use crate::core::matter::code::MatterCode;
            use crate::core::matter::code::VerKeyCode;

            let qb64 = b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let untyped = MatterBuilder::new()
                .from_qualified_base64(&qb64[..])
                .unwrap();
            assert_eq!(*untyped.code(), MatterCode::Ed25519);

            let typed: crate::core::matter::Matter<'_, VerKeyCode> = untyped.narrow().unwrap();
            let encoded = matter_to_qb64(&typed).unwrap();
            assert_eq!(&encoded, qb64);
        }

        #[test]
        fn strb64_variable_soft_roundtrip() {
            // Variable-size code (StrB64 lead-0): ss > 0, so this exercises the
            // soft-field write branch (xtra underscores + soft tail) that the
            // fixed-size cases above never reach.
            let qb64 = b"4AACnhE8oa_r";
            let matter = MatterBuilder::new()
                .from_qualified_base64(&qb64[..])
                .unwrap();
            let encoded = matter_to_qb64(&matter).unwrap();
            assert_eq!(&encoded, qb64);
        }
    }

    // ── Element-counted group encoding tests ─────────────────────────────

    mod element_groups {
        use super::*;
        use crate::core::indexer::IndexerBuilder;
        use crate::core::indexer::code::IndexedSigCode;
        use crate::core::primitives::Siger;
        use crate::stream::group::types::CesrGroup;
        use crate::stream::parse_group;
        use bytes::Bytes;

        fn build_siger(index: u32) -> Siger<'static> {
            let indexer = IndexerBuilder::new()
                .with_code(IndexedSigCode::Ed25519)
                .with_index(index)
                .unwrap()
                .with_raw(&[0u8; 64])
                .unwrap();
            Siger::new(indexer)
        }

        fn build_prefixer_qb64() -> Vec<u8> {
            let raw = [0xABu8; 32];
            let ps = 1_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            format!("D{}", &payload_b64[ps..]).into_bytes()
        }

        fn build_cigar_qb64() -> Vec<u8> {
            let raw = [0xEFu8; 64];
            let ps = 2_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            format!("0B{}", &payload_b64[ps..]).into_bytes()
        }

        fn build_saider_qb64() -> Vec<u8> {
            let raw = [0xCDu8; 32];
            let ps = 1_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            format!("E{}", &payload_b64[ps..]).into_bytes()
        }

        fn build_seqner_qb64() -> Vec<u8> {
            b"MAAB".to_vec()
        }

        fn build_dater_qb64() -> Vec<u8> {
            let raw = [0x11u8; 32];
            let ps = 1_usize;
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(&raw);
            let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
            format!("D{}", &payload_b64[ps..]).into_bytes()
        }

        #[test]
        fn encode_controller_idx_sigs_roundtrip() {
            let siger0 = build_siger(0);
            let siger1 = build_siger(1);
            let mut raw = Vec::new();
            raw.extend_from_slice(siger0.to_qb64().as_bytes());
            raw.extend_from_slice(siger1.to_qb64().as_bytes());
            let group = ControllerIdxSigs::new(Bytes::from(raw), 2);
            let encoded = encode_controller_idx_sigs_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::ControllerIdxSigs(g) => assert_eq!(g.count() as usize, 2),
                other => panic!("expected ControllerIdxSigs, got {other:?}"),
            }
        }

        #[test]
        fn encode_controller_idx_sigs_empty() {
            let group = ControllerIdxSigs::new(Bytes::new(), 0);
            let encoded = encode_controller_idx_sigs_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::ControllerIdxSigs(g) => assert_eq!(g.count() as usize, 0),
                other => panic!("expected ControllerIdxSigs, got {other:?}"),
            }
        }

        #[test]
        fn encode_witness_idx_sigs_roundtrip() {
            let siger0 = build_siger(0);
            let mut raw = Vec::new();
            raw.extend_from_slice(siger0.to_qb64().as_bytes());
            let group = WitnessIdxSigs::new(Bytes::from(raw), 1);
            let encoded = encode_witness_idx_sigs_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::WitnessIdxSigs(g) => assert_eq!(g.count() as usize, 1),
                other => panic!("expected WitnessIdxSigs, got {other:?}"),
            }
        }

        #[test]
        fn encode_non_trans_receipt_couples_roundtrip() {
            let mut raw = build_prefixer_qb64();
            raw.extend_from_slice(&build_cigar_qb64());
            let group = NonTransReceiptCouples::new(Bytes::from(raw), 1);
            let encoded = encode_non_trans_receipt_couples_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::NonTransReceiptCouples(g) => assert_eq!(g.count() as usize, 1),
                other => panic!("expected NonTransReceiptCouples, got {other:?}"),
            }
        }

        #[test]
        fn encode_trans_receipt_quadruples_roundtrip() {
            let mut raw = build_prefixer_qb64();
            raw.extend_from_slice(&build_seqner_qb64());
            raw.extend_from_slice(&build_saider_qb64());
            raw.extend_from_slice(build_siger(0).to_qb64().as_bytes());
            let group = TransReceiptQuadruples::new(Bytes::from(raw), 1);
            let encoded = encode_trans_receipt_quadruples_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::TransReceiptQuadruples(g) => assert_eq!(g.count() as usize, 1),
                other => panic!("expected TransReceiptQuadruples, got {other:?}"),
            }
        }

        #[test]
        fn encode_first_seen_replay_couples_roundtrip() {
            let mut raw = build_seqner_qb64();
            raw.extend_from_slice(&build_dater_qb64());
            let group = FirstSeenReplayCouples::new(Bytes::from(raw), 1);
            let encoded = encode_first_seen_replay_couples_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::FirstSeenReplayCouples(g) => assert_eq!(g.count() as usize, 1),
                other => panic!("expected FirstSeenReplayCouples, got {other:?}"),
            }
        }

        #[test]
        fn encode_seal_source_couples_roundtrip() {
            let mut raw = build_seqner_qb64();
            raw.extend_from_slice(&build_saider_qb64());
            let group = SealSourceCouples::new(Bytes::from(raw), 1);
            let encoded = encode_seal_source_couples_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::SealSourceCouples(g) => assert_eq!(g.count() as usize, 1),
                other => panic!("expected SealSourceCouples, got {other:?}"),
            }
        }

        #[test]
        fn encode_seal_source_triples_roundtrip() {
            let mut raw = build_prefixer_qb64();
            raw.extend_from_slice(&build_seqner_qb64());
            raw.extend_from_slice(&build_saider_qb64());
            let group = SealSourceTriples::new(Bytes::from(raw), 1);
            let encoded = encode_seal_source_triples_v1(&group).unwrap();
            let (parsed, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match parsed {
                CesrGroup::SealSourceTriples(g) => assert_eq!(g.count() as usize, 1),
                other => panic!("expected SealSourceTriples, got {other:?}"),
            }
        }
    }

    // ── Quadlet-counted group encoding tests ─────────────────────────────

    mod quadlet_groups {
        use super::*;
        use crate::core::indexer::IndexerBuilder;
        use crate::core::indexer::code::IndexedSigCode;
        use crate::stream::group::types::CesrGroup;
        use crate::stream::parse_group;

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

        fn build_inner_group() -> Vec<u8> {
            let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
            inner.extend_from_slice(&build_siger_qb64(0));
            inner
        }

        #[test]
        fn encode_attachment_group_roundtrip() {
            let inner = build_inner_group();
            let encoded = encode_attachment_group_v1(&inner).unwrap();
            let (group, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
        }

        #[test]
        fn encode_generic_group_roundtrip() {
            let inner = build_inner_group();
            let encoded = encode_generic_group_v1(&inner).unwrap();
            let (group, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(group, CesrGroup::GenericGroup(_)));
        }

        #[test]
        fn encode_body_with_attachment_group_roundtrip() {
            let inner = build_inner_group();
            let encoded = encode_body_with_attachment_group_v1(&inner).unwrap();
            let (group, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(group, CesrGroup::BodyWithAttachmentGroup(_)));
        }

        #[test]
        fn encode_non_native_body_group_roundtrip() {
            let inner = build_inner_group();
            let encoded = encode_non_native_body_group_v1(&inner).unwrap();
            let (group, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(group, CesrGroup::NonNativeBodyGroup(_)));
        }

        #[test]
        fn encode_essr_payload_group_roundtrip() {
            let inner = build_inner_group();
            let encoded = encode_essr_payload_group_v1(&inner).unwrap();
            let (group, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(group, CesrGroup::ESSRPayloadGroup(_)));
        }

        #[test]
        fn encode_quadlet_group_rejects_non_multiple_of_4() {
            let inner = vec![0u8; 5];
            let result = encode_attachment_group_v1(&inner);
            assert!(result.is_err());
        }

        #[test]
        fn encode_quadlet_group_empty() {
            let encoded = encode_attachment_group_v1(&[]).unwrap();
            let (group, rest) = parse_group(&encoded).unwrap();
            assert!(rest.is_empty());
            match group {
                CesrGroup::AttachmentGroup(ag) => assert_eq!(ag.0.quadlet_count(), 0),
                other => panic!("expected AttachmentGroup, got {other:?}"),
            }
        }
    }

    // ── V2 version string encoding tests ─────────────────────────────────

    mod version_string_v2 {
        use super::*;
        use crate::stream::message::parse_version_string_v2;

        fn make_vs(
            protocol: &str,
            proto_minor: u16,
            genus_minor: u16,
            kind: ColdCode,
            size: u32,
        ) -> VersionStringV2<'_> {
            VersionStringV2 {
                protocol,
                proto_major: 2,
                proto_minor,
                genus_major: 2,
                genus_minor,
                kind,
                size,
            }
        }

        #[test]
        fn encode_keri_json_size_zero() {
            let vs = make_vs("KERI", 0, 0, ColdCode::Json, 0);
            assert_eq!(encode_version_string_v2(&vs), b"KERICAACAAJSONAAAA.");
        }

        #[test]
        fn encode_keri_json_size_65() {
            let vs = make_vs("KERI", 0, 0, ColdCode::Json, 65);
            assert_eq!(encode_version_string_v2(&vs), b"KERICAACAAJSONAABB.");
        }

        #[test]
        fn encode_acdc_json_size_86() {
            let vs = make_vs("ACDC", 0, 0, ColdCode::Json, 86);
            assert_eq!(encode_version_string_v2(&vs), b"ACDCCAACAAJSONAABW.");
        }

        #[test]
        fn encode_keri_mgpk_size_zero() {
            let vs = make_vs("KERI", 0, 0, ColdCode::MessagePack, 0);
            assert_eq!(encode_version_string_v2(&vs), b"KERICAACAAMGPKAAAA.");
        }

        #[test]
        fn encode_keri_json_versioned() {
            let vs = make_vs("KERI", 1, 1, ColdCode::Json, 0);
            assert_eq!(encode_version_string_v2(&vs), b"KERICABCABJSONAAAA.");
        }

        #[test]
        fn encode_length_is_19() {
            let vs = make_vs("KERI", 0, 0, ColdCode::Json, 0);
            assert_eq!(encode_version_string_v2(&vs).len(), 19);
        }

        #[test]
        fn encode_cbor() {
            let vs = make_vs("KERI", 0, 0, ColdCode::Cbor, 0);
            assert_eq!(encode_version_string_v2(&vs), b"KERICAACAACBORAAAA.");
        }

        #[test]
        fn encode_cesr() {
            let vs = make_vs("KERI", 0, 0, ColdCode::CesrBase64, 0);
            assert_eq!(encode_version_string_v2(&vs), b"KERICAACAACESRAAAA.");
        }

        #[test]
        fn roundtrip_keri_json_size_zero() {
            let vs = make_vs("KERI", 0, 0, ColdCode::Json, 0);
            let encoded = encode_version_string_v2(&vs);
            let (parsed, rest) = parse_version_string_v2(&encoded).unwrap();
            assert_eq!(parsed.protocol, "KERI");
            assert_eq!(parsed.proto_major, 2);
            assert_eq!(parsed.proto_minor, 0);
            assert_eq!(parsed.genus_major, 2);
            assert_eq!(parsed.genus_minor, 0);
            assert_eq!(parsed.kind, ColdCode::Json);
            assert_eq!(parsed.size, 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn roundtrip_acdc_json_size_86() {
            let vs = make_vs("ACDC", 0, 0, ColdCode::Json, 86);
            let encoded = encode_version_string_v2(&vs);
            let (parsed, _) = parse_version_string_v2(&encoded).unwrap();
            assert_eq!(parsed.protocol, "ACDC");
            assert_eq!(parsed.size, 86);
        }

        #[test]
        fn roundtrip_versioned() {
            let vs = make_vs("KERI", 1, 1, ColdCode::Json, 0);
            let encoded = encode_version_string_v2(&vs);
            let (parsed, _) = parse_version_string_v2(&encoded).unwrap();
            assert_eq!(parsed.proto_minor, 1);
            assert_eq!(parsed.genus_minor, 1);
        }

        #[test]
        fn roundtrip_max_size() {
            let max_4_b64 = 16_777_215_u32;
            let vs = make_vs("KERI", 0, 0, ColdCode::Json, max_4_b64);
            let encoded = encode_version_string_v2(&vs);
            let (parsed, _) = parse_version_string_v2(&encoded).unwrap();
            assert_eq!(parsed.size, max_4_b64);
        }
    }

    // ── CesrEncode trait direct tests ─────────────────────────────────────

    mod encode_cesr {
        use crate::core::indexer::IndexerBuilder;
        use crate::core::indexer::code::IndexedSigCode;
        use crate::core::primitives::Siger;
        use bytes::BytesMut;

        use super::*;
        use crate::stream::parse_group;
        use crate::stream::parse_group_v2;
        use crate::stream::version::CesrEncode;
        use crate::stream::version::V1;
        use crate::stream::version::V2;

        fn build_siger_raw() -> Vec<u8> {
            let indexer = IndexerBuilder::new()
                .with_code(IndexedSigCode::Ed25519)
                .with_index(0)
                .unwrap()
                .with_raw(&[0u8; 64])
                .unwrap();
            Siger::new(indexer).to_qb64().into_bytes()
        }

        #[test]
        fn encode_cesr_v1_element_roundtrips() {
            let raw = build_siger_raw();
            let group = ControllerIdxSigs::new(bytes::Bytes::from(raw), 1);

            let mut dst = BytesMut::new();
            CesrEncode::<V1>::encode_cesr(&group, &mut dst).unwrap();

            let (parsed, rest) = parse_group(&dst).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(parsed, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
        }

        #[test]
        fn encode_cesr_v2_element_roundtrips() {
            let raw = build_siger_raw();
            let group = ControllerIdxSigs::new(bytes::Bytes::from(raw), 1);

            let mut dst = BytesMut::new();
            CesrEncode::<V2>::encode_cesr(&group, &mut dst).unwrap();

            let (parsed, rest) = parse_group_v2(&dst).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(parsed, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
        }

        #[test]
        fn encode_cesr_v1_and_legacy_produce_identical_output() {
            let raw = build_siger_raw();
            let group = ControllerIdxSigs::new(bytes::Bytes::from(raw), 1);

            let legacy = encode_controller_idx_sigs_v1(&group).unwrap();

            let mut trait_dst = BytesMut::new();
            CesrEncode::<V1>::encode_cesr(&group, &mut trait_dst).unwrap();

            assert_eq!(&trait_dst[..], &legacy[..]);
        }

        #[test]
        fn encode_cesr_v2_only_type_works() {
            let raw = build_siger_raw();
            let group = DigestSealSingles::new(bytes::Bytes::from(raw), 1);

            let mut dst = BytesMut::new();
            CesrEncode::<V2>::encode_cesr(&group, &mut dst).unwrap();
            assert!(!dst.is_empty());
        }

        #[test]
        fn encode_cesr_v1_enum_rejects_v2_only() {
            let qg = crate::stream::group::QuadletGroup::new(
                bytes::Bytes::from_static(b"ABCD"),
                crate::stream::group::parse_group_inner_v2,
            );
            let group = CesrGroup::DatagramSegmentGroup(DatagramSegmentGroup(qg));

            let mut dst = BytesMut::new();
            let result = CesrEncode::<V1>::encode_cesr(&group, &mut dst);
            assert!(result.is_err());
        }

        #[test]
        fn encode_cesr_v2_enum_accepts_all() {
            let raw = build_siger_raw();
            let group =
                CesrGroup::ControllerIdxSigs(ControllerIdxSigs::new(bytes::Bytes::from(raw), 1));

            let mut dst = BytesMut::new();
            CesrEncode::<V2>::encode_cesr(&group, &mut dst).unwrap();

            let (parsed, rest) = parse_group_v2(&dst).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(parsed, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
        }

        #[test]
        fn encode_cesr_quadlet_v1_roundtrips() {
            let mut inner_raw = Vec::new();
            inner_raw.extend_from_slice(
                &encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 1).unwrap(),
            );
            inner_raw.extend_from_slice(&build_siger_raw());

            let qg = crate::stream::group::QuadletGroup::new(
                bytes::Bytes::from(inner_raw),
                crate::stream::group::parse_group_inner,
            );
            let group = AttachmentGroup(qg);

            let mut dst = BytesMut::new();
            CesrEncode::<V1>::encode_cesr(&group, &mut dst).unwrap();

            let (parsed, rest) = parse_group(&dst).unwrap();
            assert!(rest.is_empty());
            assert!(matches!(parsed, CesrGroup::AttachmentGroup(_)));
        }
    }
}
