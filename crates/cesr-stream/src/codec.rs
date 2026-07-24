#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec::Vec};
use core::any::TypeId;
use core::fmt;
use core::marker::PhantomData;

use bytes::Bytes;
use bytes::BytesMut;
use cesr::core::counter::CounterCodeV1;
use cesr::core::counter::CounterCodeV2;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use crate::error::ParseError;
use crate::error::SpanKind;
use crate::group::AttachmentGroup;
use crate::group::BodyWithAttachmentGroup;
use crate::group::CesrGroup;
use crate::group::DatagramSegmentGroup;
use crate::group::ESSRPayloadGroup;
use crate::group::ESSRWrapperGroup;
use crate::group::FixBodyGroup;
use crate::group::GenericGroup;
use crate::group::GenericListGroup;
use crate::group::GenericMapGroup;
use crate::group::MapBodyGroup;
use crate::group::NonNativeBodyGroup;
use crate::group::QuadletGroup;
use crate::parse::TextStream;
use crate::version::CesrEncode;
use crate::version::V1;
use crate::version::Version;

/// Returns `true` if the V1 counter code is quadlet-counted.
const fn is_quadlet_v1(code: CounterCodeV1) -> bool {
    matches!(
        code,
        CounterCodeV1::AttachmentGroup
            | CounterCodeV1::BigAttachmentGroup
            | CounterCodeV1::GenericGroup
            | CounterCodeV1::BigGenericGroup
            | CounterCodeV1::BodyWithAttachmentGroup
            | CounterCodeV1::BigBodyWithAttachmentGroup
            | CounterCodeV1::NonNativeBodyGroup
            | CounterCodeV1::BigNonNativeBodyGroup
            | CounterCodeV1::ESSRPayloadGroup
            | CounterCodeV1::BigESSRPayloadGroup
    )
}

/// Maps a V1 quadlet counter code to the corresponding `CesrGroup` variant.
fn quadlet_to_group_v1(code: CounterCodeV1, qg: QuadletGroup) -> CesrGroup {
    match code {
        CounterCodeV1::AttachmentGroup | CounterCodeV1::BigAttachmentGroup => {
            CesrGroup::AttachmentGroup(AttachmentGroup::new(qg))
        }
        CounterCodeV1::GenericGroup | CounterCodeV1::BigGenericGroup => {
            CesrGroup::GenericGroup(GenericGroup::new(qg))
        }
        CounterCodeV1::BodyWithAttachmentGroup | CounterCodeV1::BigBodyWithAttachmentGroup => {
            CesrGroup::BodyWithAttachmentGroup(BodyWithAttachmentGroup::new(qg))
        }
        CounterCodeV1::NonNativeBodyGroup | CounterCodeV1::BigNonNativeBodyGroup => {
            CesrGroup::NonNativeBodyGroup(NonNativeBodyGroup::new(qg))
        }
        CounterCodeV1::ESSRPayloadGroup | CounterCodeV1::BigESSRPayloadGroup => {
            CesrGroup::ESSRPayloadGroup(ESSRPayloadGroup::new(qg))
        }
        _ => unreachable!("is_quadlet_v1 should have returned false"),
    }
}

/// Returns `true` if the V2 counter code is quadlet-counted.
const fn is_quadlet_v2(code: CounterCodeV2) -> bool {
    matches!(
        code,
        CounterCodeV2::AttachmentGroup
            | CounterCodeV2::BigAttachmentGroup
            | CounterCodeV2::GenericGroup
            | CounterCodeV2::BigGenericGroup
            | CounterCodeV2::BodyWithAttachmentGroup
            | CounterCodeV2::BigBodyWithAttachmentGroup
            | CounterCodeV2::NonNativeBodyGroup
            | CounterCodeV2::BigNonNativeBodyGroup
            | CounterCodeV2::ESSRPayloadGroup
            | CounterCodeV2::BigESSRPayloadGroup
            | CounterCodeV2::DatagramSegmentGroup
            | CounterCodeV2::BigDatagramSegmentGroup
            | CounterCodeV2::ESSRWrapperGroup
            | CounterCodeV2::BigESSRWrapperGroup
            | CounterCodeV2::FixBodyGroup
            | CounterCodeV2::BigFixBodyGroup
            | CounterCodeV2::MapBodyGroup
            | CounterCodeV2::BigMapBodyGroup
            | CounterCodeV2::GenericMapGroup
            | CounterCodeV2::BigGenericMapGroup
            | CounterCodeV2::GenericListGroup
            | CounterCodeV2::BigGenericListGroup
    )
}

/// Maps a V2 quadlet counter code to the corresponding `CesrGroup` variant.
fn quadlet_to_group_v2(code: CounterCodeV2, qg: QuadletGroup) -> CesrGroup {
    match code {
        CounterCodeV2::AttachmentGroup | CounterCodeV2::BigAttachmentGroup => {
            CesrGroup::AttachmentGroup(AttachmentGroup::new(qg))
        }
        CounterCodeV2::GenericGroup | CounterCodeV2::BigGenericGroup => {
            CesrGroup::GenericGroup(GenericGroup::new(qg))
        }
        CounterCodeV2::BodyWithAttachmentGroup | CounterCodeV2::BigBodyWithAttachmentGroup => {
            CesrGroup::BodyWithAttachmentGroup(BodyWithAttachmentGroup::new(qg))
        }
        CounterCodeV2::NonNativeBodyGroup | CounterCodeV2::BigNonNativeBodyGroup => {
            CesrGroup::NonNativeBodyGroup(NonNativeBodyGroup::new(qg))
        }
        CounterCodeV2::ESSRPayloadGroup | CounterCodeV2::BigESSRPayloadGroup => {
            CesrGroup::ESSRPayloadGroup(ESSRPayloadGroup::new(qg))
        }
        CounterCodeV2::DatagramSegmentGroup | CounterCodeV2::BigDatagramSegmentGroup => {
            CesrGroup::DatagramSegmentGroup(DatagramSegmentGroup::new(qg))
        }
        CounterCodeV2::ESSRWrapperGroup | CounterCodeV2::BigESSRWrapperGroup => {
            CesrGroup::ESSRWrapperGroup(ESSRWrapperGroup::new(qg))
        }
        CounterCodeV2::FixBodyGroup | CounterCodeV2::BigFixBodyGroup => {
            CesrGroup::FixBodyGroup(FixBodyGroup::new(qg))
        }
        CounterCodeV2::MapBodyGroup | CounterCodeV2::BigMapBodyGroup => {
            CesrGroup::MapBodyGroup(MapBodyGroup::new(qg))
        }
        CounterCodeV2::GenericMapGroup | CounterCodeV2::BigGenericMapGroup => {
            CesrGroup::GenericMapGroup(GenericMapGroup::new(qg))
        }
        CounterCodeV2::GenericListGroup | CounterCodeV2::BigGenericListGroup => {
            CesrGroup::GenericListGroup(GenericListGroup::new(qg))
        }
        _ => unreachable!("is_quadlet_v2 should have returned false"),
    }
}

/// Restores `buf` from the parse `snapshot` after a non-consuming decode
/// (`NeedBytes` or a hard error), leaving the caller's bytes intact for the
/// next poll.
///
/// `buf.split()` leaves `*buf` holding a residual shared handle to `snapshot`'s
/// allocation, so `snapshot` is not uniquely owned until that handle is dropped.
/// `mem::take` drops it first, letting `try_into_mut` reclaim the allocation in
/// place (zero-copy). The `unwrap_or_else` fallback copies only if the reclaim
/// still fails (e.g. an outstanding reference held elsewhere).
fn restore_buf(buf: &mut BytesMut, snapshot: Bytes) {
    drop(core::mem::take(buf));
    *buf = snapshot.try_into_mut().unwrap_or_else(|b| {
        let mut m = BytesMut::with_capacity(b.len());
        m.extend_from_slice(&b);
        m
    });
}

fn decode_v1(buf: &mut BytesMut) -> Result<Option<CesrGroup>, ParseError> {
    let mut ts = TextStream::new(buf.as_ref());
    let (code, count) = match ts.read_counter_v1() {
        Ok(result) => result,
        Err(ParseError::NeedBytes(_)) => return Ok(None),
        Err(e) => return Err(e),
    };

    let counter_size = ts.offset();

    if is_quadlet_v1(code) {
        let inner_bytes = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(4))
            .ok_or(ParseError::Overflow(SpanKind::QuadletCount))?;
        let total = counter_size + inner_bytes;
        if buf.len() < total {
            return Ok(None);
        }
        let frozen = buf.split_to(total).freeze();
        let payload = frozen.slice(counter_size..);
        let qg = QuadletGroup::new(payload, CesrGroup::parse_bytes);
        Ok(Some(quadlet_to_group_v1(code, qg)))
    } else {
        // Snapshot the buffer as an owned Bytes (freeze is O(1) for BytesMut),
        // parse zero-copy from it, then reattach the unconsumed remainder.
        let snapshot = buf.split().freeze();
        match CesrGroup::parse_bytes(&snapshot) {
            Ok((group, rest)) => {
                // Reattach only the unconsumed tail (empty in the common single-frame case).
                let mut leftover = BytesMut::with_capacity(rest.len());
                leftover.extend_from_slice(&rest);
                *buf = leftover;
                Ok(Some(group))
            }
            Err(ParseError::NeedBytes(_)) => {
                // Nothing consumed — restore the buffer for the next poll.
                restore_buf(buf, snapshot);
                Ok(None)
            }
            Err(e) => {
                // Restore buffer on hard error too (leave caller's bytes intact).
                restore_buf(buf, snapshot);
                Err(e)
            }
        }
    }
}

fn decode_v2(buf: &mut BytesMut) -> Result<Option<CesrGroup>, ParseError> {
    let mut ts = TextStream::new(buf.as_ref());
    let (code, count) = match ts.read_counter_v2() {
        Ok(result) => result,
        Err(ParseError::NeedBytes(_)) => return Ok(None),
        Err(e) => return Err(e),
    };

    let counter_size = ts.offset();

    if is_quadlet_v2(code) {
        let inner_bytes = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(4))
            .ok_or(ParseError::Overflow(SpanKind::QuadletCount))?;
        let total = counter_size + inner_bytes;
        if buf.len() < total {
            return Ok(None);
        }
        let frozen = buf.split_to(total).freeze();
        let payload = frozen.slice(counter_size..);
        let qg = QuadletGroup::new(payload, CesrGroup::parse_bytes_v2);
        Ok(Some(quadlet_to_group_v2(code, qg)))
    } else {
        // Snapshot the buffer as an owned Bytes (freeze is O(1) for BytesMut),
        // parse zero-copy from it, then reattach the unconsumed remainder.
        let snapshot = buf.split().freeze();
        match CesrGroup::parse_bytes_v2(&snapshot) {
            Ok((group, rest)) => {
                // Reattach only the unconsumed tail (empty in the common single-frame case).
                let mut leftover = BytesMut::with_capacity(rest.len());
                leftover.extend_from_slice(&rest);
                *buf = leftover;
                Ok(Some(group))
            }
            Err(ParseError::NeedBytes(_)) => {
                // Nothing consumed — restore the buffer for the next poll.
                restore_buf(buf, snapshot);
                Ok(None)
            }
            Err(e) => {
                // Restore buffer on hard error too (leave caller's bytes intact).
                restore_buf(buf, snapshot);
                Err(e)
            }
        }
    }
}

/// Tokio codec that frames CESR attachment groups from an async byte stream,
/// parameterised by version (`V1` or `V2`).
///
/// Use with `tokio_util::codec::Framed` to parse groups from any `AsyncRead`.
/// Quadlet-counted groups use zero-copy `Bytes` slicing directly from the
/// `BytesMut` buffer. Element-counted groups are parsed from `&[u8]`.
///
/// Encoding uses the [`CesrEncode`] trait, which prevents V2-only group types
/// from being encoded with V1 counters at compile time (when using individual
/// group types) or at runtime (when using [`CesrGroup`]).
pub struct CesrCodec<V: Version> {
    _version: PhantomData<V>,
}

impl<V: Version> CesrCodec<V> {
    /// Create a new codec for the given version.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _version: PhantomData,
        }
    }
}

impl<V: Version> fmt::Debug for CesrCodec<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CesrCodec")
            .field("version", &V::VERSION)
            .finish()
    }
}

impl<V: Version> Default for CesrCodec<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Version> Decoder for CesrCodec<V> {
    type Item = CesrGroup;
    type Error = ParseError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }
        if TypeId::of::<V>() == TypeId::of::<V1>() {
            decode_v1(buf)
        } else {
            decode_v2(buf)
        }
    }
}

impl<V: Version> Encoder<CesrGroup> for CesrCodec<V>
where
    CesrGroup: CesrEncode<V>,
{
    type Error = ParseError;

    fn encode(&mut self, item: CesrGroup, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode_cesr(dst)
    }
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
    use core::num::NonZeroUsize;

    use alloc::vec;
    use bytes::BytesMut;
    use cesr::core::counter::CounterCodeV1;
    use cesr::core::indexer::IndexerBuilder;
    use cesr::core::indexer::code::IndexedSigCode;

    use super::*;

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
        let soft = cesr::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    #[test]
    fn decode_returns_none_on_empty() {
        let mut codec = CesrCodec::<V1>::new();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_returns_none_on_incomplete() {
        let mut codec = CesrCodec::<V1>::new();
        let mut buf = BytesMut::from(&b"-A"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_complete_group() {
        let mut codec = CesrCodec::<V1>::new();
        let mut data = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(data.as_slice());

        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_leaves_remainder() {
        let mut codec = CesrCodec::<V1>::new();
        let mut data = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        data.extend_from_slice(b"EXTRA");
        let mut buf = BytesMut::from(data.as_slice());

        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert_eq!(&buf[..], b"EXTRA");
    }

    #[test]
    fn decode_incremental() {
        let mut codec = CesrCodec::<V1>::new();
        let mut full = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        full.extend_from_slice(&build_siger_qb64(0));

        let mut buf = BytesMut::from(&full[..10]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 10);
        // Byte-exact content must survive the NeedBytes restore path unchanged;
        // a length check alone would miss a corrupted retained byte.
        assert_eq!(&buf[..], &full[..10]);

        buf.extend_from_slice(&full[10..]);
        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
    }

    #[test]
    fn decode_needbytes_reclaims_buffer_in_place() {
        let mut codec = CesrCodec::<V1>::new();
        let mut full = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        full.extend_from_slice(&build_siger_qb64(0));

        // Truncated frame → non-quadlet parse returns NeedBytes → restore path.
        let mut buf = BytesMut::from(&full[..10]);
        let before = buf.as_ptr();
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // restore_buf drops buf's residual handle before try_into_mut, so the
        // original allocation is reclaimed in place — no realloc, same pointer.
        assert_eq!(
            buf.as_ptr(),
            before,
            "NeedBytes restore must reclaim the allocation in place, not copy"
        );
        assert_eq!(&buf[..], &full[..10]);
    }

    #[test]
    fn decode_malformed_returns_error() {
        let mut codec = CesrCodec::<V1>::new();
        let mut buf = BytesMut::from(&b"INVALID_NOT_A_COUNTER"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_quadlet_group_zero_copy() {
        let mut codec = CesrCodec::<V1>::new();
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets);
        outer.extend_from_slice(&inner);

        let mut buf = BytesMut::from(outer.as_slice());
        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_quadlet_group_leaves_remainder() {
        let mut codec = CesrCodec::<V1>::new();
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets);
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(b"TRAILING");

        let mut buf = BytesMut::from(outer.as_slice());
        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
        assert_eq!(&buf[..], b"TRAILING");
    }

    #[test]
    fn decode_quadlet_group_incomplete_returns_none() {
        let mut codec = CesrCodec::<V1>::new();
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets);
        outer.extend_from_slice(&inner);

        let mut buf = BytesMut::from(&outer[..outer.len() - 4]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_non_quadlet_group_slices_without_copying() {
        let mut codec = CesrCodec::<V1>::new();
        let mut data = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(data.as_slice());

        // Capture the base address range of the frame before decode. `split()` in
        // the decoder keeps the same allocation and `freeze()` is O(1), so the
        // parsed group's raw bytes must point inside this range if zero-copy.
        let start = buf.as_ptr() as usize;
        let end = start + buf.len();

        let group = codec.decode(&mut buf).unwrap().unwrap();
        let CesrGroup::ControllerIdxSigs(g) = group else {
            panic!("expected ControllerIdxSigs");
        };
        let ptr = g.raw_bytes().as_ptr() as usize;
        assert!(
            ptr >= start && ptr < end,
            "codec group must slice, not copy"
        );
    }

    #[test]
    fn decode_generic_group_zero_copy() {
        let mut codec = CesrCodec::<V1>::new();
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_qb64(CounterCodeV1::GenericGroup, quadlets);
        outer.extend_from_slice(&inner);

        let mut buf = BytesMut::from(outer.as_slice());
        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::GenericGroup(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_decode_controller_idx_sigs_roundtrip() {
        use bytes::Bytes;
        use cesr::core::primitives::Siger;
        use tokio_util::codec::Encoder;

        let mut codec = CesrCodec::<V1>::new();
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let siger = Siger::new(indexer);
        let raw = siger.to_qb64().into_bytes();
        let group = CesrGroup::ControllerIdxSigs(crate::group::ControllerIdxSigs::new(
            Bytes::from(raw),
            1,
            cesr::core::version::CesrVersion::V1,
        ));

        let mut buf = BytesMut::new();
        Encoder::encode(&mut codec, group, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(decoded, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_decode_attachment_group_roundtrip() {
        use tokio_util::codec::Encoder;

        let mut codec = CesrCodec::<V1>::new();
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets);
        outer.extend_from_slice(&inner);

        let mut buf = BytesMut::from(outer.as_slice());
        let original = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(original, CesrGroup::AttachmentGroup(_)));
        assert!(buf.is_empty());

        Encoder::encode(&mut codec, original, &mut buf).unwrap();
        let roundtripped = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(roundtripped, CesrGroup::AttachmentGroup(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_v2_only_group_with_v1_codec_returns_error() {
        use bytes::Bytes;
        use tokio_util::codec::Encoder;

        let mut codec = CesrCodec::<V1>::new();
        let qg = QuadletGroup::new(Bytes::from_static(b"ABCD"), CesrGroup::parse_bytes_v2);
        let group = CesrGroup::DatagramSegmentGroup(crate::group::DatagramSegmentGroup::new(qg));
        let mut buf = BytesMut::new();
        let result = Encoder::encode(&mut codec, group, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn v2_codec_decodes_v2_groups() {
        use core::num::NonZeroUsize;

        use crate::version::V2;
        use bytes::BytesMut;
        use cesr::core::counter::CounterCodeV2;

        fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
            let hard = code.as_str();
            let ss = code.soft_size();
            let ss_nz = NonZeroUsize::new(ss).unwrap();
            let soft = cesr::b64::encode_int(count, ss_nz);
            format!("{hard}{soft}").into_bytes()
        }

        let mut codec = CesrCodec::<V2>::new();
        let mut data = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(data.as_slice());

        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn default_codec_works() {
        let mut codec = CesrCodec::<V1>::default();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // ── V1 quadlet_to_group_v1 mapping coverage ────────────────────────────
    //
    // `is_quadlet_v1` routes these codes to `quadlet_to_group_v1`, whose match
    // arms map each code to its variant. Deleting an arm hits the
    // `unreachable!()` (panic) or picks the wrong variant. Decoding each code
    // and asserting the exact variant kills the arm-deletion mutants.

    type V1MapCase = (CounterCodeV1, fn(&CesrGroup) -> bool, &'static str);
    type V2MapCase = (CounterCodeV2, fn(&CesrGroup) -> bool, &'static str);

    #[test]
    fn decode_v1_quadlet_to_group_mapping() {
        let cases: [V1MapCase; 3] = [
            (
                CounterCodeV1::BodyWithAttachmentGroup,
                |g| matches!(g, CesrGroup::BodyWithAttachmentGroup(_)),
                "BodyWithAttachmentGroup",
            ),
            (
                CounterCodeV1::NonNativeBodyGroup,
                |g| matches!(g, CesrGroup::NonNativeBodyGroup(_)),
                "NonNativeBodyGroup",
            ),
            (
                CounterCodeV1::ESSRPayloadGroup,
                |g| matches!(g, CesrGroup::ESSRPayloadGroup(_)),
                "ESSRPayloadGroup",
            ),
        ];
        for (code, is_variant, name) in cases {
            let mut codec = CesrCodec::<V1>::new();
            let mut data = build_counter_qb64(code, 1);
            data.extend_from_slice(b"AAAA");
            let mut buf = BytesMut::from(data.as_slice());
            let group = codec
                .decode(&mut buf)
                .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"))
                .unwrap_or_else(|| panic!("{name}: decode returned None"));
            assert!(is_variant(&group), "{name}: wrong variant: {group:?}");
            assert!(buf.is_empty(), "{name}: buffer not fully consumed");
        }
    }

    // ── V2 codec coverage: quadlet_to_group_v2 mapping + decode_v2 arithmetic ─

    fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = cesr::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    fn quadlet_v2_codec_cases() -> Vec<V2MapCase> {
        vec![
            (
                CounterCodeV2::AttachmentGroup,
                (|g| matches!(g, CesrGroup::AttachmentGroup(_))) as fn(&CesrGroup) -> bool,
                "AttachmentGroup",
            ),
            (
                CounterCodeV2::GenericGroup,
                |g| matches!(g, CesrGroup::GenericGroup(_)),
                "GenericGroup",
            ),
            (
                CounterCodeV2::BodyWithAttachmentGroup,
                |g| matches!(g, CesrGroup::BodyWithAttachmentGroup(_)),
                "BodyWithAttachmentGroup",
            ),
            (
                CounterCodeV2::NonNativeBodyGroup,
                |g| matches!(g, CesrGroup::NonNativeBodyGroup(_)),
                "NonNativeBodyGroup",
            ),
            (
                CounterCodeV2::ESSRPayloadGroup,
                |g| matches!(g, CesrGroup::ESSRPayloadGroup(_)),
                "ESSRPayloadGroup",
            ),
            (
                CounterCodeV2::DatagramSegmentGroup,
                |g| matches!(g, CesrGroup::DatagramSegmentGroup(_)),
                "DatagramSegmentGroup",
            ),
            (
                CounterCodeV2::ESSRWrapperGroup,
                |g| matches!(g, CesrGroup::ESSRWrapperGroup(_)),
                "ESSRWrapperGroup",
            ),
            (
                CounterCodeV2::FixBodyGroup,
                |g| matches!(g, CesrGroup::FixBodyGroup(_)),
                "FixBodyGroup",
            ),
            (
                CounterCodeV2::MapBodyGroup,
                |g| matches!(g, CesrGroup::MapBodyGroup(_)),
                "MapBodyGroup",
            ),
            (
                CounterCodeV2::GenericMapGroup,
                |g| matches!(g, CesrGroup::GenericMapGroup(_)),
                "GenericMapGroup",
            ),
            (
                CounterCodeV2::GenericListGroup,
                |g| matches!(g, CesrGroup::GenericListGroup(_)),
                "GenericListGroup",
            ),
        ]
    }

    // Exact-frame decode: kills quadlet_to_group_v2 arm deletions AND the
    // decode_v2 arithmetic mutants that turn a complete frame into `None`
    // (`counter_size = len + after`, `total = size * inner`, `len < total` →
    // `==`/`<=`) or leave a non-empty buffer (`counter_size = len / after`).
    #[test]
    fn decode_v2_quadlet_to_group_mapping_exact_frame() {
        use crate::version::V2;

        for (code, is_variant, name) in quadlet_v2_codec_cases() {
            let mut codec = CesrCodec::<V2>::new();
            let mut data = build_counter_v2_qb64(code, 1);
            data.extend_from_slice(b"AAAA");
            let mut buf = BytesMut::from(data.as_slice());
            let group = codec
                .decode(&mut buf)
                .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"))
                .unwrap_or_else(|| panic!("{name}: decode returned None"));
            assert!(is_variant(&group), "{name}: wrong variant: {group:?}");
            assert!(buf.is_empty(), "{name}: buffer not fully consumed");
        }
    }

    // Trailing bytes after the frame: `len < total` → `>` would return `None`
    // whenever a remainder is present, so asserting `Some` + exact remainder
    // kills the `<` → `>` mutant that the exact-frame test cannot.
    #[test]
    fn decode_v2_quadlet_group_leaves_remainder() {
        use crate::version::V2;

        let mut codec = CesrCodec::<V2>::new();
        let mut inner = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_v2_qb64(CounterCodeV2::AttachmentGroup, quadlets);
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(b"TRAILING");

        let mut buf = BytesMut::from(outer.as_slice());
        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
        assert_eq!(&buf[..], b"TRAILING");
    }

    // Truncated frame: one quadlet short of `total` must yield `None`, pinning
    // the `total = counter_size + inner_bytes` addition (`+` → `-` underflows /
    // panics; `+` → `*` overshoots) and the incomplete-detection branch.
    #[test]
    fn decode_v2_quadlet_group_incomplete_returns_none() {
        use crate::version::V2;

        let mut codec = CesrCodec::<V2>::new();
        let mut inner = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = u32::try_from(inner.len() / 4).unwrap();

        let mut outer = build_counter_v2_qb64(CounterCodeV2::AttachmentGroup, quadlets);
        outer.extend_from_slice(&inner);

        let mut buf = BytesMut::from(&outer[..outer.len() - 4]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // The `Debug` impl reads `V::VERSION` rather than deriving over the
    // `PhantomData<V>` field, so the two markers must print differently.
    #[test]
    fn debug_names_the_version_marker() {
        use crate::version::V2;

        assert_eq!(
            format!("{:?}", CesrCodec::<V1>::new()),
            "CesrCodec { version: V1 }"
        );
        assert_eq!(
            format!("{:?}", CesrCodec::<V2>::new()),
            "CesrCodec { version: V2 }"
        );
    }
}
