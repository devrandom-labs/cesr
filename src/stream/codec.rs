use std::any::TypeId;
use std::marker::PhantomData;

use bytes::BytesMut;
use cesr_core::counter::CounterCodeV1;
use cesr_core::counter::CounterCodeV2;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use crate::error::ParseError;
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
use crate::group::parse_group;
use crate::group::parse_group_inner;
use crate::group::parse_group_inner_v2;
use crate::group::parse_group_v2;
use crate::parse::parse_counter;
use crate::parse::parse_counter_v2;
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
            CesrGroup::AttachmentGroup(AttachmentGroup(qg))
        }
        CounterCodeV1::GenericGroup | CounterCodeV1::BigGenericGroup => {
            CesrGroup::GenericGroup(GenericGroup(qg))
        }
        CounterCodeV1::BodyWithAttachmentGroup | CounterCodeV1::BigBodyWithAttachmentGroup => {
            CesrGroup::BodyWithAttachmentGroup(BodyWithAttachmentGroup(qg))
        }
        CounterCodeV1::NonNativeBodyGroup | CounterCodeV1::BigNonNativeBodyGroup => {
            CesrGroup::NonNativeBodyGroup(NonNativeBodyGroup(qg))
        }
        CounterCodeV1::ESSRPayloadGroup | CounterCodeV1::BigESSRPayloadGroup => {
            CesrGroup::ESSRPayloadGroup(ESSRPayloadGroup(qg))
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
            CesrGroup::AttachmentGroup(AttachmentGroup(qg))
        }
        CounterCodeV2::GenericGroup | CounterCodeV2::BigGenericGroup => {
            CesrGroup::GenericGroup(GenericGroup(qg))
        }
        CounterCodeV2::BodyWithAttachmentGroup | CounterCodeV2::BigBodyWithAttachmentGroup => {
            CesrGroup::BodyWithAttachmentGroup(BodyWithAttachmentGroup(qg))
        }
        CounterCodeV2::NonNativeBodyGroup | CounterCodeV2::BigNonNativeBodyGroup => {
            CesrGroup::NonNativeBodyGroup(NonNativeBodyGroup(qg))
        }
        CounterCodeV2::ESSRPayloadGroup | CounterCodeV2::BigESSRPayloadGroup => {
            CesrGroup::ESSRPayloadGroup(ESSRPayloadGroup(qg))
        }
        CounterCodeV2::DatagramSegmentGroup | CounterCodeV2::BigDatagramSegmentGroup => {
            CesrGroup::DatagramSegmentGroup(DatagramSegmentGroup(qg))
        }
        CounterCodeV2::ESSRWrapperGroup | CounterCodeV2::BigESSRWrapperGroup => {
            CesrGroup::ESSRWrapperGroup(ESSRWrapperGroup(qg))
        }
        CounterCodeV2::FixBodyGroup | CounterCodeV2::BigFixBodyGroup => {
            CesrGroup::FixBodyGroup(FixBodyGroup(qg))
        }
        CounterCodeV2::MapBodyGroup | CounterCodeV2::BigMapBodyGroup => {
            CesrGroup::MapBodyGroup(MapBodyGroup(qg))
        }
        CounterCodeV2::GenericMapGroup | CounterCodeV2::BigGenericMapGroup => {
            CesrGroup::GenericMapGroup(GenericMapGroup(qg))
        }
        CounterCodeV2::GenericListGroup | CounterCodeV2::BigGenericListGroup => {
            CesrGroup::GenericListGroup(GenericListGroup(qg))
        }
        _ => unreachable!("is_quadlet_v2 should have returned false"),
    }
}

fn decode_v1(buf: &mut BytesMut) -> Result<Option<CesrGroup>, ParseError> {
    let (code, count, after_counter) = match parse_counter(buf.as_ref()) {
        Ok(result) => result,
        Err(ParseError::NeedBytes(_)) => return Ok(None),
        Err(e) => return Err(e),
    };

    let counter_size = buf.len() - after_counter.len();

    if is_quadlet_v1(code) {
        let inner_bytes = usize::try_from(count).unwrap_or(0).saturating_mul(4);
        let total = counter_size + inner_bytes;
        if buf.len() < total {
            return Ok(None);
        }
        let frozen = buf.split_to(total).freeze();
        let payload = frozen.slice(counter_size..);
        let qg = QuadletGroup::new(payload, parse_group_inner);
        Ok(Some(quadlet_to_group_v1(code, qg)))
    } else {
        match parse_group(buf.as_ref()) {
            Ok((group, rest)) => {
                let consumed = buf.len() - rest.len();
                let _ = buf.split_to(consumed);
                Ok(Some(group))
            }
            Err(ParseError::NeedBytes(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn decode_v2(buf: &mut BytesMut) -> Result<Option<CesrGroup>, ParseError> {
    let (code, count, after_counter) = match parse_counter_v2(buf.as_ref()) {
        Ok(result) => result,
        Err(ParseError::NeedBytes(_)) => return Ok(None),
        Err(e) => return Err(e),
    };

    let counter_size = buf.len() - after_counter.len();

    if is_quadlet_v2(code) {
        let inner_bytes = usize::try_from(count).unwrap_or(0).saturating_mul(4);
        let total = counter_size + inner_bytes;
        if buf.len() < total {
            return Ok(None);
        }
        let frozen = buf.split_to(total).freeze();
        let payload = frozen.slice(counter_size..);
        let qg = QuadletGroup::new(payload, parse_group_inner_v2);
        Ok(Some(quadlet_to_group_v2(code, qg)))
    } else {
        match parse_group_v2(buf.as_ref()) {
            Ok((group, rest)) => {
                let consumed = buf.len() - rest.len();
                let _ = buf.split_to(consumed);
                Ok(Some(group))
            }
            Err(ParseError::NeedBytes(_)) => Ok(None),
            Err(e) => Err(e),
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
    use std::num::NonZeroUsize;

    use bytes::BytesMut;
    use cesr_core::counter::CounterCodeV1;
    use cesr_core::indexer::IndexerBuilder;
    use cesr_core::indexer::code::IndexedSigCode;

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
        let soft = cesr_utils::encode_int(count, ss_nz).unwrap();
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

        buf.extend_from_slice(&full[10..]);
        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
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
        use cesr_core::primitives::Siger;
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
        let group = CesrGroup::ControllerIdxSigs(crate::group::types::ControllerIdxSigs::new(
            Bytes::from(raw),
            1,
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
        let qg = QuadletGroup::new(
            Bytes::from_static(b"ABCD"),
            crate::group::parse_group_inner_v2,
        );
        let group = CesrGroup::DatagramSegmentGroup(crate::group::types::DatagramSegmentGroup(qg));
        let mut buf = BytesMut::new();
        let result = Encoder::encode(&mut codec, group, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn v2_codec_decodes_v2_groups() {
        use std::num::NonZeroUsize;

        use crate::version::V2;
        use bytes::BytesMut;
        use cesr_core::counter::CounterCodeV2;

        fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
            let hard = code.as_str();
            let ss = code.soft_size();
            let ss_nz = NonZeroUsize::new(ss).unwrap();
            let soft = cesr_utils::encode_int(count, ss_nz).unwrap();
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
}
