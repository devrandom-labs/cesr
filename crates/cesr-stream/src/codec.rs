#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec::Vec};
use core::fmt;
use core::marker::PhantomData;

use bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use crate::error::ParseError;
use crate::framing::{FrameLimits, MessageFramer};
use crate::group::CesrGroup;
use crate::group::GroupFrameCursor;
use crate::version::CesrEncode;
use crate::version::Version;
use cesr::core::version::CesrVersion;

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
///
/// # Partial-frame semantics
///
/// [`Decoder::decode`] returns `Ok(None)` whenever `buf` holds no complete
/// frame yet — either the buffer is empty or it carries a partial group whose
/// bytes have not all arrived (an inner [`ParseError::NeedBytes`] is folded to
/// `Ok(None)`). On `Ok(None)` the buffer is left untouched; the codec retains
/// the position after the last complete element, so later polls only retry
/// the current element. A complete group yields `Ok(Some(group))`.
/// [`Decoder::decode_eof`] reports a typed [`ParseError::Truncated`] for a
/// partial final group.
///
/// The `V1`/`V2` table is chosen by `V`; a codec never mixes version tables
/// across polls. The caller supplies explicit byte, element, signature and
/// enclosure limits through [`FrameLimits`].
pub struct CesrCodec<V: Version> {
    _version: PhantomData<V>,
    cursor: Option<GroupFrameCursor>,
    limits: FrameLimits,
}

impl<V: Version> CesrCodec<V> {
    /// Create a group codec with explicit framing limits.
    #[must_use]
    pub const fn new(limits: FrameLimits) -> Self {
        Self {
            _version: PhantomData,
            cursor: None,
            limits,
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

impl<V: Version> Decoder for CesrCodec<V> {
    type Item = CesrGroup;
    type Error = ParseError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }
        if self.cursor.is_none() {
            let next = match V::VERSION {
                CesrVersion::V1 => GroupFrameCursor::new_v1(buf),
                CesrVersion::V2 => GroupFrameCursor::new_v2(buf),
            };
            self.cursor = match next {
                Ok(cursor) => {
                    self.limits.check_elements(&cursor)?;
                    Some(cursor)
                }
                Err(ParseError::NeedBytes(missing)) => {
                    self.limits
                        .check_pending_attachment(0, buf.len(), missing)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
        }
        let Some(cursor) = self.cursor.as_mut() else {
            return Ok(None);
        };
        let total = match cursor.advance_limited(
            buf,
            self.limits.max_attachment_bytes,
            self.limits.max_group_elements,
            self.limits.max_signatures,
        ) {
            Ok(total) => total,
            Err(ParseError::NeedBytes(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        if let Some(payload) = cursor.enclosing_payload(buf)? {
            self.limits
                .scan_enclosure(payload, cursor.signature_count(), V::VERSION)?;
        }
        let framed = buf.split_to(total).freeze();
        self.cursor = None;
        let (group, remainder) = match V::VERSION {
            CesrVersion::V1 => CesrGroup::parse_bytes(&framed)?,
            CesrVersion::V2 => CesrGroup::parse_bytes_v2(&framed)?,
        };
        debug_assert!(remainder.is_empty());
        Ok(Some(group))
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(group) = self.decode(buf)? {
            return Ok(Some(group));
        }
        if buf.is_empty() {
            return Ok(None);
        }
        let result = self.cursor.as_mut().map_or_else(
            || {
                match V::VERSION {
                    CesrVersion::V1 => GroupFrameCursor::new_v1(buf),
                    CesrVersion::V2 => GroupFrameCursor::new_v2(buf),
                }
                .and_then(|mut cursor| {
                    self.limits.check_elements(&cursor)?;
                    cursor.advance_limited(
                        buf,
                        self.limits.max_attachment_bytes,
                        self.limits.max_group_elements,
                        self.limits.max_signatures,
                    )
                })
            },
            |cursor| {
                cursor.advance_limited(
                    buf,
                    self.limits.max_attachment_bytes,
                    self.limits.max_group_elements,
                    self.limits.max_signatures,
                )
            },
        );
        match result {
            Err(ParseError::NeedBytes(missing)) => Err(ParseError::Truncated { missing }),
            Err(error) => Err(error),
            Ok(_) => Ok(None),
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

/// Async buffer adapter for the sans-I/O [`MessageFramer`]. It yields the
/// exact owned wire span; body interpretation belongs to the protocol codec.
pub struct MessageCodec {
    framer: MessageFramer,
}

impl MessageCodec {
    /// Create a message codec with explicit framing limits.
    #[must_use]
    pub const fn new(limits: FrameLimits) -> Self {
        Self {
            framer: MessageFramer::new(limits),
        }
    }
}

impl Decoder for MessageCodec {
    type Item = Bytes;
    type Error = ParseError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.framer
            .advance(buf, false)
            .map(|maybe_span| maybe_span.map(|span| buf.split_to(span.total_len).freeze()))
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.framer
            .advance(buf, true)
            .map(|maybe_span| maybe_span.map(|span| buf.split_to(span.total_len).freeze()))
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
    use std::hint::black_box;
    use std::println;
    use std::time::Instant;

    use alloc::vec;
    use bytes::BytesMut;
    use cesr::core::counter::CounterCodeV1;
    use cesr::core::counter::CounterCodeV2;
    use cesr::core::indexer::IndexerBuilder;
    use cesr::core::indexer::code::IndexedSigCode;

    use super::*;
    use crate::group::QuadletGroup;
    use crate::version::{V1, V2};

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

    const fn group_limits() -> FrameLimits {
        FrameLimits {
            max_body_bytes: 1024 * 1024,
            max_attachment_bytes: 1024 * 1024,
            max_attachment_groups: 1024,
            max_group_elements: 1024,
            max_signatures: 1024,
            max_nested_groups: 1024,
            max_nesting_depth: 8,
        }
    }

    #[test]
    fn async_group_codec_rejects_declared_count_and_size_before_payload() {
        let mut policy = FrameLimits {
            max_body_bytes: 1024,
            max_attachment_bytes: 1024,
            max_attachment_groups: 4,
            max_group_elements: 1,
            max_signatures: 1,
            max_nested_groups: 4,
            max_nesting_depth: 2,
        };
        let mut counted = CesrCodec::<V1>::new(policy);
        let mut two_signatures =
            BytesMut::from(build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2).as_slice());
        assert!(matches!(
            counted.decode(&mut two_signatures),
            Err(ParseError::LimitExceeded {
                kind: crate::error::LimitKind::GroupElements,
                limit: 1,
                actual: 2,
            })
        ));

        policy.max_attachment_bytes = 8;
        let mut oversized = CesrCodec::<V1>::new(policy);
        let mut declared =
            BytesMut::from(build_counter_qb64(CounterCodeV1::AttachmentGroup, 3).as_slice());
        assert!(matches!(
            oversized.decode(&mut declared),
            Err(ParseError::LimitExceeded {
                kind: crate::error::LimitKind::AttachmentBytes,
                limit: 8,
                ..
            })
        ));

        let mut v2_counted = CesrCodec::<V2>::new(policy);
        let mut v2_declared =
            BytesMut::from(build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 2).as_slice());
        assert!(matches!(
            v2_counted.decode(&mut v2_declared),
            Err(ParseError::LimitExceeded {
                kind: crate::error::LimitKind::GroupElements,
                limit: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn async_group_codec_counts_signatures_inside_envelopes() {
        let mut payload = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        payload.extend_from_slice(&build_siger_qb64(0));
        let mut group = build_counter_qb64(
            CounterCodeV1::AttachmentGroup,
            u32::try_from(payload.len() / 4).unwrap(),
        );
        group.extend_from_slice(&payload);
        let mut policy = group_limits();
        policy.max_signatures = 0;
        let mut codec = CesrCodec::<V1>::new(policy);
        let mut buf = BytesMut::from(group.as_slice());
        assert!(matches!(
            codec.decode(&mut buf),
            Err(ParseError::LimitExceeded {
                kind: crate::error::LimitKind::Signatures,
                limit: 0,
                actual: 1,
            })
        ));
        assert_eq!(&buf[..], &group);
    }

    #[test]
    fn message_codec_uses_framer_for_partial_attachment_and_eof() {
        let mut body = b"{\"v\":\"KERI10JSON000000_\",\"t\":\"icp\"}".to_vec();
        let size = format!("{:06x}", body.len());
        body[16..22].copy_from_slice(size.as_bytes());
        let mut group = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        group.extend_from_slice(&build_siger_qb64(0));
        let mut wire = body.clone();
        wire.extend_from_slice(&group);
        wire.extend_from_slice(&body);

        let limits = FrameLimits {
            max_body_bytes: 1024,
            max_attachment_bytes: 1024,
            max_attachment_groups: 2,
            max_group_elements: 2,
            max_signatures: 2,
            max_nested_groups: 2,
            max_nesting_depth: 1,
        };
        let mut codec = MessageCodec::new(limits);
        let cut = body.len() + group.len() - 1;
        let mut buf = BytesMut::from(&wire[..cut]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&wire[cut..]);
        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&first[..], &wire[..body.len() + group.len()]);
        assert_eq!(&buf[..], body);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(&codec.decode_eof(&mut buf).unwrap().unwrap()[..], body);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_returns_none_on_empty() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_returns_none_on_incomplete() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut buf = BytesMut::from(&b"-A"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn eof_reports_typed_truncation_without_consuming_partial_group() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut buf = BytesMut::from(&b"-A"[..]);
        assert!(matches!(
            codec.decode_eof(&mut buf),
            Err(ParseError::Truncated { missing: 2 })
        ));
        assert_eq!(&buf[..], b"-A");

        let mut full = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        full.extend_from_slice(&build_siger_qb64(0));
        let mut element_codec = CesrCodec::<V1>::new(group_limits());
        let mut element_buf = BytesMut::from(&full[..full.len() - 1]);
        assert!(matches!(
            element_codec.decode_eof(&mut element_buf),
            Err(ParseError::Truncated { missing: 1 })
        ));
        assert_eq!(&element_buf[..], &full[..full.len() - 1]);
    }

    #[test]
    fn decode_complete_group() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut data = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(data.as_slice());

        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_leaves_remainder() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut data = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        data.extend_from_slice(b"EXTRA");
        let mut buf = BytesMut::from(data.as_slice());

        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert_eq!(&buf[..], b"EXTRA");
    }

    #[test]
    fn every_two_group_chunking_preserves_frames_and_remainder() {
        let mut one = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2);
        one.extend_from_slice(&build_siger_qb64(0));
        one.extend_from_slice(&build_siger_qb64(1));
        let mut two = build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1);
        two.extend_from_slice(&build_siger_qb64(0));
        let first_end = one.len();
        one.extend_from_slice(&two);
        one.extend_from_slice(b"tail");

        for split in 0..=first_end + two.len() {
            let mut codec = CesrCodec::<V1>::new(group_limits());
            let mut buf = BytesMut::from(&one[..split]);
            let first = codec.decode(&mut buf).unwrap();
            if split < first_end {
                assert!(first.is_none(), "premature first frame at {split}");
            } else {
                assert!(matches!(first, Some(CesrGroup::ControllerIdxSigs(_))));
            }
            buf.extend_from_slice(&one[split..]);
            if split < first_end {
                assert!(matches!(
                    codec.decode(&mut buf).unwrap(),
                    Some(CesrGroup::ControllerIdxSigs(_))
                ));
            }
            assert!(matches!(
                codec.decode(&mut buf).unwrap(),
                Some(CesrGroup::WitnessIdxSigs(_))
            ));
            assert_eq!(&buf[..], b"tail", "remainder at split {split}");
        }
    }

    #[test]
    fn decode_incremental() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
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
    #[ignore = "release-only A14 fragmentation measurement; run explicitly"]
    #[allow(clippy::print_stdout, reason = "explicit release measurement output")]
    fn element_group_fragmentation_measurement() {
        let signature = build_siger_qb64(0);
        for count in [1, 16, 64, 256] {
            let mut frame = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, count);
            for _ in 0..count {
                frame.extend_from_slice(&signature);
            }
            for sample in 0..35 {
                let coalesced_start = Instant::now();
                let mut coalesced = BytesMut::from(frame.as_slice());
                let mut coalesced_codec = CesrCodec::<V1>::new(group_limits());
                black_box(coalesced_codec.decode(&mut coalesced).unwrap().unwrap());
                let coalesced_ns = coalesced_start.elapsed().as_nanos();

                let fragmented_start = Instant::now();
                let mut fragmented = BytesMut::with_capacity(frame.len());
                let mut codec = CesrCodec::<V1>::new(group_limits());
                for (index, byte) in frame.iter().enumerate() {
                    fragmented.extend_from_slice(core::slice::from_ref(byte));
                    let result = codec.decode(&mut fragmented).unwrap();
                    if index + 1 == frame.len() {
                        black_box(result.expect("complete final frame"));
                    } else {
                        assert!(result.is_none(), "premature group at {index}");
                    }
                }
                if sample >= 4 {
                    println!(
                        "a14 group count={count} bytes={} sample={} coalesced_ns={} bytewise_ns={}",
                        frame.len(),
                        sample - 4,
                        coalesced_ns,
                        fragmented_start.elapsed().as_nanos()
                    );
                }
            }
        }
    }

    #[test]
    fn decode_needbytes_reclaims_buffer_in_place() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut full = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        full.extend_from_slice(&build_siger_qb64(0));

        // Truncated frame returns NeedBytes before any buffer split.
        let mut buf = BytesMut::from(&full[..10]);
        let before = buf.as_ptr();
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // The original buffer was never moved or copied.
        assert_eq!(
            buf.as_ptr(),
            before,
            "NeedBytes restore must reclaim the allocation in place, not copy"
        );
        assert_eq!(&buf[..], &full[..10]);
    }

    #[test]
    fn decode_malformed_returns_error() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut buf = BytesMut::from(&b"INVALID_NOT_A_COUNTER"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_quadlet_group_zero_copy() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
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
        let mut codec = CesrCodec::<V1>::new(group_limits());
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
        let mut codec = CesrCodec::<V1>::new(group_limits());
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
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut data = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(data.as_slice());

        // Capture the base address range of the frame before decode. `split_to()`
        // keeps the same allocation and `freeze()` is O(1), so the
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
    fn decode_element_group_keeps_large_tail_in_place() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
        let mut one = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        one.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(one.repeat(256).as_slice());
        let original = buf.as_ptr();

        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(first, CesrGroup::ControllerIdxSigs(_)));
        assert_eq!(buf.len(), one.len() * 255);
        assert_eq!(buf.as_ptr(), original.wrapping_add(one.len()));
        for _ in 1..256 {
            assert!(matches!(
                codec.decode(&mut buf).unwrap(),
                Some(CesrGroup::ControllerIdxSigs(_))
            ));
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_generic_group_zero_copy() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
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

        let mut codec = CesrCodec::<V1>::new(group_limits());
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

        let mut codec = CesrCodec::<V1>::new(group_limits());
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

        let mut codec = CesrCodec::<V1>::new(group_limits());
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

        fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
            let hard = code.as_str();
            let ss = code.soft_size();
            let ss_nz = NonZeroUsize::new(ss).unwrap();
            let soft = cesr::b64::encode_int(count, ss_nz);
            format!("{hard}{soft}").into_bytes()
        }

        let mut codec = CesrCodec::<V2>::new(group_limits());
        let mut data = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        data.extend_from_slice(&build_siger_qb64(0));
        let mut buf = BytesMut::from(data.as_slice());

        let group = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn default_codec_works() {
        let mut codec = CesrCodec::<V1>::new(group_limits());
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
            let mut codec = CesrCodec::<V1>::new(group_limits());
            let mut data = build_counter_qb64(code, 1);
            let payload = if code == CounterCodeV1::BodyWithAttachmentGroup {
                build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 0)
            } else {
                b"AAAA".to_vec()
            };
            data.extend_from_slice(&payload);
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
            let mut codec = CesrCodec::<V2>::new(group_limits());
            let payload = if matches!(
                code,
                CounterCodeV2::AttachmentGroup
                    | CounterCodeV2::GenericGroup
                    | CounterCodeV2::BodyWithAttachmentGroup
            ) {
                build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 0)
            } else {
                b"AAAA".to_vec()
            };
            let mut data = build_counter_v2_qb64(code, u32::try_from(payload.len() / 4).unwrap());
            data.extend_from_slice(&payload);
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

        let mut codec = CesrCodec::<V2>::new(group_limits());
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

        let mut codec = CesrCodec::<V2>::new(group_limits());
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
            format!("{:?}", CesrCodec::<V1>::new(group_limits())),
            "CesrCodec { version: V1 }"
        );
        assert_eq!(
            format!("{:?}", CesrCodec::<V2>::new(group_limits())),
            "CesrCodec { version: V2 }"
        );
    }
}
