use crate::core::counter::CounterCodeV1;
use crate::core::counter::CounterCodeV2;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};
use bytes::Bytes;

use crate::stream::error::ParseError;
use crate::stream::parse::skip_counter;
use crate::stream::parse::skip_indexer;
use crate::stream::parse::skip_matter;

use super::types::TransLastIdxSigGroups;

pub(super) fn parse(
    input: &[u8],
    count: u32,
) -> Result<(TransLastIdxSigGroups, &[u8]), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_matter(&input[offset..])?;
        let counter_slice = &input[offset..];
        let counter_size = skip_counter(counter_slice)?;
        let (code, sub_count, _) = crate::stream::parse::parse_counter(counter_slice)?;
        if code != CounterCodeV1::ControllerIdxSigs {
            return Err(ParseError::Malformed(format!(
                "expected -A counter inside -H group, got {}",
                code.as_str()
            )));
        }
        offset += counter_size;
        for _ in 0..sub_count {
            offset += skip_indexer(&input[offset..])?;
        }
    }
    let raw = Bytes::copy_from_slice(&input[..offset]);
    Ok((
        TransLastIdxSigGroups::new(raw, count, false),
        &input[offset..],
    ))
}

pub(super) fn parse_v2(
    input: &[u8],
    count: u32,
) -> Result<(TransLastIdxSigGroups, &[u8]), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_matter(&input[offset..])?;
        let counter_slice = &input[offset..];
        let counter_size = skip_counter(counter_slice)?;
        let (code, sub_count, _) = crate::stream::parse::parse_counter_v2(counter_slice)?;
        if code != CounterCodeV2::ControllerIdxSigs {
            return Err(ParseError::Malformed(format!(
                "expected -K counter inside -Y group (V2), got {}",
                code.as_str()
            )));
        }
        offset += counter_size;
        for _ in 0..sub_count {
            offset += skip_indexer(&input[offset..])?;
        }
    }
    let raw = Bytes::copy_from_slice(&input[..offset]);
    Ok((
        TransLastIdxSigGroups::new(raw, count, true),
        &input[offset..],
    ))
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
    use crate::core::counter::CounterCodeV1;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use base64::{Engine, engine::general_purpose as b64};
    use core::num::NonZeroUsize;

    fn build_ed25519_qb64() -> Vec<u8> {
        let raw = [0xAB_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
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

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::utils::encode_int(count, ss_nz).unwrap();
        format!("{hard}{soft}").into_bytes()
    }

    #[test]
    fn parse_zero_elements() {
        let (group, rest) = parse(b"", 0).unwrap();
        assert_eq!(group.count(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_one_group_with_two_sigs() {
        let mut input = build_ed25519_qb64();
        input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2));
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(&build_siger_qb64(1));

        let (group, rest) = parse(&input, 1).unwrap();
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

        let (group, rest) = parse(&input, 1).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(rest, b"MORE");
    }
}
