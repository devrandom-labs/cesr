#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};
use bytes::Bytes;

use crate::stream::error::ParseError;
use crate::stream::parse::skip_indexer;
use crate::stream::parse::skip_matter;

use super::types::TransReceiptQuadruples;

pub(super) fn parse(
    input: &[u8],
    count: u32,
) -> Result<(TransReceiptQuadruples, &[u8]), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_matter(&input[offset..])?;
        offset += skip_matter(&input[offset..])?;
        offset += skip_matter(&input[offset..])?;
        offset += skip_indexer(&input[offset..])?;
    }
    let raw = Bytes::copy_from_slice(&input[..offset]);
    Ok((TransReceiptQuadruples::new(raw, count), &input[offset..]))
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
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use base64::{Engine, engine::general_purpose as b64};

    fn build_ed25519_qb64() -> Vec<u8> {
        let raw = [0xAB_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_blake3_256_qb64() -> Vec<u8> {
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
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

    #[test]
    fn parse_zero_elements() {
        let (group, rest) = parse(b"", 0).unwrap();
        assert_eq!(group.count(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_one_quadruple() {
        let mut input = build_ed25519_qb64();
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        input.extend_from_slice(&build_siger_qb64(0));
        let (group, rest) = parse(&input, 1).unwrap();
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
        let (group, rest) = parse(&input, 1).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(rest, b"TAIL");
    }
}
