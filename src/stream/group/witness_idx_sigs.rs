use bytes::Bytes;

use crate::error::ParseError;
use crate::parse::skip_indexer;

use super::types::WitnessIdxSigs;

pub(super) fn parse(input: &[u8], count: u32) -> Result<(WitnessIdxSigs, &[u8]), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_indexer(&input[offset..])?;
    }
    let raw = Bytes::copy_from_slice(&input[..offset]);
    Ok((WitnessIdxSigs::new(raw, count), &input[offset..]))
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
    fn parse_one_siger() {
        let input = build_siger_qb64(0);
        let (group, rest) = parse(&input, 1).unwrap();
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
        let (group, rest) = parse(&input, 2).unwrap();
        assert_eq!(group.count(), 2);
        assert!(rest.is_empty());
    }

    #[test]
    fn trailing_bytes_preserved() {
        let mut input = build_siger_qb64(0);
        input.extend_from_slice(b"TAIL");
        let (group, rest) = parse(&input, 1).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(rest, b"TAIL");
    }
}
