#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec::Vec;
use bytes::Bytes;

use crate::stream::error::ParseError;
use crate::stream::parse::skip_indexer;

use super::types::ControllerIdxSigs;

pub(super) fn parse(input: &Bytes, count: u32) -> Result<(ControllerIdxSigs, Bytes), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_indexer(&input[offset..])?;
    }
    let raw = input.slice(..offset);
    let rest = input.slice(offset..);
    Ok((ControllerIdxSigs::new(raw, count), rest))
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
        let (group, rest) = parse(&Bytes::new(), 0).unwrap();
        assert_eq!(group.count(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_one_siger() {
        let input = build_siger_qb64(0);
        let buf = Bytes::copy_from_slice(&input);
        let (group, rest) = parse(&buf, 1).unwrap();
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
        let buf = Bytes::copy_from_slice(&input);
        let (group, rest) = parse(&buf, 3).unwrap();
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
        let buf = Bytes::copy_from_slice(&input);
        let (group, rest) = parse(&buf, 1).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(rest, Bytes::from_static(b"TRAILING"));
    }

    #[test]
    fn insufficient_data_errors() {
        let input = build_siger_qb64(0);
        let buf = Bytes::copy_from_slice(&input);
        let result = parse(&buf, 2);
        assert!(result.is_err());
    }

    #[test]
    fn parse_slices_without_copying() {
        use bytes::Bytes;
        let input = build_siger_qb64(0);
        let parent = Bytes::copy_from_slice(&input);
        let parent_start = parent.as_ptr() as usize;
        let parent_end = parent_start + parent.len();

        let (group, _rest) = parse(&parent, 1).unwrap();
        let raw_ptr = group.raw_bytes().as_ptr() as usize;

        // A slice points INTO the parent buffer; a copy would point to a fresh alloc.
        assert!(
            raw_ptr >= parent_start && raw_ptr < parent_end,
            "group raw must be a slice of the parent buffer, not a copy"
        );
    }
}
