#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};
use bytes::Bytes;

use crate::stream::error::ParseError;
use crate::stream::parse::skip_matter;

use super::types::BlindedStateQuadruples;

pub(super) fn parse(
    input: &Bytes,
    count: u32,
) -> Result<(BlindedStateQuadruples, Bytes), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_matter(&input[offset..])?;
        offset += skip_matter(&input[offset..])?;
        offset += skip_matter(&input[offset..])?;
        offset += skip_matter(&input[offset..])?;
    }
    let raw = input.slice(..offset);
    let rest = input.slice(offset..);
    Ok((BlindedStateQuadruples::new(raw, count), rest))
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
    use base64::{Engine, engine::general_purpose as b64};

    fn build_blake3_256_qb64() -> Vec<u8> {
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_tag3_labeler_qb64() -> Vec<u8> {
        b"XAAA".to_vec()
    }

    fn build_one_quadruple() -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&build_blake3_256_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        input.extend_from_slice(&build_tag3_labeler_qb64());
        input
    }

    #[test]
    fn parse_zero_elements() {
        let (group, rest) = parse(&Bytes::new(), 0).unwrap();
        assert_eq!(group.count(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_one_quadruple() {
        let input = build_one_quadruple();
        let (group, rest) = parse(&Bytes::copy_from_slice(&input), 1).unwrap();
        assert_eq!(group.count(), 1);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_two_quadruples() {
        let mut input = build_one_quadruple();
        input.extend_from_slice(&build_one_quadruple());
        let (group, rest) = parse(&Bytes::copy_from_slice(&input), 2).unwrap();
        assert_eq!(group.count(), 2);
        assert!(rest.is_empty());
    }

    #[test]
    fn trailing_bytes_preserved() {
        let mut input = build_one_quadruple();
        input.extend_from_slice(b"TAIL");
        let (group, rest) = parse(&Bytes::copy_from_slice(&input), 1).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(rest, Bytes::from_static(b"TAIL"));
    }

    #[test]
    fn parse_slices_without_copying() {
        let input = build_one_quadruple();
        let parent = Bytes::copy_from_slice(&input);
        let parent_start = parent.as_ptr() as usize;
        let parent_end = parent_start + parent.len();

        let (group, _rest) = parse(&parent, 1).unwrap();
        let raw_ptr = group.raw_bytes().as_ptr() as usize;

        assert!(
            raw_ptr >= parent_start && raw_ptr < parent_end,
            "BlindedStateQuadruples raw must be a slice of the parent buffer, not a copy"
        );
    }
}
