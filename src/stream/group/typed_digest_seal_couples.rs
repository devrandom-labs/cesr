use bytes::Bytes;

use crate::error::ParseError;
use crate::parse::skip_matter;

use super::types::TypedDigestSealCouples;

pub(super) fn parse(
    input: &[u8],
    count: u32,
) -> Result<(TypedDigestSealCouples, &[u8]), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_matter(&input[offset..])?;
        offset += skip_matter(&input[offset..])?;
    }
    let raw = Bytes::copy_from_slice(&input[..offset]);
    Ok((TypedDigestSealCouples::new(raw, count), &input[offset..]))
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

    fn build_tag7_verser_qb64() -> Vec<u8> {
        b"YAAAAAAA".to_vec()
    }

    fn build_blake3_256_qb64() -> Vec<u8> {
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    #[test]
    fn parse_zero_elements() {
        let (group, rest) = parse(b"", 0).unwrap();
        assert_eq!(group.count(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_one_couple() {
        let mut input = build_tag7_verser_qb64();
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse(&input, 1).unwrap();
        assert_eq!(group.count(), 1);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_three_couples() {
        let mut input = Vec::new();
        for _ in 0..3 {
            input.extend_from_slice(&build_tag7_verser_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse(&input, 3).unwrap();
        assert_eq!(group.count(), 3);
        assert!(rest.is_empty());
    }

    #[test]
    fn trailing_bytes_preserved() {
        let mut input = build_tag7_verser_qb64();
        input.extend_from_slice(&build_blake3_256_qb64());
        input.extend_from_slice(b"EXTRA");
        let (group, rest) = parse(&input, 1).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(rest, b"EXTRA");
    }
}
