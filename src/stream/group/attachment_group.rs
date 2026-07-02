use crate::stream::error::ParseError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec::Vec};

use super::quadlet_group::parse_quadlets;
use super::types::AttachmentGroup;

pub(super) fn parse(input: &[u8], count: u32) -> Result<(AttachmentGroup, &[u8]), ParseError> {
    let (qg, rest) = parse_quadlets(input, count)?;
    Ok((AttachmentGroup(qg), rest))
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
    use core::num::NonZeroUsize;

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

    #[test]
    fn parse_zero_quadlets() {
        let (group, rest) = parse(b"", 0).unwrap();
        assert_eq!(group.0.quadlet_count(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_single_inner_group() {
        let mut payload = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        payload.extend_from_slice(&build_siger_qb64(0));
        let quadlets = payload.len() / 4;
        assert_eq!(payload.len() % 4, 0);

        let (group, rest) = parse(&payload, u32::try_from(quadlets).unwrap()).unwrap();
        let items: Vec<_> = group.0.collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_ok());
        assert!(rest.is_empty());
    }

    #[test]
    fn trailing_bytes_preserved() {
        let mut payload = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        payload.extend_from_slice(&build_siger_qb64(0));
        let quadlets = payload.len() / 4;

        payload.extend_from_slice(b"TRAILING");
        let (group, rest) = parse(&payload, u32::try_from(quadlets).unwrap()).unwrap();
        let items: Vec<_> = group.0.collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_ok());
        assert_eq!(rest, b"TRAILING");
    }

    #[test]
    fn insufficient_data_errors() {
        let result = parse(b"ABCD", 10);
        assert!(result.is_err());
    }
}
