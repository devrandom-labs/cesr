use core::fmt;

use bytes::Bytes;

use crate::stream::error::ParseError;

use super::types::CesrGroup;

type GroupParser = fn(&Bytes) -> Result<(CesrGroup, Bytes), ParseError>;

/// A lazy, streaming iterator over inner groups in a quadlet-counted CESR container.
///
/// The total byte size is known upfront from the counter (`count * 4`).
/// Inner groups are parsed on-demand as the iterator is advanced.
pub struct QuadletGroup {
    input: Bytes,
    cursor: usize,
    errored: bool,
    parser: GroupParser,
}

impl QuadletGroup {
    pub(crate) fn new(input: Bytes, parser: GroupParser) -> Self {
        Self {
            input,
            cursor: 0,
            errored: false,
            parser,
        }
    }

    /// Total size of this group in quadlets (4-byte units).
    pub const fn quadlet_count(&self) -> usize {
        self.input.len() / 4
    }

    /// Returns the raw payload bytes (without any counter prefix).
    pub fn raw_bytes(&self) -> &[u8] {
        &self.input
    }

    /// Returns the group's payload as a cheap (O(1) refcount) `Bytes` handle
    /// sharing the underlying buffer.
    ///
    /// Named `to_bytes` (not `raw`) because crate-wide `raw()` returns a
    /// borrowed `&[u8]`; this returns an owned, cheaply-cloned `Bytes`.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.input.clone()
    }
}

impl fmt::Debug for QuadletGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuadletGroup")
            .field("quadlets", &self.quadlet_count())
            .field("cursor", &self.cursor)
            .field("errored", &self.errored)
            .finish_non_exhaustive()
    }
}

impl Iterator for QuadletGroup {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.input.len() || self.errored {
            return None;
        }
        let remaining = self.input.slice(self.cursor..);
        match (self.parser)(&remaining) {
            Ok((group, rest)) => {
                self.cursor = self.input.len() - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.errored = true;
                Some(Err(e))
            }
        }
    }
}

pub(super) fn parse_quadlets(
    input: &Bytes,
    count: u32,
) -> Result<(QuadletGroup, Bytes), ParseError> {
    // checked_mul guards 32-bit usize targets (wasm32) where u32 * 4 can overflow.
    let total_bytes = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(4))
        .ok_or_else(|| ParseError::Malformed("quadlet count overflow".into()))?;
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
    let group_bytes = input.slice(..total_bytes);
    let rest = input.slice(total_bytes..);
    Ok((
        QuadletGroup::new(group_bytes, super::parse_group_bytes),
        rest,
    ))
}

pub(super) fn parse_quadlets_v2(
    input: &Bytes,
    count: u32,
) -> Result<(QuadletGroup, Bytes), ParseError> {
    // checked_mul guards 32-bit usize targets (wasm32) where u32 * 4 can overflow.
    let total_bytes = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(4))
        .ok_or_else(|| ParseError::Malformed("quadlet count overflow".into()))?;
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
    let group_bytes = input.slice(..total_bytes);
    let rest = input.slice(total_bytes..);
    Ok((
        QuadletGroup::new(group_bytes, super::parse_group_bytes_v2),
        rest,
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
    use alloc::format;
    use alloc::vec::Vec;
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

    fn build_controller_idx_sigs_group() -> Vec<u8> {
        let mut g = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        g.extend_from_slice(&build_siger_qb64(0));
        g
    }

    #[test]
    fn parse_quadlets_huge_count_needs_bytes_no_panic() {
        let input = Bytes::from_static(b"AAAA");
        let err = parse_quadlets(&input, u32::MAX).unwrap_err();
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    #[test]
    fn parse_quadlets_v2_huge_count_needs_bytes_no_panic() {
        let input = Bytes::from_static(b"AAAA");
        let err = parse_quadlets_v2(&input, u32::MAX).unwrap_err();
        assert!(matches!(err, ParseError::NeedBytes(_)));
    }

    // `NeedBytes` value = `total_bytes - input.len()`. count=2 → total 8, input
    // 4 → exactly 4 missing. `-` → `+` gives 12, `-` → `/` gives 2; the exact
    // assertion pins the shortfall arithmetic for both parse_quadlets and _v2.
    #[test]
    fn parse_quadlets_need_bytes_reports_exact_shortfall() {
        let input = Bytes::from_static(b"AAAA");
        let err = parse_quadlets(&input, 2).unwrap_err();
        assert_eq!(err, ParseError::NeedBytes(4));
    }

    #[test]
    fn parse_quadlets_v2_need_bytes_reports_exact_shortfall() {
        let input = Bytes::from_static(b"AAAA");
        let err = parse_quadlets_v2(&input, 2).unwrap_err();
        assert_eq!(err, ParseError::NeedBytes(4));
    }

    // Exact-size boundary: `input.len() == total_bytes` must SUCCEED. `<` → `<=`
    // turns the exact-fit case into `NeedBytes(0)`. count=2 → total 8, input 8.
    #[test]
    fn parse_quadlets_v2_exact_size_succeeds() {
        let input = Bytes::from_static(b"AAAABBBB");
        let (group, rest) = parse_quadlets_v2(&input, 2).unwrap();
        assert_eq!(group.quadlet_count(), 2);
        assert_eq!(group.raw_bytes(), b"AAAABBBB");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_quadlets_exact_size_succeeds() {
        let input = Bytes::from_static(b"AAAABBBB");
        let (group, rest) = parse_quadlets(&input, 2).unwrap();
        assert_eq!(group.quadlet_count(), 2);
        assert_eq!(group.raw_bytes(), b"AAAABBBB");
        assert!(rest.is_empty());
    }

    // Iterating a QuadletGroup over two inner groups must yield BOTH. The cursor
    // advance `self.input.len() - rest.len()` (`-` → `+`) overshoots past the
    // end after the first group, and the `cursor >= input.len()` guard
    // (`>=` → `<`) stops immediately; either way the count drops below 2.
    #[test]
    fn quadlet_group_iterates_all_inner_groups() {
        let mut payload = build_controller_idx_sigs_group();
        payload.extend_from_slice(&build_controller_idx_sigs_group());
        let quadlets = u32::try_from(payload.len() / 4).unwrap();

        let parent = Bytes::copy_from_slice(&payload);
        let (group, rest) = parse_quadlets(&parent, quadlets).unwrap();
        assert!(rest.is_empty());

        let inner: Vec<_> = group.collect::<Result<_, _>>().unwrap();
        assert_eq!(inner.len(), 2, "QuadletGroup must yield both inner groups");
        assert!(matches!(inner[0], CesrGroup::ControllerIdxSigs(_)));
        assert!(matches!(inner[1], CesrGroup::ControllerIdxSigs(_)));
    }

    #[test]
    fn parse_quadlets_slices_without_copying() {
        let payload = b"AAAABBBB";
        let parent = Bytes::copy_from_slice(payload);
        let parent_start = parent.as_ptr() as usize;
        let parent_end = parent_start + parent.len();

        let (group, _rest) = parse_quadlets(&parent, 2).unwrap();
        let raw_ptr = group.raw_bytes().as_ptr() as usize;

        assert!(
            raw_ptr >= parent_start && raw_ptr < parent_end,
            "QuadletGroup raw must be a slice of the parent buffer, not a copy"
        );
    }
}
