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
    #[must_use]
    pub fn raw(&self) -> Bytes {
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
}
