use core::fmt;

use bytes::Bytes;

use crate::stream::error::ParseError;

use super::types::CesrGroup;

type GroupParser = fn(&[u8]) -> Result<(CesrGroup, &[u8]), ParseError>;

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
        let remaining = &self.input[self.cursor..];
        match (self.parser)(remaining) {
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
    input: &[u8],
    count: u32,
) -> Result<(QuadletGroup, &[u8]), ParseError> {
    let total_bytes = usize::try_from(count).unwrap_or(0).saturating_mul(4);
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
    let group_bytes = Bytes::copy_from_slice(&input[..total_bytes]);
    let rest = &input[total_bytes..];
    Ok((
        QuadletGroup::new(group_bytes, super::parse_group_inner),
        rest,
    ))
}

pub(super) fn parse_quadlets_v2(
    input: &[u8],
    count: u32,
) -> Result<(QuadletGroup, &[u8]), ParseError> {
    let total_bytes = usize::try_from(count).unwrap_or(0).saturating_mul(4);
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
    let group_bytes = Bytes::copy_from_slice(&input[..total_bytes]);
    let rest = &input[total_bytes..];
    Ok((
        QuadletGroup::new(group_bytes, super::parse_group_inner_v2),
        rest,
    ))
}
