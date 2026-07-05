#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec::Vec;
use bytes::Bytes;

use crate::stream::error::ParseError;

/// A lazy, streaming iterator over items in a CESR group.
///
/// Backed by a `Bytes` buffer (ref-counted, 'static). Each `.next()` call
/// parses exactly one item and advances the cursor. Items that require
/// Base64 decoding allocate their own memory; the `Bytes` buffer itself
/// is not copied.
pub struct GroupIter<F> {
    input: Bytes,
    cursor: usize,
    count: u32,
    remaining: u32,
    parser: F,
    errored: bool,
}

impl<T, F> GroupIter<F>
where
    F: Fn(&[u8]) -> Result<(T, usize), ParseError>,
{
    /// Create a new `GroupIter` from a `Bytes` buffer, element count, and parser function.
    pub const fn new(input: Bytes, count: u32, parser: F) -> Self {
        Self {
            input,
            cursor: 0,
            count,
            remaining: count,
            parser,
            errored: false,
        }
    }

    /// Consume this iterator and return any unconsumed bytes.
    pub fn into_remaining(self) -> Bytes {
        self.input.slice(self.cursor..)
    }

    /// Return the full input buffer backing this iterator.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.input
    }

    /// Return the original element count this iterator was created with.
    pub const fn count(&self) -> u32 {
        self.count
    }
}

impl<T, F> Iterator for GroupIter<F>
where
    F: Fn(&[u8]) -> Result<(T, usize), ParseError>,
{
    type Item = Result<T, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.errored {
            return None;
        }
        self.remaining -= 1;
        match (self.parser)(&self.input[self.cursor..]) {
            Ok((item, consumed)) => {
                self.cursor += consumed;
                Some(Ok(item))
            }
            Err(e) => {
                self.errored = true;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let r = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        (0, Some(r))
    }
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

    fn parse_4_bytes(input: &[u8]) -> Result<(Vec<u8>, usize), ParseError> {
        if input.len() < 4 {
            return Err(ParseError::NeedBytes(4 - input.len()));
        }
        Ok((input[..4].to_vec(), 4))
    }

    #[test]
    fn iter_yields_correct_count() {
        let data = Bytes::from_static(b"AAAABBBBCCCC");
        let iter = GroupIter::new(data, 3, parse_4_bytes);
        let items: Vec<_> = iter.collect();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_ref().unwrap(), &b"AAAA".to_vec());
        assert_eq!(items[1].as_ref().unwrap(), &b"BBBB".to_vec());
        assert_eq!(items[2].as_ref().unwrap(), &b"CCCC".to_vec());
    }

    #[test]
    fn iter_zero_count_yields_nothing() {
        let data = Bytes::from_static(b"AAAA");
        let iter = GroupIter::new(data, 0, parse_4_bytes);
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn iter_stops_on_error() {
        let data = Bytes::from_static(b"AAAAB");
        let iter = GroupIter::new(data, 2, parse_4_bytes);
        let items: Vec<_> = iter.collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }

    #[test]
    fn raw_bytes_returns_full_input() {
        let data = Bytes::from_static(b"AAAABBBBCCCC");
        let iter = GroupIter::new(data, 3, parse_4_bytes);
        assert_eq!(iter.raw_bytes(), b"AAAABBBBCCCC");
    }

    #[test]
    fn count_returns_original_element_count() {
        let data = Bytes::from_static(b"AAAABBBB");
        let mut iter = GroupIter::new(data, 2, parse_4_bytes);
        assert_eq!(GroupIter::count(&iter), 2);
        let _ = iter.next();
        assert_eq!(GroupIter::count(&iter), 2);
    }

    #[test]
    fn remaining_returns_unconsumed_bytes() {
        let data = Bytes::from_static(b"AAAABBBBEXTRA");
        let mut iter = GroupIter::new(data, 2, parse_4_bytes);
        let _ = iter.next();
        let _ = iter.next();
        assert_eq!(iter.into_remaining(), Bytes::from_static(b"EXTRA"));
    }
}
