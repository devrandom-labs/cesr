use super::error::Error;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;
use num_traits::{AsPrimitive, PrimInt, sign::Unsigned};

/// The canonical CESR URL-safe Base64 alphabet (RFC 4648 §5): 6-bit index → ASCII byte.
///
/// Single source of truth for the whole crate. Every module's Base64 work — the
/// integer codec here, the qb64↔qb2 conversion in `stream::binary`, the
/// `stream::util` / `indexer` helpers — draws from this one table.
pub(crate) const B64_ALPHABET: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Reverse map: ASCII byte → 6-bit value, or `255` for non-alphabet bytes.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "const table build: i < 64 fits u8; alphabet bytes are ASCII (< 128) so index < 256"
)]
pub(crate) const B64_REVERSE: [u8; 256] = {
    let mut table = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        table[B64_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

#[allow(
    clippy::as_conversions,
    clippy::missing_const_for_fn,
    reason = "c is guarded by is_ascii(), so c as usize is safe (0..=127); const fn incompatible with Result + Error"
)]
pub(crate) fn b64_char_to_index(c: char) -> Result<u8, Error> {
    if c.is_ascii() {
        let idx = B64_REVERSE[c as usize];
        if idx != 255 {
            return Ok(idx);
        }
    }
    Err(Error::InvalidBase64Char(c))
}

pub(crate) fn b64_index_to_char<N>(i: N) -> Result<char, Error>
where
    N: PrimInt + Unsigned + AsPrimitive<usize> + Into<u8>,
{
    let idx: u8 = i.into();
    B64_ALPHABET
        .get(i.as_())
        .map(|&b| char::from(b))
        .ok_or(Error::InvalidBase64Value(idx))
}

#[cfg(test)]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "test code: as casts on indices known to be < 128"
)]
mod tests {
    use super::*;

    // --- b64_char_to_index ---

    #[test]
    fn char_to_index_a_is_0() {
        assert_eq!(b64_char_to_index('A').unwrap(), 0);
    }

    #[test]
    fn char_to_index_z_is_25() {
        assert_eq!(b64_char_to_index('Z').unwrap(), 25);
    }

    #[test]
    fn char_to_index_a_lower_is_26() {
        assert_eq!(b64_char_to_index('a').unwrap(), 26);
    }

    #[test]
    fn char_to_index_z_lower_is_51() {
        assert_eq!(b64_char_to_index('z').unwrap(), 51);
    }

    #[test]
    fn char_to_index_0_is_52() {
        assert_eq!(b64_char_to_index('0').unwrap(), 52);
    }

    #[test]
    fn char_to_index_9_is_61() {
        assert_eq!(b64_char_to_index('9').unwrap(), 61);
    }

    #[test]
    fn char_to_index_hyphen_is_62() {
        assert_eq!(b64_char_to_index('-').unwrap(), 62);
    }

    #[test]
    fn char_to_index_underscore_is_63() {
        assert_eq!(b64_char_to_index('_').unwrap(), 63);
    }

    #[test]
    fn char_to_index_rejects_plus() {
        let err = b64_char_to_index('+').unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('+'));
    }

    #[test]
    fn char_to_index_rejects_slash() {
        let err = b64_char_to_index('/').unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('/'));
    }

    #[test]
    fn char_to_index_rejects_space() {
        let err = b64_char_to_index(' ').unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char(' '));
    }

    #[test]
    fn char_to_index_rejects_non_ascii() {
        let err = b64_char_to_index('\u{00e9}').unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('\u{00e9}'));
    }

    // --- b64_index_to_char ---

    #[test]
    fn index_to_char_0_is_a() {
        assert_eq!(b64_index_to_char(0u8).unwrap(), 'A');
    }

    #[test]
    fn index_to_char_25_is_z() {
        assert_eq!(b64_index_to_char(25u8).unwrap(), 'Z');
    }

    #[test]
    fn index_to_char_26_is_a_lower() {
        assert_eq!(b64_index_to_char(26u8).unwrap(), 'a');
    }

    #[test]
    fn index_to_char_51_is_z_lower() {
        assert_eq!(b64_index_to_char(51u8).unwrap(), 'z');
    }

    #[test]
    fn index_to_char_52_is_0() {
        assert_eq!(b64_index_to_char(52u8).unwrap(), '0');
    }

    #[test]
    fn index_to_char_61_is_9() {
        assert_eq!(b64_index_to_char(61u8).unwrap(), '9');
    }

    #[test]
    fn index_to_char_62_is_hyphen() {
        assert_eq!(b64_index_to_char(62u8).unwrap(), '-');
    }

    #[test]
    fn index_to_char_63_is_underscore() {
        assert_eq!(b64_index_to_char(63u8).unwrap(), '_');
    }

    #[test]
    fn index_to_char_64_is_err() {
        let err = b64_index_to_char(64u8).unwrap_err();
        assert_eq!(err, Error::InvalidBase64Value(64));
    }

    #[test]
    fn index_to_char_255_is_err() {
        let err = b64_index_to_char(255u8).unwrap_err();
        assert_eq!(err, Error::InvalidBase64Value(255));
    }

    // --- roundtrip: index_to_char then char_to_index ---

    #[test]
    fn index_char_roundtrip_all_64_values() {
        for i in 0u8..64 {
            let c = b64_index_to_char(i).unwrap();
            let j = b64_char_to_index(c).unwrap();
            assert_eq!(i, j, "roundtrip failed for index {i}, char {c}");
        }
    }

    // --- B64_ALPHABET table correctness ---

    #[test]
    fn b64_alphabet_has_64_entries() {
        assert_eq!(B64_ALPHABET.len(), 64);
    }

    #[test]
    fn b64_alphabet_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &c in &B64_ALPHABET {
            assert!(seen.insert(c), "duplicate byte '{c}' in B64_ALPHABET");
        }
    }

    #[test]
    fn b64_alphabet_matches_rfc4648_url_safe() {
        // RFC 4648 Table 2: URL-safe base64 alphabet
        let expected = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        assert_eq!(&B64_ALPHABET, expected);
    }

    // --- B64_REVERSE table correctness ---

    #[test]
    fn reverse_maps_all_valid_chars() {
        for (i, &c) in B64_ALPHABET.iter().enumerate() {
            assert_eq!(
                B64_REVERSE[usize::from(c)],
                u8::try_from(i).unwrap(),
                "B64_REVERSE['{c}'] should be {i}"
            );
        }
    }

    #[test]
    fn reverse_marks_invalid_chars_as_255() {
        // Check a sampling of characters not in the URL-safe base64 alphabet
        for &c in b"+/= \n\t@!#" {
            assert_eq!(
                B64_REVERSE[usize::from(c)],
                255,
                "B64_REVERSE['{c}'] should be 255 (invalid)"
            );
        }
    }
}
