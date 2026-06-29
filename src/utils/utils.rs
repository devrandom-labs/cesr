use super::error::Error;
use num_traits::{AsPrimitive, PrimInt, sign::Unsigned};

static B64_URL_CHARS: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '-', '_',
];

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const context: loop index i < 64 fits u8, char is ASCII so fits usize"
)]
const B64_DECODE_INDEX: [u8; 128] = {
    let mut table = [255u8; 128];
    let mut i = 0;
    while i < B64_URL_CHARS.len() {
        table[B64_URL_CHARS[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Returns `true` if every byte in `bytes` is a valid URL-safe Base64 character.
#[must_use]
pub fn is_b64_url_safe_charset(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[allow(
    clippy::as_conversions,
    clippy::missing_const_for_fn,
    reason = "c is guarded by is_ascii(), so c as usize is safe (0..=127); const fn incompatible with Result + Error"
)]
pub(crate) fn b64_char_to_index(c: char) -> Result<u8, Error> {
    if c.is_ascii() {
        let idx = B64_DECODE_INDEX[c as usize];
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
    B64_URL_CHARS
        .get(i.as_())
        .copied()
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

    // --- is_b64_url_safe_charset ---

    #[test]
    fn b64_charset_accepts_uppercase() {
        assert!(is_b64_url_safe_charset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }

    #[test]
    fn b64_charset_accepts_lowercase() {
        assert!(is_b64_url_safe_charset(b"abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn b64_charset_accepts_digits() {
        assert!(is_b64_url_safe_charset(b"0123456789"));
    }

    #[test]
    fn b64_charset_accepts_hyphen_underscore() {
        assert!(is_b64_url_safe_charset(b"-_"));
    }

    #[test]
    fn b64_charset_accepts_empty() {
        assert!(is_b64_url_safe_charset(b""));
    }

    #[test]
    fn b64_charset_accepts_mixed_valid() {
        assert!(is_b64_url_safe_charset(b"ABCabc012-_"));
    }

    #[test]
    fn b64_charset_rejects_plus() {
        assert!(!is_b64_url_safe_charset(b"+"));
    }

    #[test]
    fn b64_charset_rejects_slash() {
        assert!(!is_b64_url_safe_charset(b"/"));
    }

    #[test]
    fn b64_charset_rejects_equals() {
        assert!(!is_b64_url_safe_charset(b"="));
    }

    #[test]
    fn b64_charset_rejects_space() {
        assert!(!is_b64_url_safe_charset(b" "));
    }

    #[test]
    fn b64_charset_rejects_newline() {
        assert!(!is_b64_url_safe_charset(b"\n"));
    }

    #[test]
    fn b64_charset_rejects_tab() {
        assert!(!is_b64_url_safe_charset(b"\t"));
    }

    #[test]
    fn b64_charset_rejects_null_byte() {
        assert!(!is_b64_url_safe_charset(b"\0"));
    }

    #[test]
    fn b64_charset_rejects_high_ascii() {
        assert!(!is_b64_url_safe_charset(&[0x80]));
    }

    #[test]
    fn b64_charset_rejects_at_sign() {
        assert!(!is_b64_url_safe_charset(b"@"));
    }

    #[test]
    fn b64_charset_rejects_mixed_with_one_bad() {
        // All good except one bad char in the middle
        assert!(!is_b64_url_safe_charset(b"ABC+def"));
    }

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

    // --- B64_URL_CHARS table correctness ---

    #[test]
    fn b64_url_chars_has_64_entries() {
        assert_eq!(B64_URL_CHARS.len(), 64);
    }

    #[test]
    fn b64_url_chars_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &c in &B64_URL_CHARS {
            assert!(seen.insert(c), "duplicate character '{c}' in B64_URL_CHARS");
        }
    }

    #[test]
    fn b64_url_chars_matches_rfc4648_url_safe() {
        // RFC 4648 Table 2: URL-safe base64 alphabet
        let expected = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let actual: String = B64_URL_CHARS.iter().collect();
        assert_eq!(actual, expected);
    }

    // --- B64_DECODE_INDEX table correctness ---

    #[test]
    fn decode_index_maps_all_valid_chars() {
        for (i, &c) in B64_URL_CHARS.iter().enumerate() {
            assert_eq!(
                B64_DECODE_INDEX[c as usize], i as u8,
                "B64_DECODE_INDEX['{c}'] should be {i}"
            );
        }
    }

    #[test]
    fn decode_index_marks_invalid_chars_as_255() {
        // Check a sampling of characters not in the URL-safe base64 alphabet
        for &c in b"+/= \n\t@!#" {
            assert_eq!(
                B64_DECODE_INDEX[c as usize], 255,
                "B64_DECODE_INDEX['{c}'] should be 255 (invalid)"
            );
        }
    }
}
