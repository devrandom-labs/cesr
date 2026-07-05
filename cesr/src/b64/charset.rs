/// Returns `true` if every byte in `bytes` is a valid URL-safe Base64 character.
#[must_use]
pub fn is_b64_url_safe_charset(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
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
}
