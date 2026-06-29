#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{format, string::ToString, vec, vec::Vec,};
use thiserror::Error as ThisError;

/// Errors from CESR Base64 encode/decode operations.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum Error {
    /// The decoded Base64 value exceeds the target integer type's maximum.
    #[error(
        "Integer Overflow: The decoded Base64 value exceeds the maximum size for the target integer type."
    )]
    IntegerOverflow,
    /// A character was encountered that is not in the URL-safe Base64 alphabet.
    #[error(
        "Invalid Base64 Character: Encountered '{0}', which is not part of the URL-safe Base64 character set."
    )]
    InvalidBase64Char(char),
    /// A numeric Base64 value (0–63) was out of bounds.
    #[error(
        "Invalid Base64 Value: The value {0} is out of bounds for the Base64 character set (0-63)."
    )]
    InvalidBase64Value(u8),

    /// The input stream ended before enough bytes were available.
    #[error(
        "Short Binary Stream: More bytes were expected to complete the parsing operation, but the stream ended."
    )]
    ShortBinaryStream,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Display formatting ---

    #[test]
    fn integer_overflow_display() {
        let err = Error::IntegerOverflow;
        let msg = err.to_string();
        assert!(
            msg.contains("Integer Overflow"),
            "expected 'Integer Overflow' in: {msg}"
        );
    }

    #[test]
    fn invalid_base64_char_display_contains_char() {
        let err = Error::InvalidBase64Char('+');
        let msg = err.to_string();
        assert!(msg.contains('+'), "expected '+' in: {msg}");
    }

    #[test]
    fn invalid_base64_char_display_contains_label() {
        let err = Error::InvalidBase64Char('!');
        let msg = err.to_string();
        assert!(
            msg.contains("Invalid Base64 Character"),
            "expected 'Invalid Base64 Character' in: {msg}"
        );
    }

    #[test]
    fn invalid_base64_value_display_contains_value() {
        let err = Error::InvalidBase64Value(65);
        let msg = err.to_string();
        assert!(msg.contains("65"), "expected '65' in: {msg}");
    }

    #[test]
    fn invalid_base64_value_display_contains_label() {
        let err = Error::InvalidBase64Value(99);
        let msg = err.to_string();
        assert!(
            msg.contains("Invalid Base64 Value"),
            "expected 'Invalid Base64 Value' in: {msg}"
        );
    }

    #[test]
    fn short_binary_stream_display() {
        let err = Error::ShortBinaryStream;
        let msg = err.to_string();
        assert!(
            msg.contains("Short Binary Stream"),
            "expected 'Short Binary Stream' in: {msg}"
        );
    }

    // --- PartialEq / Eq ---

    #[test]
    fn same_variants_are_equal() {
        assert_eq!(Error::IntegerOverflow, Error::IntegerOverflow);
        assert_eq!(Error::ShortBinaryStream, Error::ShortBinaryStream);
        assert_eq!(Error::InvalidBase64Char('x'), Error::InvalidBase64Char('x'));
        assert_eq!(Error::InvalidBase64Value(10), Error::InvalidBase64Value(10));
    }

    #[test]
    fn different_payloads_are_not_equal() {
        assert_ne!(Error::InvalidBase64Char('x'), Error::InvalidBase64Char('y'));
        assert_ne!(Error::InvalidBase64Value(10), Error::InvalidBase64Value(11));
    }

    #[test]
    fn different_variants_are_not_equal() {
        assert_ne!(Error::IntegerOverflow, Error::ShortBinaryStream);
    }

    // --- Debug ---

    #[test]
    fn error_debug_contains_variant_name() {
        let cases: Vec<(&str, Error)> = vec![
            ("IntegerOverflow", Error::IntegerOverflow),
            ("InvalidBase64Char", Error::InvalidBase64Char('!')),
            ("InvalidBase64Value", Error::InvalidBase64Value(99)),
            ("ShortBinaryStream", Error::ShortBinaryStream),
        ];
        for (expected_name, err) in cases {
            let debug = format!("{err:?}");
            assert!(
                debug.contains(expected_name),
                "expected '{expected_name}' in debug output: {debug}"
            );
        }
    }

    // --- core::error::Error trait ---

    #[test]
    fn error_implements_std_error() {
        fn assert_std_error<T: core::error::Error>() {}
        assert_std_error::<Error>();
    }
}
