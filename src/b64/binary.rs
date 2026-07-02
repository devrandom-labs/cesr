use super::{alphabet::b64_index_to_char, error::Error};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;
use core::num::NonZeroUsize;

/// Encodes a binary byte stream into a Base64 URL-safe string of exactly
/// `length` characters.
///
/// # Errors
///
/// Returns [`Error::ShortBinaryStream`] if `stream` has fewer bytes than needed
/// to produce `length` Base64 characters.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "sextet is masked to 6 bits, always fits u8"
)]
pub fn encode_binary(stream: &[u8], length: NonZeroUsize) -> Result<String, Error> {
    let n = (length.get() * 3).div_ceil(4);
    if n > stream.len() {
        return Err(Error::ShortBinaryStream);
    }
    let mut output = String::with_capacity(length.get());
    let mut accumulator: u32 = 0;
    let mut bits_in_accumulator: u8 = 0;
    for &byte in &stream[..n] {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits_in_accumulator += 8;
        while bits_in_accumulator >= 6 && output.len() < length.get() {
            let shift = bits_in_accumulator - 6;
            let sextet = (accumulator >> shift) as u8;
            let ch = b64_index_to_char(sextet)?;
            output.push(ch);
            bits_in_accumulator -= 6;
            accumulator &= (1 << bits_in_accumulator) - 1;
        }
    }
    Ok(output)
}

#[cfg(test)]
#[allow(
    clippy::shadow_reuse,
    clippy::shadow_same,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal,
    reason = "test code: shadowing for ergonomics, as casts in proptest strategies, long literals from spec"
)]
mod test {
    use super::encode_binary;
    use core::num::NonZeroUsize;
    use rstest::rstest;

    #[rstest]
    #[case(&[0xf8, 0x10, 0x02], 4, "-BAC")]
    #[case(&[0xf8, 0x10, 0x00], 3, "-BA")]
    #[case(&[0xf8, 0x10],2, "-B")]
    #[case(&[0xf8],1, "-")]
    fn code_binary_to_base64_test(
        #[case] stream: &[u8],
        #[case] len: usize,
        #[case] expected: &str,
    ) {
        let length = NonZeroUsize::new(len).unwrap();
        let result = encode_binary(stream, length);
        assert!(result.is_ok());
        let actual = result.unwrap();
        assert_eq!(actual, expected);
    }

    // --- encode_binary edge cases ---

    #[test]
    fn encode_binary_rejects_short_stream() {
        // Request 4 chars (needs ceil(4*3/4) = 3 bytes) but provide only 2
        let len = NonZeroUsize::new(4).unwrap();
        let result = encode_binary(&[0xf8, 0x10], len);
        assert!(result.is_err());
    }

    #[test]
    fn encode_binary_single_byte() {
        let len = NonZeroUsize::new(1).unwrap();
        let result = encode_binary(&[0x00], len).unwrap();
        assert_eq!(result, "A");
    }

    #[test]
    fn encode_binary_all_ones() {
        let len = NonZeroUsize::new(4).unwrap();
        let result = encode_binary(&[0xff, 0xff, 0xff], len).unwrap();
        assert_eq!(result, "____");
    }

    #[test]
    fn encode_binary_all_zeros() {
        let len = NonZeroUsize::new(4).unwrap();
        let result = encode_binary(&[0x00, 0x00, 0x00], len).unwrap();
        assert_eq!(result, "AAAA");
    }
}
