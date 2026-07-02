use super::{error::Error, utils::B64_ALPHABET, utils::b64_index_to_char};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{string::String, vec};
use core::num::NonZeroUsize;
use num_traits::{AsPrimitive, PrimInt, sign::Unsigned};

/// Encodes an integer into a Base64 URL-safe string of a minimum length.
///
/// If the Base64 representation of the value is shorter than `min_len`, it will
/// be left-padded with 'A's. If it is longer, the full string will be returned.
/// This single utility handles both fixed-size Counters (when pre-validated by
/// the caller) and variable-size fields. It is the crate's canonical
/// integer→Base64 encoder — `stream::util::int_to_b64` delegates here.
///
/// Infallible: every 6-bit group is a valid alphabet index by construction.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "ilog(64)+1 fits usize; x%64 fits u8, indexes the 64-entry alphabet"
)]
pub fn encode_int<T>(value: T, min_len: NonZeroUsize) -> String
where
    T: PrimInt + Unsigned + AsPrimitive<u64>,
{
    let val: u64 = value.as_();
    let required_len = if val == 0 { 1 } else { val.ilog(64) + 1 } as usize;
    let final_length = required_len.max(min_len.get());
    let mut buffer = vec![b'A'; final_length];
    let mut i = final_length;
    let mut x = val;
    while x > 0 {
        if i == 0 {
            break;
        }
        i -= 1;
        buffer[i] = B64_ALPHABET[(x % 64) as usize];
        x /= 64;
    }
    buffer.into_iter().map(char::from).collect()
}

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
    use super::{encode_binary, encode_int};
    use crate::utils::utils::is_b64_url_safe_charset;
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use rstest::rstest;

    proptest! {
        #[test]
        fn base64_value_len_is_valid( v in 0..101_u32, l in 1..1001_usize) {
            let required_len = if v == 0 { 1 } else { (v.ilog(64) + 1) as usize };
            let expected_len = required_len.max(l);
            let required_length = NonZeroUsize::new(expected_len).unwrap();
            let base64_output = encode_int( v,required_length);
            prop_assert_eq!(base64_output.len(), expected_len, "the output is: {}, expected len: {}", base64_output, expected_len);
        }


        #[test]
        fn base64_value_should_have_correct_char_as_prefix_when_len_is_large(v in 0..63_u32, l in 2..1001_usize) {
            let required_length = NonZeroUsize::new(l).unwrap();
            let base64_output = encode_int( v, required_length);
            let first_char = base64_output.chars().next().unwrap();
            prop_assert_eq!(first_char, 'A');

        }

        #[test]
        fn base64_char_length_should_be_valid_if_len_is_0((v, sl) in (64..120213011_u32).prop_map(|v| {
            let len = v.ilog(64) + 1;
            (v, len)
        })) {
            // length is short so the len of output is totally dependent on the value
            let required_length = NonZeroUsize::new(1).unwrap();
            let base64_output = encode_int(v, required_length);
            prop_assert_eq!(base64_output.len(), sl as usize, "the output is:{}", base64_output);
        }
    }

    #[rstest]
    #[case(0, 1, "A")]
    #[case(1, 1, "B")]
    #[case(0, 2, "AA")]
    #[case(1, 2, "AB")]
    #[case(10, 4, "AAAK")]
    #[case(27, 1, "b")]
    #[case(27, 2, "Ab")]
    #[case(80, 1, "BQ")]
    #[case(248, 1, "D4")]
    #[case(4095, 2, "__")]
    #[case(4096, 1, "BAA")]
    #[case(6011, 1, "Bd7")]
    #[case(16777215, 4, "____")]
    fn u32_to_base64_should_be_valid(#[case] n: u32, #[case] length: usize, #[case] b64: &str) {
        let length = NonZeroUsize::new(length).unwrap();
        assert_eq!(encode_int(n, length), b64);
    }

    #[rstest]
    #[case(0, 1, "A")]
    #[case(1, 1, "B")]
    #[case(0, 2, "AA")]
    #[case(1, 2, "AB")]
    #[case(10, 4, "AAAK")]
    #[case(27, 1, "b")]
    #[case(27, 2, "Ab")]
    #[case(80, 1, "BQ")]
    fn u8_to_base64_should_be_valid(#[case] n: u8, #[case] length: usize, #[case] b64: &str) {
        let length = NonZeroUsize::new(length).unwrap();
        assert_eq!(encode_int(n, length), b64);
    }

    #[rstest]
    #[case(0, 1, "A")]
    #[case(1, 1, "B")]
    #[case(0, 2, "AA")]
    #[case(1, 2, "AB")]
    #[case(10, 4, "AAAK")]
    #[case(27, 1, "b")]
    #[case(27, 2, "Ab")]
    #[case(80, 1, "BQ")]
    fn u16_to_base64_should_be_valid(#[case] n: u16, #[case] length: usize, #[case] b64: &str) {
        let length = NonZeroUsize::new(length).unwrap();
        assert_eq!(encode_int(n, length), b64);
    }

    #[rstest]
    #[case(4095, 2, "__")]
    #[case(4096, 1, "BAA")]
    #[case(6011, 1, "Bd7")]
    #[case(16777215, 4, "____")]
    fn u64_to_base64_should_be_valid(#[case] n: u64, #[case] length: usize, #[case] b64: &str) {
        let length = NonZeroUsize::new(length).unwrap();
        assert_eq!(encode_int(n, length), b64);
    }

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

    // --- encode/decode roundtrip proptests ---

    proptest! {
        #[test]
        fn encode_decode_u32_roundtrip(v in 0u32..16_777_216) {
            use crate::utils::decode::decode_to_int;
            let encoded = encode_int(v, NonZeroUsize::new(1).unwrap());
            let decoded: u32 = decode_to_int(&encoded).unwrap();
            prop_assert_eq!(v, decoded);
        }

        #[test]
        fn encode_decode_u64_roundtrip(v in 0u64..68_719_476_736) {
            use crate::utils::decode::decode_to_int;
            let encoded = encode_int(v, NonZeroUsize::new(1).unwrap());
            let decoded: u64 = decode_to_int(&encoded).unwrap();
            prop_assert_eq!(v, decoded);
        }

        #[test]
        fn encode_int_output_is_valid_b64(v in 0u32..16_777_216, l in 1usize..20) {
            let len = NonZeroUsize::new(l).unwrap();
            let encoded = encode_int(v, len);
            prop_assert!(
                is_b64_url_safe_charset(encoded.as_bytes()),
                "output '{}' has non-B64 chars",
                encoded
            );
        }
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
