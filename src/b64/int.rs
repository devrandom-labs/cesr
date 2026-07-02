use super::{alphabet::B64_ALPHABET, alphabet::b64_char_to_index, error::Error};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{string::String, vec};
use core::num::NonZeroUsize;
use num_traits::{AsPrimitive, PrimInt, ops::checked::CheckedShl, sign::Unsigned};

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

/// Decodes a Base64 URL-safe string into an unsigned integer of type `N`.
///
/// # Errors
///
/// Returns [`Error::InvalidBase64Char`] if any character is not a valid URL-safe
/// Base64 character, or [`Error::IntegerOverflow`] if the decoded value exceeds
/// the capacity of `N`.
pub fn decode_to_int<T, N>(stream: T) -> Result<N, Error>
where
    T: AsRef<str>,
    N: PrimInt + Unsigned + CheckedShl + 'static,
{
    let mut out: N = N::zero();
    for c in stream.as_ref().chars() {
        let b64_val = b64_char_to_index(c)?;
        let wide_val = N::from(b64_val).ok_or(Error::IntegerOverflow)?;
        if out.leading_zeros() < 6 {
            return Err(Error::IntegerOverflow);
        }
        out = out
            .checked_shl(6)
            .and_then(|shifted| shifted.checked_add(&wide_val))
            .ok_or(Error::IntegerOverflow)?;
    }
    Ok(out)
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
    use super::{decode_to_int, encode_int};
    use crate::b64::charset::is_b64_url_safe_charset;
    use crate::b64::error::Error;
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

    // --- encode/decode roundtrip proptests ---

    proptest! {
        #[test]
        fn encode_decode_u32_roundtrip(v in 0u32..16_777_216) {
            use super::decode_to_int;
            let encoded = encode_int(v, NonZeroUsize::new(1).unwrap());
            let decoded: u32 = decode_to_int(&encoded).unwrap();
            prop_assert_eq!(v, decoded);
        }

        #[test]
        fn encode_decode_u64_roundtrip(v in 0u64..68_719_476_736) {
            use super::decode_to_int;
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

    #[rstest]
    #[case("A", 0)]
    #[case("B", 1)]
    #[case("b", 27)]
    #[case("Ab", 27)]
    #[case("BQ", 80)]
    #[case("__", 4095)]
    #[case("BAA", 4096)]
    #[case("Bd7", 6011)]
    #[case("____", 16_777_215)]
    fn base64_to_u32(#[case] b64: &str, #[case] output: u32) {
        let actual: u32 = decode_to_int(b64).unwrap();
        assert_eq!(actual, output);
    }

    #[rstest]
    #[case("A", 0)]
    #[case("B", 1)]
    #[case("b", 27)]
    #[case("Ab", 27)]
    #[case("BQ", 80)]
    fn base64_to_u8(#[case] b64: &str, #[case] output: u8) {
        let actual: u8 = decode_to_int(b64).unwrap();
        assert_eq!(actual, output);
    }

    #[rstest]
    #[case("A", 0)]
    #[case("B", 1)]
    #[case("b", 27)]
    #[case("Ab", 27)]
    #[case("BQ", 80)]
    fn base64_to_u16(#[case] b64: &str, #[case] output: u16) {
        let actual: u16 = decode_to_int(b64).unwrap();
        assert_eq!(actual, output);
    }

    #[rstest]
    #[case("__", 4095)]
    #[case("BAA", 4096)]
    #[case("Bd7", 6011)]
    #[case("____", 16_777_215)]
    fn base64_to_u64(#[case] b64: &str, #[case] output: u64) {
        let actual: u64 = decode_to_int(b64).unwrap();
        assert_eq!(actual, output);
    }

    #[rstest]
    #[case("__", 4095)]
    #[case("BAA", 4096)]
    #[case("Bd7", 6011)]
    #[case("____", 16_777_215)]
    fn base64_to_usize(#[case] b64: &str, #[case] output: usize) {
        let actual: usize = decode_to_int(b64).unwrap();
        assert_eq!(actual, output);
    }

    #[rstest]
    #[case("__")]
    #[case("BAA")]
    #[case("E_")]
    fn base64_to_u8_should_overflow(#[case] b64: &str) {
        let actual = decode_to_int::<_, u8>(b64);
        assert!(actual.is_err(), "Expected an overflow error, but got Ok");
        let err = actual.unwrap_err();
        assert!(
            matches!(err, Error::IntegerOverflow),
            "Expected Error::IntegerOverflow, but got {err:?}"
        );
    }

    // --- edge cases ---

    #[test]
    fn decode_empty_string_is_zero() {
        let result: u32 = decode_to_int("").unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn decode_single_a_is_zero() {
        let result: u32 = decode_to_int("A").unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn decode_rejects_invalid_char_plus() {
        let result = decode_to_int::<_, u32>("+");
        let err = result.unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('+'));
    }

    #[test]
    fn decode_rejects_space() {
        let result = decode_to_int::<_, u32>(" ");
        let err = result.unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char(' '));
    }

    #[test]
    fn decode_u16_overflow() {
        // "BAAA" = 1*64^3 = 262144 which overflows u16 (max 65535)
        let result = decode_to_int::<_, u16>("BAAA");
        let err = result.unwrap_err();
        assert_eq!(err, Error::IntegerOverflow);
    }

    #[test]
    fn decode_max_u8() {
        // D=3, _=63 -> 3*64 + 63 = 255 = u8::MAX
        let result: u8 = decode_to_int("D_").unwrap();
        assert_eq!(result, 255);
    }

    #[test]
    fn decode_just_over_u8_max() {
        // E=4, A=0 -> 4*64 + 0 = 256, overflows u8
        let result = decode_to_int::<_, u8>("EA");
        let err = result.unwrap_err();
        assert_eq!(err, Error::IntegerOverflow);
    }

    #[test]
    fn decode_max_u16() {
        // u16::MAX = 65535 = 15*64^2 + 63*64 + 63 = "P__"
        let result: u16 = decode_to_int("P__").unwrap();
        assert_eq!(result, 65535);
    }

    #[test]
    fn decode_rejects_slash() {
        let result = decode_to_int::<_, u32>("/");
        let err = result.unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('/'));
    }

    #[test]
    fn decode_rejects_equals() {
        let result = decode_to_int::<_, u32>("=");
        let err = result.unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('='));
    }

    #[test]
    fn decode_rejects_invalid_in_middle() {
        // Valid chars around an invalid one
        let result = decode_to_int::<_, u32>("A+B");
        let err = result.unwrap_err();
        assert_eq!(err, Error::InvalidBase64Char('+'));
    }
}
