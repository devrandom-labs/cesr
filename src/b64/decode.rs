use super::{alphabet::b64_char_to_index, error::Error};
use num_traits::{PrimInt, ops::checked::CheckedShl, sign::Unsigned};

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
mod test {
    use super::decode_to_int;
    use crate::b64::error::Error;
    use rstest::rstest;

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
