use crate::error::ParseError;

/// Top-3-bit classification of CESR stream first byte (keripy `ColdCodex`).
///
/// The top 3 bits of the first byte in a CESR stream determine which
/// encoding domain is in use. This gives finer granularity than [`ColdCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tritet {
    /// 0b000 — Annotated CESR Base64
    AnB64 = 0,
    /// 0b001 — Counter code Base64
    CtB64 = 1,
    /// 0b010 — `OpCode` Base64
    OpB64 = 2,
    /// 0b011 — JSON map start
    Json = 3,
    /// 0b100 — `MessagePack` fixed map
    Mgpk1 = 4,
    /// 0b101 — CBOR map
    Cbor = 5,
    /// 0b110 — `MessagePack` big map
    Mgpk2 = 6,
    /// 0b111 — Counter/OpCode binary
    CtOpB2 = 7,
}

impl Tritet {
    /// Classify a CESR stream byte into its tritet category.
    ///
    /// Uses the top 3 bits (`byte >> 5`) to determine the encoding domain.
    /// This is the same classification used by keripy's `Coldage`.
    #[must_use]
    pub fn detect(byte: u8) -> Self {
        match byte >> 5 {
            0 => Self::AnB64,
            1 => Self::CtB64,
            2 => Self::OpB64,
            3 => Self::Json,
            4 => Self::Mgpk1,
            5 => Self::Cbor,
            6 => Self::Mgpk2,
            7 => Self::CtOpB2,
            _ => unreachable!(),
        }
    }
}

impl From<Tritet> for ColdCode {
    fn from(t: Tritet) -> Self {
        match t {
            Tritet::AnB64 | Tritet::CtB64 | Tritet::OpB64 => Self::CesrBase64,
            Tritet::Json => Self::Json,
            Tritet::Mgpk1 | Tritet::Mgpk2 => Self::MessagePack,
            Tritet::Cbor => Self::Cbor,
            Tritet::CtOpB2 => Self::CesrBinary,
        }
    }
}

/// Encoding format of a CESR stream detected from the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdCode {
    /// CESR Base64 text encoding (most common for KERI)
    CesrBase64,
    /// CESR native binary encoding
    CesrBinary,
    /// JSON (RFC 8259)
    Json,
    /// CBOR (RFC 7049)
    Cbor,
    /// `MessagePack`
    MessagePack,
}

impl ColdCode {
    /// Detect stream encoding from the first byte.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Malformed`] if the byte starts no known
    /// encoding domain.
    pub const fn detect(first_byte: u8) -> Result<Self, ParseError> {
        match first_byte {
            b'{' => Ok(Self::Json),
            0xa0..=0xbf => Ok(Self::Cbor),
            0x80..=0x8f | 0xde | 0xdf => Ok(Self::MessagePack),
            b if b & 0x80 != 0 => Ok(Self::CesrBinary),
            b if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' => Ok(Self::CesrBase64),
            _ => Err(ParseError::UnknownColdStart { byte: first_byte }),
        }
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

    #[test]
    fn detect_json() {
        assert_eq!(ColdCode::detect(b'{'), Ok(ColdCode::Json));
    }

    #[test]
    fn detect_cesr_base64_letters() {
        assert_eq!(ColdCode::detect(b'A'), Ok(ColdCode::CesrBase64));
        assert_eq!(ColdCode::detect(b'z'), Ok(ColdCode::CesrBase64));
        assert_eq!(ColdCode::detect(b'-'), Ok(ColdCode::CesrBase64));
        assert_eq!(ColdCode::detect(b'_'), Ok(ColdCode::CesrBase64));
    }

    #[test]
    fn detect_cesr_base64_digits() {
        assert_eq!(ColdCode::detect(b'0'), Ok(ColdCode::CesrBase64));
        assert_eq!(ColdCode::detect(b'9'), Ok(ColdCode::CesrBase64));
    }

    #[test]
    fn detect_cbor() {
        assert_eq!(ColdCode::detect(0xa0), Ok(ColdCode::Cbor));
        assert_eq!(ColdCode::detect(0xbf), Ok(ColdCode::Cbor));
    }

    #[test]
    fn detect_msgpack() {
        assert_eq!(ColdCode::detect(0x80), Ok(ColdCode::MessagePack));
        assert_eq!(ColdCode::detect(0x8f), Ok(ColdCode::MessagePack));
        assert_eq!(ColdCode::detect(0xde), Ok(ColdCode::MessagePack));
    }

    #[test]
    fn detect_cesr_binary() {
        assert_eq!(ColdCode::detect(0xC0), Ok(ColdCode::CesrBinary));
        assert_eq!(ColdCode::detect(0xFF), Ok(ColdCode::CesrBinary));
    }

    #[test]
    fn detect_unknown() {
        assert!(ColdCode::detect(0x00).is_err());
    }

    #[test]
    fn tritet_classification() {
        assert_eq!(Tritet::detect(b'-'), Tritet::CtB64); // 0x2D >> 5 = 1
        assert_eq!(Tritet::detect(b'{'), Tritet::Json); // 0x7B >> 5 = 3
        assert_eq!(Tritet::detect(0xE0), Tritet::CtOpB2); // 0xE0 >> 5 = 7
        assert_eq!(Tritet::detect(0x00), Tritet::AnB64); // 0x00 >> 5 = 0
        assert_eq!(Tritet::detect(0x80), Tritet::Mgpk1); // 0x80 >> 5 = 4
        assert_eq!(Tritet::detect(0xA0), Tritet::Cbor); // 0xA0 >> 5 = 5
        assert_eq!(Tritet::detect(0xC0), Tritet::Mgpk2); // 0xC0 >> 5 = 6
        assert_eq!(Tritet::detect(b'A'), Tritet::OpB64); // 0x41 >> 5 = 2
        assert_eq!(Tritet::detect(b'0'), Tritet::CtB64); // 0x30 >> 5 = 1
    }

    #[test]
    fn tritet_to_cold_code() {
        assert_eq!(ColdCode::from(Tritet::CtB64), ColdCode::CesrBase64);
        assert_eq!(ColdCode::from(Tritet::OpB64), ColdCode::CesrBase64);
        assert_eq!(ColdCode::from(Tritet::AnB64), ColdCode::CesrBase64);
        assert_eq!(ColdCode::from(Tritet::CtOpB2), ColdCode::CesrBinary);
        assert_eq!(ColdCode::from(Tritet::Json), ColdCode::Json);
        assert_eq!(ColdCode::from(Tritet::Mgpk1), ColdCode::MessagePack);
        assert_eq!(ColdCode::from(Tritet::Mgpk2), ColdCode::MessagePack);
        assert_eq!(ColdCode::from(Tritet::Cbor), ColdCode::Cbor);
    }

    #[test]
    fn tritet_all_bytes_covered() {
        for byte in 0u8..=255 {
            let tritet = Tritet::detect(byte);
            let _cold: ColdCode = tritet.into();
        }
    }

    #[test]
    fn detect_rejects_unknown_lead_byte() {
        // 0x7f: not JSON, not a CBOR/MsgPack head, high bit clear, and not
        // in the CESR text alphabet.
        assert_eq!(
            ColdCode::detect(0x7f).unwrap_err(),
            ParseError::UnknownColdStart { byte: 0x7f }
        );
    }
}
