#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec::Vec,};
use super::cesr_code::CesrCode;
use super::sealed::Sealed;
use crate::core::matter::{
    MatterPart,
    error::{ParsingError, ValidationError},
    sizage::{Sizage, SizeType},
};
use crate::core::utils::{get_hard_size_from_byte, get_hard_size_from_sextet};
use crate::utils::encode_binary;
use core::{num::NonZeroUsize, str::FromStr};
use strum::{AsRefStr, Display, EnumIter, EnumString, IntoStaticStr, VariantNames};

/// Number of Base64 characters in the header of a small variable-size code (`4`, `5`, `6`).
pub const SMALL_VAR_HEADER_SIZE: u8 = 3;
/// Number of Base64 characters in the header of a large variable-size code (`7`, `8`, `9`).
pub const LARGE_VAR_HEADER_SIZE: u8 = 6;

const SMALL_VAR_SIZES: [char; 3] = ['4', '5', '6'];
const LARGE_VAR_SIZES: [char; 3] = ['7', '8', '9'];

/// All Matter CESR primitive codes as a single untyped enum.
///
/// Each variant maps to a unique Base64 code string via `#[strum(serialize = "...")]`.
/// For typed access to specific subsets use `DigestCode`, `VerKeyCode`, etc.
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Copy,
    Hash,
    AsRefStr,
    EnumString,
    IntoStaticStr,
    VariantNames,
    Display,
    EnumIter,
)]
#[allow(
    non_camel_case_types,
    reason = "CESR spec uses underscored code names like Blake3_256"
)]
pub enum MatterCode {
    /// Ed25519 256-bit random seed for a private key (`A`).
    #[strum(serialize = "A")]
    Ed25519Seed,
    /// Ed25519 verification key, non-transferable basic derivation (`B`).
    #[strum(serialize = "B")]
    Ed25519N,
    /// X25519 public encryption key, may be converted from `Ed25519` or `Ed25519N` (`C`).
    #[strum(serialize = "C")]
    X25519,
    /// Ed25519 verification key, basic derivation (`D`).
    #[strum(serialize = "D")]
    Ed25519,
    /// BLAKE3 256-bit digest, self-addressing derivation (`E`).
    #[strum(serialize = "E")]
    Blake3_256,
    /// `BLAKE2b` 256-bit digest, self-addressing derivation (`F`).
    #[strum(serialize = "F")]
    Blake2b_256,
    /// BLAKE2s 256-bit digest, self-addressing derivation (`G`).
    #[strum(serialize = "G")]
    Blake2s_256,
    /// SHA3-256 digest, self-addressing derivation (`H`).
    #[strum(serialize = "H")]
    SHA3_256,
    /// SHA2-256 digest, self-addressing derivation (`I`).
    #[strum(serialize = "I")]
    SHA2_256,
    /// ECDSA secp256k1 256-bit random seed for a private key (`J`).
    #[strum(serialize = "J")]
    ECDSA256k1Seed,
    /// Ed448 448-bit random seed for a private key (`K`).
    #[strum(serialize = "K")]
    Ed448Seed,
    /// X448 public encryption key, converted from Ed448 (`L`).
    #[strum(serialize = "L")]
    X448,
    /// Short 2-byte integer (`M`).
    #[strum(serialize = "M")]
    Short,
    /// Big 8-byte integer (`N`).
    #[strum(serialize = "N")]
    Big,
    /// X25519 private decryption key/seed, may be converted from Ed25519 (`O`).
    #[strum(serialize = "O")]
    X25519Private,
    /// X25519 sealed box 124-char qb64 cipher of a 44-char qb64 seed (`P`).
    #[strum(serialize = "P")]
    X25519CipherSeed,
    /// ECDSA secp256r1 256-bit random seed for a private key (`Q`).
    #[strum(serialize = "Q")]
    ECDSA256r1Seed,
    /// Tall 5-byte integer (`R`).
    #[strum(serialize = "R")]
    Tall,
    /// Large 11-byte integer (`S`).
    #[strum(serialize = "S")]
    Large,
    /// Great 14-byte integer (`T`).
    #[strum(serialize = "T")]
    Great,
    /// Vast 17-byte integer (`U`).
    #[strum(serialize = "U")]
    Vast,
    /// Label1: 1-byte label with lead size 1 (`V`).
    #[strum(serialize = "V")]
    Label1,
    /// Label2: 2-byte label with lead size 0 (`W`).
    #[strum(serialize = "W")]
    Label2,
    /// Tag3: 3 Base64-encoded chars for special values (`X`).
    #[strum(serialize = "X")]
    Tag3,
    /// Tag7: 7 Base64-encoded chars for special values (`Y`).
    #[strum(serialize = "Y")]
    Tag7,
    /// Tag11: 11 Base64-encoded chars for special values (`Z`).
    #[strum(serialize = "Z")]
    Tag11,
    /// Salt/seed/nonce/blind, 256 bits (`a`).
    #[strum(serialize = "a")]
    Salt256,
    /// Salt/seed/nonce, 128 bits, or "Huge" number (`0A`).
    #[strum(serialize = "0A")]
    Salt128,
    /// Ed25519 signature (`0B`).
    #[strum(serialize = "0B")]
    Ed25519Sig,
    /// ECDSA secp256k1 signature (`0C`).
    #[strum(serialize = "0C")]
    ECDSA256k1Sig,
    /// BLAKE3 512-bit digest, self-addressing derivation (`0D`).
    #[strum(serialize = "0D")]
    Blake3_512,
    /// `BLAKE2b` 512-bit digest, self-addressing derivation (`0E`).
    #[strum(serialize = "0E")]
    Blake2b_512,
    /// SHA3-512 digest, self-addressing derivation (`0F`).
    #[strum(serialize = "0F")]
    SHA3_512,
    /// SHA2-512 digest, self-addressing derivation (`0G`).
    #[strum(serialize = "0G")]
    SHA2_512,
    /// Long 4-byte integer (`0H`).
    #[strum(serialize = "0H")]
    Long,
    /// ECDSA secp256r1 signature (`0I`).
    #[strum(serialize = "0I")]
    ECDSA256r1Sig,
    /// Tag1: 1 Base64 char + 1 prepad for special values (`0J`).
    #[strum(serialize = "0J")]
    Tag1,
    /// Tag2: 2 Base64-encoded chars for special values (`0K`).
    #[strum(serialize = "0K")]
    Tag2,
    /// Tag5: 5 Base64-encoded chars + 1 prepad for special values (`0L`).
    #[strum(serialize = "0L")]
    Tag5,
    /// Tag6: 6 Base64-encoded chars for special values (`0M`).
    #[strum(serialize = "0M")]
    Tag6,
    /// Tag9: 9 Base64-encoded chars + 1 prepad for special values (`0N`).
    #[strum(serialize = "0N")]
    Tag9,
    /// Tag10: 10 Base64-encoded chars for special values (`0O`).
    #[strum(serialize = "0O")]
    Tag10,
    /// `GramHeadNeck`: 32 Base64 chars for a memogram head with neck (`0P`).
    #[strum(serialize = "0P")]
    GramHeadNeck,
    /// `GramHead`: 28 Base64 chars for a memogram head only (`0Q`).
    #[strum(serialize = "0Q")]
    GramHead,
    /// `GramHeadAIDNeck`: 76 Base64 chars for a memogram head with AID and neck (`0R`).
    #[strum(serialize = "0R")]
    GramHeadAIDNeck,
    /// `GramHeadAID`: 72 Base64 chars for a memogram head with AID only (`0S`).
    #[strum(serialize = "0S")]
    GramHeadAID,
    /// ECDSA secp256k1 verification key, non-transferable basic derivation (`1AAA`).
    #[strum(serialize = "1AAA")]
    ECDSA256k1N,
    /// ECDSA secp256k1 public verification or encryption key, basic derivation (`1AAB`).
    #[strum(serialize = "1AAB")]
    ECDSA256k1,
    /// Ed448 non-transferable public signing verification key, basic derivation (`1AAC`).
    #[strum(serialize = "1AAC")]
    Ed448N,
    /// Ed448 public signing verification key, basic derivation (`1AAD`).
    #[strum(serialize = "1AAD")]
    Ed448,
    /// Ed448 signature, self-signing derivation (`1AAE`).
    #[strum(serialize = "1AAE")]
    Ed448Sig,
    /// Tag4: 4 Base64-encoded chars for special values (`1AAF`).
    #[strum(serialize = "1AAF")]
    Tag4,
    /// Base64 custom-encoded 32-char ISO-8601 `DateTime` (`1AAG`).
    #[strum(serialize = "1AAG")]
    DateTime,
    /// X25519 sealed box 100-char qb64 cipher of a 24-char qb64 salt (`1AAH`).
    #[strum(serialize = "1AAH")]
    X25519CipherSalt,
    /// ECDSA secp256r1 verification key, non-transferable basic derivation (`1AAI`).
    #[strum(serialize = "1AAI")]
    ECDSA256r1N,
    /// ECDSA secp256r1 verification or encryption key, basic derivation (`1AAJ`).
    #[strum(serialize = "1AAJ")]
    ECDSA256r1,
    /// Null / None / empty value (`1AAK`).
    #[strum(serialize = "1AAK")]
    Null,
    /// Boolean false value (`1AAL`).
    #[strum(serialize = "1AAL")]
    No,
    /// Boolean true value (`1AAM`).
    #[strum(serialize = "1AAM")]
    Yes,
    /// Tag8: 8 Base64-encoded chars for special values (`1AAN`).
    #[strum(serialize = "1AAN")]
    Tag8,
    /// Escape code for escaping special map fields (`1AAO`).
    #[strum(serialize = "1AAO")]
    Escape,
    /// Empty value for Nonce, UUID, or related fields (`1AAP`).
    #[strum(serialize = "1AAP")]
    Empty,
    /// Testing only: fixed special values with non-empty raw, lead size 0 (`1__-`).
    #[strum(serialize = "1__-")]
    TBD0S,
    /// Testing only: fixed with lead size 0 (`1___`).
    #[strum(serialize = "1___")]
    TBD0,
    /// Testing only: fixed special values with non-empty raw, lead size 1 (`2__-`).
    #[strum(serialize = "2__-")]
    TBD1S,
    /// Testing only: fixed with lead size 1 (`2___`).
    #[strum(serialize = "2___")]
    TBD1,
    /// Testing only: fixed special values with non-empty raw, lead size 2 (`3__-`).
    #[strum(serialize = "3__-")]
    TBD2S,
    /// Testing only: fixed with lead size 2 (`3___`).
    #[strum(serialize = "3___")]
    TBD2,
    /// Variable-length Base64-only string, lead size 0 (`4A`).
    #[strum(serialize = "4A")]
    StrB64_L0,
    /// Variable-length Base64-only string, lead size 1 (`5A`).
    #[strum(serialize = "5A")]
    StrB64_L1,
    /// Variable-length Base64-only string, lead size 2 (`6A`).
    #[strum(serialize = "6A")]
    StrB64_L2,
    /// Variable-length Base64-only string (big), lead size 0 (`7AAA`).
    #[strum(serialize = "7AAA")]
    StrB64Big_L0,
    /// Variable-length Base64-only string (big), lead size 1 (`8AAA`).
    #[strum(serialize = "8AAA")]
    StrB64Big_L1,
    /// Variable-length Base64-only string (big), lead size 2 (`9AAA`).
    #[strum(serialize = "9AAA")]
    StrB64Big_L2,
    /// Variable-length byte string, lead size 0 (`4B`).
    #[strum(serialize = "4B")]
    Bytes_L0,
    /// Variable-length byte string, lead size 1 (`5B`).
    #[strum(serialize = "5B")]
    Bytes_L1,
    /// Variable-length byte string, lead size 2 (`6B`).
    #[strum(serialize = "6B")]
    Bytes_L2,
    /// Variable-length byte string (big), lead size 0 (`7AAB`).
    #[strum(serialize = "7AAB")]
    BytesBig_L0,
    /// Variable-length byte string (big), lead size 1 (`8AAB`).
    #[strum(serialize = "8AAB")]
    BytesBig_L1,
    /// Variable-length byte string (big), lead size 2 (`9AAB`).
    #[strum(serialize = "9AAB")]
    BytesBig_L2,
    /// X25519 sealed-box cipher of sniffable plaintext, lead size 0 (`4C`).
    #[strum(serialize = "4C")]
    X25519Cipher_L0,
    /// X25519 sealed-box cipher of sniffable plaintext, lead size 1 (`5C`).
    #[strum(serialize = "5C")]
    X25519Cipher_L1,
    /// X25519 sealed-box cipher of sniffable plaintext, lead size 2 (`6C`).
    #[strum(serialize = "6C")]
    X25519Cipher_L2,
    /// X25519 sealed-box cipher of sniffable plaintext (big), lead size 0 (`7AAC`).
    #[strum(serialize = "7AAC")]
    X25519CipherBig_L0,
    /// X25519 sealed-box cipher of sniffable plaintext (big), lead size 1 (`8AAC`).
    #[strum(serialize = "8AAC")]
    X25519CipherBig_L1,
    /// X25519 sealed-box cipher of sniffable plaintext (big), lead size 2 (`9AAC`).
    #[strum(serialize = "9AAC")]
    X25519CipherBig_L2,
    /// X25519 sealed-box cipher of qb64 plaintext, lead size 0 (`4D`).
    #[strum(serialize = "4D")]
    X25519CipherQB64_L0,
    /// X25519 sealed-box cipher of qb64 plaintext, lead size 1 (`5D`).
    #[strum(serialize = "5D")]
    X25519CipherQB64_L1,
    /// X25519 sealed-box cipher of qb64 plaintext, lead size 2 (`6D`).
    #[strum(serialize = "6D")]
    X25519CipherQB64_L2,
    /// X25519 sealed-box cipher of qb64 plaintext (big), lead size 0 (`7AAD`).
    #[strum(serialize = "7AAD")]
    X25519CipherQB64Big_L0,
    /// X25519 sealed-box cipher of qb64 plaintext (big), lead size 1 (`8AAD`).
    #[strum(serialize = "8AAD")]
    X25519CipherQB64Big_L1,
    /// X25519 sealed-box cipher of qb64 plaintext (big), lead size 2 (`9AAD`).
    #[strum(serialize = "9AAD")]
    X25519CipherQB64Big_L2,
    /// X25519 sealed-box cipher of qb2 plaintext, lead size 0 (`4E`).
    #[strum(serialize = "4E")]
    X25519CipherQB2_L0,
    /// X25519 sealed-box cipher of qb2 plaintext, lead size 1 (`5E`).
    #[strum(serialize = "5E")]
    X25519CipherQB2_L1,
    /// X25519 sealed-box cipher of qb2 plaintext, lead size 2 (`6E`).
    #[strum(serialize = "6E")]
    X25519CipherQB2_L2,
    /// X25519 sealed-box cipher of qb2 plaintext (big), lead size 0 (`7AAE`).
    #[strum(serialize = "7AAE")]
    X25519CipherQB2Big_L0,
    /// X25519 sealed-box cipher of qb2 plaintext (big), lead size 1 (`8AAE`).
    #[strum(serialize = "8AAE")]
    X25519CipherQB2Big_L1,
    /// X25519 sealed-box cipher of qb2 plaintext (big), lead size 2 (`9AAE`).
    #[strum(serialize = "9AAE")]
    X25519CipherQB2Big_L2,
    /// HPKE Base cipher of sniffable plaintext, lead size 0 (`4F`).
    #[strum(serialize = "4F")]
    HPKEBaseCipher_L0,
    /// HPKE Base cipher of sniffable plaintext, lead size 1 (`5F`).
    #[strum(serialize = "5F")]
    HPKEBaseCipher_L1,
    /// HPKE Base cipher of sniffable plaintext, lead size 2 (`6F`).
    #[strum(serialize = "6F")]
    HPKEBaseCipher_L2,
    /// HPKE Base cipher of sniffable plaintext (big), lead size 0 (`7AAF`).
    #[strum(serialize = "7AAF")]
    HPKEBaseCipherBig_L0,
    /// HPKE Base cipher of sniffable plaintext (big), lead size 1 (`8AAF`).
    #[strum(serialize = "8AAF")]
    HPKEBaseCipherBig_L1,
    /// HPKE Base cipher of sniffable plaintext (big), lead size 2 (`9AAF`).
    #[strum(serialize = "9AAF")]
    HPKEBaseCipherBig_L2,
    /// Decimal Base64 float/int string, lead size 0 (`4H`).
    #[strum(serialize = "4H")]
    Decimal_L0,
    /// Decimal Base64 float/int string, lead size 1 (`5H`).
    #[strum(serialize = "5H")]
    Decimal_L1,
    /// Decimal Base64 float/int string, lead size 2 (`6H`).
    #[strum(serialize = "6H")]
    Decimal_L2,
    /// Decimal Base64 float/int string (big), lead size 0 (`7AAH`).
    #[strum(serialize = "7AAH")]
    DecimalBig_L0,
    /// Decimal Base64 float/int string (big), lead size 1 (`8AAH`).
    #[strum(serialize = "8AAH")]
    DecimalBig_L1,
    /// Decimal Base64 float/int string (big), lead size 2 (`9AAH`).
    #[strum(serialize = "9AAH")]
    DecimalBig_L2,
}

impl MatterCode {
    /// Parses a `MatterCode` from a Base64-encoded byte stream.
    ///
    /// # Errors
    ///
    /// Returns `ParsingError` if the stream is empty, too short, contains
    /// invalid UTF-8, or does not match a known matter code.
    pub fn from_base64_stream(stream: &[u8]) -> Result<Self, ParsingError> {
        let hs: usize = stream
            .first()
            .ok_or(ParsingError::EmptyStream)
            .and_then(|b| {
                get_hard_size_from_byte(*b).ok_or_else(|| ParsingError::MalformedCode {
                    part: MatterPart::Head,
                    found: b.to_string(),
                })
            })?
            .into();
        if stream.len() < hs {
            return Err(ParsingError::StreamTooShort(MatterPart::Head));
        }
        let code_str = str::from_utf8(&stream[..hs]).map_err(ParsingError::InvalidUtf8)?;
        let code = Self::from_str(code_str)
            .map_err(|_| ParsingError::UnknownMatterCode(code_str.to_owned()))?;
        Ok(code)
    }

    /// Parses a `MatterCode` from a binary (qb2) byte stream.
    ///
    /// # Errors
    ///
    /// Returns `ParsingError` if the stream is empty, too short, or does
    /// not match a known matter code.
    pub fn from_stream(stream: &[u8]) -> Result<Self, ParsingError> {
        let hard_size: usize = stream
            .first()
            .ok_or(ParsingError::EmptyStream)
            .map(|b| b >> 2)
            .and_then(|b| {
                get_hard_size_from_sextet(b).ok_or_else(|| ParsingError::MalformedCode {
                    part: MatterPart::Head,
                    found: b.to_string(),
                })
            })?
            .into();

        let hard_size_nz = NonZeroUsize::new(hard_size).ok_or(ParsingError::EmptyStream)?;
        let bhs = (hard_size_nz.get() * 3).div_ceil(4);
        if stream.len() < bhs {
            return Err(ParsingError::StreamTooShort(MatterPart::Head));
        }
        let code_str = encode_binary(stream, hard_size_nz).map_err(ParsingError::Conversion)?;
        let code = Self::from_str(&code_str)
            .map_err(|_| ParsingError::UnknownMatterCode(code_str.clone()))?;
        Ok(code)
    }

    /// `BextCodex` is codex of all variable sized Base64 Text (Bext) derivation codes.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    #[must_use]
    pub const fn is_base64_text_code(&self) -> bool {
        matches!(
            self,
            Self::StrB64_L0
                | Self::StrB64_L1
                | Self::StrB64_L2
                | Self::StrB64Big_L0
                | Self::StrB64Big_L1
                | Self::StrB64Big_L2
        )
    }

    /// `TextCodex` is codex of all variable sized byte string (Text) derivation codes.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    #[must_use]
    pub const fn is_text_code(&self) -> bool {
        matches!(
            self,
            Self::Bytes_L0
                | Self::Bytes_L1
                | Self::Bytes_L2
                | Self::BytesBig_L0
                | Self::BytesBig_L1
                | Self::BytesBig_L2
        )
    }

    /// `DecimalCodex` is codex of all variable sized Base64 String representation
    /// of decimal numbers both signed and unsigned, float and int.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    #[must_use]
    pub const fn is_base_64_decimal(&self) -> bool {
        matches!(
            self,
            Self::Decimal_L0
                | Self::Decimal_L1
                | Self::Decimal_L2
                | Self::DecimalBig_L0
                | Self::DecimalBig_L1
                | Self::DecimalBig_L2
        )
    }

    /// `DigCodex` is codex all digest derivation codes. This is needed to ensure
    /// delegated inception using a self-addressing derivation i.e. digest derivation
    /// code.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    #[must_use]
    pub const fn is_digest(&self) -> bool {
        matches!(
            self,
            Self::Blake3_256
                | Self::Blake2b_256
                | Self::Blake2s_256
                | Self::SHA3_256
                | Self::SHA2_256
                | Self::Blake3_512
                | Self::Blake2b_512
                | Self::SHA3_512
                | Self::SHA2_512
        )
    }

    /// `NonceCodex` is codex all derivation codes for  salty nonces (UUIDs) either
    /// as random numbers or as digests deterministically derived from salty nonces.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_nonce(&self) -> bool {
        matches!(
            self,
            Self::Empty
                | Self::Salt128
                | Self::Salt256
                | Self::Blake3_256
                | Self::Blake2b_256
                | Self::Blake2s_256
                | Self::SHA3_256
                | Self::SHA2_256
                | Self::Blake3_512
                | Self::Blake2b_512
                | Self::SHA3_512
                | Self::SHA2_512
        )
    }

    /// `NumCodex` is codex of Base64 derivation codes for compactly representing
    /// numbers across a wide rage of sizes.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_base64_num(&self) -> bool {
        matches!(
            self,
            Self::Short
                | Self::Long
                | Self::Tall
                | Self::Big
                | Self::Large
                | Self::Great
                | Self::Vast
                | Self::Salt128 // this is Huge in keripy :/
        )
    }

    /// `TagCodex` is codex of Base64 derivation codes for compactly representing
    /// various small Base64 tag values as special code soft part values.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_base64_tag(&self) -> bool {
        matches!(
            self,
            Self::Tag1
                | Self::Tag2
                | Self::Tag3
                | Self::Tag4
                | Self::Tag5
                | Self::Tag6
                | Self::Tag7
                | Self::Tag8
                | Self::Tag9
                | Self::Tag10
                | Self::Tag11
        )
    }

    /// `LabelCodex` is codex of codes to compactly ser/des labels and string values
    /// in maps or lists.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_label(&self) -> bool {
        matches!(
            self,
            Self::Empty
                | Self::Tag1
                | Self::Tag2
                | Self::Tag3
                | Self::Tag4
                | Self::Tag5
                | Self::Tag6
                | Self::Tag7
                | Self::Tag8
                | Self::Tag9
                | Self::Tag10
                | Self::Tag11
                | Self::StrB64_L0
                | Self::StrB64_L1
                | Self::StrB64_L2
                | Self::StrB64Big_L0
                | Self::StrB64Big_L1
                | Self::StrB64Big_L2
                | Self::Label1
                | Self::Label2
                | Self::Bytes_L0
                | Self::Bytes_L1
                | Self::Bytes_L2
                | Self::BytesBig_L0
                | Self::BytesBig_L1
                | Self::BytesBig_L2
        )
    }

    /// `PreCodex` is codex all identifier prefix derivation codes.
    /// This is needed to verify valid inception events.
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_prefix_derivation(&self) -> bool {
        matches!(
            self,
            Self::Ed25519N
                | Self::Ed25519
                | Self::Blake3_256
                | Self::Blake2b_256
                | Self::Blake2s_256
                | Self::SHA3_256
                | Self::SHA2_256
                | Self::Blake3_512
                | Self::Blake2b_512
                | Self::SHA3_512
                | Self::SHA2_512
                | Self::ECDSA256k1N
                | Self::ECDSA256k1
                | Self::Ed448N
                | Self::Ed448
                | Self::Ed448Sig
                | Self::ECDSA256r1N
                | Self::ECDSA256r1
        )
    }

    /// `NonTransCodex` is codex all non-transferable derivation codes
    ///Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_non_transferable(&self) -> bool {
        matches!(
            self,
            Self::Ed25519N | Self::ECDSA256k1N | Self::Ed448N | Self::ECDSA256r1N
        )
    }

    /// `PreNonDigCodex` is codex all prefixive but non-digestive derivation codes
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via "in" operator works.
    #[must_use]
    pub const fn is_prefix_non_digestive(&self) -> bool {
        matches!(
            self,
            Self::Ed25519N
                | Self::Ed25519
                | Self::ECDSA256k1N
                | Self::ECDSA256k1
                | Self::Ed448N
                | Self::Ed448
                | Self::ECDSA256r1N
                | Self::ECDSA256r1
        )
    }

    /// Returns the `Sizage` descriptor for this code.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "exhaustive lookup table over 110 CESR code variants"
    )]
    pub const fn get_sizage(&self) -> Sizage {
        match self {
            Self::Ed25519Seed
            | Self::Ed25519N
            | Self::X25519
            | Self::Ed25519
            | Self::Blake3_256
            | Self::Blake2b_256
            | Self::Blake2s_256
            | Self::SHA3_256
            | Self::SHA2_256
            | Self::ECDSA256k1Seed
            | Self::X25519Private
            | Self::ECDSA256r1Seed
            | Self::Salt256 => Sizage::new(1, 0, 0, SizeType::Fixed(44), 0),
            Self::Ed448Seed | Self::X448 => Sizage::new(1, 0, 0, SizeType::Fixed(76), 0),
            Self::Short | Self::Label2 => Sizage::new(1, 0, 0, SizeType::Fixed(4), 0),
            Self::Big => Sizage::new(1, 0, 0, SizeType::Fixed(12), 0),
            Self::X25519CipherSeed => Sizage::new(1, 0, 0, SizeType::Fixed(124), 0),
            Self::Tall => Sizage::new(1, 0, 0, SizeType::Fixed(8), 0),
            Self::Large => Sizage::new(1, 0, 0, SizeType::Fixed(16), 0),
            Self::Great => Sizage::new(1, 0, 0, SizeType::Fixed(20), 0),
            Self::Vast => Sizage::new(1, 0, 0, SizeType::Fixed(24), 0),
            Self::Label1 => Sizage::new(1, 0, 0, SizeType::Fixed(4), 1),
            Self::Tag3 => Sizage::new(1, 3, 0, SizeType::Fixed(4), 0),
            Self::Tag7 => Sizage::new(1, 7, 0, SizeType::Fixed(8), 0),
            Self::Tag11 => Sizage::new(1, 11, 0, SizeType::Fixed(12), 0),
            Self::Salt128 => Sizage::new(2, 0, 0, SizeType::Fixed(24), 0),
            Self::Ed25519Sig
            | Self::ECDSA256k1Sig
            | Self::Blake3_512
            | Self::Blake2b_512
            | Self::SHA3_512
            | Self::SHA2_512
            | Self::ECDSA256r1Sig => Sizage::new(2, 0, 0, SizeType::Fixed(88), 0),
            Self::Long => Sizage::new(2, 0, 0, SizeType::Fixed(8), 0),
            Self::Tag1 => Sizage::new(2, 2, 1, SizeType::Fixed(4), 0),
            Self::Tag2 => Sizage::new(2, 2, 0, SizeType::Fixed(4), 0),
            Self::Tag5 => Sizage::new(2, 6, 1, SizeType::Fixed(8), 0),
            Self::Tag6 => Sizage::new(2, 6, 0, SizeType::Fixed(8), 0),
            Self::Tag9 => Sizage::new(2, 10, 1, SizeType::Fixed(12), 0),
            Self::Tag10 => Sizage::new(2, 10, 0, SizeType::Fixed(12), 0),
            Self::GramHeadNeck => Sizage::new(2, 22, 0, SizeType::Fixed(32), 0),
            Self::GramHead => Sizage::new(2, 22, 0, SizeType::Fixed(28), 0),
            Self::GramHeadAIDNeck => Sizage::new(2, 22, 0, SizeType::Fixed(76), 0),
            Self::GramHeadAID => Sizage::new(2, 22, 0, SizeType::Fixed(72), 0),
            Self::ECDSA256k1N | Self::ECDSA256k1 | Self::ECDSA256r1N | Self::ECDSA256r1 => {
                Sizage::new(4, 0, 0, SizeType::Fixed(48), 0)
            }
            Self::Ed448N | Self::Ed448 => Sizage::new(4, 0, 0, SizeType::Fixed(80), 0),
            Self::Ed448Sig => Sizage::new(4, 0, 0, SizeType::Fixed(156), 0),
            Self::Tag4 => Sizage::new(4, 4, 0, SizeType::Fixed(8), 0),
            Self::DateTime => Sizage::new(4, 0, 0, SizeType::Fixed(36), 0),
            Self::X25519CipherSalt => Sizage::new(4, 0, 0, SizeType::Fixed(100), 0),
            Self::Null | Self::No | Self::Yes | Self::Escape | Self::Empty => {
                Sizage::new(4, 0, 0, SizeType::Fixed(4), 0)
            }
            Self::Tag8 => Sizage::new(4, 8, 0, SizeType::Fixed(12), 0),
            Self::TBD0S => Sizage::new(4, 2, 0, SizeType::Fixed(12), 0),
            Self::TBD0 => Sizage::new(4, 0, 0, SizeType::Fixed(8), 0),
            Self::TBD1S => Sizage::new(4, 2, 1, SizeType::Fixed(12), 1),
            Self::TBD1 => Sizage::new(4, 0, 0, SizeType::Fixed(8), 1),
            Self::TBD2S => Sizage::new(4, 2, 0, SizeType::Fixed(12), 2),
            Self::TBD2 => Sizage::new(4, 0, 0, SizeType::Fixed(8), 2),
            Self::StrB64_L0
            | Self::Bytes_L0
            | Self::X25519Cipher_L0
            | Self::X25519CipherQB64_L0
            | Self::X25519CipherQB2_L0
            | Self::HPKEBaseCipher_L0
            | Self::Decimal_L0 => Sizage::new(2, 2, 0, SizeType::Small, 0),
            Self::StrB64_L1
            | Self::Bytes_L1
            | Self::X25519Cipher_L1
            | Self::X25519CipherQB64_L1
            | Self::X25519CipherQB2_L1
            | Self::HPKEBaseCipher_L1
            | Self::Decimal_L1 => Sizage::new(2, 2, 0, SizeType::Small, 1),
            Self::StrB64_L2
            | Self::Bytes_L2
            | Self::X25519Cipher_L2
            | Self::X25519CipherQB64_L2
            | Self::X25519CipherQB2_L2
            | Self::HPKEBaseCipher_L2
            | Self::Decimal_L2 => Sizage::new(2, 2, 0, SizeType::Small, 2),
            Self::StrB64Big_L0
            | Self::BytesBig_L0
            | Self::X25519CipherBig_L0
            | Self::X25519CipherQB64Big_L0
            | Self::X25519CipherQB2Big_L0
            | Self::HPKEBaseCipherBig_L0
            | Self::DecimalBig_L0 => Sizage::new(4, 4, 0, SizeType::Large, 0),
            Self::StrB64Big_L1
            | Self::BytesBig_L1
            | Self::X25519CipherBig_L1
            | Self::X25519CipherQB64Big_L1
            | Self::X25519CipherQB2Big_L1
            | Self::HPKEBaseCipherBig_L1
            | Self::DecimalBig_L1 => Sizage::new(4, 4, 0, SizeType::Large, 1),
            Self::StrB64Big_L2
            | Self::BytesBig_L2
            | Self::X25519CipherBig_L2
            | Self::X25519CipherQB64Big_L2
            | Self::X25519CipherQB2Big_L2
            | Self::HPKEBaseCipherBig_L2
            | Self::DecimalBig_L2 => Sizage::new(4, 4, 0, SizeType::Large, 2),
        }
    }

    /// Promotes this variable-size code to the appropriate variant for the given size and lead.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the code cannot be promoted (e.g. fixed-size code,
    /// size exceeds capacity, or invalid lead).
    pub fn promote(&self, size: usize, lead: usize) -> Result<Self, ValidationError> {
        match self.get_sizage().fs() {
            SizeType::Small if size < 64_usize.pow(2) => {
                promote_same_size(*self, &SMALL_VAR_SIZES, lead, 2)
            }
            SizeType::Small if size < 64_usize.pow(4) => {
                promote_small_to_large(*self, &LARGE_VAR_SIZES, lead, 4)
            }
            SizeType::Large if size < (64_usize.pow(4) - 1) => {
                promote_same_size(*self, &LARGE_VAR_SIZES, lead, 4)
            }
            _ => Err(ValidationError::IncompatiblePromotion(self.to_string())),
        }
    }

    /// Returns raw size in bytes not including leader for a given code.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidSizingOperation` if the code is variable-size.
    pub fn raw_size(&self) -> Result<usize, ValidationError> {
        let Sizage { hs, ss, fs, ls, .. } = self.get_sizage();
        if let SizeType::Fixed(v) = fs {
            let code_size = usize::from(hs) + usize::from(ss);
            let raw_size = ((usize::from(v) - code_size) * 3 / 4) - usize::from(ls);
            return Ok(raw_size);
        }
        Err(ValidationError::InvalidSizingOperation(self.to_string()))
    }

    /// Returns `true` if this code is a special fixed-size code with soft data.
    #[must_use]
    pub const fn is_special(&self) -> bool {
        let Sizage { fs, ss, .. } = self.get_sizage();
        matches!(fs, SizeType::Fixed(_)) && ss > 0
    }
}

// does the actual promotion of the code
fn promote_same_size(
    matter_code: MatterCode,
    code_map: &[char],
    lead: usize,
    hs: usize,
) -> Result<MatterCode, ValidationError> {
    let s = code_map
        .get(lead)
        .ok_or_else(|| ValidationError::InvalidPromotionTarget {
            code: matter_code.to_string(),
            lead,
        })?;
    let code_str: &str = matter_code.as_ref();
    let code = format!("{s}{}", &code_str[1..hs]);
    MatterCode::try_from(code.as_str()).map_err(|_| ValidationError::InvalidPromotionResult {
        from: code_str.to_owned(),
        to: code,
    })
}

fn promote_small_to_large(
    matter_code: MatterCode,
    code_map: &[char],
    lead: usize,
    hs: usize,
) -> Result<MatterCode, ValidationError> {
    let s = code_map
        .get(lead)
        .ok_or_else(|| ValidationError::InvalidPromotionTarget {
            code: matter_code.to_string(),
            lead,
        })?;
    let code_str: &str = matter_code.as_ref();
    let code = format!("{s}{}{}", &"AAAA"[0..hs - 2], &code_str[1..2]);
    MatterCode::try_from(code.as_str()).map_err(|_| ValidationError::InvalidPromotionResult {
        from: code_str.to_owned(),
        to: code,
    })
}

impl Sealed for MatterCode {}

impl CesrCode for MatterCode {
    fn to_matter_code(&self) -> MatterCode {
        *self
    }

    fn as_str(&self) -> &'static str {
        self.into() // uses IntoStaticStr from strum
    }

    // get_sizage and raw_size use default impls which delegate to to_matter_code()
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::too_many_arguments,
    reason = "tests use panic for assertions; rstest parameterized tests exceed argument limit"
)]
mod tests {
    use super::*;
    use rstest::rstest;
    use core::str::FromStr;
    use strum::{IntoEnumIterator, ParseError};

    macro_rules! with_payload {
        ($bytes:expr) => {{
            const PAYLOAD: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
            let mut vec = Vec::from($bytes);
            vec.extend_from_slice(PAYLOAD);
            vec
        }};
    }

    #[test]
    fn test_codex_string_roundtrip() {
        for variant in MatterCode::iter() {
            let code_str: &'static str = variant.into();
            let code_string = variant.to_string();
            assert_eq!(code_str, code_string);

            // Test EnumString (FromStr)
            let parsed_variant = MatterCode::from_str(code_str).unwrap();
            assert_eq!(variant, parsed_variant);

            // Test AsRefStr
            let code_as_ref: &str = variant.as_ref();
            assert_eq!(code_str, code_as_ref);
        }
    }

    #[test]
    fn test_invalid_code_parsing() {
        let result = MatterCode::from_str("!NOT_A_CODE!");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::VariantNotFound);
    }

    #[test]
    fn spot_check_codes() {
        assert_eq!(MatterCode::Ed25519N.as_ref(), "B");
    }

    #[rstest]
    #[case("A_payload", Ok(MatterCode::Ed25519Seed))]
    #[case("B_payload", Ok(MatterCode::Ed25519N))]
    #[case("C_payload", Ok(MatterCode::X25519))]
    #[case("D_payload", Ok(MatterCode::Ed25519))]
    #[case("E_payload", Ok(MatterCode::Blake3_256))]
    #[case("F_payload", Ok(MatterCode::Blake2b_256))]
    #[case("G_payload", Ok(MatterCode::Blake2s_256))]
    #[case("H_payload", Ok(MatterCode::SHA3_256))]
    #[case("I_payload", Ok(MatterCode::SHA2_256))]
    #[case("J_payload", Ok(MatterCode::ECDSA256k1Seed))]
    #[case("K_payload", Ok(MatterCode::Ed448Seed))]
    #[case("L_payload", Ok(MatterCode::X448))]
    #[case("M_payload", Ok(MatterCode::Short))]
    #[case("N_payload", Ok(MatterCode::Big))]
    #[case("O_payload", Ok(MatterCode::X25519Private))]
    #[case("P_payload", Ok(MatterCode::X25519CipherSeed))]
    #[case("Q_payload", Ok(MatterCode::ECDSA256r1Seed))]
    #[case("R_payload", Ok(MatterCode::Tall))]
    #[case("S_payload", Ok(MatterCode::Large))]
    #[case("T_payload", Ok(MatterCode::Great))]
    #[case("U_payload", Ok(MatterCode::Vast))]
    #[case("V_payload", Ok(MatterCode::Label1))]
    #[case("W_payload", Ok(MatterCode::Label2))]
    #[case("X_payload", Ok(MatterCode::Tag3))]
    #[case("Y_payload", Ok(MatterCode::Tag7))]
    #[case("Z_payload", Ok(MatterCode::Tag11))]
    #[case("a_payload", Ok(MatterCode::Salt256))]
    #[case("0A_payload", Ok(MatterCode::Salt128))]
    #[case("0B_payload", Ok(MatterCode::Ed25519Sig))]
    #[case("0C_payload", Ok(MatterCode::ECDSA256k1Sig))]
    #[case("0D_payload", Ok(MatterCode::Blake3_512))]
    #[case("0E_payload", Ok(MatterCode::Blake2b_512))]
    #[case("0F_payload", Ok(MatterCode::SHA3_512))]
    #[case("0G_payload", Ok(MatterCode::SHA2_512))]
    #[case("0H_payload", Ok(MatterCode::Long))]
    #[case("0I_payload", Ok(MatterCode::ECDSA256r1Sig))]
    #[case("0J_payload", Ok(MatterCode::Tag1))]
    #[case("0K_payload", Ok(MatterCode::Tag2))]
    #[case("0L_payload", Ok(MatterCode::Tag5))]
    #[case("0M_payload", Ok(MatterCode::Tag6))]
    #[case("0N_payload", Ok(MatterCode::Tag9))]
    #[case("0O_payload", Ok(MatterCode::Tag10))]
    #[case("0P_payload", Ok(MatterCode::GramHeadNeck))]
    #[case("0Q_payload", Ok(MatterCode::GramHead))]
    #[case("0R_payload", Ok(MatterCode::GramHeadAIDNeck))]
    #[case("0S_payload", Ok(MatterCode::GramHeadAID))]
    #[case("1AAA_payload", Ok(MatterCode::ECDSA256k1N))]
    #[case("1AAB_payload", Ok(MatterCode::ECDSA256k1))]
    #[case("1AAC_payload", Ok(MatterCode::Ed448N))]
    #[case("1AAD_payload", Ok(MatterCode::Ed448))]
    #[case("1AAE_payload", Ok(MatterCode::Ed448Sig))]
    #[case("1AAF_payload", Ok(MatterCode::Tag4))]
    #[case("1AAG_payload", Ok(MatterCode::DateTime))]
    #[case("1AAH_payload", Ok(MatterCode::X25519CipherSalt))]
    #[case("1AAI_payload", Ok(MatterCode::ECDSA256r1N))]
    #[case("1AAJ_payload", Ok(MatterCode::ECDSA256r1))]
    #[case("1AAK_payload", Ok(MatterCode::Null))]
    #[case("1AAL_payload", Ok(MatterCode::No))]
    #[case("1AAM_payload", Ok(MatterCode::Yes))]
    #[case("1AAN_payload", Ok(MatterCode::Tag8))]
    #[case("1AAO_payload", Ok(MatterCode::Escape))]
    #[case("1AAP_payload", Ok(MatterCode::Empty))]
    #[case("1__-_payload", Ok(MatterCode::TBD0S))]
    #[case("1____payload", Ok(MatterCode::TBD0))]
    #[case("2__-_payload", Ok(MatterCode::TBD1S))]
    #[case("2____payload", Ok(MatterCode::TBD1))]
    #[case("3__-_payload", Ok(MatterCode::TBD2S))]
    #[case("3____payload", Ok(MatterCode::TBD2))]
    #[case("4A_payload", Ok(MatterCode::StrB64_L0))]
    #[case("5A_payload", Ok(MatterCode::StrB64_L1))]
    #[case("6A_payload", Ok(MatterCode::StrB64_L2))]
    #[case("7AAA_payload", Ok(MatterCode::StrB64Big_L0))]
    #[case("8AAA_payload", Ok(MatterCode::StrB64Big_L1))]
    #[case("9AAA_payload", Ok(MatterCode::StrB64Big_L2))]
    #[case("4B_payload", Ok(MatterCode::Bytes_L0))]
    #[case("5B_payload", Ok(MatterCode::Bytes_L1))]
    #[case("6B_payload", Ok(MatterCode::Bytes_L2))]
    #[case("7AAB_payload", Ok(MatterCode::BytesBig_L0))]
    #[case("8AAB_payload", Ok(MatterCode::BytesBig_L1))]
    #[case("9AAB_payload", Ok(MatterCode::BytesBig_L2))]
    #[case("4C_payload", Ok(MatterCode::X25519Cipher_L0))]
    #[case("5C_payload", Ok(MatterCode::X25519Cipher_L1))]
    #[case("6C_payload", Ok(MatterCode::X25519Cipher_L2))]
    #[case("7AAC_payload", Ok(MatterCode::X25519CipherBig_L0))]
    #[case("8AAC_payload", Ok(MatterCode::X25519CipherBig_L1))]
    #[case("9AAC_payload", Ok(MatterCode::X25519CipherBig_L2))]
    #[case("4D_payload", Ok(MatterCode::X25519CipherQB64_L0))]
    #[case("5D_payload", Ok(MatterCode::X25519CipherQB64_L1))]
    #[case("6D_payload", Ok(MatterCode::X25519CipherQB64_L2))]
    #[case("7AAD_payload", Ok(MatterCode::X25519CipherQB64Big_L0))]
    #[case("8AAD_payload", Ok(MatterCode::X25519CipherQB64Big_L1))]
    #[case("9AAD_payload", Ok(MatterCode::X25519CipherQB64Big_L2))]
    #[case("4E_payload", Ok(MatterCode::X25519CipherQB2_L0))]
    #[case("5E_payload", Ok(MatterCode::X25519CipherQB2_L1))]
    #[case("6E_payload", Ok(MatterCode::X25519CipherQB2_L2))]
    #[case("7AAE_payload", Ok(MatterCode::X25519CipherQB2Big_L0))]
    #[case("8AAE_payload", Ok(MatterCode::X25519CipherQB2Big_L1))]
    #[case("9AAE_payload", Ok(MatterCode::X25519CipherQB2Big_L2))]
    #[case("4F_payload", Ok(MatterCode::HPKEBaseCipher_L0))]
    #[case("5F_payload", Ok(MatterCode::HPKEBaseCipher_L1))]
    #[case("6F_payload", Ok(MatterCode::HPKEBaseCipher_L2))]
    #[case("7AAF_payload", Ok(MatterCode::HPKEBaseCipherBig_L0))]
    #[case("8AAF_payload", Ok(MatterCode::HPKEBaseCipherBig_L1))]
    #[case("9AAF_payload", Ok(MatterCode::HPKEBaseCipherBig_L2))]
    #[case("4H_payload", Ok(MatterCode::Decimal_L0))]
    #[case("5H_payload", Ok(MatterCode::Decimal_L1))]
    #[case("6H_payload", Ok(MatterCode::Decimal_L2))]
    #[case("7AAH_payload", Ok(MatterCode::DecimalBig_L0))]
    #[case("8AAH_payload", Ok(MatterCode::DecimalBig_L1))]
    #[case("9AAH_payload", Ok(MatterCode::DecimalBig_L2))]
    fn test_from_base64_stream_valid(
        #[case] input: &str,
        #[case] expected: Result<MatterCode, ParsingError>,
    ) {
        assert_eq!(
            MatterCode::from_base64_stream(input.as_bytes()).unwrap(),
            expected.unwrap()
        );
    }

    #[rstest]
    // 1-char codes (1 byte)
    #[case(with_payload!(&[0x00]), Ok(MatterCode::Ed25519Seed))]
    #[case(with_payload!(&[0x04]), Ok(MatterCode::Ed25519N))]
    #[case(with_payload!(&[0x08]), Ok(MatterCode::X25519))]
    #[case(with_payload!(&[0x0C]), Ok(MatterCode::Ed25519))]
    #[case(with_payload!(&[0x10]), Ok(MatterCode::Blake3_256))]
    #[case(with_payload!(&[0x14]), Ok(MatterCode::Blake2b_256))]
    #[case(with_payload!(&[0x18]), Ok(MatterCode::Blake2s_256))]
    #[case(with_payload!(&[0x1C]), Ok(MatterCode::SHA3_256))]
    #[case(with_payload!(&[0x20]), Ok(MatterCode::SHA2_256))]
    #[case(with_payload!(&[0x24]), Ok(MatterCode::ECDSA256k1Seed))]
    #[case(with_payload!(&[0x28]), Ok(MatterCode::Ed448Seed))]
    #[case(with_payload!(&[0x2C]), Ok(MatterCode::X448))]
    #[case(with_payload!(&[0x30]), Ok(MatterCode::Short))]
    #[case(with_payload!(&[0x34]), Ok(MatterCode::Big))]
    #[case(with_payload!(&[0x38]), Ok(MatterCode::X25519Private))]
    #[case(with_payload!(&[0x3C]), Ok(MatterCode::X25519CipherSeed))]
    #[case(with_payload!(&[0x40]), Ok(MatterCode::ECDSA256r1Seed))]
    #[case(with_payload!(&[0x44]), Ok(MatterCode::Tall))]
    #[case(with_payload!(&[0x48]), Ok(MatterCode::Large))]
    #[case(with_payload!(&[0x4C]), Ok(MatterCode::Great))]
    #[case(with_payload!(&[0x50]), Ok(MatterCode::Vast))]
    #[case(with_payload!(&[0x54]), Ok(MatterCode::Label1))]
    #[case(with_payload!(&[0x58]), Ok(MatterCode::Label2))]
    #[case(with_payload!(&[0x5C]), Ok(MatterCode::Tag3))]
    #[case(with_payload!(&[0x60]), Ok(MatterCode::Tag7))]
    #[case(with_payload!(&[0x64]), Ok(MatterCode::Tag11))]
    #[case(with_payload!(&[0x68]), Ok(MatterCode::Salt256))]
    // 2-char codes (2 bytes)
    #[case(with_payload!(&[0xD0, 0x08]), Ok(MatterCode::Salt128))]
    #[case(with_payload!(&[0xD0, 0x1F]), Ok(MatterCode::Ed25519Sig))]
    #[case(with_payload!(&[0xD0, 0x20]), Ok(MatterCode::ECDSA256k1Sig))]
    #[case(with_payload!(&[0xD0, 0x30]), Ok(MatterCode::Blake3_512))]
    #[case(with_payload!(&[0xD0, 0x40]), Ok(MatterCode::Blake2b_512))]
    #[case(with_payload!(&[0xD0, 0x50]), Ok(MatterCode::SHA3_512))]
    #[case(with_payload!(&[0xD0, 0x60]), Ok(MatterCode::SHA2_512))]
    #[case(with_payload!(&[0xD0, 0x70]), Ok(MatterCode::Long))]
    #[case(with_payload!(&[0xD0, 0x80]), Ok(MatterCode::ECDSA256r1Sig))]
    #[case(with_payload!(&[0xD0, 0x90]), Ok(MatterCode::Tag1))]
    #[case(with_payload!(&[0xD0, 0xA0]), Ok(MatterCode::Tag2))]
    #[case(with_payload!(&[0xD0, 0xB0]), Ok(MatterCode::Tag5))]
    #[case(with_payload!(&[0xD0, 0xC0]), Ok(MatterCode::Tag6))]
    #[case(with_payload!(&[0xD0, 0xD0]), Ok(MatterCode::Tag9))]
    #[case(with_payload!(&[0xD0, 0xE0]), Ok(MatterCode::Tag10))]
    #[case(with_payload!(&[0xD0, 0xF0]), Ok(MatterCode::GramHeadNeck))]
    #[case(with_payload!(&[0xD1, 0x00]), Ok(MatterCode::GramHead))]
    #[case(with_payload!(&[0xD1, 0x10]), Ok(MatterCode::GramHeadAIDNeck))]
    #[case(with_payload!(&[0xD1, 0x20]), Ok(MatterCode::GramHeadAID))]
    // // 4-char codes (3 bytes)
    #[case(with_payload!(&[0xD4, 0x00, 0x00]), Ok(MatterCode::ECDSA256k1N))]
    #[case(with_payload!(&[0xD4, 0x00, 0x01]), Ok(MatterCode::ECDSA256k1))]
    #[case(with_payload!(&[0xD4, 0x00, 0x02]), Ok(MatterCode::Ed448N))]
    #[case(with_payload!(&[0xD4, 0x00, 0x03]), Ok(MatterCode::Ed448))]
    #[case(with_payload!(&[0xD4, 0x00, 0x04]), Ok(MatterCode::Ed448Sig))]
    #[case(with_payload!(&[0xD4, 0x00, 0x05]), Ok(MatterCode::Tag4))]
    #[case(with_payload!(&[0xD4, 0x00, 0x06]), Ok(MatterCode::DateTime))]
    #[case(with_payload!(&[0xD4, 0x00, 0x07]), Ok(MatterCode::X25519CipherSalt))]
    #[case(with_payload!(&[0xD4, 0x00, 0x08]), Ok(MatterCode::ECDSA256r1N))]
    #[case(with_payload!(&[0xD4, 0x00, 0x09]), Ok(MatterCode::ECDSA256r1))]
    #[case(with_payload!(&[0xD4, 0x00, 0x0A]), Ok(MatterCode::Null))]
    #[case(with_payload!(&[0xD4, 0x00, 0x0B]), Ok(MatterCode::No))]
    #[case(with_payload!(&[0xD4, 0x00, 0x0C]), Ok(MatterCode::Yes))]
    #[case(with_payload!(&[0xD4, 0x00, 0x0D]), Ok(MatterCode::Tag8))]
    #[case(with_payload!(&[0xD4, 0x00, 0x0E]), Ok(MatterCode::Escape))]
    #[case(with_payload!(&[0xD4, 0x00, 0x0F]), Ok(MatterCode::Empty))]
    #[case(with_payload!(&[0xD7, 0xFF, 0xFE]), Ok(MatterCode::TBD0S))]
    #[case(with_payload!(&[0xD7, 0xFF, 0xFF]), Ok(MatterCode::TBD0))]
    #[case(with_payload!(&[0xDB, 0xFF, 0xFE]), Ok(MatterCode::TBD1S))]
    #[case(with_payload!(&[0xDB, 0xFF, 0xFF]), Ok(MatterCode::TBD1))]
    #[case(with_payload!(&[0xDF, 0xFF, 0xFE]), Ok(MatterCode::TBD2S))]
    #[case(with_payload!(&[0xDF, 0xFF, 0xFF]), Ok(MatterCode::TBD2))]
    // // Variable size codes
    #[case(with_payload!(&[0xE0, 0x00]), Ok(MatterCode::StrB64_L0))]
    #[case(with_payload!(&[0xE4, 0x00]), Ok(MatterCode::StrB64_L1))]
    #[case(with_payload!(&[0xE8, 0x00]), Ok(MatterCode::StrB64_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x00]), Ok(MatterCode::StrB64Big_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x00]), Ok(MatterCode::StrB64Big_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x00]), Ok(MatterCode::StrB64Big_L2))]
    #[case(with_payload!(&[0xE0, 0x10]), Ok(MatterCode::Bytes_L0))]
    #[case(with_payload!(&[0xE4, 0x10]), Ok(MatterCode::Bytes_L1))]
    #[case(with_payload!(&[0xE8, 0x10]), Ok(MatterCode::Bytes_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x01]), Ok(MatterCode::BytesBig_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x01]), Ok(MatterCode::BytesBig_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x01]), Ok(MatterCode::BytesBig_L2))]
    #[case(with_payload!(&[0xE0, 0x20]), Ok(MatterCode::X25519Cipher_L0))]
    #[case(with_payload!(&[0xE4, 0x20]), Ok(MatterCode::X25519Cipher_L1))]
    #[case(with_payload!(&[0xE8, 0x20]), Ok(MatterCode::X25519Cipher_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x02]), Ok(MatterCode::X25519CipherBig_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x02]), Ok(MatterCode::X25519CipherBig_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x02]), Ok(MatterCode::X25519CipherBig_L2))]
    #[case(with_payload!(&[0xE0, 0x30]), Ok(MatterCode::X25519CipherQB64_L0))]
    #[case(with_payload!(&[0xE4, 0x30]), Ok(MatterCode::X25519CipherQB64_L1))]
    #[case(with_payload!(&[0xE8, 0x30]), Ok(MatterCode::X25519CipherQB64_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x03]), Ok(MatterCode::X25519CipherQB64Big_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x03]), Ok(MatterCode::X25519CipherQB64Big_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x03]), Ok(MatterCode::X25519CipherQB64Big_L2))]
    #[case(with_payload!(&[0xE0, 0x40]), Ok(MatterCode::X25519CipherQB2_L0))]
    #[case(with_payload!(&[0xE4, 0x40]), Ok(MatterCode::X25519CipherQB2_L1))]
    #[case(with_payload!(&[0xE8, 0x40]), Ok(MatterCode::X25519CipherQB2_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x04]), Ok(MatterCode::X25519CipherQB2Big_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x04]), Ok(MatterCode::X25519CipherQB2Big_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x04]), Ok(MatterCode::X25519CipherQB2Big_L2))]
    #[case(with_payload!(&[0xE0, 0x50]), Ok(MatterCode::HPKEBaseCipher_L0))]
    #[case(with_payload!(&[0xE4, 0x50]), Ok(MatterCode::HPKEBaseCipher_L1))]
    #[case(with_payload!(&[0xE8, 0x50]), Ok(MatterCode::HPKEBaseCipher_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x05]), Ok(MatterCode::HPKEBaseCipherBig_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x05]), Ok(MatterCode::HPKEBaseCipherBig_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x05]), Ok(MatterCode::HPKEBaseCipherBig_L2))]
    #[case(with_payload!(&[0xE0, 0x70]), Ok(MatterCode::Decimal_L0))]
    #[case(with_payload!(&[0xE4, 0x70]), Ok(MatterCode::Decimal_L1))]
    #[case(with_payload!(&[0xE8, 0x70]), Ok(MatterCode::Decimal_L2))]
    #[case(with_payload!(&[0xEC, 0x00, 0x07]), Ok(MatterCode::DecimalBig_L0))]
    #[case(with_payload!(&[0xF0, 0x00, 0x07]), Ok(MatterCode::DecimalBig_L1))]
    #[case(with_payload!(&[0xF4, 0x00, 0x07]), Ok(MatterCode::DecimalBig_L2))]
    fn test_all_matter_codes_from_byte_stream(
        #[case] input: Vec<u8>,
        #[case] expected: Result<MatterCode, ParsingError>,
    ) {
        assert_eq!(MatterCode::from_stream(&input), expected);
    }

    #[rstest]
    #[case(MatterCode::StrB64_L0, 100, 1, Ok(MatterCode::StrB64_L1))]
    #[case(MatterCode::Bytes_L1, 200, 2, Ok(MatterCode::Bytes_L2))]
    #[case(MatterCode::Decimal_L2, 1, 0, Ok(MatterCode::Decimal_L0))]
    #[case(MatterCode::StrB64_L0, 5000, 0, Ok(MatterCode::StrB64Big_L0))] // "4A" -> "7AAA"
    #[case(MatterCode::Bytes_L1, 5000, 2, Ok(MatterCode::BytesBig_L2))] // "5B" -> "9AAB"
    #[case(MatterCode::Decimal_L2, 10000, 1, Ok(MatterCode::DecimalBig_L1))] // "6H" -> "8AAH"
    #[case(MatterCode::StrB64Big_L0, 20000, 1, Ok(MatterCode::StrB64Big_L1))] // "7AAA" -> "8AAA"
    #[case(MatterCode::BytesBig_L1, 20000, 0, Ok(MatterCode::BytesBig_L0))] // "8AAB" -> "7AAB"
    #[case(MatterCode::DecimalBig_L2, 20000, 2, Ok(MatterCode::DecimalBig_L2))] // "9AAH" -> "9AAH"
    #[case(
        MatterCode::Ed25519,
        100,
        0,
        Err(ValidationError::IncompatiblePromotion("D".to_owned()))
    )]
    #[case(
        MatterCode::StrB64_L0,
        64_usize.pow(4) + 1,
        0,
        Err(ValidationError::IncompatiblePromotion("4A".to_owned()))
    )]
    #[case(
        MatterCode::StrB64_L1,
        100,
        3,
        Err(ValidationError::InvalidPromotionTarget { code: "5A".to_owned(), lead: 3 })
    )]
    fn test_code_promotion(
        #[case] original: MatterCode,
        #[case] size: usize,
        #[case] lead: usize,
        #[case] expected: Result<MatterCode, ValidationError>,
    ) {
        assert_eq!(original.promote(size, lead), expected);
    }

    #[test]
    fn test_codex_categorization() {
        assert!(MatterCode::Blake3_256.is_digest());
        assert!(MatterCode::Blake3_256.is_nonce());
        assert!(!MatterCode::Blake3_256.is_text_code());
        assert!(MatterCode::StrB64_L0.is_base64_text_code());
        assert!(MatterCode::StrB64_L0.is_label());
        assert!(!MatterCode::StrB64_L0.is_digest());
        assert!(MatterCode::Ed25519N.is_non_transferable());
        assert!(MatterCode::Ed25519N.is_prefix_derivation());
        assert!(MatterCode::Short.is_base64_num());
        assert!(!MatterCode::Short.is_base64_tag());
        assert!(MatterCode::Tag4.is_base64_tag());
        assert!(MatterCode::Tag4.is_label());
    }

    #[rstest]
    #[case(MatterCode::Ed25519Seed, Ok(32))] // ((44 - 1) * 3 / 4) - 0 = 32
    #[case(MatterCode::Ed25519Sig, Ok(64))] // ((88 - 2) * 3 / 4) - 0 = 64
    #[case(MatterCode::Ed448Sig, Ok(114))] // ((156 - 4) * 3 / 4) - 0 = 114
    #[case(MatterCode::Label1, Ok(1))] // ((4 - 1) * 3 / 4) - 1 = 1
    #[case(
        MatterCode::StrB64_L0,
        Err(ValidationError::InvalidSizingOperation("4A".to_owned()))
    )]
    #[case(
        MatterCode::BytesBig_L1,
        Err(ValidationError::InvalidSizingOperation("8AAB".to_owned()))
    )]
    fn test_raw_size_calculation(
        #[case] code: MatterCode,
        #[case] expected: Result<usize, ValidationError>,
    ) {
        assert_eq!(code.raw_size(), expected);
    }

    // ── Sizage conformance tests ──────────────────────────────────────
    // Verifies every MatterCode variant's get_sizage() output matches
    // the expected values from the Python KERI spec.
    #[rstest]
    // 1-char fixed codes (hs=1, ss=0)
    #[case(MatterCode::Ed25519Seed, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Ed25519N, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::X25519, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Ed25519, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Blake3_256, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Blake2b_256, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Blake2s_256, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::SHA3_256, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::SHA2_256, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::ECDSA256k1Seed, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Ed448Seed, 1, 0, 0, Some(76_u16), 0)]
    #[case(MatterCode::X448, 1, 0, 0, Some(76_u16), 0)]
    #[case(MatterCode::Short, 1, 0, 0, Some(4_u16), 0)]
    #[case(MatterCode::Big, 1, 0, 0, Some(12_u16), 0)]
    #[case(MatterCode::X25519Private, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::X25519CipherSeed, 1, 0, 0, Some(124_u16), 0)]
    #[case(MatterCode::ECDSA256r1Seed, 1, 0, 0, Some(44_u16), 0)]
    #[case(MatterCode::Tall, 1, 0, 0, Some(8_u16), 0)]
    #[case(MatterCode::Large, 1, 0, 0, Some(16_u16), 0)]
    #[case(MatterCode::Great, 1, 0, 0, Some(20_u16), 0)]
    #[case(MatterCode::Vast, 1, 0, 0, Some(24_u16), 0)]
    #[case(MatterCode::Label1, 1, 0, 0, Some(4_u16), 1)]
    #[case(MatterCode::Label2, 1, 0, 0, Some(4_u16), 0)]
    // 1-char special codes (hs=1, ss>0)
    #[case(MatterCode::Tag3, 1, 3, 0, Some(4_u16), 0)]
    #[case(MatterCode::Tag7, 1, 7, 0, Some(8_u16), 0)]
    #[case(MatterCode::Tag11, 1, 11, 0, Some(12_u16), 0)]
    // 1-char fixed code (Salt256)
    #[case(MatterCode::Salt256, 1, 0, 0, Some(44_u16), 0)]
    // 2-char fixed codes (hs=2, ss=0)
    #[case(MatterCode::Salt128, 2, 0, 0, Some(24_u16), 0)]
    #[case(MatterCode::Ed25519Sig, 2, 0, 0, Some(88_u16), 0)]
    #[case(MatterCode::ECDSA256k1Sig, 2, 0, 0, Some(88_u16), 0)]
    #[case(MatterCode::Blake3_512, 2, 0, 0, Some(88_u16), 0)]
    #[case(MatterCode::Blake2b_512, 2, 0, 0, Some(88_u16), 0)]
    #[case(MatterCode::SHA3_512, 2, 0, 0, Some(88_u16), 0)]
    #[case(MatterCode::SHA2_512, 2, 0, 0, Some(88_u16), 0)]
    #[case(MatterCode::Long, 2, 0, 0, Some(8_u16), 0)]
    #[case(MatterCode::ECDSA256r1Sig, 2, 0, 0, Some(88_u16), 0)]
    // 2-char special codes (hs=2, ss>0, fixed)
    #[case(MatterCode::Tag1, 2, 2, 1, Some(4_u16), 0)]
    #[case(MatterCode::Tag2, 2, 2, 0, Some(4_u16), 0)]
    #[case(MatterCode::Tag5, 2, 6, 1, Some(8_u16), 0)]
    #[case(MatterCode::Tag6, 2, 6, 0, Some(8_u16), 0)]
    #[case(MatterCode::Tag9, 2, 10, 1, Some(12_u16), 0)]
    #[case(MatterCode::Tag10, 2, 10, 0, Some(12_u16), 0)]
    #[case(MatterCode::GramHeadNeck, 2, 22, 0, Some(32_u16), 0)]
    #[case(MatterCode::GramHead, 2, 22, 0, Some(28_u16), 0)]
    #[case(MatterCode::GramHeadAIDNeck, 2, 22, 0, Some(76_u16), 0)]
    #[case(MatterCode::GramHeadAID, 2, 22, 0, Some(72_u16), 0)]
    // 4-char fixed codes (hs=4, ss=0)
    #[case(MatterCode::ECDSA256k1N, 4, 0, 0, Some(48_u16), 0)]
    #[case(MatterCode::ECDSA256k1, 4, 0, 0, Some(48_u16), 0)]
    #[case(MatterCode::Ed448N, 4, 0, 0, Some(80_u16), 0)]
    #[case(MatterCode::Ed448, 4, 0, 0, Some(80_u16), 0)]
    #[case(MatterCode::Ed448Sig, 4, 0, 0, Some(156_u16), 0)]
    #[case(MatterCode::DateTime, 4, 0, 0, Some(36_u16), 0)]
    #[case(MatterCode::X25519CipherSalt, 4, 0, 0, Some(100_u16), 0)]
    #[case(MatterCode::ECDSA256r1N, 4, 0, 0, Some(48_u16), 0)]
    #[case(MatterCode::ECDSA256r1, 4, 0, 0, Some(48_u16), 0)]
    #[case(MatterCode::Null, 4, 0, 0, Some(4_u16), 0)]
    #[case(MatterCode::No, 4, 0, 0, Some(4_u16), 0)]
    #[case(MatterCode::Yes, 4, 0, 0, Some(4_u16), 0)]
    #[case(MatterCode::Escape, 4, 0, 0, Some(4_u16), 0)]
    #[case(MatterCode::Empty, 4, 0, 0, Some(4_u16), 0)]
    // 4-char special codes (hs=4, ss>0, fixed)
    #[case(MatterCode::Tag4, 4, 4, 0, Some(8_u16), 0)]
    #[case(MatterCode::Tag8, 4, 8, 0, Some(12_u16), 0)]
    #[case(MatterCode::TBD0S, 4, 2, 0, Some(12_u16), 0)]
    #[case(MatterCode::TBD0, 4, 0, 0, Some(8_u16), 0)]
    #[case(MatterCode::TBD1S, 4, 2, 1, Some(12_u16), 1)]
    #[case(MatterCode::TBD1, 4, 0, 0, Some(8_u16), 1)]
    #[case(MatterCode::TBD2S, 4, 2, 0, Some(12_u16), 2)]
    #[case(MatterCode::TBD2, 4, 0, 0, Some(8_u16), 2)]
    // Variable-size small codes (hs=2, ss=2, fs=Small)
    #[case(MatterCode::StrB64_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::StrB64_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::StrB64_L2, 2, 2, 0, None, 2)]
    #[case(MatterCode::Bytes_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::Bytes_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::Bytes_L2, 2, 2, 0, None, 2)]
    #[case(MatterCode::X25519Cipher_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::X25519Cipher_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::X25519Cipher_L2, 2, 2, 0, None, 2)]
    #[case(MatterCode::X25519CipherQB64_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::X25519CipherQB64_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::X25519CipherQB64_L2, 2, 2, 0, None, 2)]
    #[case(MatterCode::X25519CipherQB2_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::X25519CipherQB2_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::X25519CipherQB2_L2, 2, 2, 0, None, 2)]
    #[case(MatterCode::HPKEBaseCipher_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::HPKEBaseCipher_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::HPKEBaseCipher_L2, 2, 2, 0, None, 2)]
    #[case(MatterCode::Decimal_L0, 2, 2, 0, None, 0)]
    #[case(MatterCode::Decimal_L1, 2, 2, 0, None, 1)]
    #[case(MatterCode::Decimal_L2, 2, 2, 0, None, 2)]
    // Variable-size large codes (hs=4, ss=4, fs=Large)
    #[case(MatterCode::StrB64Big_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::StrB64Big_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::StrB64Big_L2, 4, 4, 0, None, 2)]
    #[case(MatterCode::BytesBig_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::BytesBig_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::BytesBig_L2, 4, 4, 0, None, 2)]
    #[case(MatterCode::X25519CipherBig_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::X25519CipherBig_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::X25519CipherBig_L2, 4, 4, 0, None, 2)]
    #[case(MatterCode::X25519CipherQB64Big_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::X25519CipherQB64Big_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::X25519CipherQB64Big_L2, 4, 4, 0, None, 2)]
    #[case(MatterCode::X25519CipherQB2Big_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::X25519CipherQB2Big_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::X25519CipherQB2Big_L2, 4, 4, 0, None, 2)]
    #[case(MatterCode::HPKEBaseCipherBig_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::HPKEBaseCipherBig_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::HPKEBaseCipherBig_L2, 4, 4, 0, None, 2)]
    #[case(MatterCode::DecimalBig_L0, 4, 4, 0, None, 0)]
    #[case(MatterCode::DecimalBig_L1, 4, 4, 0, None, 1)]
    #[case(MatterCode::DecimalBig_L2, 4, 4, 0, None, 2)]
    fn sizage_matches_keri_spec(
        #[case] code: MatterCode,
        #[case] expected_hs: usize,
        #[case] expected_ss: usize,
        #[case] expected_xs: usize,
        #[case] expected_fs: Option<u16>,
        #[case] expected_ls: usize,
    ) {
        let sizage = code.get_sizage();
        assert_eq!(sizage.hs(), expected_hs, "hs mismatch for {code:?}");
        assert_eq!(sizage.ss(), expected_ss, "ss mismatch for {code:?}");
        assert_eq!(sizage.xs(), expected_xs, "xs mismatch for {code:?}");
        assert_eq!(sizage.ls(), expected_ls, "ls mismatch for {code:?}");
        match (sizage.fs(), &expected_fs) {
            (SizeType::Fixed(a), Some(b)) => {
                assert_eq!(u16::from(*a), *b, "fs mismatch for {code:?}");
            }
            (SizeType::Small | SizeType::Large, None) => {}
            (SizeType::Fixed(_), None) | (SizeType::Small | SizeType::Large, Some(_)) => panic!(
                "SizeType mismatch for {code:?}: got {:?}, expected fs={expected_fs:?}",
                sizage.fs(),
            ),
        }
    }

    #[rstest]
    #[case(&[], Err(ParsingError::EmptyStream))]
    #[case(
        &with_payload!(&[0xD4, 0x00, 0x00])[0..2],
        Err(ParsingError::StreamTooShort(MatterPart::Head))
    )]
    #[case(
        &with_payload!(&[0xD0, 0x1F])[0..1],
        Err(ParsingError::StreamTooShort(MatterPart::Head))
    )]
    #[case(&[0xFF], Err(ParsingError::MalformedCode { part: MatterPart::Head, found: "63".to_owned() }))]
    fn test_from_stream_errors(
        #[case] input: &[u8],
        #[case] expected: Result<MatterCode, ParsingError>,
    ) {
        assert_eq!(MatterCode::from_stream(input), expected);
    }

    #[test]
    fn all_code_strings_are_unique() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for variant in MatterCode::iter() {
            let code_str: &'static str = variant.into();
            assert!(
                seen.insert(code_str),
                "Duplicate code string: {code_str} for {variant:?}"
            );
        }
    }

    #[test]
    fn no_code_is_prefix_of_another() {
        let codes: Vec<&'static str> = MatterCode::iter()
            .map(|v| -> &'static str { v.into() })
            .collect();
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j && a.len() < b.len() {
                    assert!(
                        !b.starts_with(a),
                        "Code '{a}' is a prefix of '{b}' — ambiguous parsing"
                    );
                }
            }
        }
    }

    #[test]
    fn variant_count_matches_expected() {
        let count = MatterCode::iter().count();
        assert!(
            count >= 109,
            "Expected at least 109 MatterCode variants, found {count}"
        );
    }

    // ── Structural Invariant Tests ──────────────────────────────────────
    // Corresponds to keripy: tests/core/test_coring.py::test_matter_class
    // These verify algebraic relationships that must hold for every code
    // in the CESR code table per the specification.

    #[test]
    fn all_fixed_codes_have_fs_divisible_by_4() {
        // In base64, every primitive must occupy a multiple of 4 characters
        // so it can be cleanly decoded to bytes (4 b64 chars = 3 bytes).
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            if let SizeType::Fixed(fs) = sizage.fs {
                assert_eq!(
                    fs % 4,
                    0,
                    "Code {code:?} has fs={fs} which is not divisible by 4"
                );
            }
        }
    }

    #[test]
    fn all_codes_cs_not_3_mod_4() {
        // In base64, cs (code size = hs + ss) cannot be 3 mod 4
        // because that would leave 2 raw bits which cannot encode a full byte.
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            let cs = sizage.hs + sizage.ss;
            assert_ne!(
                cs % 4,
                3,
                "Code {code:?} has cs={cs} (hs={}, ss={}) which is 3 mod 4",
                sizage.hs,
                sizage.ss
            );
        }
    }

    #[test]
    fn all_codes_hs_is_1_2_or_4() {
        // CESR only defines 1-char, 2-char, and 4-char hard code sizes.
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            assert!(
                sizage.hs == 1 || sizage.hs == 2 || sizage.hs == 4,
                "Code {code:?} has unexpected hs={}",
                sizage.hs
            );
        }
    }

    #[test]
    fn fixed_non_special_codes_raw_size_consistency() {
        // For fixed, non-special codes (ss==0): the raw_size() method
        // should match the algebraic formula: ((fs - cs) * 3 / 4) - ls
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            if let SizeType::Fixed(fs_val) = sizage.fs
                && sizage.ss == 0
            {
                let cs = usize::from(sizage.hs) + usize::from(sizage.ss);
                let rs = ((usize::from(fs_val) - cs) * 3 / 4) - usize::from(sizage.ls);
                let computed = code.raw_size().unwrap();
                assert_eq!(
                    rs, computed,
                    "Code {code:?}: formula gives rs={rs} but raw_size()={computed}"
                );
            }
        }
    }

    #[test]
    fn fixed_codes_full_size_reconstructible() {
        // For fixed, non-special codes (ss==0): the data bytes (rs + ls)
        // must equal (fs - cs) * 3 / 4, verifying the full size is consistent
        // with the raw size and lead size.
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            if let SizeType::Fixed(fs_val) = sizage.fs
                && sizage.ss == 0
            {
                let cs = usize::from(sizage.hs) + usize::from(sizage.ss);
                let rs = code.raw_size().unwrap();
                let ls = usize::from(sizage.ls);
                let total_data_chars = usize::from(fs_val) - cs;
                let data_bytes = total_data_chars * 3 / 4;
                assert_eq!(
                    data_bytes,
                    rs + ls,
                    "Code {code:?}: data_bytes={data_bytes} but rs+ls={}",
                    rs + ls
                );
            }
        }
    }

    #[test]
    fn variable_codes_have_correct_structure() {
        // Variable-size codes must follow specific structural rules:
        // Small: hs=2, ss=2; Large: hs=4, ss=4; ls always <= 2
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            match sizage.fs {
                SizeType::Small => {
                    assert_eq!(sizage.hs, 2, "Small code {code:?} should have hs=2");
                    assert_eq!(sizage.ss, 2, "Small code {code:?} should have ss=2");
                    assert!(sizage.ls <= 2, "Small code {code:?} has ls={}", sizage.ls);
                }
                SizeType::Large => {
                    assert_eq!(sizage.hs, 4, "Large code {code:?} should have hs=4");
                    assert_eq!(sizage.ss, 4, "Large code {code:?} should have ss=4");
                    assert!(sizage.ls <= 2, "Large code {code:?} has ls={}", sizage.ls);
                }
                SizeType::Fixed(_) => {}
            }
        }
    }

    #[test]
    fn x25519_cipher_qb64_big_l2_is_large() {
        let sizage = MatterCode::X25519CipherQB64Big_L2.get_sizage();
        assert!(
            matches!(sizage.fs, SizeType::Large),
            "X25519CipherQB64Big_L2 must be SizeType::Large (matching keripy)"
        );
        assert_eq!(sizage.hs, 4);
        assert_eq!(sizage.ss, 4);
        assert_eq!(sizage.ls, 2);
    }

    #[test]
    fn lead_size_is_0_1_or_2() {
        // Lead size (ls) represents the number of leading zero-pad bytes.
        // In base64, at most 2 pad characters ("==") are possible, so ls <= 2.
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            assert!(
                sizage.ls <= 2,
                "Code {code:?} has ls={} which exceeds maximum of 2",
                sizage.ls
            );
        }
    }

    #[test]
    fn variable_codes_come_in_l0_l1_l2_triplets() {
        // Every variable-size code family should have exactly one variant for
        // each lead size (0, 1, 2), forming balanced triplets.
        //
        // We classify codes by their hs value rather than SizeType to avoid
        // being affected by the known X25519CipherQB64Big_L2 SizeType
        // mismatch (SizeType::Small with hs=4).
        //
        // Variable codes: hs=2 are "Small" family, hs=4 are "Large" family.
        let is_variable = |c: &MatterCode| {
            let s = c.get_sizage();
            matches!(s.fs, SizeType::Small | SizeType::Large)
        };

        // Small variable codes: hs=2, ss=2
        let small_codes: Vec<_> = MatterCode::iter()
            .filter(|c| is_variable(c) && c.get_sizage().hs == 2)
            .collect();
        let small_l0 = small_codes
            .iter()
            .filter(|c| c.get_sizage().ls == 0)
            .count();
        let small_l1 = small_codes
            .iter()
            .filter(|c| c.get_sizage().ls == 1)
            .count();
        let small_l2 = small_codes
            .iter()
            .filter(|c| c.get_sizage().ls == 2)
            .count();
        assert_eq!(
            small_l0, small_l1,
            "Small codes: L0 count ({small_l0}) != L1 count ({small_l1})"
        );
        assert_eq!(
            small_l1, small_l2,
            "Small codes: L1 count ({small_l1}) != L2 count ({small_l2})"
        );

        // Large variable codes: hs=4, ss=4
        let large_codes: Vec<_> = MatterCode::iter()
            .filter(|c| is_variable(c) && c.get_sizage().hs == 4)
            .collect();
        let large_l0 = large_codes
            .iter()
            .filter(|c| c.get_sizage().ls == 0)
            .count();
        let large_l1 = large_codes
            .iter()
            .filter(|c| c.get_sizage().ls == 1)
            .count();
        let large_l2 = large_codes
            .iter()
            .filter(|c| c.get_sizage().ls == 2)
            .count();
        assert_eq!(
            large_l0, large_l1,
            "Large codes: L0 count ({large_l0}) != L1 count ({large_l1})"
        );
        assert_eq!(
            large_l1, large_l2,
            "Large codes: L1 count ({large_l1}) != L2 count ({large_l2})"
        );
    }

    #[test]
    fn code_string_length_matches_hs() {
        // The hard-size (hs) defines the length of the code string prefix.
        // The strum-serialized string for each code must be exactly hs characters.
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            let code_str: &str = code.as_ref();
            assert_eq!(
                code_str.len(),
                usize::from(sizage.hs),
                "Code {code:?} has string '{code_str}' (len={}) but hs={}",
                code_str.len(),
                sizage.hs
            );
        }
    }

    #[test]
    fn xs_only_nonzero_for_expected_codes() {
        // xs (extra size / prepad) should only be non-zero for codes that
        // need an extra prepad character in their encoding. Per the code table,
        // these are Tag1, Tag5, Tag9 (all xs=1) and TBD1S (xs=1).
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            if sizage.xs > 0 {
                assert!(
                    matches!(
                        code,
                        MatterCode::Tag1 | MatterCode::Tag5 | MatterCode::Tag9 | MatterCode::TBD1S
                    ),
                    "Code {code:?} has xs={} but is not an expected odd-tag code",
                    sizage.xs
                );
                assert_eq!(
                    sizage.xs, 1,
                    "Code {code:?} has xs={} but expected xs=1",
                    sizage.xs
                );
            }
        }
    }

    // ── is_special predicate tests ──────────────────────────────────────
    // Corresponds to keripy: tests/core/test_coring.py::test_matter_class
    // "special" codes have fixed fs AND ss > 0 (they carry soft data
    // within a fixed-size frame, unlike variable-size codes).

    #[test]
    fn is_special_true_for_tag_codes() {
        let special_codes = [
            MatterCode::Tag1,
            MatterCode::Tag2,
            MatterCode::Tag3,
            MatterCode::Tag4,
            MatterCode::Tag5,
            MatterCode::Tag6,
            MatterCode::Tag7,
            MatterCode::Tag8,
            MatterCode::Tag9,
            MatterCode::Tag10,
            MatterCode::Tag11,
        ];
        for code in special_codes {
            assert!(code.is_special(), "{code:?} should be special");
        }
    }

    #[test]
    fn is_special_true_for_gram_codes() {
        let gram_codes = [
            MatterCode::GramHeadNeck,
            MatterCode::GramHead,
            MatterCode::GramHeadAIDNeck,
            MatterCode::GramHeadAID,
        ];
        for code in gram_codes {
            assert!(code.is_special(), "{code:?} should be special");
        }
    }

    #[test]
    fn is_special_true_for_tbd_s_codes() {
        let tbd_s_codes = [MatterCode::TBD0S, MatterCode::TBD1S, MatterCode::TBD2S];
        for code in tbd_s_codes {
            assert!(code.is_special(), "{code:?} should be special");
        }
    }

    #[test]
    fn is_special_false_for_basic_crypto_codes() {
        let non_special = [
            MatterCode::Ed25519Seed,
            MatterCode::Ed25519N,
            MatterCode::Ed25519,
            MatterCode::Blake3_256,
            MatterCode::SHA2_256,
            MatterCode::Ed25519Sig,
            MatterCode::ECDSA256k1Sig,
            MatterCode::Short,
            MatterCode::Long,
            MatterCode::Salt128,
        ];
        for code in non_special {
            assert!(!code.is_special(), "{code:?} should NOT be special");
        }
    }

    #[test]
    fn is_special_false_for_variable_codes() {
        let variable = [
            MatterCode::StrB64_L0,
            MatterCode::Bytes_L1,
            MatterCode::BytesBig_L2,
        ];
        for code in variable {
            assert!(
                !code.is_special(),
                "{code:?} should NOT be special (variable)"
            );
        }
    }

    #[test]
    fn is_special_exhaustive_agrees_with_definition() {
        // Exhaustively verify is_special() for all codes matches the
        // definition: fixed fs AND ss > 0.
        for code in MatterCode::iter() {
            let sizage = code.get_sizage();
            let expected = matches!(sizage.fs, SizeType::Fixed(_)) && sizage.ss > 0;
            assert_eq!(
                code.is_special(),
                expected,
                "Code {:?}: is_special()={} but expected={} (fs={:?}, ss={})",
                code,
                code.is_special(),
                expected,
                sizage.fs,
                sizage.ss
            );
        }
    }
}
