use super::xizage::{Xizage, XizageSize};
use thiserror::Error as ThisError;

/// Whether the indexed signature carries both current and prior-next indices.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum IndexMode {
    /// Index appears in both current signing and prior-next key lists.
    Both,
    /// Index for current signing key list only.
    CurrentOnly,
}

/// Error returned when a hard code string is not a recognized indexed signature
/// code.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum CodeError {
    /// The hard code string does not match any known indexed signature code.
    #[error("unknown indexed sig code: '{0}'")]
    UnknownCode(String),
}

/// The 16 CESR indexed signature codes.
///
/// Each variant maps to a fixed CESR hard code string, a sizage table entry,
/// and metadata about its index mode, raw size, and capacity.
///
/// "Crt" (current-only) variants carry only the signer's index in the current
/// key list. Non-Crt variants carry both a current index and a prior-next
/// "ondex".
///
/// "Big" variants use a wider soft field and support larger index values than
/// their small counterparts.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum IndexedSigCode {
    /// Ed25519 indexed signature — `"A"`
    Ed25519,
    /// Ed25519 current-only indexed signature — `"B"`
    Ed25519Crt,
    /// ECDSA secp256k1 indexed signature — `"C"`
    ECDSA256k1,
    /// ECDSA secp256k1 current-only indexed signature — `"D"`
    ECDSA256k1Crt,
    /// ECDSA P-256 indexed signature — `"E"`
    ECDSA256r1,
    /// ECDSA P-256 current-only indexed signature — `"F"`
    ECDSA256r1Crt,
    /// Ed448 indexed signature — `"0A"`
    Ed448,
    /// Ed448 current-only indexed signature — `"0B"`
    Ed448Crt,
    /// Ed25519 big indexed signature — `"2A"`
    Ed25519Big,
    /// Ed25519 big current-only indexed signature — `"2B"`
    Ed25519BigCrt,
    /// ECDSA secp256k1 big indexed signature — `"2C"`
    ECDSA256k1Big,
    /// ECDSA secp256k1 big current-only indexed signature — `"2D"`
    ECDSA256k1BigCrt,
    /// ECDSA P-256 big indexed signature — `"2E"`
    ECDSA256r1Big,
    /// ECDSA P-256 big current-only indexed signature — `"2F"`
    ECDSA256r1BigCrt,
    /// Ed448 big indexed signature — `"3A"`
    Ed448Big,
    /// Ed448 big current-only indexed signature — `"3B"`
    Ed448BigCrt,
}

impl IndexedSigCode {
    /// Returns the CESR wire code string for this variant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "A",
            Self::Ed25519Crt => "B",
            Self::ECDSA256k1 => "C",
            Self::ECDSA256k1Crt => "D",
            Self::ECDSA256r1 => "E",
            Self::ECDSA256r1Crt => "F",
            Self::Ed448 => "0A",
            Self::Ed448Crt => "0B",
            Self::Ed25519Big => "2A",
            Self::Ed25519BigCrt => "2B",
            Self::ECDSA256k1Big => "2C",
            Self::ECDSA256k1BigCrt => "2D",
            Self::ECDSA256r1Big => "2E",
            Self::ECDSA256r1BigCrt => "2F",
            Self::Ed448Big => "3A",
            Self::Ed448BigCrt => "3B",
        }
    }

    /// Parses a hard code string back to the corresponding enum variant.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::UnknownCode`] if `hard` does not match any known
    /// indexed signature code.
    pub fn from_hard(hard: &str) -> Result<Self, CodeError> {
        match hard {
            "A" => Ok(Self::Ed25519),
            "B" => Ok(Self::Ed25519Crt),
            "C" => Ok(Self::ECDSA256k1),
            "D" => Ok(Self::ECDSA256k1Crt),
            "E" => Ok(Self::ECDSA256r1),
            "F" => Ok(Self::ECDSA256r1Crt),
            "0A" => Ok(Self::Ed448),
            "0B" => Ok(Self::Ed448Crt),
            "2A" => Ok(Self::Ed25519Big),
            "2B" => Ok(Self::Ed25519BigCrt),
            "2C" => Ok(Self::ECDSA256k1Big),
            "2D" => Ok(Self::ECDSA256k1BigCrt),
            "2E" => Ok(Self::ECDSA256r1Big),
            "2F" => Ok(Self::ECDSA256r1BigCrt),
            "3A" => Ok(Self::Ed448Big),
            "3B" => Ok(Self::Ed448BigCrt),
            _ => Err(CodeError::UnknownCode(hard.to_owned())),
        }
    }

    /// Returns the [`Xizage`] sizage entry for this code (from the cesride
    /// reference table).
    #[must_use]
    pub const fn get_xizage(&self) -> Xizage {
        match self {
            Self::Ed25519
            | Self::Ed25519Crt
            | Self::ECDSA256k1
            | Self::ECDSA256k1Crt
            | Self::ECDSA256r1
            | Self::ECDSA256r1Crt => Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0),
            Self::Ed448 | Self::Ed448Crt => Xizage::new(2, 2, 1, XizageSize::Fixed(156), 0),
            Self::Ed25519Big
            | Self::Ed25519BigCrt
            | Self::ECDSA256k1Big
            | Self::ECDSA256k1BigCrt
            | Self::ECDSA256r1Big
            | Self::ECDSA256r1BigCrt => Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0),
            Self::Ed448Big | Self::Ed448BigCrt => Xizage::new(2, 6, 3, XizageSize::Fixed(160), 0),
        }
    }

    /// Returns the [`IndexMode`] for this code.
    ///
    /// `Both` variants carry a current index and a prior-next "ondex".
    /// `CurrentOnly` variants carry only the current index.
    #[must_use]
    pub const fn mode(&self) -> IndexMode {
        match self {
            Self::Ed25519
            | Self::ECDSA256k1
            | Self::ECDSA256r1
            | Self::Ed448
            | Self::Ed25519Big
            | Self::ECDSA256k1Big
            | Self::ECDSA256r1Big
            | Self::Ed448Big => IndexMode::Both,

            Self::Ed25519Crt
            | Self::ECDSA256k1Crt
            | Self::ECDSA256r1Crt
            | Self::Ed448Crt
            | Self::Ed25519BigCrt
            | Self::ECDSA256k1BigCrt
            | Self::ECDSA256r1BigCrt
            | Self::Ed448BigCrt => IndexMode::CurrentOnly,
        }
    }

    /// Returns `true` if this is a "big" variant with a wider index field.
    #[must_use]
    pub const fn is_big(&self) -> bool {
        match self {
            Self::Ed25519
            | Self::Ed25519Crt
            | Self::ECDSA256k1
            | Self::ECDSA256k1Crt
            | Self::ECDSA256r1
            | Self::ECDSA256r1Crt
            | Self::Ed448
            | Self::Ed448Crt => false,

            Self::Ed25519Big
            | Self::Ed25519BigCrt
            | Self::ECDSA256k1Big
            | Self::ECDSA256k1BigCrt
            | Self::ECDSA256r1Big
            | Self::ECDSA256r1BigCrt
            | Self::Ed448Big
            | Self::Ed448BigCrt => true,
        }
    }

    /// Returns the raw signature size in bytes.
    ///
    /// Ed25519 and ECDSA (256-bit) signatures are 64 bytes.
    /// Ed448 signatures are 114 bytes.
    /// The size is the same regardless of small vs. big variants.
    #[must_use]
    pub const fn raw_size(&self) -> usize {
        match self {
            Self::Ed25519
            | Self::Ed25519Crt
            | Self::Ed25519Big
            | Self::Ed25519BigCrt
            | Self::ECDSA256k1
            | Self::ECDSA256k1Crt
            | Self::ECDSA256k1Big
            | Self::ECDSA256k1BigCrt
            | Self::ECDSA256r1
            | Self::ECDSA256r1Crt
            | Self::ECDSA256r1Big
            | Self::ECDSA256r1BigCrt => 64,

            Self::Ed448 | Self::Ed448Crt | Self::Ed448Big | Self::Ed448BigCrt => 114,
        }
    }

    /// Returns the maximum index value this code can encode.
    ///
    /// Formula: `64^(ss - os) - 1` where `ss` is the soft size and `os` is the
    /// ondex size from the sizage table.
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn max_index(&self) -> u32 {
        let xizage = self.get_xizage();
        let exp = (xizage.ss - xizage.os) as u32;
        64u32.pow(exp) - 1
    }

    /// Returns the maximum ondex (other-index) value, or `None` for
    /// current-only codes.
    ///
    /// For `Both`-mode codes with `os > 0`: `64^os - 1`.
    /// For `Both`-mode codes with `os == 0` (small codes): the ondex must equal
    /// the index, so the max ondex equals `max_index()`.
    #[must_use]
    #[allow(clippy::as_conversions, reason = "From::from() is not const-stable")]
    pub const fn max_ondex(&self) -> Option<u32> {
        match self.mode() {
            IndexMode::CurrentOnly => None,
            IndexMode::Both => {
                let os = self.get_xizage().os as u32;
                if os == 0 {
                    Some(self.max_index())
                } else {
                    Some(64u32.pow(os) - 1)
                }
            }
        }
    }

    /// Auto-upgrades a small code to its big counterpart if `index` exceeds the
    /// small code's maximum index capacity.
    ///
    /// If the code is already big, or if `index` fits in the small code, returns
    /// `self` unchanged.
    #[must_use]
    pub const fn for_index(self, index: u32) -> Self {
        if self.is_big() || index <= self.max_index() {
            return self;
        }
        match self {
            Self::Ed25519 => Self::Ed25519Big,
            Self::Ed25519Crt => Self::Ed25519BigCrt,
            Self::ECDSA256k1 => Self::ECDSA256k1Big,
            Self::ECDSA256k1Crt => Self::ECDSA256k1BigCrt,
            Self::ECDSA256r1 => Self::ECDSA256r1Big,
            Self::ECDSA256r1Crt => Self::ECDSA256r1BigCrt,
            Self::Ed448 => Self::Ed448Big,
            Self::Ed448Crt => Self::Ed448BigCrt,
            // Big variants are already handled above.
            _ => self,
        }
    }
}

/// Maps the first character of a CESR code to the hard (stable) size in
/// characters.
///
/// Returns `None` if the character is not a valid CESR code lead.
#[must_use]
pub const fn hardage(c: char) -> Option<usize> {
    match c {
        'A'..='Z' | 'a'..='z' => Some(1),
        '0'..='4' => Some(2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ── as_str / from_hard roundtrip ─────────────────────────────────────

    #[rstest]
    #[case(IndexedSigCode::Ed25519, "A")]
    #[case(IndexedSigCode::Ed25519Crt, "B")]
    #[case(IndexedSigCode::ECDSA256k1, "C")]
    #[case(IndexedSigCode::ECDSA256k1Crt, "D")]
    #[case(IndexedSigCode::ECDSA256r1, "E")]
    #[case(IndexedSigCode::ECDSA256r1Crt, "F")]
    #[case(IndexedSigCode::Ed448, "0A")]
    #[case(IndexedSigCode::Ed448Crt, "0B")]
    #[case(IndexedSigCode::Ed25519Big, "2A")]
    #[case(IndexedSigCode::Ed25519BigCrt, "2B")]
    #[case(IndexedSigCode::ECDSA256k1Big, "2C")]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, "2D")]
    #[case(IndexedSigCode::ECDSA256r1Big, "2E")]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, "2F")]
    #[case(IndexedSigCode::Ed448Big, "3A")]
    #[case(IndexedSigCode::Ed448BigCrt, "3B")]
    fn as_str_values(#[case] code: IndexedSigCode, #[case] expected: &str) {
        assert_eq!(code.as_str(), expected);
    }

    #[rstest]
    #[case(IndexedSigCode::Ed25519, "A")]
    #[case(IndexedSigCode::Ed25519Crt, "B")]
    #[case(IndexedSigCode::ECDSA256k1, "C")]
    #[case(IndexedSigCode::ECDSA256k1Crt, "D")]
    #[case(IndexedSigCode::ECDSA256r1, "E")]
    #[case(IndexedSigCode::ECDSA256r1Crt, "F")]
    #[case(IndexedSigCode::Ed448, "0A")]
    #[case(IndexedSigCode::Ed448Crt, "0B")]
    #[case(IndexedSigCode::Ed25519Big, "2A")]
    #[case(IndexedSigCode::Ed25519BigCrt, "2B")]
    #[case(IndexedSigCode::ECDSA256k1Big, "2C")]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, "2D")]
    #[case(IndexedSigCode::ECDSA256r1Big, "2E")]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, "2F")]
    #[case(IndexedSigCode::Ed448Big, "3A")]
    #[case(IndexedSigCode::Ed448BigCrt, "3B")]
    fn from_hard_roundtrip(#[case] code: IndexedSigCode, #[case] wire: &str) {
        assert_eq!(IndexedSigCode::from_hard(wire).unwrap(), code);
        assert_eq!(IndexedSigCode::from_hard(code.as_str()).unwrap(), code);
    }

    #[rstest]
    #[case("Z")]
    #[case("0Z")]
    #[case("XX")]
    #[case("")]
    fn from_hard_unknown(#[case] bad: &str) {
        assert!(IndexedSigCode::from_hard(bad).is_err());
        let err = IndexedSigCode::from_hard(bad).unwrap_err();
        assert_eq!(err, CodeError::UnknownCode(bad.to_owned()));
    }

    // ── get_xizage ──────────────────────────────────────────────────────

    #[rstest]
    #[case(
        IndexedSigCode::Ed25519,
        Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0)
    )]
    #[case(
        IndexedSigCode::Ed25519Crt,
        Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256k1,
        Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256k1Crt,
        Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256r1,
        Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256r1Crt,
        Xizage::new(1, 1, 0, XizageSize::Fixed(88), 0)
    )]
    #[case(IndexedSigCode::Ed448, Xizage::new(2, 2, 1, XizageSize::Fixed(156), 0))]
    #[case(
        IndexedSigCode::Ed448Crt,
        Xizage::new(2, 2, 1, XizageSize::Fixed(156), 0)
    )]
    #[case(
        IndexedSigCode::Ed25519Big,
        Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0)
    )]
    #[case(
        IndexedSigCode::Ed25519BigCrt,
        Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256k1Big,
        Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256k1BigCrt,
        Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256r1Big,
        Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0)
    )]
    #[case(
        IndexedSigCode::ECDSA256r1BigCrt,
        Xizage::new(2, 4, 2, XizageSize::Fixed(92), 0)
    )]
    #[case(
        IndexedSigCode::Ed448Big,
        Xizage::new(2, 6, 3, XizageSize::Fixed(160), 0)
    )]
    #[case(
        IndexedSigCode::Ed448BigCrt,
        Xizage::new(2, 6, 3, XizageSize::Fixed(160), 0)
    )]
    fn xizage_values(#[case] code: IndexedSigCode, #[case] expected: Xizage) {
        assert_eq!(code.get_xizage(), expected);
    }

    // ── mode ────────────────────────────────────────────────────────────

    #[rstest]
    #[case(IndexedSigCode::Ed25519, IndexMode::Both)]
    #[case(IndexedSigCode::Ed25519Crt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::ECDSA256k1, IndexMode::Both)]
    #[case(IndexedSigCode::ECDSA256k1Crt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::ECDSA256r1, IndexMode::Both)]
    #[case(IndexedSigCode::ECDSA256r1Crt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::Ed448, IndexMode::Both)]
    #[case(IndexedSigCode::Ed448Crt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::Ed25519Big, IndexMode::Both)]
    #[case(IndexedSigCode::Ed25519BigCrt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::ECDSA256k1Big, IndexMode::Both)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::ECDSA256r1Big, IndexMode::Both)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, IndexMode::CurrentOnly)]
    #[case(IndexedSigCode::Ed448Big, IndexMode::Both)]
    #[case(IndexedSigCode::Ed448BigCrt, IndexMode::CurrentOnly)]
    fn mode_values(#[case] code: IndexedSigCode, #[case] expected: IndexMode) {
        assert_eq!(code.mode(), expected);
    }

    // ── is_big ──────────────────────────────────────────────────────────

    #[rstest]
    #[case(IndexedSigCode::Ed25519, false)]
    #[case(IndexedSigCode::Ed25519Crt, false)]
    #[case(IndexedSigCode::ECDSA256k1, false)]
    #[case(IndexedSigCode::ECDSA256k1Crt, false)]
    #[case(IndexedSigCode::ECDSA256r1, false)]
    #[case(IndexedSigCode::ECDSA256r1Crt, false)]
    #[case(IndexedSigCode::Ed448, false)]
    #[case(IndexedSigCode::Ed448Crt, false)]
    #[case(IndexedSigCode::Ed25519Big, true)]
    #[case(IndexedSigCode::Ed25519BigCrt, true)]
    #[case(IndexedSigCode::ECDSA256k1Big, true)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, true)]
    #[case(IndexedSigCode::ECDSA256r1Big, true)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, true)]
    #[case(IndexedSigCode::Ed448Big, true)]
    #[case(IndexedSigCode::Ed448BigCrt, true)]
    fn is_big_values(#[case] code: IndexedSigCode, #[case] expected: bool) {
        assert_eq!(code.is_big(), expected);
    }

    // ── raw_size ────────────────────────────────────────────────────────

    #[rstest]
    #[case(IndexedSigCode::Ed25519, 64)]
    #[case(IndexedSigCode::Ed25519Crt, 64)]
    #[case(IndexedSigCode::ECDSA256k1, 64)]
    #[case(IndexedSigCode::ECDSA256k1Crt, 64)]
    #[case(IndexedSigCode::ECDSA256r1, 64)]
    #[case(IndexedSigCode::ECDSA256r1Crt, 64)]
    #[case(IndexedSigCode::Ed448, 114)]
    #[case(IndexedSigCode::Ed448Crt, 114)]
    #[case(IndexedSigCode::Ed25519Big, 64)]
    #[case(IndexedSigCode::Ed25519BigCrt, 64)]
    #[case(IndexedSigCode::ECDSA256k1Big, 64)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, 64)]
    #[case(IndexedSigCode::ECDSA256r1Big, 64)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, 64)]
    #[case(IndexedSigCode::Ed448Big, 114)]
    #[case(IndexedSigCode::Ed448BigCrt, 114)]
    fn raw_size_values(#[case] code: IndexedSigCode, #[case] expected: usize) {
        assert_eq!(code.raw_size(), expected);
    }

    // ── max_index ───────────────────────────────────────────────────────

    #[rstest]
    // Small codes: ss=1, os=0 => 64^1 - 1 = 63
    #[case(IndexedSigCode::Ed25519, 63)]
    #[case(IndexedSigCode::Ed25519Crt, 63)]
    #[case(IndexedSigCode::ECDSA256k1, 63)]
    #[case(IndexedSigCode::ECDSA256k1Crt, 63)]
    #[case(IndexedSigCode::ECDSA256r1, 63)]
    #[case(IndexedSigCode::ECDSA256r1Crt, 63)]
    // Small Ed448: ss=2, os=1 => 64^1 - 1 = 63
    #[case(IndexedSigCode::Ed448, 63)]
    #[case(IndexedSigCode::Ed448Crt, 63)]
    // Big Ed25519/ECDSA: ss=4, os=2 => 64^2 - 1 = 4095
    #[case(IndexedSigCode::Ed25519Big, 4095)]
    #[case(IndexedSigCode::Ed25519BigCrt, 4095)]
    #[case(IndexedSigCode::ECDSA256k1Big, 4095)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, 4095)]
    #[case(IndexedSigCode::ECDSA256r1Big, 4095)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, 4095)]
    // Big Ed448: ss=6, os=3 => 64^3 - 1 = 262_143
    #[case(IndexedSigCode::Ed448Big, 262_143)]
    #[case(IndexedSigCode::Ed448BigCrt, 262_143)]
    fn max_index_values(#[case] code: IndexedSigCode, #[case] expected: u32) {
        assert_eq!(code.max_index(), expected);
    }

    // ── max_ondex ───────────────────────────────────────────────────────

    #[rstest]
    // Small Both (os=0): ondex must equal index, so max_ondex = max_index = 63
    #[case(IndexedSigCode::Ed25519, Some(63))]
    #[case(IndexedSigCode::ECDSA256k1, Some(63))]
    #[case(IndexedSigCode::ECDSA256r1, Some(63))]
    // Small CurrentOnly: None
    #[case(IndexedSigCode::Ed25519Crt, None)]
    #[case(IndexedSigCode::ECDSA256k1Crt, None)]
    #[case(IndexedSigCode::ECDSA256r1Crt, None)]
    // Small Ed448 Both (os=1): 64^1 - 1 = 63
    #[case(IndexedSigCode::Ed448, Some(63))]
    #[case(IndexedSigCode::Ed448Crt, None)]
    // Big Both Ed25519/ECDSA (os=2): 64^2 - 1 = 4095
    #[case(IndexedSigCode::Ed25519Big, Some(4095))]
    #[case(IndexedSigCode::Ed25519BigCrt, None)]
    #[case(IndexedSigCode::ECDSA256k1Big, Some(4095))]
    #[case(IndexedSigCode::ECDSA256k1BigCrt, None)]
    #[case(IndexedSigCode::ECDSA256r1Big, Some(4095))]
    #[case(IndexedSigCode::ECDSA256r1BigCrt, None)]
    // Big Ed448 Both (os=3): 64^3 - 1 = 262_143
    #[case(IndexedSigCode::Ed448Big, Some(262_143))]
    #[case(IndexedSigCode::Ed448BigCrt, None)]
    fn max_ondex_values(#[case] code: IndexedSigCode, #[case] expected: Option<u32>) {
        assert_eq!(code.max_ondex(), expected);
    }

    // ── for_index ───────────────────────────────────────────────────────

    #[rstest]
    // Index fits in small code: no upgrade
    #[case(IndexedSigCode::Ed25519, 0, IndexedSigCode::Ed25519)]
    #[case(IndexedSigCode::Ed25519, 63, IndexedSigCode::Ed25519)]
    #[case(IndexedSigCode::Ed25519Crt, 63, IndexedSigCode::Ed25519Crt)]
    #[case(IndexedSigCode::ECDSA256k1, 0, IndexedSigCode::ECDSA256k1)]
    #[case(IndexedSigCode::ECDSA256r1, 63, IndexedSigCode::ECDSA256r1)]
    #[case(IndexedSigCode::Ed448, 63, IndexedSigCode::Ed448)]
    // Index exceeds small max: auto-upgrade
    #[case(IndexedSigCode::Ed25519, 64, IndexedSigCode::Ed25519Big)]
    #[case(IndexedSigCode::Ed25519Crt, 64, IndexedSigCode::Ed25519BigCrt)]
    #[case(IndexedSigCode::ECDSA256k1, 100, IndexedSigCode::ECDSA256k1Big)]
    #[case(IndexedSigCode::ECDSA256k1Crt, 100, IndexedSigCode::ECDSA256k1BigCrt)]
    #[case(IndexedSigCode::ECDSA256r1, 200, IndexedSigCode::ECDSA256r1Big)]
    #[case(IndexedSigCode::ECDSA256r1Crt, 200, IndexedSigCode::ECDSA256r1BigCrt)]
    #[case(IndexedSigCode::Ed448, 64, IndexedSigCode::Ed448Big)]
    #[case(IndexedSigCode::Ed448Crt, 64, IndexedSigCode::Ed448BigCrt)]
    // Already big: no change
    #[case(IndexedSigCode::Ed25519Big, 0, IndexedSigCode::Ed25519Big)]
    #[case(IndexedSigCode::Ed25519Big, 4095, IndexedSigCode::Ed25519Big)]
    #[case(IndexedSigCode::Ed448Big, 262_143, IndexedSigCode::Ed448Big)]
    fn for_index_values(
        #[case] code: IndexedSigCode,
        #[case] index: u32,
        #[case] expected: IndexedSigCode,
    ) {
        assert_eq!(code.for_index(index), expected);
    }

    // ── hardage ─────────────────────────────────────────────────────────

    #[rstest]
    #[case('A', Some(1))]
    #[case('Z', Some(1))]
    #[case('a', Some(1))]
    #[case('z', Some(1))]
    #[case('M', Some(1))]
    #[case('0', Some(2))]
    #[case('1', Some(2))]
    #[case('2', Some(2))]
    #[case('3', Some(2))]
    #[case('4', Some(2))]
    #[case('5', None)]
    #[case('9', None)]
    #[case('-', None)]
    #[case('_', None)]
    #[case(' ', None)]
    fn hardage_values(#[case] c: char, #[case] expected: Option<usize>) {
        assert_eq!(hardage(c), expected);
    }

    // ── for_index preserves mode ────────────────────────────────────────

    #[test]
    fn for_index_preserves_mode() {
        // Both stays Both
        assert_eq!(
            IndexedSigCode::Ed25519.for_index(64).mode(),
            IndexMode::Both
        );
        // CurrentOnly stays CurrentOnly
        assert_eq!(
            IndexedSigCode::Ed25519Crt.for_index(64).mode(),
            IndexMode::CurrentOnly,
        );
    }

    // ── for_index preserves raw_size ────────────────────────────────────

    #[test]
    fn for_index_preserves_raw_size() {
        assert_eq!(
            IndexedSigCode::Ed25519.for_index(64).raw_size(),
            IndexedSigCode::Ed25519.raw_size(),
        );
        assert_eq!(
            IndexedSigCode::Ed448.for_index(64).raw_size(),
            IndexedSigCode::Ed448.raw_size(),
        );
    }
}
