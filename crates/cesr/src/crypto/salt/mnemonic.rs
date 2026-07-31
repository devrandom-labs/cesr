//! 12-word BIP-39 mnemonic backup for [`Salt`] ([#274] K-custody).
//!
//! Encodes the 128-bit root salt as 12 English words: the 132-bit stream is
//! the raw entropy followed by a 4-bit checksum (top nibble of
//! `SHA-256(entropy)`), split MSB-first into 12 × 11-bit indices into the
//! BIP-39 English wordlist.
//!
//! The words encode the SALT only — recovering keys additionally requires the
//! argon2id [`Tier`](super::Tier) and the derivation-path convention used when
//! the keys were made; record those alongside the phrase or fix them by
//! convention. Deliberately NOT wallet-seed compatible: BIP-39's PBKDF2 seed
//! step is skipped, the recovered entropy feeds [`Salt::stretch`] instead.
//!
//! [#274]: https://github.com/devrandom-labs/cesr/issues/274

use alloc::string::String;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::bip39_words::WORDS;
use super::{SALT_LEN, Salt};
use crate::crypto::error::MnemonicError;

/// A 12-word phrase encodes 132 bits: 128 entropy + 4 checksum.
const WORD_COUNT: usize = 12;
/// Each word indexes a 2048-entry list, so carries 11 bits.
const WORD_BITS: usize = 11;
/// Total encoded bits (132).
const TOTAL_BITS: usize = WORD_COUNT * WORD_BITS;
/// Bytes backing the 132-bit stream: 16 entropy bytes + 1 checksum byte
/// whose top nibble is used and whose bottom nibble stays zero.
const STREAM_BYTES: usize = SALT_LEN + 1;

/// Top 4 bits of `SHA-256(entropy)` — the BIP-39 checksum for 128-bit entropy.
fn checksum_nibble(entropy: &[u8; SALT_LEN]) -> u8 {
    Sha256::digest(entropy)[0] >> 4
}

impl Salt {
    /// Encodes the salt as a 12-word BIP-39 English mnemonic: lowercase,
    /// single-space separated, wrapped in [`Zeroizing`] because the phrase is
    /// the root secret in another alphabet.
    ///
    /// The words encode the SALT only — recovering keys also requires the
    /// argon2id [`Tier`](super::Tier) and path convention used at derivation.
    /// Not a wallet seed phrase: no PBKDF2; the entropy feeds
    /// [`Salt::stretch`].
    #[must_use]
    pub fn to_mnemonic(&self) -> Zeroizing<String> {
        let mut stream = Zeroizing::new([0u8; STREAM_BYTES]);
        stream[..SALT_LEN].copy_from_slice(&self.raw[..]);
        stream[SALT_LEN] = checksum_nibble(&self.raw) << 4;

        let mut indices = Zeroizing::new([0usize; WORD_COUNT]);
        for pos in 0..TOTAL_BITS {
            let bit = usize::from((stream[pos / 8] >> (7 - pos % 8)) & 1);
            indices[pos / WORD_BITS] = (indices[pos / WORD_BITS] << 1) | bit;
        }

        let mut phrase = Zeroizing::new(String::new());
        for (i, index) in indices.iter().enumerate() {
            if i > 0 {
                phrase.push(' ');
            }
            phrase.push_str(WORDS[index & 0x7FF]);
        }
        phrase
    }

    /// Decodes a 12-word BIP-39 English mnemonic back into a salt. Words are
    /// matched ASCII-case-insensitively and any amount of whitespace between
    /// them is tolerated.
    ///
    /// # Errors
    ///
    /// [`MnemonicError::WordCount`] if the phrase is not exactly 12 words,
    /// [`MnemonicError::UnknownWord`] (position only — the word itself is
    /// secret material and never appears in the error) if a word is not in
    /// the wordlist, [`MnemonicError::Checksum`] if the embedded 4-bit
    /// checksum does not match the decoded entropy.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, MnemonicError> {
        let actual = phrase.split_ascii_whitespace().count();
        if actual != WORD_COUNT {
            return Err(MnemonicError::WordCount { actual });
        }

        let mut indices = Zeroizing::new([0usize; WORD_COUNT]);
        for (i, word) in phrase.split_ascii_whitespace().enumerate() {
            let index = WORDS
                .iter()
                .position(|candidate| candidate.eq_ignore_ascii_case(word))
                .ok_or(MnemonicError::UnknownWord { index: i })?;
            indices[i] = index;
        }

        let mut stream = Zeroizing::new([0u8; STREAM_BYTES]);
        for pos in 0..TOTAL_BITS {
            let bit = (indices[pos / WORD_BITS] >> (WORD_BITS - 1 - pos % WORD_BITS)) & 1;
            if bit == 1 {
                stream[pos / 8] |= 1 << (7 - pos % 8);
            }
        }

        let mut raw = Zeroizing::new([0u8; SALT_LEN]);
        raw.copy_from_slice(&stream[..SALT_LEN]);
        if stream[SALT_LEN] >> 4 != checksum_nibble(&raw) {
            return Err(MnemonicError::Checksum);
        }
        Ok(Self { raw })
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::disallowed_methods,
    reason = "test assertions use unwrap and panic for clarity"
)]
mod tests {
    use alloc::string::ToString;

    use rstest::rstest;

    use super::*;

    /// qb64 rendering — the only equality handle on `Salt` (no `PartialEq`,
    /// raw bytes deliberately unexposed).
    fn qb64(salt: &Salt) -> String {
        salt.primitive().unwrap().to_qb64()
    }

    fn salt_from_hex(entropy_hex: &str) -> Salt {
        let raw = hex::decode(entropy_hex).unwrap();
        Salt::from_raw(&raw).unwrap()
    }

    // All 8 official 128-bit English vectors from trezor/python-mnemonic
    // vectors.json (fetched 2026-07-31).
    #[rstest]
    #[case(
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    )]
    #[case(
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )]
    #[case(
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    )]
    #[case(
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    )]
    #[case(
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    )]
    #[case(
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow"
    )]
    #[case(
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train"
    )]
    #[case(
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture"
    )]
    fn trezor_vector_round_trips(#[case] entropy_hex: &str, #[case] mnemonic: &str) {
        let salt = salt_from_hex(entropy_hex);
        assert_eq!(salt.to_mnemonic().as_str(), mnemonic);
        let recovered = Salt::from_mnemonic(mnemonic).unwrap();
        assert_eq!(qb64(&recovered), qb64(&salt));
    }

    #[rstest]
    #[case(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        11
    )]
    #[case(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about about",
        13
    )]
    #[case("", 0)]
    fn wrong_word_count_is_typed_error(#[case] phrase: &str, #[case] expected: usize) {
        let err = Salt::from_mnemonic(phrase).unwrap_err();
        assert!(matches!(err, MnemonicError::WordCount { actual } if actual == expected));
    }

    #[test]
    fn unknown_word_reports_position_not_word() {
        let err = Salt::from_mnemonic(
            "abandon abandon abandon abandon abandon qwerty abandon abandon abandon abandon abandon about",
        )
        .unwrap_err();
        assert!(matches!(err, MnemonicError::UnknownWord { index: 5 }));
        assert!(!err.to_string().contains("qwerty"));
    }

    #[test]
    fn bad_checksum_is_typed_error() {
        // All-zero entropy requires the final word `about` (checksum 3), so
        // twelve `abandon`s (checksum 0) must fail the checksum, not parse.
        let err = Salt::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        )
        .unwrap_err();
        assert!(matches!(err, MnemonicError::Checksum));
    }

    #[test]
    fn decode_is_ascii_case_insensitive() {
        let lower =
            Salt::from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong").unwrap();
        let upper =
            Salt::from_mnemonic("ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO Zoo zOO WRONG").unwrap();
        assert_eq!(qb64(&upper), qb64(&lower));
    }

    #[test]
    fn decode_tolerates_arbitrary_whitespace() {
        let canonical = Salt::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let messy = Salt::from_mnemonic(
            "  abandon\tabandon abandon  abandon abandon abandon\nabandon abandon abandon abandon abandon\t about ",
        )
        .unwrap();
        assert_eq!(qb64(&messy), qb64(&canonical));
    }

    // --- wordlist integrity: pinned to the upstream bitcoin/bips bytes ---

    #[test]
    fn wordlist_is_sorted_unique_abandon_to_zoo() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(WORDS[0], "abandon");
        assert_eq!(WORDS[2047], "zoo");
        assert!(WORDS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn wordlist_matches_upstream_sha256() {
        // Reconstruct the exact upstream english.txt bytes (one word per
        // line, trailing newline) and pin their SHA-256.
        let mut text = WORDS.join("\n");
        text.push('\n');
        let digest = Sha256::digest(text.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    mod prop {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// encode → decode recovers the same salt for arbitrary entropy,
            /// and the phrase is always exactly 12 words.
            #[test]
            fn mnemonic_round_trips_any_salt(raw in proptest::array::uniform16(any::<u8>())) {
                let salt = Salt::from_raw(&raw).unwrap();
                let phrase = salt.to_mnemonic();
                prop_assert_eq!(phrase.split_ascii_whitespace().count(), 12);
                let recovered = Salt::from_mnemonic(&phrase).unwrap();
                prop_assert_eq!(qb64(&recovered), qb64(&salt));
            }
        }
    }
}
