use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec, vec::Vec};

use base64::{Engine, engine::general_purpose as b64};

use super::code::IndexedSigCode;
use super::xizage::XizageSize;

/// Base64 URL-safe alphabet used for integer-to-character encoding.
const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes a `u32` as a base64 string of exactly `len` characters.
///
/// Returns an empty string when `len` is 0.  Left-pads with `'A'` (= 0) when
/// the value requires fewer characters than `len`.
fn int_to_b64(value: u32, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    let mut buf = vec![b'A'; len];
    let mut v = value;
    let mut i = len;
    while v > 0 && i > 0 {
        i -= 1;
        #[allow(clippy::as_conversions, reason = "v % 64 always fits in usize")]
        let idx = (v % 64) as usize;
        buf[i] = B64_CHARS[idx];
        v /= 64;
    }
    String::from_utf8(buf.clone()).unwrap_or_default()
}

/// An indexed CESR primitive container.
///
/// Holds the decoded form of an indexed signature: the code, the signer's
/// index in the key list, an optional "other index" (ondex), and the raw
/// signature bytes.
///
/// Construct via [`IndexerBuilder`](super::builder::IndexerBuilder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indexer<'a> {
    code: IndexedSigCode,
    index: u32,
    ondex: Option<u32>, // None for CurrentOnly codes
    raw: Cow<'a, [u8]>,
}

impl<'a> Indexer<'a> {
    /// Creates a new `Indexer`. This is `pub(crate)` -- external callers must use `IndexerBuilder`.
    pub(crate) const fn new(
        code: IndexedSigCode,
        index: u32,
        ondex: Option<u32>,
        raw: Cow<'a, [u8]>,
    ) -> Self {
        Self {
            code,
            index,
            ondex,
            raw,
        }
    }

    /// Returns the indexed signature code.
    #[must_use]
    pub const fn code(&self) -> IndexedSigCode {
        self.code
    }

    /// Returns the signer's key-list index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the "other index" (prior-next key index), or `None` for `CurrentOnly` codes.
    #[must_use]
    pub const fn ondex(&self) -> Option<u32> {
        self.ondex
    }

    /// Returns the raw signature bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Returns the full CESR-encoded size in characters.
    #[must_use]
    pub fn full_size(&self) -> usize {
        match self.code.get_xizage().fs {
            XizageSize::Fixed(n) => usize::from(n),
            XizageSize::Variable => {
                unreachable!("no variable-size indexed sig codes exist")
            }
        }
    }

    /// Encodes this Indexer into its qualified Base64 (qb64) CESR wire format.
    ///
    /// The qb64 string consists of a header (code + base64-encoded index and
    /// ondex) followed by the base64-encoded raw signature bytes.
    ///
    /// # Panics
    ///
    /// Panics if the resulting string length does not match the expected full
    /// size. This indicates a bug in the sizage table or encoding logic.
    #[must_use]
    pub fn to_qb64(&self) -> String {
        let xizage = self.code.get_xizage();
        let hs = usize::from(xizage.hs);
        let ss = usize::from(xizage.ss);
        let os = usize::from(xizage.os);
        let ls = usize::from(xizage.ls);
        let fs = self.full_size();

        let ms = ss - os; // main index size in b64 chars

        // Pad size: number of zero bytes to prepend to raw before base64 encoding.
        let ps = (3 - (self.raw.len() % 3)) % 3;

        // Build the header: code string + base64-encoded index + base64-encoded ondex.
        let code_str = self.code.as_str();

        // Encode the main index (ms chars). For all 16 current codes ms >= 1.
        let index_b64 = int_to_b64(self.index, ms);

        // Encode the ondex. When os == 0, produce an empty string (no ondex on wire).
        // For CurrentOnly codes ondex is None and the `os` slot is zero-filled;
        // keripy does the same (differential-tested — see keripy_diff::indexer).
        let ondex_val = self.ondex.unwrap_or(0);
        let ondex_b64 = int_to_b64(ondex_val, os);

        let header = format!("{code_str}{index_b64}{ondex_b64}");
        debug_assert_eq!(header.len(), hs + ss);

        // Pad raw bytes and base64-encode.
        let mut padded = vec![0u8; self.raw.len() + ps];
        padded[ps..].copy_from_slice(&self.raw);
        let b64_raw = b64::URL_SAFE_NO_PAD.encode(&padded);

        // Strip leading characters: skip (ps - ls) chars from the b64 output.
        let stripped = &b64_raw[(ps - ls)..];

        let full = format!("{header}{stripped}");
        assert_eq!(
            full.len(),
            fs,
            "qb64 length {} != expected fs {} for code {:?}",
            full.len(),
            fs,
            self.code,
        );
        full
    }

    /// Encodes this Indexer into its qualified binary (qb2) CESR wire format.
    ///
    /// This is the binary counterpart of [`to_qb64`](Self::to_qb64). It
    /// produces the compact binary encoding by base64-decoding the qb64 form.
    #[must_use]
    pub fn to_qb2(&self) -> Vec<u8> {
        let qb64 = self.to_qb64();
        b64::URL_SAFE_NO_PAD.decode(qb64).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;

    use rstest::rstest;

    use super::*;
    use crate::core::indexer::builder::IndexerBuilder;

    #[test]
    fn accessors() {
        let raw = vec![0u8; 64];
        let indexer = Indexer::new(IndexedSigCode::Ed25519, 3, Some(3), Cow::Borrowed(&raw));
        assert_eq!(indexer.code(), IndexedSigCode::Ed25519);
        assert_eq!(indexer.index(), 3);
        assert_eq!(indexer.ondex(), Some(3));
        assert_eq!(indexer.raw().len(), 64);
    }

    #[test]
    fn ondex_none_for_current_only() {
        let raw = vec![0u8; 64];
        let indexer = Indexer::new(IndexedSigCode::Ed25519Crt, 5, None, Cow::Borrowed(&raw));
        assert_eq!(indexer.ondex(), None);
    }

    #[rstest]
    #[case(IndexedSigCode::Ed25519, 88)]
    #[case(IndexedSigCode::Ed25519Crt, 88)]
    #[case(IndexedSigCode::Ed448, 156)]
    #[case(IndexedSigCode::Ed25519Big, 92)]
    #[case(IndexedSigCode::Ed448Big, 160)]
    fn full_size(#[case] code: IndexedSigCode, #[case] expected: usize) {
        let raw = vec![0u8; code.raw_size()];
        let indexer = Indexer::new(code, 0, Some(0), Cow::Owned(raw));
        assert_eq!(indexer.full_size(), expected);
    }

    #[test]
    fn owned_indexer_is_static() {
        // Passing a Vec (owned data) gives Indexer<'static> naturally via Cow
        let indexer: Indexer<'static> = Indexer::new(
            IndexedSigCode::Ed25519,
            0,
            Some(0),
            Cow::Owned(vec![0u8; 64]),
        );
        assert_eq!(indexer.code(), IndexedSigCode::Ed25519);
    }

    #[test]
    fn clone_and_eq() {
        let raw = vec![0u8; 64];
        let a = Indexer::new(IndexedSigCode::Ed25519, 0, Some(0), Cow::Owned(raw));
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── to_qb64 / to_qb2 encoding tests ─────────────────────────────────

    #[test]
    fn to_qb64_cesride_vector() {
        // Known cesride test vector: Ed25519, index=0
        // Header: "AA" (code "A" + index "A"=0), followed by 86 chars of b64-encoded raw.
        let qb64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";

        // Decode to binary to extract the raw signature bytes.
        let qb2 = b64::URL_SAFE_NO_PAD.decode(qb64).unwrap();
        // qb2 is 66 bytes: 2 bytes code+index header, then 64 bytes raw.
        assert_eq!(qb2.len(), 66);
        let raw = &qb2[2..];
        assert_eq!(raw.len(), 64);

        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(raw)
            .unwrap();
        assert_eq!(indexer.to_qb64(), qb64);
    }

    #[test]
    fn to_qb64_with_nonzero_index() {
        // Ed25519 with index=5
        // header = "A" (code) + "F" (index 5 in 1-char b64) = "AF"
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(5)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 88);
        assert!(qb64.starts_with("AF")); // code "A" + index "F"(=5)
    }

    #[test]
    fn to_qb64_big_code() {
        // Ed25519Big with index=100
        // code "2A", hs=2, ss=4, os=2, ms=2
        // header = "2A" + encode_int(100, 2) + encode_int(100, 2)
        // encode_int(100, 2) = "Bk" (100 = 1*64+36, 'B'=1, 'k'=36)
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_index(100)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 92); // fs=92 for big
        assert!(qb64.starts_with("2A")); // code
    }

    #[test]
    fn to_qb2_roundtrips_with_qb64() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0xAB; 64])
            .unwrap();
        let qb64 = indexer.to_qb64();
        let qb2 = indexer.to_qb2();
        // qb2 should be the base64 decode of qb64
        let decoded = b64::URL_SAFE_NO_PAD.decode(&qb64).unwrap();
        assert_eq!(qb2, decoded);
    }

    #[rstest]
    #[case(IndexedSigCode::Ed25519)]
    #[case(IndexedSigCode::Ed25519Crt)]
    #[case(IndexedSigCode::ECDSA256k1)]
    #[case(IndexedSigCode::ECDSA256k1Crt)]
    #[case(IndexedSigCode::ECDSA256r1)]
    #[case(IndexedSigCode::ECDSA256r1Crt)]
    #[case(IndexedSigCode::Ed448)]
    #[case(IndexedSigCode::Ed448Crt)]
    #[case(IndexedSigCode::Ed25519Big)]
    #[case(IndexedSigCode::Ed25519BigCrt)]
    #[case(IndexedSigCode::ECDSA256k1Big)]
    #[case(IndexedSigCode::ECDSA256k1BigCrt)]
    #[case(IndexedSigCode::ECDSA256r1Big)]
    #[case(IndexedSigCode::ECDSA256r1BigCrt)]
    #[case(IndexedSigCode::Ed448Big)]
    #[case(IndexedSigCode::Ed448BigCrt)]
    fn full_size_matches_qb64_len(#[case] code: IndexedSigCode) {
        let raw = vec![0u8; code.raw_size()];
        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(0)
            .unwrap()
            .with_raw(&raw)
            .unwrap();
        assert_eq!(
            indexer.to_qb64().len(),
            indexer.full_size(),
            "qb64 length mismatch for code {code:?}",
        );
    }

    #[test]
    fn to_qb64_current_only_produces_valid_output() {
        // Ed25519Crt (CurrentOnly, os=0): header = "B" + index_b64
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Crt)
            .with_index(3)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 88);
        assert!(qb64.starts_with("BD")); // code "B" + index 3 = "D"
    }

    #[test]
    fn to_qb64_ed448_has_ondex_field() {
        // Ed448 (Both): hs=2, ss=2, os=1, ms=1
        // header = "0A" + encode_int(index, 1) + encode_int(ondex, 1)
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448)
            .with_index(7)
            .unwrap()
            .with_raw(&[0u8; 114])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 156);
        // header = "0A" + "H" (7) + "H" (7, ondex=index for Both)
        assert!(qb64.starts_with("0AHH"));
    }

    #[test]
    fn to_qb64_ed448_with_different_ondex() {
        // Ed448 (Both) with index=2, ondex=5
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448)
            .with_indices(2, 5)
            .unwrap()
            .with_raw(&[0u8; 114])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 156);
        // header = "0A" + "C" (2) + "F" (5)
        assert!(qb64.starts_with("0ACF"));
    }

    #[test]
    fn to_qb64_big_with_different_indices() {
        // Ed25519Big (Both) with index=10, ondex=20
        // hs=2, ss=4, os=2, ms=2
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519Big)
            .with_indices(10, 20)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 92);
        // header = "2A" + encode_int(10, 2) + encode_int(20, 2)
        // encode_int(10, 2) = "AK", encode_int(20, 2) = "AU"
        assert!(qb64.starts_with("2AAKAU"));
    }

    #[test]
    fn to_qb2_len_is_three_quarters_of_qb64() {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        let qb64_len = indexer.to_qb64().len();
        let qb2_len = indexer.to_qb2().len();
        // base64 decoding: qb2_len = qb64_len * 3 / 4
        assert_eq!(qb2_len * 4, qb64_len * 3);
    }

    #[test]
    fn to_qb64_ed448_big_code() {
        // Ed448Big: hs=2, ss=6, os=3, fs=160
        // index=1000, ondex=500
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed448Big)
            .with_indices(1000, 500)
            .unwrap()
            .with_raw(&[0xFF; 114])
            .unwrap();
        let qb64 = indexer.to_qb64();
        assert_eq!(qb64.len(), 160);
        assert!(qb64.starts_with("3A"));
    }
}
