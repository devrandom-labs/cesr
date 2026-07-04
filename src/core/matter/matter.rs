#![allow(
    dead_code,
    reason = "fields are used by downstream builder and accessors"
)]
use super::code::{CesrCode, MatterCode};
use super::error::ValidationError;
use super::sizage::SizeType;
use alloc::borrow::Cow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};

/// A CESR-encoded primitive with typed code `C`, a raw payload, and an optional soft field.
#[derive(Clone)]
pub struct Matter<'a, C: CesrCode> {
    code: C,
    raw: Cow<'a, [u8]>,
    soft: Cow<'a, str>,
}

impl<'a, C: CesrCode> Matter<'a, C> {
    /// B64 pad char for special codes with xtra size pre-padded soft values
    pub const PAD: &'static str = "_";

    #[must_use]
    pub(crate) const fn new(code: C, raw: Cow<'a, [u8]>, soft: Cow<'a, str>) -> Self {
        Self { code, raw, soft }
    }

    /// Returns the CESR code of this primitive.
    #[must_use]
    pub const fn code(&self) -> &C {
        &self.code
    }

    /// Returns the soft (variable-length metadata) field of this primitive.
    #[must_use]
    pub fn soft(&self) -> &str {
        self.soft.as_ref()
    }

    /// Returns the raw binary payload of this primitive.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.raw.as_ref()
    }

    /// Construct a `Matter` without validation. Only available with the
    /// `test-utils` feature — intended for tests that need to create
    /// intentionally malformed primitives (e.g. wrong-size signatures).
    #[cfg(feature = "test-utils")]
    pub const fn new_unchecked(code: C, raw: Cow<'a, [u8]>, soft: Cow<'a, str>) -> Self {
        Self { code, raw, soft }
    }
}

impl<C: CesrCode> Matter<'_, C> {
    /// Encodes this primitive into its qualified Base64 (qb64) CESR wire
    /// format as bytes (`qb64b`).
    ///
    /// The output is allocated once at the final size `fs`; the Base64 payload
    /// is written directly into it, then the header (code + soft field) is
    /// written over the first `cs` bytes. Supports all fixed- and variable-size
    /// CESR codes.
    ///
    /// # Panics
    ///
    /// Panics only on an internal-invariant break (a corrupt sizage table or a
    /// mis-sized output buffer) — impossible for any `Matter` built through the
    /// validated builder. This mirrors [`Indexer::to_qb64`] and is the
    /// programmer-bug carve-out, not a data-validation path.
    #[must_use]
    pub fn to_qb64b(&self) -> Vec<u8> {
        let sizage = self.code.get_sizage();
        let hs = sizage.hs();
        let ss = sizage.ss();
        let xs = sizage.xs();
        let ls = sizage.ls();
        let cs = hs + ss;
        let ps = cs % 4;

        let code_str = self.code.as_str();
        let raw = self.raw();

        let fs = match sizage.fs() {
            SizeType::Fixed(fixed) => usize::from(*fixed),
            SizeType::Small | SizeType::Large => {
                let raw_with_lead = raw.len() + ls;
                let quadlets = raw_with_lead.div_ceil(3);
                (quadlets * 4) + cs
            }
        };

        // Base64-encode `[ls+ps zero bytes] ++ raw`. The leading zero bytes
        // realign the payload to a 3-byte boundary; their Base64 image is `ps`
        // pad chars that land in the header region and are overwritten below.
        let pad_len = ls + ps;
        let mut padded = Vec::with_capacity(pad_len + raw.len());
        padded.resize(pad_len, 0);
        padded.extend_from_slice(raw);

        let mut out = vec![0u8; fs];
        let b64_start = cs - ps;
        let Ok(written) = URL_SAFE_NO_PAD.encode_slice(&padded, &mut out[b64_start..]) else {
            unreachable!("qb64 output buffer is sized to fs; base64 cannot overflow")
        };
        assert_eq!(
            b64_start + written,
            fs,
            "qb64 length mismatch for code {code_str}: expected {fs}, got {}",
            b64_start + written
        );

        out[..hs].copy_from_slice(code_str.as_bytes());
        if ss > 0 {
            out[hs..hs + xs].fill(b'_');
            out[hs + xs..cs].copy_from_slice(self.soft().as_bytes());
        }
        out
    }

    /// Encodes this primitive into its qualified Base64 (qb64) CESR wire format
    /// as a `String`.
    ///
    /// qb64 output is pure ASCII (URL-safe Base64 alphabet + CESR code chars),
    /// so UTF-8 validity is guaranteed by construction.
    ///
    /// # Panics
    ///
    /// Never, in practice: see [`Self::to_qb64b`]. The `from_utf8` step cannot
    /// fail because qb64 bytes are ASCII.
    #[must_use]
    pub fn to_qb64(&self) -> String {
        let Ok(s) = String::from_utf8(self.to_qb64b()) else {
            unreachable!("qb64 bytes are ASCII (base64 alphabet + CESR code chars)")
        };
        s
    }
}

impl<C: CesrCode> Matter<'_, C> {
    /// Convert to `Matter<'static>` by owning any borrowed fields.
    ///
    /// Near-zero cost: `raw` is always already owned (base64 decode produces
    /// new bytes), so only the `soft` field (0-4 bytes for most codes) is
    /// cloned when borrowed.
    pub fn into_static(self) -> Matter<'static, C> {
        let raw: Cow<'static, [u8]> = match self.raw {
            Cow::Owned(v) => Cow::Owned(v),
            Cow::Borrowed(b) => Cow::Owned(b.to_vec()),
        };
        let soft: Cow<'static, str> = match self.soft {
            Cow::Owned(s) => Cow::Owned(s),
            Cow::Borrowed("") => Cow::Borrowed(""),
            Cow::Borrowed(s) => Cow::Owned(s.to_owned()),
        };
        Matter::new(self.code, raw, soft)
    }
}

impl<'a> Matter<'a, MatterCode> {
    /// Converts this untyped `Matter<MatterCode>` into a typed `Matter<C>`.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] if the code cannot be narrowed to `C`.
    pub fn narrow<C>(self) -> Result<Matter<'a, C>, ValidationError>
    where
        C: CesrCode + TryFrom<MatterCode, Error = ValidationError>,
    {
        let code = C::try_from(self.code)?;
        Ok(Matter {
            code,
            raw: self.raw,
            soft: self.soft,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::{
        DigestCode, MatterCode, NumberCode, SeedCode, SignatureCode, VerKeyCode,
    };
    use alloc::borrow::Cow;
    use rstest::rstest;

    #[test]
    fn typed_matter_holds_correct_code_type() {
        let code = VerKeyCode::Ed25519;
        let raw = vec![0u8; 32];
        let m: Matter<'_, VerKeyCode> = Matter::new(code, Cow::Owned(raw), Cow::from(""));
        assert_eq!(*m.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn untyped_matter_holds_any_code() {
        let code = MatterCode::Blake3_256;
        let raw = vec![0u8; 32];
        let m: Matter<'_, MatterCode> = Matter::new(code, Cow::Owned(raw), Cow::from(""));
        assert_eq!(*m.code(), MatterCode::Blake3_256);
    }

    #[test]
    fn narrow_untyped_to_verkey() {
        let code = MatterCode::Ed25519;
        let raw = vec![0u8; 32];
        let untyped = Matter::new(code, Cow::Owned(raw), Cow::from(""));
        let typed: Matter<'_, VerKeyCode> = untyped.narrow().unwrap();
        assert_eq!(*typed.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn narrow_rejects_wrong_code_family() {
        let code = MatterCode::Blake3_256;
        let raw = vec![0u8; 32];
        let untyped = Matter::new(code, Cow::Owned(raw), Cow::from(""));
        let result: Result<Matter<'_, VerKeyCode>, _> = untyped.narrow();
        assert!(result.is_err());
    }

    // --- Successful narrowing for all typed code families ---

    #[rstest]
    #[case(MatterCode::Ed25519, VerKeyCode::Ed25519)]
    #[case(MatterCode::Ed25519N, VerKeyCode::Ed25519N)]
    #[case(MatterCode::ECDSA256k1, VerKeyCode::ECDSA256k1)]
    #[case(MatterCode::ECDSA256k1N, VerKeyCode::ECDSA256k1N)]
    #[case(MatterCode::Ed448, VerKeyCode::Ed448)]
    #[case(MatterCode::Ed448N, VerKeyCode::Ed448N)]
    #[case(MatterCode::ECDSA256r1, VerKeyCode::ECDSA256r1)]
    #[case(MatterCode::ECDSA256r1N, VerKeyCode::ECDSA256r1N)]
    fn narrow_to_verkey_succeeds(#[case] matter_code: MatterCode, #[case] expected: VerKeyCode) {
        let matter = Matter::new(matter_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let typed: Matter<VerKeyCode> = matter.narrow().unwrap();
        assert_eq!(*typed.code(), expected);
    }

    #[rstest]
    #[case(MatterCode::Blake3_256, DigestCode::Blake3_256)]
    #[case(MatterCode::Blake2b_256, DigestCode::Blake2b_256)]
    #[case(MatterCode::Blake2s_256, DigestCode::Blake2s_256)]
    #[case(MatterCode::SHA3_256, DigestCode::SHA3_256)]
    #[case(MatterCode::SHA2_256, DigestCode::SHA2_256)]
    #[case(MatterCode::Blake3_512, DigestCode::Blake3_512)]
    #[case(MatterCode::Blake2b_512, DigestCode::Blake2b_512)]
    #[case(MatterCode::SHA3_512, DigestCode::SHA3_512)]
    #[case(MatterCode::SHA2_512, DigestCode::SHA2_512)]
    fn narrow_to_digest_succeeds(#[case] matter_code: MatterCode, #[case] expected: DigestCode) {
        let matter = Matter::new(matter_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let typed: Matter<DigestCode> = matter.narrow().unwrap();
        assert_eq!(*typed.code(), expected);
    }

    #[rstest]
    #[case(MatterCode::Ed25519Sig, SignatureCode::Ed25519Sig)]
    #[case(MatterCode::ECDSA256k1Sig, SignatureCode::ECDSA256k1Sig)]
    #[case(MatterCode::ECDSA256r1Sig, SignatureCode::ECDSA256r1Sig)]
    #[case(MatterCode::Ed448Sig, SignatureCode::Ed448Sig)]
    fn narrow_to_signature_succeeds(
        #[case] matter_code: MatterCode,
        #[case] expected: SignatureCode,
    ) {
        let matter = Matter::new(matter_code, Cow::Owned(vec![0u8; 64]), Cow::from(""));
        let typed: Matter<SignatureCode> = matter.narrow().unwrap();
        assert_eq!(*typed.code(), expected);
    }

    #[rstest]
    #[case(MatterCode::Ed25519Seed, SeedCode::Ed25519Seed)]
    #[case(MatterCode::ECDSA256k1Seed, SeedCode::ECDSA256k1Seed)]
    #[case(MatterCode::Ed448Seed, SeedCode::Ed448Seed)]
    #[case(MatterCode::ECDSA256r1Seed, SeedCode::ECDSA256r1Seed)]
    fn narrow_to_seed_succeeds(#[case] matter_code: MatterCode, #[case] expected: SeedCode) {
        let matter = Matter::new(matter_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let typed: Matter<SeedCode> = matter.narrow().unwrap();
        assert_eq!(*typed.code(), expected);
    }

    #[rstest]
    #[case(MatterCode::Short, NumberCode::Short)]
    #[case(MatterCode::Long, NumberCode::Long)]
    #[case(MatterCode::Tall, NumberCode::Tall)]
    #[case(MatterCode::Big, NumberCode::Big)]
    #[case(MatterCode::Large, NumberCode::Large)]
    #[case(MatterCode::Great, NumberCode::Great)]
    #[case(MatterCode::Vast, NumberCode::Vast)]
    fn narrow_to_number_succeeds(#[case] matter_code: MatterCode, #[case] expected: NumberCode) {
        let matter = Matter::new(matter_code, Cow::Owned(vec![0u8; 2]), Cow::from(""));
        let typed: Matter<NumberCode> = matter.narrow().unwrap();
        assert_eq!(*typed.code(), expected);
    }

    // --- Failed narrowing — wrong family ---

    #[rstest]
    #[case(MatterCode::Blake3_256)]
    #[case(MatterCode::Ed25519Sig)]
    #[case(MatterCode::Short)]
    #[case(MatterCode::Ed25519Seed)]
    fn narrow_to_verkey_rejects_wrong_family(#[case] wrong_code: MatterCode) {
        let matter = Matter::new(wrong_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let result: Result<Matter<VerKeyCode>, _> = matter.narrow();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(MatterCode::Ed25519)]
    #[case(MatterCode::Ed25519Sig)]
    #[case(MatterCode::Short)]
    fn narrow_to_digest_rejects_wrong_family(#[case] wrong_code: MatterCode) {
        let matter = Matter::new(wrong_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let result: Result<Matter<DigestCode>, _> = matter.narrow();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(MatterCode::Ed25519)]
    #[case(MatterCode::Blake3_256)]
    fn narrow_to_signature_rejects_wrong_family(#[case] wrong_code: MatterCode) {
        let matter = Matter::new(wrong_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let result: Result<Matter<SignatureCode>, _> = matter.narrow();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(MatterCode::Ed25519)]
    #[case(MatterCode::Blake3_256)]
    fn narrow_to_seed_rejects_wrong_family(#[case] wrong_code: MatterCode) {
        let matter = Matter::new(wrong_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let result: Result<Matter<SeedCode>, _> = matter.narrow();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(MatterCode::Ed25519)]
    #[case(MatterCode::Blake3_256)]
    fn narrow_to_number_rejects_wrong_family(#[case] wrong_code: MatterCode) {
        let matter = Matter::new(wrong_code, Cow::Owned(vec![0u8; 32]), Cow::from(""));
        let result: Result<Matter<NumberCode>, _> = matter.narrow();
        assert!(result.is_err());
    }

    mod to_qb64 {
        use super::*;
        use crate::core::matter::builder::MatterBuilder;
        use crate::core::matter::code::{MatterCode, VerKeyCode};
        use alloc::format;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        fn build_and_check(expected: &[u8]) {
            let matter = MatterBuilder::new()
                .from_qualified_base64(expected)
                .expect("valid qb64 should parse");
            assert_eq!(matter.to_qb64b(), expected, "to_qb64b mismatch");
            assert_eq!(matter.to_qb64().as_bytes(), expected, "to_qb64 mismatch");
            assert_eq!(
                matter.to_qb64().into_bytes(),
                matter.to_qb64b(),
                "to_qb64 and to_qb64b disagree"
            );
        }

        fn fixed_qb64(code_char: &str, raw: &[u8], ps: usize) -> Vec<u8> {
            let mut padded = vec![0u8; ps];
            padded.extend_from_slice(raw);
            let payload_b64 = B64.encode(&padded);
            format!("{code_char}{}", &payload_b64[ps..]).into_bytes()
        }

        #[test]
        fn ed25519_verkey_roundtrip() {
            build_and_check(&fixed_qb64("D", &[0xABu8; 32], 1));
        }

        #[test]
        fn ed25519_sig_roundtrip() {
            build_and_check(&fixed_qb64("0B", &[0xEFu8; 64], 2));
        }

        #[test]
        fn blake3_256_digest_roundtrip() {
            build_and_check(&fixed_qb64("E", &[0xCDu8; 32], 1));
        }

        #[test]
        fn short_number_roundtrip() {
            build_and_check(b"MAAB");
        }

        #[test]
        fn strb64_variable_soft_roundtrip() {
            build_and_check(b"4AACnhE8oa_r");
        }

        #[test]
        fn lead_byte_code_roundtrip() {
            // exercises the ls>0 lead-byte path
            // Label1 (code "V", ls=1) qb64 vector from test_vectors::FIXED_VECTORS.
            build_and_check(b"VAAt");
        }

        #[test]
        fn xtra_underscore_code_roundtrip() {
            // exercises the xs>0 underscore-fill path
            // Tag1 (code "0J", ss=2, xs=1) qb64 vector from test_vectors::FIXED_VECTORS.
            build_and_check(b"0J_A");
        }

        #[test]
        fn narrowed_verkey_encodes_same_as_untyped() {
            let qb64 = b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let untyped = MatterBuilder::new()
                .from_qualified_base64(&qb64[..])
                .expect("valid qb64");
            assert_eq!(*untyped.code(), MatterCode::Ed25519);
            let typed: Matter<'_, VerKeyCode> = untyped.narrow().expect("narrow to verkey");
            assert_eq!(typed.to_qb64b(), qb64, "typed to_qb64b mismatch");
        }
    }
}
