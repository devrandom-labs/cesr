#![allow(
    dead_code,
    reason = "fields are used by downstream builder and accessors"
)]
use super::code::{CesrCode, MatterCode};
use super::error::ValidationError;
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, vec};

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
}
