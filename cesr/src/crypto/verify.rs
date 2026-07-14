use crate::core::matter::code::VerKeyCode;
use crate::core::primitives::{Siger, Verfer};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::ToString, vec};

use crate::crypto::algo::{Algorithm, Ed25519, Secp256k1, Secp256r1};
use crate::crypto::error::{
    CodeMismatchError, IndexedVerifyError, SignatureError, VerificationError,
};
use crate::crypto::signature::Signature;

/// Verifies `sig` over `data` using the algorithm indicated by `verfer`'s CESR
/// code — the verifier-key-driven entry point for KERI verification, where the
/// verifier holds only public keys.
///
/// Generic over [`Signature`], so the *same* function verifies both non-indexed
/// ([`Cigar`](crate::core::primitives::Cigar)) and indexed
/// ([`Siger`](crate::core::primitives::Siger)) signatures — the caller never
/// branches on "indexed or not". It mirrors keripy's
/// `siger.verfer.verify(siger.raw, ser)` while composing into lazy iterator
/// chains over `stream`-parsed signature groups:
/// `sigers.try_for_each(|s| verify(verfer, msg, s))`.
///
/// `Ok(())` means valid. The check is strict: the signature's code must belong
/// to `verfer`'s algorithm, otherwise [`CodeMismatchError`] is returned rather
/// than a silent failure. (For a [`Siger`](crate::core::primitives::Siger) the
/// index is CESR framing metadata and is not part of the signed payload.)
///
/// # Errors
///
/// Returns [`VerificationError::CodeMismatch`] if the signature's code does not
/// match `verfer`'s algorithm (or the verkey code is unsupported, e.g. Ed448),
/// or [`VerificationError::Signature`] wrapping [`SignatureError::Invalid`] if
/// the signature does not match — or another [`SignatureError`] if the key or
/// signature bytes are malformed.
pub fn verify<S: Signature>(
    verfer: &Verfer<'_>,
    data: &[u8],
    sig: &S,
) -> Result<(), VerificationError> {
    match verfer.code() {
        VerKeyCode::Ed25519 | VerKeyCode::Ed25519N => verify_as::<Ed25519, S>(verfer, data, sig),
        VerKeyCode::ECDSA256k1 | VerKeyCode::ECDSA256k1N => {
            verify_as::<Secp256k1, S>(verfer, data, sig)
        }
        VerKeyCode::ECDSA256r1 | VerKeyCode::ECDSA256r1N => {
            verify_as::<Secp256r1, S>(verfer, data, sig)
        }
        VerKeyCode::Ed448 | VerKeyCode::Ed448N => Err(VerificationError::CodeMismatch(
            CodeMismatchError::IncompatibleCodes {
                verkey: format!("{:?}", verfer.code()),
                signature: sig.code_name(),
            },
        )),
    }
}

/// Verifies each indexed signature against the key it addresses, lazily.
///
/// Each item is the signature's key-index on success, or the failure that stopped
/// it: the index addressed no key ([`IndexedVerifyError::IndexOutOfRange`]) or the
/// cryptographic check failed ([`IndexedVerifyError::Verification`]).
///
/// The resolve step [`verify`] cannot do alone: an indexed signature means
/// "signature by the key at position `index`", so this maps `siger.index()` onto
/// `keys[index]` and then defers to [`verify`]. Zero-alloc and borrowing — it
/// yields an iterator that holds only borrows of `keys`, `data`, and `sigs`. The
/// index is CESR framing metadata and is not part of the signed payload.
///
/// Compose threshold satisfaction over the yielded indices:
/// `verify_indexed(keys, data, sigs).collect::<Result<Vec<_>, _>>()?` then
/// `threshold.satisfied_by(indices)`.
pub fn verify_indexed<'a>(
    keys: &'a [Verfer<'a>],
    data: &'a [u8],
    sigs: impl IntoIterator<Item = &'a Siger<'a>> + 'a,
) -> impl Iterator<Item = Result<u32, IndexedVerifyError>> + 'a {
    sigs.into_iter().map(move |sig| {
        let index = sig.index();
        let out_of_range = || IndexedVerifyError::IndexOutOfRange {
            index,
            key_count: keys.len(),
        };
        let position = usize::try_from(index).map_err(|_| out_of_range())?;
        let key = keys.get(position).ok_or_else(out_of_range)?;
        verify(key, data, sig)?;
        Ok(index)
    })
}

/// Verifies `sig` as algorithm `A`: strict code-ownership check, then the
/// compile-time-dispatched per-curve crypto via [`Algorithm::verify_bytes`].
fn verify_as<A: Algorithm, S: Signature>(
    verfer: &Verfer<'_>,
    data: &[u8],
    sig: &S,
) -> Result<(), VerificationError> {
    if !sig.belongs_to::<A>() {
        return Err(VerificationError::CodeMismatch(
            CodeMismatchError::IncompatibleCodes {
                verkey: format!("{:?}", verfer.code()),
                signature: sig.code_name(),
            },
        ));
    }
    A::verify_bytes(verfer.raw(), data, sig.raw()).map_err(VerificationError::from)
}

pub(crate) fn verify_ed25519(key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk_bytes: [u8; 32] = key.try_into().map_err(|_| {
        SignatureError::VerificationFailed(format!(
            "invalid Ed25519 public key length: {}",
            key.len()
        ))
    })?;

    let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))?;

    let sig_bytes: [u8; 64] =
        sig.try_into()
            .map_err(|_| SignatureError::InvalidSignatureLength {
                expected: 64,
                actual: sig.len(),
            })?;

    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(data, &signature)
        .map_err(|_| SignatureError::Invalid)
}

pub(crate) fn verify_secp256k1(key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};

    let verifying_key = VerifyingKey::from_sec1_bytes(key)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))?;

    if sig.len() != 64 {
        return Err(SignatureError::InvalidSignatureLength {
            expected: 64,
            actual: sig.len(),
        });
    }

    let signature = Signature::from_slice(sig)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))?;

    verifying_key
        .verify(data, &signature)
        .map_err(|_| SignatureError::Invalid)
}

pub(crate) fn verify_secp256r1(key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};

    let verifying_key = VerifyingKey::from_sec1_bytes(key)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))?;

    if sig.len() != 64 {
        return Err(SignatureError::InvalidSignatureLength {
            expected: 64,
            actual: sig.len(),
        });
    }

    let signature = Signature::from_slice(sig)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))?;

    verifying_key
        .verify(data, &signature)
        .map_err(|_| SignatureError::Invalid)
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test assertions use unwrap for clarity"
)]
mod tests {
    use super::*;
    use crate::core::indexer::code::IndexMode;
    use crate::core::matter::code::VerKeyCode;
    use crate::core::primitives::Siger;
    use crate::crypto::algo::{Ed25519, Secp256k1, Secp256r1};
    use crate::crypto::keypair::KeyPair;
    use crate::keri::SigningThreshold;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn verify_ed25519_standalone() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let data = b"standalone verify test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();

        verify(&verfer, data, &sig).unwrap();
    }

    #[test]
    fn verify_ed25519n_standalone() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let data = b"non-transferable test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519N).unwrap();

        // Same crypto, different code -- should still verify
        verify(&verfer, data, &sig).unwrap();
    }

    #[test]
    fn verify_secp256k1_standalone() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let data = b"secp256k1 verify test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256k1).unwrap();

        verify(&verfer, data, &sig).unwrap();
    }

    #[test]
    fn verify_secp256r1_standalone() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let data = b"secp256r1 verify test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256r1).unwrap();

        verify(&verfer, data, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_data_standalone() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp.sign(b"correct").unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();

        let err = verify(&verfer, b"wrong", &sig).err().unwrap();
        assert!(matches!(
            err,
            VerificationError::Signature(SignatureError::Invalid)
        ));
    }

    #[test]
    fn verify_rejects_code_mismatch() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp.sign(b"test").unwrap();
        // Use ECDSA verfer code with Ed25519 key bytes -- should fail.
        // Bypass builder validation since Ed25519 key (32 bytes) doesn't
        // match ECDSA256k1's expected raw_size (33 bytes).
        let ed_verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        let verfer = Matter::new_unchecked(
            VerKeyCode::ECDSA256k1,
            Cow::Owned(ed_verfer.raw().to_vec()),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &sig);
        // This should either fail to verify or return an error
        // since the key bytes are Ed25519 but we're treating them as ECDSA
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_ed448_unsupported() {
        use crate::core::matter::builder::MatterBuilder;
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed448)
            .with_raw(vec![0u8; 57])
            .unwrap()
            .build()
            .unwrap();
        let sig = MatterBuilder::new()
            .with_code(crate::core::matter::code::SignatureCode::Ed448Sig)
            .with_raw(vec![0u8; 114])
            .unwrap()
            .build()
            .unwrap();
        let result = verify(&verfer, b"test", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_ed448n_unsupported() {
        use crate::core::matter::builder::MatterBuilder;
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed448N)
            .with_raw(vec![0u8; 57])
            .unwrap()
            .build()
            .unwrap();
        let sig = MatterBuilder::new()
            .with_code(crate::core::matter::code::SignatureCode::Ed448Sig)
            .with_raw(vec![0u8; 114])
            .unwrap()
            .build()
            .unwrap();
        let result = verify(&verfer, b"test", &sig);
        assert!(result.is_err());
    }

    // ===== Cross-algorithm rejection tests =====
    // Signatures produced by one algorithm must not verify with another
    // algorithm's key, even if the raw byte sizes happen to match.

    #[test]
    fn verify_secp256k1_sig_with_ed25519_verfer_fails() {
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let sig_k = kp_k.sign(b"test").unwrap();
        let kp_e = KeyPair::<Ed25519>::generate().unwrap();
        let verfer_e = kp_e.verfer(VerKeyCode::Ed25519).unwrap();
        // Strict: the secp256k1 signature code does not belong to Ed25519, so it
        // is rejected as a code mismatch before any crypto is attempted.
        let err = verify(&verfer_e, b"test", &sig_k).err().unwrap();
        assert!(matches!(
            err,
            VerificationError::CodeMismatch(CodeMismatchError::IncompatibleCodes { .. })
        ));
    }

    #[test]
    fn verify_ed25519_sig_with_secp256k1_verfer_fails() {
        let kp_e = KeyPair::<Ed25519>::generate().unwrap();
        let sig_e = kp_e.sign(b"test").unwrap();
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer_k = kp_k.verfer(VerKeyCode::ECDSA256k1).unwrap();
        // secp256k1 verify should fail with an Ed25519-generated signature
        let result = verify(&verfer_k, b"test", &sig_e);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ed25519_sig_with_secp256r1_verfer_fails() {
        let kp_e = KeyPair::<Ed25519>::generate().unwrap();
        let sig_e = kp_e.sign(b"test").unwrap();
        let kp_r = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer_r = kp_r.verfer(VerKeyCode::ECDSA256r1).unwrap();
        // secp256r1 verify should fail with an Ed25519-generated signature
        let result = verify(&verfer_r, b"test", &sig_e);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secp256r1_sig_with_secp256k1_verfer_fails() {
        let kp_r = KeyPair::<Secp256r1>::generate().unwrap();
        let sig_r = kp_r.sign(b"test").unwrap();
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer_k = kp_k.verfer(VerKeyCode::ECDSA256k1).unwrap();
        // secp256k1 verify should reject a secp256r1 signature
        let result = verify(&verfer_k, b"test", &sig_r);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secp256k1_sig_with_secp256r1_verfer_fails() {
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let sig_k = kp_k.sign(b"test").unwrap();
        let kp_r = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer_r = kp_r.verfer(VerKeyCode::ECDSA256r1).unwrap();
        // secp256r1 verify should reject a secp256k1 signature
        let result = verify(&verfer_r, b"test", &sig_k);
        assert!(result.is_err());
    }

    // ===== Truncated / invalid signature length tests =====
    // Signatures with wrong raw byte lengths should produce errors.

    #[test]
    fn verify_ed25519_with_truncated_sig() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        // Ed25519 signatures must be 64 bytes; 32 is too short
        let bad_sig = Matter::new_unchecked(
            crate::core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![0u8; 32]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secp256k1_with_truncated_sig() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256k1).unwrap();
        // secp256k1 signatures must be 64 bytes; 32 is too short
        let bad_sig = Matter::new_unchecked(
            crate::core::matter::code::SignatureCode::ECDSA256k1Sig,
            Cow::Owned(vec![0u8; 32]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secp256r1_with_truncated_sig() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256r1).unwrap();
        // secp256r1 signatures must be 64 bytes; 32 is too short
        let bad_sig = Matter::new_unchecked(
            crate::core::matter::code::SignatureCode::ECDSA256r1Sig,
            Cow::Owned(vec![0u8; 32]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ed25519_with_oversized_sig() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        // 128 bytes is too long for a 64-byte Ed25519 signature
        let bad_sig = Matter::new_unchecked(
            crate::core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![0u8; 128]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_with_empty_sig_bytes() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        let bad_sig = Matter::new_unchecked(
            crate::core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ed25519_with_invalid_public_key_length() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        // 16 bytes is not a valid Ed25519 public key (needs 32)
        let verfer = Matter::new_unchecked(
            VerKeyCode::Ed25519,
            Cow::Owned(vec![0u8; 16]),
            Cow::from(""),
        );
        let sig = Matter::new_unchecked(
            crate::core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![0u8; 64]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &sig);
        assert!(result.is_err());
    }

    // ===== Verfer-driven indexed verification (verify_indexed) =====

    #[test]
    fn verify_indexed_with_key_state_verfer() {
        // The KERI verification model: verify against a verfer held from key
        // state, not the KeyPair. Works with only the public key.
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"event", 0, IndexMode::Both).unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();

        verify(&verfer, b"event", &siger).unwrap();
    }

    #[test]
    fn verify_indexed_using_sigers_own_verfer() {
        // sign_indexed attaches the signer's verfer; keripy's
        // `siger.verfer.verify(siger.raw, ser)` shape.
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let siger = kp
            .sign_indexed(b"event", 2, IndexMode::CurrentOnly)
            .unwrap();
        let verfer = siger.verfer().unwrap();

        verify(verfer, b"event", &siger).unwrap();
    }

    #[test]
    fn verify_indexed_rejects_tampered_data() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let siger = kp.sign_indexed(b"correct", 0, IndexMode::Both).unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256r1).unwrap();

        let err = verify(&verfer, b"tampered", &siger).err().unwrap();
        assert!(matches!(
            err,
            VerificationError::Signature(SignatureError::Invalid)
        ));
    }

    #[test]
    fn verify_indexed_rejects_cross_algorithm_code() {
        // Strict: an Ed25519 verfer must reject a secp256k1 Siger by code,
        // surfacing CodeMismatchError rather than a crypto failure.
        let k1 = KeyPair::<Secp256k1>::generate().unwrap();
        let k1_siger = k1.sign_indexed(b"event", 0, IndexMode::Both).unwrap();
        let ed = KeyPair::<Ed25519>::generate().unwrap();
        let ed_verfer = ed.verfer(VerKeyCode::Ed25519).unwrap();

        let err = verify(&ed_verfer, b"event", &k1_siger).err().unwrap();
        assert!(matches!(
            err,
            VerificationError::CodeMismatch(CodeMismatchError::IncompatibleCodes { .. })
        ));
    }

    #[test]
    fn verify_indexed_composes_lazily_over_a_signature_group() {
        // The whole point: a group of indexed sigs verifies through a lazy
        // iterator chain that short-circuits on the first failure and folds
        // the `()` successes away. No intermediate allocation.
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        let msg = b"shared event bytes";

        let sigers = [
            kp.sign_indexed(msg, 0, IndexMode::Both).unwrap(),
            kp.sign_indexed(msg, 1, IndexMode::Both).unwrap(),
            kp.sign_indexed(msg, 2, IndexMode::Both).unwrap(),
        ];

        sigers
            .iter()
            .try_for_each(|s| verify(&verfer, msg, s))
            .unwrap();

        // One tampered signature (from a different key) short-circuits the fold.
        let other = KeyPair::<Ed25519>::generate().unwrap();
        let bad = other.sign_indexed(msg, 1, IndexMode::Both).unwrap();
        let mixed = [
            kp.sign_indexed(msg, 0, IndexMode::Both).unwrap(),
            bad,
            kp.sign_indexed(msg, 2, IndexMode::Both).unwrap(),
        ];
        let result = mixed.iter().try_for_each(|s| verify(&verfer, msg, s));
        assert!(result.is_err());
    }

    // ── verify_indexed combinator ─────────────────────────────────────────

    fn keyed_group(msg: &[u8], n: u32) -> (Vec<Verfer<'static>>, Vec<Siger<'static>>) {
        let mut keys = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..n {
            let kp = KeyPair::<Ed25519>::generate().unwrap();
            keys.push(kp.verfer(VerKeyCode::Ed25519).unwrap().into_static());
            sigs.push(kp.sign_indexed(msg, i, IndexMode::Both).unwrap());
        }
        (keys, sigs)
    }

    #[test]
    fn verify_indexed_yields_each_verified_index_in_order() {
        let msg = b"shared event bytes";
        let (keys, sigs) = keyed_group(msg, 3);
        let got: Result<Vec<u32>, _> = verify_indexed(&keys, msg, &sigs).collect();
        assert_eq!(got.unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn verify_indexed_rejects_out_of_range_index() {
        let msg = b"event";
        // Two keys, but a signature indexed at position 2 (== key_count).
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let keys = vec![
            kp.verfer(VerKeyCode::Ed25519).unwrap().into_static(),
            kp.verfer(VerKeyCode::Ed25519).unwrap().into_static(),
        ];
        let sigs = [kp.sign_indexed(msg, 2, IndexMode::Both).unwrap()];
        let err = verify_indexed(&keys, msg, &sigs)
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            IndexedVerifyError::IndexOutOfRange {
                index: 2,
                key_count: 2
            }
        ));
    }

    #[test]
    fn verify_indexed_rejects_signature_from_the_wrong_key() {
        let msg = b"event";
        // key at position 0 is a DIFFERENT key than the one that signed index 0.
        let signer = KeyPair::<Ed25519>::generate().unwrap();
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        let keys = vec![impostor.verfer(VerKeyCode::Ed25519).unwrap().into_static()];
        let sigs = [signer.sign_indexed(msg, 0, IndexMode::Both).unwrap()];
        let err = verify_indexed(&keys, msg, &sigs)
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, IndexedVerifyError::Verification(_)));
    }

    #[test]
    fn verify_indexed_fails_fast_on_first_bad_signature() {
        let msg = b"event";
        let (mut keys, mut sigs) = keyed_group(msg, 3);
        // Replace the middle signature with one from an unrelated key.
        let impostor = KeyPair::<Ed25519>::generate().unwrap();
        sigs[1] = impostor.sign_indexed(msg, 1, IndexMode::Both).unwrap();
        keys[1] = KeyPair::<Ed25519>::generate()
            .unwrap()
            .verfer(VerKeyCode::Ed25519)
            .unwrap()
            .into_static();
        let got: Result<Vec<u32>, _> = verify_indexed(&keys, msg, &sigs).collect();
        assert!(matches!(got, Err(IndexedVerifyError::Verification(_))));
    }

    #[test]
    fn verify_indexed_composes_with_tholder_satisfy() {
        let msg = b"shared event bytes";
        let (keys, sigs) = keyed_group(msg, 3);
        let indices: Vec<u32> = verify_indexed(&keys, msg, &sigs)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(SigningThreshold::Simple(3).satisfied_by(indices.iter().copied()));
        assert!(!SigningThreshold::Simple(4).satisfied_by(indices));
    }
}
