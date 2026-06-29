use cesr_core::matter::code::VerKeyCode;
use cesr_core::primitives::{Cigar, Verfer};
use terrors::OneOf;

use crate::error::{CodeMismatchError, SignatureError};

/// Verifies `sig` over `data` using the algorithm indicated by `verfer`'s CESR code.
///
/// # Errors
///
/// Returns a [`SignatureError`] if the key or signature bytes are invalid, or a
/// [`CodeMismatchError`] if the verkey code is not yet supported (e.g., Ed448).
pub fn verify(
    verfer: &Verfer<'_>,
    data: &[u8],
    sig: &Cigar<'_>,
) -> Result<bool, OneOf<(SignatureError, CodeMismatchError)>> {
    match verfer.code() {
        VerKeyCode::Ed25519 | VerKeyCode::Ed25519N => {
            verify_ed25519(verfer.raw(), data, sig.raw()).map_err(OneOf::new)
        }
        VerKeyCode::ECDSA256k1 | VerKeyCode::ECDSA256k1N => {
            verify_secp256k1(verfer.raw(), data, sig.raw()).map_err(OneOf::new)
        }
        VerKeyCode::ECDSA256r1 | VerKeyCode::ECDSA256r1N => {
            verify_secp256r1(verfer.raw(), data, sig.raw()).map_err(OneOf::new)
        }
        VerKeyCode::Ed448 | VerKeyCode::Ed448N => {
            Err(OneOf::new(CodeMismatchError::IncompatibleCodes {
                verkey: format!("{:?}", verfer.code()),
                signature: "Ed448 not yet supported".into(),
            }))
        }
    }
}

fn verify_ed25519(key: &[u8], data: &[u8], sig: &[u8]) -> Result<bool, SignatureError> {
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
    Ok(verifying_key.verify_strict(data, &signature).is_ok())
}

fn verify_secp256k1(key: &[u8], data: &[u8], sig: &[u8]) -> Result<bool, SignatureError> {
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

    Ok(verifying_key.verify(data, &signature).is_ok())
}

fn verify_secp256r1(key: &[u8], data: &[u8], sig: &[u8]) -> Result<bool, SignatureError> {
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

    Ok(verifying_key.verify(data, &signature).is_ok())
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test assertions use unwrap for clarity"
)]
mod tests {
    use super::*;
    use crate::algo::{Ed25519, Secp256k1, Secp256r1};
    use crate::keypair::KeyPair;
    use cesr_core::matter::code::VerKeyCode;

    #[test]
    fn verify_ed25519_standalone() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let data = b"standalone verify test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();

        let result = verify(&verfer, data, &sig).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_ed25519n_standalone() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let data = b"non-transferable test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519N).unwrap();

        // Same crypto, different code -- should still verify
        let result = verify(&verfer, data, &sig).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_secp256k1_standalone() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let data = b"secp256k1 verify test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256k1).unwrap();

        let result = verify(&verfer, data, &sig).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_secp256r1_standalone() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let data = b"secp256r1 verify test";
        let sig = kp.sign(data).unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256r1).unwrap();

        let result = verify(&verfer, data, &sig).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_rejects_wrong_data_standalone() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp.sign(b"correct").unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();

        assert!(!verify(&verfer, b"wrong", &sig).unwrap());
    }

    #[test]
    fn verify_rejects_code_mismatch() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
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
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn verify_rejects_ed448_unsupported() {
        use cesr_core::matter::builder::MatterBuilder;
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed448)
            .with_raw(vec![0u8; 57])
            .unwrap()
            .build()
            .unwrap();
        let sig = MatterBuilder::new()
            .with_code(cesr_core::matter::code::SignatureCode::Ed448Sig)
            .with_raw(vec![0u8; 114])
            .unwrap()
            .build()
            .unwrap();
        let result = verify(&verfer, b"test", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_ed448n_unsupported() {
        use cesr_core::matter::builder::MatterBuilder;
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed448N)
            .with_raw(vec![0u8; 57])
            .unwrap()
            .build()
            .unwrap();
        let sig = MatterBuilder::new()
            .with_code(cesr_core::matter::code::SignatureCode::Ed448Sig)
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
        // Ed25519 verify should reject a secp256k1 signature (both are 64 bytes)
        assert!(!verify(&verfer_e, b"test", &sig_k).unwrap());
    }

    #[test]
    fn verify_ed25519_sig_with_secp256k1_verfer_fails() {
        let kp_e = KeyPair::<Ed25519>::generate().unwrap();
        let sig_e = kp_e.sign(b"test").unwrap();
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer_k = kp_k.verfer(VerKeyCode::ECDSA256k1).unwrap();
        // secp256k1 verify should fail with an Ed25519-generated signature
        let result = verify(&verfer_k, b"test", &sig_e);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn verify_ed25519_sig_with_secp256r1_verfer_fails() {
        let kp_e = KeyPair::<Ed25519>::generate().unwrap();
        let sig_e = kp_e.sign(b"test").unwrap();
        let kp_r = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer_r = kp_r.verfer(VerKeyCode::ECDSA256r1).unwrap();
        // secp256r1 verify should fail with an Ed25519-generated signature
        let result = verify(&verfer_r, b"test", &sig_e);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn verify_secp256r1_sig_with_secp256k1_verfer_fails() {
        let kp_r = KeyPair::<Secp256r1>::generate().unwrap();
        let sig_r = kp_r.sign(b"test").unwrap();
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer_k = kp_k.verfer(VerKeyCode::ECDSA256k1).unwrap();
        // secp256k1 verify should reject a secp256r1 signature
        let result = verify(&verfer_k, b"test", &sig_r);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn verify_secp256k1_sig_with_secp256r1_verfer_fails() {
        let kp_k = KeyPair::<Secp256k1>::generate().unwrap();
        let sig_k = kp_k.sign(b"test").unwrap();
        let kp_r = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer_r = kp_r.verfer(VerKeyCode::ECDSA256r1).unwrap();
        // secp256r1 verify should reject a secp256k1 signature
        let result = verify(&verfer_r, b"test", &sig_k);
        assert!(result.is_err() || !result.unwrap());
    }

    // ===== Truncated / invalid signature length tests =====
    // Signatures with wrong raw byte lengths should produce errors.

    #[test]
    fn verify_ed25519_with_truncated_sig() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        // Ed25519 signatures must be 64 bytes; 32 is too short
        let bad_sig = Matter::new_unchecked(
            cesr_core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![0u8; 32]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secp256k1_with_truncated_sig() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256k1).unwrap();
        // secp256k1 signatures must be 64 bytes; 32 is too short
        let bad_sig = Matter::new_unchecked(
            cesr_core::matter::code::SignatureCode::ECDSA256k1Sig,
            Cow::Owned(vec![0u8; 32]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secp256r1_with_truncated_sig() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256r1).unwrap();
        // secp256r1 signatures must be 64 bytes; 32 is too short
        let bad_sig = Matter::new_unchecked(
            cesr_core::matter::code::SignatureCode::ECDSA256r1Sig,
            Cow::Owned(vec![0u8; 32]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ed25519_with_oversized_sig() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        // 128 bytes is too long for a 64-byte Ed25519 signature
        let bad_sig = Matter::new_unchecked(
            cesr_core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![0u8; 128]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_with_empty_sig_bytes() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        let bad_sig = Matter::new_unchecked(
            cesr_core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_ed25519_with_invalid_public_key_length() {
        use cesr_core::matter::Matter;
        use std::borrow::Cow;
        // 16 bytes is not a valid Ed25519 public key (needs 32)
        let verfer = Matter::new_unchecked(
            VerKeyCode::Ed25519,
            Cow::Owned(vec![0u8; 16]),
            Cow::from(""),
        );
        let sig = Matter::new_unchecked(
            cesr_core::matter::code::SignatureCode::Ed25519Sig,
            Cow::Owned(vec![0u8; 64]),
            Cow::from(""),
        );
        let result = verify(&verfer, b"test", &sig);
        assert!(result.is_err());
    }
}
