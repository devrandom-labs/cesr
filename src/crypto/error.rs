#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, string::ToString};
/// Errors arising from signing or signature verification operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// The underlying cryptographic signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// The raw signature byte slice has an unexpected length.
    #[error("invalid signature bytes: expected {expected} bytes, got {actual}")]
    InvalidSignatureLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length received.
        actual: usize,
    },
    /// Signature verification failed (wrong key, tampered data, or malformed sig).
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

/// Errors arising from key generation or construction from a seed.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The raw seed byte slice has an unexpected length.
    #[error("invalid seed bytes: expected {expected} bytes, got {actual}")]
    InvalidSeedLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length received.
        actual: usize,
    },
    /// The seed bytes cannot be interpreted as a valid private key.
    #[error("invalid seed bytes: {0}")]
    InvalidSeedBytes(String),
    /// The CESR seed code does not match the expected algorithm.
    #[error("invalid seed code: expected {expected}, got {actual}")]
    InvalidSeedCode {
        /// Expected CESR seed code name.
        expected: String,
        /// Actual CESR seed code name found.
        actual: String,
    },
    /// The public key bytes cannot be parsed as a valid key for this algorithm.
    #[error("invalid public key bytes: {0}")]
    InvalidPublicKey(String),
    /// OS or algorithm key generation failed.
    #[error("key generation failed: {0}")]
    GenerationFailed(String),
    /// Building a CESR primitive from key material failed.
    #[error("key build failed: {0}")]
    BuildFailed(String),
}

/// Errors arising from digest computation.
#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    /// Building the CESR digest primitive failed.
    #[error("digest build failed: {0}")]
    BuildFailed(String),
}

/// Error produced when a verification key code and signature code are incompatible.
#[derive(Debug, thiserror::Error)]
pub enum CodeMismatchError {
    /// The verkey algorithm does not match the signature algorithm.
    #[error("verkey code {verkey} incompatible with signature code {signature}")]
    IncompatibleCodes {
        /// CESR verkey code name.
        verkey: String,
        /// CESR signature code name.
        signature: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_error_displays_signing_failed() {
        let err = SignatureError::SigningFailed("test".into());
        assert_eq!(err.to_string(), "signing failed: test");
    }

    #[test]
    fn signature_error_displays_invalid_length() {
        let err = SignatureError::InvalidSignatureLength {
            expected: 64,
            actual: 32,
        };
        assert!(err.to_string().contains("64"));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn key_error_displays_invalid_seed_length() {
        let err = KeyError::InvalidSeedLength {
            expected: 32,
            actual: 16,
        };
        assert!(err.to_string().contains("32"));
        assert!(err.to_string().contains("16"));
    }

    #[test]
    fn code_mismatch_error_displays_incompatible() {
        let err = CodeMismatchError::IncompatibleCodes {
            verkey: "Ed25519".into(),
            signature: "ECDSA256k1Sig".into(),
        };
        assert!(err.to_string().contains("Ed25519"));
        assert!(err.to_string().contains("ECDSA256k1Sig"));
    }

    // ===== Additional Display coverage =====

    #[test]
    fn key_error_displays_invalid_seed_bytes() {
        let err = KeyError::InvalidSeedBytes("some reason".into());
        assert!(err.to_string().contains("some reason"));
        assert!(err.to_string().contains("invalid seed bytes"));
    }

    #[test]
    fn key_error_displays_invalid_public_key() {
        let err = KeyError::InvalidPublicKey("bad key data".into());
        assert!(err.to_string().contains("bad key data"));
        assert!(err.to_string().contains("invalid public key"));
    }

    #[test]
    fn key_error_displays_generation_failed() {
        let err = KeyError::GenerationFailed("rng error".into());
        assert!(err.to_string().contains("rng error"));
        assert!(err.to_string().contains("generation failed"));
    }

    #[test]
    fn signature_error_displays_verification_failed() {
        let err = SignatureError::VerificationFailed("bad sig".into());
        assert!(err.to_string().contains("bad sig"));
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn key_error_displays_invalid_seed_code() {
        let err = KeyError::InvalidSeedCode {
            expected: "Ed25519Seed".into(),
            actual: "ECDSA256k1Seed".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Ed25519Seed"));
        assert!(msg.contains("ECDSA256k1Seed"));
        assert!(msg.contains("invalid seed code"));
    }

    // ===== Debug trait coverage =====

    #[test]
    fn signature_error_debug_format() {
        let err = SignatureError::SigningFailed("debug test".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("SigningFailed"));
        assert!(debug.contains("debug test"));
    }

    #[test]
    fn key_error_debug_format() {
        let err = KeyError::InvalidSeedLength {
            expected: 32,
            actual: 0,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidSeedLength"));
    }

    #[test]
    fn code_mismatch_error_debug_format() {
        let err = CodeMismatchError::IncompatibleCodes {
            verkey: "Ed25519".into(),
            signature: "ECDSA256k1Sig".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("IncompatibleCodes"));
    }
}
