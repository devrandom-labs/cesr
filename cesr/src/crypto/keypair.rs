#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::ToString, vec, vec::Vec};
use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::core::indexer::IndexerBuilder;
use crate::core::indexer::code::IndexMode;
use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{SeedCode, SignatureCode, VerKeyCode};
use crate::core::primitives::{Cigar, Siger, Signer, Verfer};

use crate::crypto::algo::{Algorithm, Ed25519, Secp256k1, Secp256r1};
use crate::crypto::error::{KeyError, SignatureError};
use crate::crypto::signature::Signature;

/// A signing/verification key pair for algorithm `A`, with zeroed secret on drop.
pub struct KeyPair<A: Algorithm> {
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    _algo: PhantomData<A>,
}

impl<A: Algorithm> KeyPair<A> {
    /// Returns a CESR-encoded verification key primitive with the given code.
    ///
    /// # Errors
    ///
    /// Returns an error if the `MatterBuilder` fails to construct the verifier primitive.
    pub fn verfer(&self, code: VerKeyCode) -> Result<Verfer<'_>, KeyError> {
        MatterBuilder::new()
            .with_code(code)
            .with_raw(&self.public[..])
            .map_err(|e| KeyError::BuildFailed(e.to_string()))?
            .build()
            .map_err(|e| KeyError::BuildFailed(e.to_string()))
    }

    /// Returns a CESR-encoded seed primitive for the algorithm's private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the `MatterBuilder` fails to construct the signer primitive.
    pub fn signer(&self) -> Result<Signer<'_>, KeyError> {
        MatterBuilder::new()
            .with_code(A::SEED_CODE)
            .with_raw(self.secret.as_slice())
            .map_err(|e| KeyError::BuildFailed(e.to_string()))?
            .build()
            .map_err(|e| KeyError::BuildFailed(e.to_string()))
    }
}

impl<A: Algorithm> KeyPair<A> {
    /// Verifies `sig` over `data` against this key pair's public key.
    ///
    /// One method for both non-indexed ([`Cigar`]) and indexed ([`Siger`])
    /// signatures — `S` is inferred from the argument and the per-curve crypto
    /// is dispatched on `A` at compile time. `Ok(())` means the signature is
    /// valid; a failed verification is an [`Err`], never a silent `Ok`, so it
    /// flows into `?` and `iter().try_for_each(..)`.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::CodeMismatch`] if the signature's code does not
    /// belong to `A`, [`SignatureError::Invalid`] if the signature does not
    /// match, or another [`SignatureError`] if the key or signature bytes are
    /// malformed.
    pub fn verify<S: Signature>(&self, data: &[u8], sig: &S) -> Result<(), SignatureError> {
        if !sig.belongs_to::<A>() {
            return Err(SignatureError::CodeMismatch {
                expected: A::NAME.into(),
                actual: sig.code_name(),
            });
        }
        A::verify_bytes(&self.public, data, sig.raw())
    }
}

impl KeyPair<Ed25519> {
    /// Generates a fresh Ed25519 key pair using the OS random number generator.
    ///
    /// # Errors
    ///
    /// Returns an error if OS random number generation fails.
    pub fn generate() -> Result<Self, KeyError> {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public = signing_key.verifying_key().to_bytes().to_vec();
        let secret = Zeroizing::new(signing_key.to_bytes().to_vec());

        Ok(Self {
            secret,
            public,
            _algo: PhantomData,
        })
    }

    /// Reconstructs an Ed25519 key pair from a CESR seed primitive.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed has the wrong code or invalid byte length.
    pub fn from_seed(seed: &Signer<'_>) -> Result<Self, KeyError> {
        use ed25519_dalek::SigningKey;

        if *seed.code() != SeedCode::Ed25519Seed {
            return Err(KeyError::InvalidSeedCode {
                expected: format!("{:?}", SeedCode::Ed25519Seed),
                actual: format!("{:?}", seed.code()),
            });
        }

        let bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(
                seed.raw()
                    .try_into()
                    .map_err(|_| KeyError::InvalidSeedLength {
                        expected: 32,
                        actual: seed.raw().len(),
                    })?,
            );

        let signing_key = SigningKey::from_bytes(&bytes);
        let public = signing_key.verifying_key().to_bytes().to_vec();
        let secret = Zeroizing::new(signing_key.to_bytes().to_vec());

        Ok(Self {
            secret,
            public,
            _algo: PhantomData,
        })
    }

    /// Signs `data` with this Ed25519 key, returning a CESR-encoded non-indexed signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or the signature primitive fails to build.
    pub fn sign(&self, data: &[u8]) -> Result<Cigar<'static>, SignatureError> {
        use ed25519_dalek::{Signer as _, SigningKey};

        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            self.secret
                .as_slice()
                .try_into()
                .map_err(|_| SignatureError::SigningFailed("invalid secret key length".into()))?,
        );

        let signing_key = SigningKey::from_bytes(&bytes);
        let sig = signing_key.sign(data);

        MatterBuilder::new()
            .with_code(SignatureCode::Ed25519Sig)
            .with_raw(sig.to_bytes().to_vec())
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .build()
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))
    }

    /// Signs `data` with an indexed signature at the given key `index` and `mode`.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or building the indexed signature fails.
    pub fn sign_indexed(
        &self,
        data: &[u8],
        index: u32,
        mode: IndexMode,
    ) -> Result<Siger<'static>, SignatureError> {
        use ed25519_dalek::{Signer as _, SigningKey};

        let small_code = match mode {
            IndexMode::Both => Ed25519::IDX_BOTH,
            IndexMode::CurrentOnly => Ed25519::IDX_CRT,
        };
        let code = small_code.for_index(index);

        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            self.secret
                .as_slice()
                .try_into()
                .map_err(|_| SignatureError::SigningFailed("invalid secret key length".into()))?,
        );

        let signing_key = SigningKey::from_bytes(&bytes);
        let sig = signing_key.sign(data);
        let sig_bytes = sig.to_bytes().to_vec();

        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(index)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .with_raw(sig_bytes)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let verfer = MatterBuilder::new()
            .with_code(Ed25519::VERKEY_CODE)
            .with_raw(self.public.clone())
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .build()
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        Ok(Siger::new(indexer).with_verfer(verfer))
    }
}

impl KeyPair<Secp256k1> {
    /// Generates a fresh secp256k1 key pair using the OS random number generator.
    ///
    /// # Errors
    ///
    /// Returns an error if OS random number generation fails.
    pub fn generate() -> Result<Self, KeyError> {
        use k256::ecdsa::SigningKey;
        use rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let public = signing_key
            .verifying_key()
            .to_encoded_point(true) // compressed
            .as_bytes()
            .to_vec();
        let secret = Zeroizing::new(signing_key.to_bytes().to_vec());

        Ok(Self {
            secret,
            public,
            _algo: PhantomData,
        })
    }

    /// Reconstructs a secp256k1 key pair from a CESR seed primitive.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed has the wrong code or invalid scalar bytes.
    pub fn from_seed(seed: &Signer<'_>) -> Result<Self, KeyError> {
        use k256::ecdsa::SigningKey;

        if *seed.code() != SeedCode::ECDSA256k1Seed {
            return Err(KeyError::InvalidSeedCode {
                expected: format!("{:?}", SeedCode::ECDSA256k1Seed),
                actual: format!("{:?}", seed.code()),
            });
        }

        let signing_key = SigningKey::from_slice(seed.raw())
            .map_err(|e| KeyError::InvalidSeedBytes(e.to_string()))?;

        let public = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let secret = Zeroizing::new(signing_key.to_bytes().to_vec());

        Ok(Self {
            secret,
            public,
            _algo: PhantomData,
        })
    }

    /// Signs `data` with this secp256k1 key, returning a CESR-encoded non-indexed signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or the signature primitive fails to build.
    pub fn sign(&self, data: &[u8]) -> Result<Cigar<'static>, SignatureError> {
        use k256::ecdsa::{SigningKey, signature::Signer as _};

        let signing_key = SigningKey::from_slice(&self.secret)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let sig: k256::ecdsa::Signature = signing_key.sign(data);

        // Store as r || s (32 bytes each, big-endian) matching keripy
        let r_bytes = sig.r().to_bytes();
        let s_bytes = sig.s().to_bytes();
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&r_bytes);
        raw.extend_from_slice(&s_bytes);

        MatterBuilder::new()
            .with_code(SignatureCode::ECDSA256k1Sig)
            .with_raw(raw)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .build()
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))
    }

    /// Signs `data` with an indexed secp256k1 signature at the given key `index` and `mode`.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or building the indexed signature fails.
    pub fn sign_indexed(
        &self,
        data: &[u8],
        index: u32,
        mode: IndexMode,
    ) -> Result<Siger<'static>, SignatureError> {
        use k256::ecdsa::{SigningKey, signature::Signer as _};

        let small_code = match mode {
            IndexMode::Both => Secp256k1::IDX_BOTH,
            IndexMode::CurrentOnly => Secp256k1::IDX_CRT,
        };
        let code = small_code.for_index(index);

        let signing_key = SigningKey::from_slice(&self.secret)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let sig: k256::ecdsa::Signature = signing_key.sign(data);
        let r_bytes = sig.r().to_bytes();
        let s_bytes = sig.s().to_bytes();
        let mut sig_bytes = Vec::with_capacity(64);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);

        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(index)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .with_raw(sig_bytes)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let verfer = MatterBuilder::new()
            .with_code(Secp256k1::VERKEY_CODE)
            .with_raw(self.public.clone())
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .build()
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        Ok(Siger::new(indexer).with_verfer(verfer))
    }
}

impl KeyPair<Secp256r1> {
    /// Generates a fresh secp256r1 (P-256) key pair using the OS random number generator.
    ///
    /// # Errors
    ///
    /// Returns an error if OS random number generation fails.
    pub fn generate() -> Result<Self, KeyError> {
        use p256::ecdsa::SigningKey;
        use rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let public = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let secret = Zeroizing::new(signing_key.to_bytes().to_vec());

        Ok(Self {
            secret,
            public,
            _algo: PhantomData,
        })
    }

    /// Reconstructs a secp256r1 key pair from a CESR seed primitive.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed has the wrong code or invalid scalar bytes.
    pub fn from_seed(seed: &Signer<'_>) -> Result<Self, KeyError> {
        use p256::ecdsa::SigningKey;

        if *seed.code() != SeedCode::ECDSA256r1Seed {
            return Err(KeyError::InvalidSeedCode {
                expected: format!("{:?}", SeedCode::ECDSA256r1Seed),
                actual: format!("{:?}", seed.code()),
            });
        }

        let signing_key = SigningKey::from_slice(seed.raw())
            .map_err(|e| KeyError::InvalidSeedBytes(e.to_string()))?;

        let public = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let secret = Zeroizing::new(signing_key.to_bytes().to_vec());

        Ok(Self {
            secret,
            public,
            _algo: PhantomData,
        })
    }

    /// Signs `data` with this secp256r1 key, returning a CESR-encoded non-indexed signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or the signature primitive fails to build.
    pub fn sign(&self, data: &[u8]) -> Result<Cigar<'static>, SignatureError> {
        use p256::ecdsa::{SigningKey, signature::Signer as _};

        let signing_key = SigningKey::from_slice(&self.secret)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let sig: p256::ecdsa::Signature = signing_key.sign(data);

        let r_bytes = sig.r().to_bytes();
        let s_bytes = sig.s().to_bytes();
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&r_bytes);
        raw.extend_from_slice(&s_bytes);

        MatterBuilder::new()
            .with_code(SignatureCode::ECDSA256r1Sig)
            .with_raw(raw)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .build()
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))
    }

    /// Signs `data` with an indexed secp256r1 signature at the given key `index` and `mode`.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or building the indexed signature fails.
    pub fn sign_indexed(
        &self,
        data: &[u8],
        index: u32,
        mode: IndexMode,
    ) -> Result<Siger<'static>, SignatureError> {
        use p256::ecdsa::{SigningKey, signature::Signer as _};

        let small_code = match mode {
            IndexMode::Both => Secp256r1::IDX_BOTH,
            IndexMode::CurrentOnly => Secp256r1::IDX_CRT,
        };
        let code = small_code.for_index(index);

        let signing_key = SigningKey::from_slice(&self.secret)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let sig: p256::ecdsa::Signature = signing_key.sign(data);
        let r_bytes = sig.r().to_bytes();
        let s_bytes = sig.s().to_bytes();
        let mut sig_bytes = Vec::with_capacity(64);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);

        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(index)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .with_raw(sig_bytes)
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        let verfer = MatterBuilder::new()
            .with_code(Secp256r1::VERKEY_CODE)
            .with_raw(self.public.clone())
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?
            .build()
            .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

        Ok(Siger::new(indexer).with_verfer(verfer))
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::disallowed_methods,
    reason = "test assertions use unwrap and panic for clarity"
)]
mod tests {
    use super::*;
    use crate::core::matter::code::{SeedCode, SignatureCode, VerKeyCode};
    use crate::crypto::algo::Ed25519;

    #[test]
    fn ed25519_generate_produces_valid_keypair() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        assert_eq!(*kp.signer().unwrap().code(), SeedCode::Ed25519Seed);
        assert_eq!(kp.signer().unwrap().raw().len(), 32);
    }

    #[test]
    fn ed25519_verfer_returns_correct_code() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap();
        assert_eq!(*verfer.code(), VerKeyCode::Ed25519);
        assert_eq!(verfer.raw().len(), 32);
    }

    #[test]
    fn ed25519_verfer_non_transferable() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519N).unwrap();
        assert_eq!(*verfer.code(), VerKeyCode::Ed25519N);
    }

    #[test]
    fn ed25519_sign_produces_valid_signature() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp.sign(b"hello world").unwrap();
        assert_eq!(*sig.code(), SignatureCode::Ed25519Sig);
        assert_eq!(sig.raw().len(), 64);
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let data = b"test message";
        let sig = kp.sign(data).unwrap();
        kp.verify(data, &sig).unwrap();
    }

    #[test]
    fn ed25519_verify_rejects_wrong_data() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp.sign(b"correct data").unwrap();
        assert!(matches!(
            kp.verify(b"wrong data", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn ed25519_verify_rejects_wrong_key() {
        let kp1 = KeyPair::<Ed25519>::generate().unwrap();
        let kp2 = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp1.sign(b"test").unwrap();
        assert!(matches!(
            kp2.verify(b"test", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn ed25519_from_seed_rejects_wrong_code() {
        use crate::core::matter::builder::MatterBuilder;
        let wrong_seed = MatterBuilder::new()
            .with_code(SeedCode::ECDSA256k1Seed)
            .with_raw(vec![0u8; 32])
            .unwrap()
            .build()
            .unwrap();
        let result = KeyPair::<Ed25519>::from_seed(&wrong_seed);
        match result {
            Err(err) => assert!(err.to_string().contains("invalid seed code")),
            Ok(_) => panic!("expected InvalidSeedCode error"),
        }
    }

    #[test]
    fn ed25519_from_seed_roundtrip() {
        let kp1 = KeyPair::<Ed25519>::generate().unwrap();
        let seed = kp1.signer().unwrap();
        let kp2 = KeyPair::<Ed25519>::from_seed(&seed).unwrap();

        // Same public key
        assert_eq!(
            kp1.verfer(VerKeyCode::Ed25519).unwrap().raw(),
            kp2.verfer(VerKeyCode::Ed25519).unwrap().raw()
        );

        // Signature from kp2 verifies with kp1's verfer
        let sig = kp2.sign(b"test").unwrap();
        kp1.verify(b"test", &sig).unwrap();
    }

    // --- secp256k1 tests ---

    use crate::crypto::algo::Secp256k1;

    #[test]
    fn secp256k1_generate_produces_valid_keypair() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        assert_eq!(*kp.signer().unwrap().code(), SeedCode::ECDSA256k1Seed);
        assert_eq!(kp.signer().unwrap().raw().len(), 32);
    }

    #[test]
    fn secp256k1_verfer_compressed_point() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256k1).unwrap();
        assert_eq!(*verfer.code(), VerKeyCode::ECDSA256k1);
        assert_eq!(verfer.raw().len(), 33); // SEC1 compressed point
    }

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let data = b"test message";
        let sig = kp.sign(data).unwrap();
        assert_eq!(*sig.code(), SignatureCode::ECDSA256k1Sig);
        assert_eq!(sig.raw().len(), 64); // r || s
        kp.verify(data, &sig).unwrap();
    }

    #[test]
    fn secp256k1_verify_rejects_wrong_data() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let sig = kp.sign(b"correct").unwrap();
        assert!(matches!(
            kp.verify(b"wrong", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn secp256k1_from_seed_roundtrip() {
        let kp1 = KeyPair::<Secp256k1>::generate().unwrap();
        let seed = kp1.signer().unwrap();
        let kp2 = KeyPair::<Secp256k1>::from_seed(&seed).unwrap();
        assert_eq!(
            kp1.verfer(VerKeyCode::ECDSA256k1).unwrap().raw(),
            kp2.verfer(VerKeyCode::ECDSA256k1).unwrap().raw()
        );
    }

    // --- secp256r1 tests ---

    use crate::crypto::algo::Secp256r1;

    #[test]
    fn secp256r1_generate_produces_valid_keypair() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        assert_eq!(*kp.signer().unwrap().code(), SeedCode::ECDSA256r1Seed);
        assert_eq!(kp.signer().unwrap().raw().len(), 32);
    }

    #[test]
    fn secp256r1_verfer_compressed_point() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::ECDSA256r1).unwrap();
        assert_eq!(*verfer.code(), VerKeyCode::ECDSA256r1);
        assert_eq!(verfer.raw().len(), 33);
    }

    #[test]
    fn secp256r1_sign_verify_roundtrip() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let data = b"test message";
        let sig = kp.sign(data).unwrap();
        assert_eq!(*sig.code(), SignatureCode::ECDSA256r1Sig);
        assert_eq!(sig.raw().len(), 64);
        kp.verify(data, &sig).unwrap();
    }

    #[test]
    fn secp256r1_verify_rejects_wrong_data() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let sig = kp.sign(b"correct").unwrap();
        assert!(matches!(
            kp.verify(b"wrong", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn secp256r1_from_seed_roundtrip() {
        let kp1 = KeyPair::<Secp256r1>::generate().unwrap();
        let seed = kp1.signer().unwrap();
        let kp2 = KeyPair::<Secp256r1>::from_seed(&seed).unwrap();
        assert_eq!(
            kp1.verfer(VerKeyCode::ECDSA256r1).unwrap().raw(),
            kp2.verfer(VerKeyCode::ECDSA256r1).unwrap().raw()
        );
    }

    // ===== Empty data signing tests =====
    // Verify that signing and verifying empty byte slices works correctly
    // for all algorithms.

    #[test]
    fn ed25519_sign_empty_data() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let sig = kp.sign(b"").unwrap();
        kp.verify(b"", &sig).unwrap();
        assert!(matches!(
            kp.verify(b"not empty", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn secp256k1_sign_empty_data() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let sig = kp.sign(b"").unwrap();
        kp.verify(b"", &sig).unwrap();
        assert!(matches!(
            kp.verify(b"not empty", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn secp256r1_sign_empty_data() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let sig = kp.sign(b"").unwrap();
        kp.verify(b"", &sig).unwrap();
        assert!(matches!(
            kp.verify(b"not empty", &sig),
            Err(SignatureError::Invalid)
        ));
    }

    // ===== Seed edge case tests =====
    // Verify from_seed rejects seeds with wrong length or wrong code.

    #[test]
    fn ed25519_from_seed_rejects_short_raw() {
        use crate::core::matter::Matter;
        use alloc::borrow::Cow;
        let short_seed = Matter::new_unchecked(
            SeedCode::Ed25519Seed,
            Cow::Owned(vec![0u8; 16]),
            Cow::from(""),
        );
        let result = KeyPair::<Ed25519>::from_seed(&short_seed);
        assert!(result.is_err());
    }

    #[test]
    fn secp256k1_from_seed_rejects_wrong_code() {
        use crate::core::matter::builder::MatterBuilder;
        let wrong_seed = MatterBuilder::new()
            .with_code(SeedCode::Ed25519Seed)
            .with_raw(vec![1u8; 32])
            .unwrap()
            .build()
            .unwrap();
        match KeyPair::<Secp256k1>::from_seed(&wrong_seed) {
            Err(err) => assert!(
                err.to_string().contains("invalid seed code"),
                "unexpected error message: {err}",
            ),
            Ok(_) => panic!("expected InvalidSeedCode error"),
        }
    }

    #[test]
    fn secp256r1_from_seed_rejects_wrong_code() {
        use crate::core::matter::builder::MatterBuilder;
        let wrong_seed = MatterBuilder::new()
            .with_code(SeedCode::Ed25519Seed)
            .with_raw(vec![1u8; 32])
            .unwrap()
            .build()
            .unwrap();
        match KeyPair::<Secp256r1>::from_seed(&wrong_seed) {
            Err(err) => assert!(
                err.to_string().contains("invalid seed code"),
                "unexpected error message: {err}",
            ),
            Ok(_) => panic!("expected InvalidSeedCode error"),
        }
    }

    #[test]
    fn secp256k1_from_seed_rejects_zero_scalar() {
        use crate::core::matter::builder::MatterBuilder;
        // Zero is not a valid secp256k1 private key (must be in [1, n-1])
        let zero_seed = MatterBuilder::new()
            .with_code(SeedCode::ECDSA256k1Seed)
            .with_raw(vec![0u8; 32])
            .unwrap()
            .build()
            .unwrap();
        let result = KeyPair::<Secp256k1>::from_seed(&zero_seed);
        assert!(result.is_err());
    }

    #[test]
    fn secp256r1_from_seed_rejects_zero_scalar() {
        use crate::core::matter::builder::MatterBuilder;
        // Zero is not a valid secp256r1 private key (must be in [1, n-1])
        let zero_seed = MatterBuilder::new()
            .with_code(SeedCode::ECDSA256r1Seed)
            .with_raw(vec![0u8; 32])
            .unwrap()
            .build()
            .unwrap();
        let result = KeyPair::<Secp256r1>::from_seed(&zero_seed);
        assert!(result.is_err());
    }

    // ===== Indexed signature tests =====

    use crate::core::indexer::code::{IndexMode, IndexedSigCode};

    // --- Ed25519 indexed sig tests ---

    #[test]
    fn ed25519_sign_indexed_both_mode() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        assert_eq!(siger.code(), IndexedSigCode::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), Some(0));
        assert_eq!(siger.raw().len(), 64);
        assert!(siger.verfer().is_some());
    }

    #[test]
    fn ed25519_sign_indexed_current_only() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp
            .sign_indexed(b"test data", 5, IndexMode::CurrentOnly)
            .unwrap();
        assert_eq!(siger.code(), IndexedSigCode::Ed25519Crt);
        assert!(siger.ondex().is_none());
    }

    #[test]
    fn ed25519_sign_indexed_auto_upgrades_to_big() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 100, IndexMode::Both).unwrap();
        assert_eq!(siger.code(), IndexedSigCode::Ed25519Big);
        assert_eq!(siger.index(), 100);
    }

    #[test]
    fn ed25519_sign_indexed_verify_roundtrip() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        // Verify by constructing a Cigar from the raw sig bytes
        let cigar = MatterBuilder::new()
            .with_code(SignatureCode::Ed25519Sig)
            .with_raw(siger.raw().to_vec())
            .unwrap()
            .build()
            .unwrap();
        kp.verify(b"test data", &cigar).unwrap();
    }

    // --- Secp256k1 indexed sig tests ---

    #[test]
    fn secp256k1_sign_indexed_both_mode() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        assert_eq!(siger.code(), IndexedSigCode::ECDSA256k1);
        assert_eq!(siger.raw().len(), 64);
        assert!(siger.verfer().is_some());
    }

    #[test]
    fn secp256k1_sign_indexed_verify_roundtrip() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        let cigar = MatterBuilder::new()
            .with_code(SignatureCode::ECDSA256k1Sig)
            .with_raw(siger.raw().to_vec())
            .unwrap()
            .build()
            .unwrap();
        kp.verify(b"test data", &cigar).unwrap();
    }

    // --- Secp256r1 indexed sig tests ---

    #[test]
    fn secp256r1_sign_indexed_both_mode() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        assert_eq!(siger.code(), IndexedSigCode::ECDSA256r1);
        assert_eq!(siger.raw().len(), 64);
        assert!(siger.verfer().is_some());
    }

    // ===== Indexed signature verification (verify_indexed) =====

    // --- Ed25519 ---

    #[test]
    fn ed25519_verify_indexed_roundtrip_both() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        kp.verify(b"test data", &siger).unwrap();
    }

    #[test]
    fn ed25519_verify_indexed_roundtrip_current_only() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"msg", 5, IndexMode::CurrentOnly).unwrap();
        kp.verify(b"msg", &siger).unwrap();
    }

    #[test]
    fn ed25519_verify_indexed_roundtrip_big_index() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"msg", 100, IndexMode::Both).unwrap();
        assert_eq!(siger.code(), IndexedSigCode::Ed25519Big);
        kp.verify(b"msg", &siger).unwrap();
    }

    #[test]
    fn ed25519_verify_indexed_rejects_tampered_data() {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"correct", 0, IndexMode::Both).unwrap();
        assert!(matches!(
            kp.verify(b"tampered", &siger),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn ed25519_verify_indexed_rejects_wrong_key() {
        let kp1 = KeyPair::<Ed25519>::generate().unwrap();
        let kp2 = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp1.sign_indexed(b"data", 0, IndexMode::Both).unwrap();
        assert!(matches!(
            kp2.verify(b"data", &siger),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn ed25519_verify_indexed_rejects_wrong_algorithm_code() {
        // Strict policy: an Ed25519 key pair must reject a secp256k1 indexed
        // signature by code, not silently return `false`.
        let ed = KeyPair::<Ed25519>::generate().unwrap();
        let k1 = KeyPair::<Secp256k1>::generate().unwrap();
        let k1_siger = k1.sign_indexed(b"data", 0, IndexMode::Both).unwrap();
        let err = ed.verify(b"data", &k1_siger).err().unwrap();
        assert!(
            matches!(err, SignatureError::CodeMismatch { .. }),
            "expected CodeMismatch, got {err:?}"
        );
    }

    #[test]
    fn ed25519_verify_indexed_index_is_not_signed() {
        // The CESR index is framing metadata, NOT part of the signed payload:
        // re-indexing a valid signature does not invalidate it cryptographically.
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let siger = kp.sign_indexed(b"data", 0, IndexMode::Both).unwrap();

        let reindexed = Siger::new(
            IndexerBuilder::new()
                .with_code(IndexedSigCode::Ed25519)
                .with_index(4)
                .unwrap()
                .with_raw(siger.raw().to_vec())
                .unwrap(),
        );

        assert_ne!(reindexed.index(), siger.index());
        kp.verify(b"data", &reindexed).unwrap();
    }

    // --- Secp256k1 ---

    #[test]
    fn secp256k1_verify_indexed_roundtrip() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        kp.verify(b"test data", &siger).unwrap();
    }

    #[test]
    fn secp256k1_verify_indexed_rejects_tampered_data() {
        let kp = KeyPair::<Secp256k1>::generate().unwrap();
        let siger = kp
            .sign_indexed(b"correct", 3, IndexMode::CurrentOnly)
            .unwrap();
        assert!(matches!(
            kp.verify(b"tampered", &siger),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn secp256k1_verify_indexed_rejects_wrong_algorithm_code() {
        let k1 = KeyPair::<Secp256k1>::generate().unwrap();
        let ed = KeyPair::<Ed25519>::generate().unwrap();
        let ed_siger = ed.sign_indexed(b"data", 0, IndexMode::Both).unwrap();
        let err = k1.verify(b"data", &ed_siger).err().unwrap();
        assert!(
            matches!(err, SignatureError::CodeMismatch { .. }),
            "expected CodeMismatch, got {err:?}"
        );
    }

    // --- Secp256r1 ---

    #[test]
    fn secp256r1_verify_indexed_roundtrip() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let siger = kp.sign_indexed(b"test data", 0, IndexMode::Both).unwrap();
        kp.verify(b"test data", &siger).unwrap();
    }

    #[test]
    fn secp256r1_verify_indexed_rejects_tampered_data() {
        let kp = KeyPair::<Secp256r1>::generate().unwrap();
        let siger = kp.sign_indexed(b"correct", 0, IndexMode::Both).unwrap();
        assert!(matches!(
            kp.verify(b"tampered", &siger),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn secp256r1_verify_indexed_rejects_wrong_algorithm_code() {
        let r1 = KeyPair::<Secp256r1>::generate().unwrap();
        let ed = KeyPair::<Ed25519>::generate().unwrap();
        let ed_siger = ed.sign_indexed(b"data", 0, IndexMode::Both).unwrap();
        let err = r1.verify(b"data", &ed_siger).err().unwrap();
        assert!(
            matches!(err, SignatureError::CodeMismatch { .. }),
            "expected CodeMismatch, got {err:?}"
        );
    }

    // ===== Property-based tests =====

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Ed25519 sign-then-verify roundtrip holds for arbitrary data.
            #[test]
            fn ed25519_sign_verify_random_data(
                data in proptest::collection::vec(any::<u8>(), 0..1024)
            ) {
                let kp = KeyPair::<Ed25519>::generate().unwrap();
                let sig = kp.sign(&data).unwrap();
                prop_assert!(kp.verify(&data, &sig).is_ok());
            }
        }

        proptest! {
            /// Secp256k1 sign-then-verify roundtrip holds for arbitrary data.
            #[test]
            fn secp256k1_sign_verify_random_data(
                data in proptest::collection::vec(any::<u8>(), 0..1024)
            ) {
                let kp = KeyPair::<Secp256k1>::generate().unwrap();
                let sig = kp.sign(&data).unwrap();
                prop_assert!(kp.verify(&data, &sig).is_ok());
            }
        }

        proptest! {
            /// Secp256r1 sign-then-verify roundtrip holds for arbitrary data.
            #[test]
            fn secp256r1_sign_verify_random_data(
                data in proptest::collection::vec(any::<u8>(), 0..1024)
            ) {
                let kp = KeyPair::<Secp256r1>::generate().unwrap();
                let sig = kp.sign(&data).unwrap();
                prop_assert!(kp.verify(&data, &sig).is_ok());
            }
        }

        proptest! {
            /// Ed25519 signature size is always 64 bytes regardless of input.
            #[test]
            fn ed25519_sig_always_64_bytes(
                data in proptest::collection::vec(any::<u8>(), 0..512)
            ) {
                let kp = KeyPair::<Ed25519>::generate().unwrap();
                let sig = kp.sign(&data).unwrap();
                prop_assert_eq!(sig.raw().len(), 64);
                prop_assert_eq!(*sig.code(), SignatureCode::Ed25519Sig);
            }
        }

        proptest! {
            /// Secp256k1 signature size is always 64 bytes (r || s) regardless
            /// of input.
            #[test]
            fn secp256k1_sig_always_64_bytes(
                data in proptest::collection::vec(any::<u8>(), 0..512)
            ) {
                let kp = KeyPair::<Secp256k1>::generate().unwrap();
                let sig = kp.sign(&data).unwrap();
                prop_assert_eq!(sig.raw().len(), 64);
                prop_assert_eq!(*sig.code(), SignatureCode::ECDSA256k1Sig);
            }
        }

        proptest! {
            /// Secp256r1 signature size is always 64 bytes (r || s) regardless
            /// of input.
            #[test]
            fn secp256r1_sig_always_64_bytes(
                data in proptest::collection::vec(any::<u8>(), 0..512)
            ) {
                let kp = KeyPair::<Secp256r1>::generate().unwrap();
                let sig = kp.sign(&data).unwrap();
                prop_assert_eq!(sig.raw().len(), 64);
                prop_assert_eq!(*sig.code(), SignatureCode::ECDSA256r1Sig);
            }
        }

        proptest! {
            /// Ed25519 sign_indexed → verify_indexed roundtrip holds for
            /// arbitrary data and index.
            #[test]
            fn ed25519_verify_indexed_random(
                data in proptest::collection::vec(any::<u8>(), 0..1024),
                index in 0u32..300,
            ) {
                let kp = KeyPair::<Ed25519>::generate().unwrap();
                let siger = kp.sign_indexed(&data, index, IndexMode::Both).unwrap();
                prop_assert!(kp.verify(&data, &siger).is_ok());
            }
        }

        proptest! {
            /// Secp256k1 sign_indexed → verify_indexed roundtrip holds for
            /// arbitrary data and index.
            #[test]
            fn secp256k1_verify_indexed_random(
                data in proptest::collection::vec(any::<u8>(), 0..1024),
                index in 0u32..300,
            ) {
                let kp = KeyPair::<Secp256k1>::generate().unwrap();
                let siger = kp.sign_indexed(&data, index, IndexMode::CurrentOnly).unwrap();
                prop_assert!(kp.verify(&data, &siger).is_ok());
            }
        }

        proptest! {
            /// Secp256r1 sign_indexed → verify_indexed roundtrip holds for
            /// arbitrary data and index.
            #[test]
            fn secp256r1_verify_indexed_random(
                data in proptest::collection::vec(any::<u8>(), 0..1024),
                index in 0u32..300,
            ) {
                let kp = KeyPair::<Secp256r1>::generate().unwrap();
                let siger = kp.sign_indexed(&data, index, IndexMode::Both).unwrap();
                prop_assert!(kp.verify(&data, &siger).is_ok());
            }
        }
    }
}
