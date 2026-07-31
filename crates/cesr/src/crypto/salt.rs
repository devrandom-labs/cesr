//! Deterministic salt material and argon2id seed stretching.
//!
//! `Salt` is the root secret for deterministic key derivation ([#93] K7):
//! 16 random bytes (CESR `Salt128`, code `0A`) stretched through argon2id13
//! with libsodium-compatible cost parameters into Ed25519 seeds. Byte-identical
//! to keripy's `Salter.stretch` so a salt (or the passcode that produced it)
//! yields the same keys — and therefore the same AID — in either stack.
//!
//! The raw salt is held in [`Zeroizing`] and never exposed by accessor; export
//! goes through [`Salt::primitive`] as a deliberate, visible act.

use alloc::string::ToString;

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::NoncerCode;
use crate::core::matter::error::MatterBuildError;
use crate::core::primitives::Noncer;
use crate::crypto::algo::Ed25519;
use crate::crypto::error::SaltError;
use crate::crypto::keypair::KeyPair;

/// Raw byte length of a `Salt128` salt.
pub const SALT_LEN: usize = 16;

/// Raw byte length of a stretched Ed25519 seed.
pub const SEED_LEN: usize = 32;

/// Argon2id cost tier, mirroring libsodium's `crypto_pwhash` limits
/// (keripy `Tiers`): interactive / moderate / sensitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// opslimit 2, memlimit 64 MiB (libsodium *interactive*; keripy `low`).
    Low,
    /// opslimit 3, memlimit 256 MiB (libsodium *moderate*; keripy `med`).
    Medium,
    /// opslimit 4, memlimit 1 GiB (libsodium *sensitive*; keripy `high`).
    High,
}

impl Tier {
    /// `(t_cost, m_cost_kib)` for this tier. `m_cost` is libsodium's
    /// memlimit divided by 1024, per the argon2 KiB convention.
    const fn costs(self) -> (u32, u32) {
        match self {
            Self::Low => (2, 65_536),
            Self::Medium => (3, 262_144),
            Self::High => (4, 1_048_576),
        }
    }
}

/// A 128-bit root salt for deterministic key derivation.
pub struct Salt {
    raw: Zeroizing<[u8; SALT_LEN]>,
}

impl core::fmt::Debug for Salt {
    /// Redacted: the root secret never appears in debug output.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Salt").finish_non_exhaustive()
    }
}

impl Salt {
    /// Wraps exactly [`SALT_LEN`] raw bytes.
    ///
    /// # Errors
    ///
    /// [`SaltError::InvalidLength`] if `raw` is not exactly [`SALT_LEN`] bytes.
    pub fn from_raw(raw: &[u8]) -> Result<Self, SaltError> {
        let bytes: [u8; SALT_LEN] = raw
            .try_into()
            .map_err(|_| SaltError::InvalidLength { actual: raw.len() })?;
        Ok(Self {
            raw: Zeroizing::new(bytes),
        })
    }

    /// Parses a qualified base64 `Salt128` primitive (`0A...`).
    ///
    /// # Errors
    ///
    /// [`SaltError::Parse`] / [`SaltError::Validation`] if the text is not a
    /// well-formed noncer primitive, [`SaltError::InvalidCode`] if it is a
    /// noncer but not `Salt128`.
    pub fn from_qb64(qb64: &str) -> Result<Self, SaltError> {
        let untyped = MatterBuilder::new().from_qualified_base64(qb64.as_bytes().to_vec())?;
        let noncer: Noncer<'_> = untyped.narrow::<NoncerCode>()?;
        if *noncer.code() != NoncerCode::Salt128 {
            return Err(SaltError::InvalidCode {
                actual: alloc::format!("{:?}", noncer.code()),
            });
        }
        Self::from_raw(noncer.raw())
    }

    /// Generates a fresh random salt from the OS random number generator.
    ///
    /// # Errors
    ///
    /// [`SaltError::Rng`] if OS randomness is unavailable.
    pub fn generate() -> Result<Self, SaltError> {
        let mut bytes = Zeroizing::new([0u8; SALT_LEN]);
        OsRng
            .try_fill_bytes(&mut bytes[..])
            .map_err(|e| SaltError::Rng(e.to_string()))?;
        Ok(Self { raw: bytes })
    }

    /// Exports the salt as a CESR `Salt128` primitive. This is the only way
    /// raw salt material leaves this type — persisting or displaying the
    /// result re-exposes the root secret; do it deliberately.
    ///
    /// # Errors
    ///
    /// [`SaltError::Parse`] if the primitive fails to build (never in
    /// practice for a correct-length raw).
    pub fn primitive(&self) -> Result<Noncer<'static>, SaltError> {
        Ok(MatterBuilder::new()
            .with_code(NoncerCode::Salt128)
            .with_raw(self.raw.to_vec())
            .map_err(MatterBuildError::from)?
            .build()?)
    }

    /// Stretches `path` into a 32-byte seed with argon2id13 at `tier` cost —
    /// byte-identical to keripy `Salter.stretch` / libsodium `crypto_pwhash`.
    ///
    /// # Errors
    ///
    /// [`SaltError::Stretch`] if argon2 rejects the parameters or fails.
    pub fn stretch(&self, path: &str, tier: Tier) -> Result<Zeroizing<[u8; SEED_LEN]>, SaltError> {
        let (t_cost, m_cost) = tier.costs();
        self.stretch_with(path, t_cost, m_cost)
    }

    /// keripy `temp=True` stretch (opslimit 1, memlimit 8 KiB) — differential
    /// vector generation only; cryptographically weak on purpose.
    ///
    /// # Errors
    ///
    /// [`SaltError::Stretch`] if argon2 rejects the parameters or fails.
    #[cfg(feature = "test-utils")]
    pub fn stretch_temp(&self, path: &str) -> Result<Zeroizing<[u8; SEED_LEN]>, SaltError> {
        self.stretch_with(path, 1, 8)
    }

    fn stretch_with(
        &self,
        path: &str,
        t_cost: u32,
        m_cost: u32,
    ) -> Result<Zeroizing<[u8; SEED_LEN]>, SaltError> {
        let params = Params::new(m_cost, t_cost, 1, Some(SEED_LEN)).map_err(SaltError::Stretch)?;
        let ctx = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        ctx.hash_password_into(path.as_bytes(), &self.raw[..], &mut seed[..])
            .map_err(SaltError::Stretch)?;
        Ok(seed)
    }

    /// Derives a deterministic Ed25519 key pair for `path` at `tier`.
    ///
    /// # Errors
    ///
    /// [`SaltError::Stretch`] if the underlying stretch fails.
    pub fn key_pair(&self, path: &str, tier: Tier) -> Result<KeyPair<Ed25519>, SaltError> {
        let seed = self.stretch(path, tier)?;
        Ok(KeyPair::from_seed_bytes(&seed))
    }

    /// [`Salt::key_pair`] at keripy `temp=True` cost — vector generation only.
    ///
    /// # Errors
    ///
    /// [`SaltError::Stretch`] if the underlying stretch fails.
    #[cfg(feature = "test-utils")]
    pub fn key_pair_temp(&self, path: &str) -> Result<KeyPair<Ed25519>, SaltError> {
        let seed = self.stretch_temp(path)?;
        Ok(KeyPair::from_seed_bytes(&seed))
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

    const RAW: [u8; SALT_LEN] = *b"0123456789abcdef";

    #[test]
    fn from_raw_accepts_exact_length() {
        let salt = Salt::from_raw(&RAW).unwrap();
        let qb64 = salt.primitive().unwrap().to_qb64();
        assert_eq!(qb64, "0AAwMTIzNDU2Nzg5YWJjZGVm");
    }

    #[test]
    fn from_raw_rejects_wrong_length() {
        let err = Salt::from_raw(&RAW[..15]).unwrap_err();
        assert!(matches!(err, SaltError::InvalidLength { actual: 15 }));
    }

    #[test]
    fn qb64_round_trips() {
        let salt = Salt::from_raw(&RAW).unwrap();
        let qb64 = salt.primitive().unwrap().to_qb64();
        let back = Salt::from_qb64(&qb64).unwrap();
        assert_eq!(back.primitive().unwrap().to_qb64(), qb64);
    }

    #[test]
    fn from_qb64_rejects_non_salt_code() {
        // A Blake3-256 digest primitive ("E" code), not a salt.
        let err = Salt::from_qb64("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap_err();
        assert!(matches!(
            err,
            SaltError::Validation(_) | SaltError::InvalidCode { .. }
        ));
    }

    #[test]
    fn from_qb64_truncated_is_typed_error_not_panic() {
        assert!(Salt::from_qb64("0AAwMTIz").is_err());
    }

    #[test]
    fn generate_produces_distinct_salts() {
        let a = Salt::generate().unwrap();
        let b = Salt::generate().unwrap();
        assert_ne!(
            a.primitive().unwrap().to_qb64(),
            b.primitive().unwrap().to_qb64()
        );
    }

    #[test]
    fn stretch_is_deterministic_and_path_sensitive() {
        let salt = Salt::from_raw(&RAW).unwrap();
        let a = salt.stretch_temp("00").unwrap();
        let b = salt.stretch_temp("00").unwrap();
        let c = salt.stretch_temp("01").unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn different_salts_stretch_differently() {
        let a = Salt::from_raw(&RAW).unwrap().stretch_temp("00").unwrap();
        let b = Salt::from_raw(b"fedcba9876543210")
            .unwrap()
            .stretch_temp("00")
            .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn key_pair_from_same_path_verifies_its_own_signature() {
        let salt = Salt::from_raw(&RAW).unwrap();
        let kp = salt.key_pair_temp("00").unwrap();
        let sig = kp.sign(b"data").unwrap();
        kp.verify(b"data", &sig).unwrap();
    }
}
