//! Key custody: the [`Custodian`] boundary and the deterministic salty
//! reference implementation ([#93] K7).
//!
//! A custodian owns private key material and answers three questions the
//! KERI core needs: which verification keys are current ([`Custodian::incept`],
//! [`Custodian::rotate`] — each returning the next-key commitments alongside),
//! and what are the indexed signatures over a serialized event
//! ([`Custodian::sign`]). Everything else — storage, passcode UX, hardware
//! backends — lives above this trait.
//!
//! [`SaltyCustodian`] is the deterministic phone/IoT default: every key is
//! re-derived on demand from a 128-bit root [`Salt`] via argon2id
//! ([`cesr::crypto::salt`]), so custody state is three counters and a path
//! convention. Its [`SaltyCustodian::params`] deliberately exclude salt
//! material — persist them LOCALLY and re-supply the salt (or the passcode
//! that derives it) at reconstruction. Transmitting custody state to another
//! party is the key-light trade-off signify makes; it is never the default
//! here.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use cesr::core::indexer::code::IndexMode;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::Siger;
use cesr::crypto::salt::{Salt, Tier};
use cesr::crypto::{DigestError, KeyError, SaltError, SignatureError, digest};
use keri_events::{Digest, VerifyingKey};

/// How many keys an establishment event exposes and commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySpec {
    /// Number of current signing keys to derive.
    pub count: usize,
    /// Number of next keys to commit to (must be 0 when non-transferable).
    pub ncount: usize,
    /// Whether the identifier is transferable (can ever rotate).
    pub transferable: bool,
}

/// The public output of an establishment operation: current verification
/// keys and the digests committing to the next set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCommitment {
    /// Current verification keys, in signing order.
    pub verkeys: Vec<VerifyingKey<'static>>,
    /// Blake3-256 commitments to the next verification keys, in order.
    pub next_digests: Vec<Digest<'static>>,
}

/// Key custody boundary: derive/expose establishment key sets and produce
/// indexed signatures. Object-safe so hardware-backed custodians can sit
/// behind `dyn Custodian`.
pub trait Custodian {
    /// Failure domain of this custodian.
    type Error;

    /// Derives the inception key sets.
    ///
    /// # Errors
    ///
    /// Implementation-defined; for [`SaltyCustodian`] see [`CustodyError`].
    fn incept(&mut self, spec: KeySpec) -> Result<KeyCommitment, Self::Error>;

    /// Rotates: promotes the committed next set to current and commits to a
    /// fresh next set.
    ///
    /// # Errors
    ///
    /// Implementation-defined; for [`SaltyCustodian`] see [`CustodyError`].
    fn rotate(&mut self, spec: KeySpec) -> Result<KeyCommitment, Self::Error>;

    /// Signs `ser` with every current key, returning indexed signatures in
    /// key order. `indices` overrides the per-key signature index (length
    /// must equal the current key count); `None` uses each key's position.
    ///
    /// # Errors
    ///
    /// Implementation-defined; for [`SaltyCustodian`] see [`CustodyError`].
    fn sign(&self, ser: &[u8], indices: Option<&[u32]>) -> Result<Vec<Siger<'static>>, Self::Error>;
}

/// Errors from [`SaltyCustodian`] operations.
#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    /// `incept` called twice.
    #[error("custodian already incepted")]
    AlreadyIncepted,
    /// `rotate` or `sign` called before `incept`.
    #[error("custodian not incepted")]
    NotIncepted,
    /// Inception with zero current keys.
    #[error("inception requires at least one current key")]
    EmptyCurrentKeys,
    /// Non-transferable custody cannot commit to next keys.
    #[error("non-transferable custody cannot commit next keys (ncount {ncount})")]
    NonTransferableNextKeys {
        /// The rejected next-key count.
        ncount: usize,
    },
    /// Rotation on a non-transferable or abandoned (empty next set) custodian.
    #[error("custodian cannot rotate (non-transferable or abandoned)")]
    NotRotatable,
    /// Rotation must expose exactly the committed next set.
    #[error("rotation must expose the committed next set: expected {expected}, got {actual}")]
    RotationCountMismatch {
        /// The committed next-key count.
        expected: usize,
        /// The requested current-key count.
        actual: usize,
    },
    /// `sign` indices length does not match the current key count.
    #[error("sign indices length {actual} != current key count {expected}")]
    IndicesLengthMismatch {
        /// Current key count.
        expected: usize,
        /// Provided indices length.
        actual: usize,
    },
    /// Key-index arithmetic overflowed.
    #[error("key index arithmetic overflowed")]
    IndexOverflow,
    /// Salt stretch failed.
    #[error(transparent)]
    Salt(#[from] SaltError),
    /// Key material handling failed.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// Signing failed.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// Next-key digest computation failed.
    #[error(transparent)]
    Digest(#[from] DigestError),
}

/// Derivation-path stem convention — which wallet family the derived keys
/// interoperate with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathConvention {
    /// keripy `Manager` default: stem is the account index in lowercase hex
    /// (`keeping.py:542`).
    Keripy,
    /// signify: fixed stem `"signify:aid"` (`keeping.ts:312`).
    Signify,
    /// Explicit stem string (keripy/signify both accept custom stems).
    Custom(String),
}

/// Deterministic salt-derived custody: keys are re-derived on demand from a
/// root [`Salt`]; state is counters plus a path convention.
pub struct SaltyCustodian {
    salt: Salt,
    tier: Tier,
    convention: PathConvention,
    pidx: u64,
    ridx: u64,
    kidx: u64,
    count: usize,
    ncount: usize,
    transferable: bool,
    incepted: bool,
}

impl SaltyCustodian {
    /// A fresh, un-incepted custodian for account index 0.
    #[must_use]
    pub const fn new(salt: Salt, tier: Tier, convention: PathConvention) -> Self {
        Self {
            salt,
            tier,
            convention,
            pidx: 0,
            ridx: 0,
            kidx: 0,
            count: 0,
            ncount: 0,
            transferable: true,
            incepted: false,
        }
    }

    /// The derivation path for one key: `stem + hex(ridx) + hex(kidx)`,
    /// keripy `keeping.py:542-544`.
    #[must_use]
    pub fn derivation_path(&self, ridx: u64, kidx: u64) -> String {
        let stem = match &self.convention {
            PathConvention::Keripy => format!("{:x}", self.pidx),
            PathConvention::Signify => String::from("signify:aid"),
            PathConvention::Custom(stem) => stem.clone(),
        };
        format!("{stem}{ridx:x}{kidx:x}")
    }

    fn derive_set(
        &self,
        ridx: u64,
        kidx: u64,
        count: usize,
        code: VerKeyCode,
    ) -> Result<Vec<VerifyingKey<'static>>, CustodyError> {
        (0..count)
            .map(|i| {
                let offset = u64::try_from(i).map_err(|_| CustodyError::IndexOverflow)?;
                let key_index = kidx.checked_add(offset).ok_or(CustodyError::IndexOverflow)?;
                let path = self.derivation_path(ridx, key_index);
                let kp = self.salt.key_pair(&path, self.tier)?;
                Ok(VerifyingKey::from_matter(kp.verfer(code)?.into_static()))
            })
            .collect()
    }

    fn commit_set(
        verkeys: &[VerifyingKey<'static>],
    ) -> Result<Vec<Digest<'static>>, CustodyError> {
        verkeys
            .iter()
            .map(|vk| {
                Ok(Digest::from_matter(digest(
                    DigestCode::Blake3_256,
                    &vk.to_qb64b(),
                )?))
            })
            .collect()
    }

    /// The coordinates one rung up — `(ridx + 1, kidx + count)`, keripy's
    /// next-set bookkeeping (`keeping.py:1019-1030`).
    fn rung_up(ridx: u64, kidx: u64, count: usize) -> Result<(u64, u64), CustodyError> {
        let count64 = u64::try_from(count).map_err(|_| CustodyError::IndexOverflow)?;
        let up_r = ridx.checked_add(1).ok_or(CustodyError::IndexOverflow)?;
        let up_k = kidx.checked_add(count64).ok_or(CustodyError::IndexOverflow)?;
        Ok((up_r, up_k))
    }
}

impl Custodian for SaltyCustodian {
    type Error = CustodyError;

    fn incept(&mut self, spec: KeySpec) -> Result<KeyCommitment, CustodyError> {
        if self.incepted {
            return Err(CustodyError::AlreadyIncepted);
        }
        if spec.count == 0 {
            return Err(CustodyError::EmptyCurrentKeys);
        }
        if !spec.transferable && spec.ncount != 0 {
            return Err(CustodyError::NonTransferableNextKeys {
                ncount: spec.ncount,
            });
        }
        let code = if spec.transferable {
            VerKeyCode::Ed25519
        } else {
            VerKeyCode::Ed25519N
        };
        let verkeys = self.derive_set(self.ridx, self.kidx, spec.count, code)?;

        let upcoming = Self::rung_up(self.ridx, self.kidx, spec.count)?;
        let next = self.derive_set(upcoming.0, upcoming.1, spec.ncount, VerKeyCode::Ed25519)?;
        let next_digests = Self::commit_set(&next)?;

        self.count = spec.count;
        self.ncount = spec.ncount;
        self.transferable = spec.transferable;
        self.incepted = true;
        Ok(KeyCommitment {
            verkeys,
            next_digests,
        })
    }

    fn rotate(&mut self, spec: KeySpec) -> Result<KeyCommitment, CustodyError> {
        if !self.incepted {
            return Err(CustodyError::NotIncepted);
        }
        if !self.transferable || self.ncount == 0 {
            return Err(CustodyError::NotRotatable);
        }
        if spec.count != self.ncount {
            return Err(CustodyError::RotationCountMismatch {
                expected: self.ncount,
                actual: spec.count,
            });
        }
        let current = Self::rung_up(self.ridx, self.kidx, self.count)?;
        let verkeys = self.derive_set(current.0, current.1, spec.count, VerKeyCode::Ed25519)?;

        let upcoming = Self::rung_up(current.0, current.1, spec.count)?;
        let next = self.derive_set(upcoming.0, upcoming.1, spec.ncount, VerKeyCode::Ed25519)?;
        let next_digests = Self::commit_set(&next)?;

        self.ridx = current.0;
        self.kidx = current.1;
        self.count = spec.count;
        self.ncount = spec.ncount;
        Ok(KeyCommitment {
            verkeys,
            next_digests,
        })
    }

    fn sign(
        &self,
        ser: &[u8],
        indices: Option<&[u32]>,
    ) -> Result<Vec<Siger<'static>>, CustodyError> {
        if !self.incepted {
            return Err(CustodyError::NotIncepted);
        }
        if let Some(idx) = indices
            && idx.len() != self.count
        {
            return Err(CustodyError::IndicesLengthMismatch {
                expected: self.count,
                actual: idx.len(),
            });
        }
        (0..self.count)
            .map(|i| {
                let offset = u64::try_from(i).map_err(|_| CustodyError::IndexOverflow)?;
                let key_index = self
                    .kidx
                    .checked_add(offset)
                    .ok_or(CustodyError::IndexOverflow)?;
                let path = self.derivation_path(self.ridx, key_index);
                let kp = self.salt.key_pair(&path, self.tier)?;
                let index = indices.map_or_else(
                    || u32::try_from(i).map_err(|_| CustodyError::IndexOverflow),
                    |idx| Ok(idx[i]),
                )?;
                Ok(kp.sign_indexed(ser, index, IndexMode::Both)?)
            })
            .collect()
    }
}

/// Persistable [`SaltyCustodian`] state — everything EXCEPT the salt.
///
/// Persist locally; reconstruct with [`SaltyCustodian::resume`] by
/// re-supplying the salt (or re-deriving it from the passcode). Shipping
/// these fields plus the salt to another party hands over the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaltyParams {
    /// Derivation-path stem convention.
    pub convention: PathConvention,
    /// Argon2id cost tier.
    pub tier: Tier,
    /// Account (prefix) index.
    pub pidx: u64,
    /// Rotation index of the current key set.
    pub ridx: u64,
    /// Key index of the first current key.
    pub kidx: u64,
    /// Current key count.
    pub count: usize,
    /// Committed next-key count.
    pub ncount: usize,
    /// Whether the identifier is transferable.
    pub transferable: bool,
    /// Whether inception has happened.
    pub incepted: bool,
}

impl SaltyCustodian {
    /// Snapshot of the custody counters for local persistence — never
    /// includes salt material.
    #[must_use]
    pub fn params(&self) -> SaltyParams {
        SaltyParams {
            convention: self.convention.clone(),
            tier: self.tier,
            pidx: self.pidx,
            ridx: self.ridx,
            kidx: self.kidx,
            count: self.count,
            ncount: self.ncount,
            transferable: self.transferable,
            incepted: self.incepted,
        }
    }

    /// Reconstructs a custodian from persisted [`SaltyParams`] plus the
    /// re-supplied root salt.
    #[must_use]
    pub fn resume(salt: Salt, params: SaltyParams) -> Self {
        Self {
            salt,
            tier: params.tier,
            convention: params.convention,
            pidx: params.pidx,
            ridx: params.ridx,
            kidx: params.kidx,
            count: params.count,
            ncount: params.ncount,
            transferable: params.transferable,
            incepted: params.incepted,
        }
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
    use cesr::core::primitives::Verfer;

    #[test]
    fn custodian_is_object_safe() {
        fn probe(_: &dyn Custodian<Error = CustodyError>) {}
        let _ = probe;
    }

    const RAW: &[u8; 16] = b"0123456789abcdef";

    fn salty() -> SaltyCustodian {
        SaltyCustodian::new(
            Salt::from_raw(RAW).unwrap(),
            Tier::Low,
            PathConvention::Keripy,
        )
    }

    #[test]
    fn keripy_path_convention_builds_stem_from_pidx() {
        let c = salty();
        assert_eq!(c.derivation_path(0, 0), "000");
        assert_eq!(c.derivation_path(1, 2), "012");
        assert_eq!(c.derivation_path(16, 31), "0101f");
    }

    #[test]
    fn signify_path_convention_uses_fixed_stem() {
        let c = SaltyCustodian::new(
            Salt::from_raw(RAW).unwrap(),
            Tier::Low,
            PathConvention::Signify,
        );
        assert_eq!(c.derivation_path(0, 0), "signify:aid00");
    }

    #[test]
    fn incept_derives_deterministic_commitment() {
        let spec = KeySpec {
            count: 1,
            ncount: 1,
            transferable: true,
        };
        let a = salty().incept(spec).unwrap();
        let b = salty().incept(spec).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.verkeys.len(), 1);
        assert_eq!(a.next_digests.len(), 1);
        assert_eq!(*a.verkeys[0].code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn incept_twice_is_rejected() {
        let mut c = salty();
        let spec = KeySpec {
            count: 1,
            ncount: 1,
            transferable: true,
        };
        c.incept(spec).unwrap();
        assert!(matches!(c.incept(spec), Err(CustodyError::AlreadyIncepted)));
    }

    #[test]
    fn non_transferable_incept_uses_n_code_and_rejects_next_keys() {
        let mut c = salty();
        let bad = KeySpec {
            count: 1,
            ncount: 1,
            transferable: false,
        };
        assert!(matches!(
            c.incept(bad),
            Err(CustodyError::NonTransferableNextKeys { ncount: 1 })
        ));
        let good = KeySpec {
            count: 1,
            ncount: 0,
            transferable: false,
        };
        let out = salty().incept(good).unwrap();
        assert_eq!(*out.verkeys[0].code(), VerKeyCode::Ed25519N);
        assert!(out.next_digests.is_empty());
    }

    #[test]
    fn rotate_promotes_the_committed_next_set() {
        let mut c = salty();
        let icp = c
            .incept(KeySpec {
                count: 1,
                ncount: 1,
                transferable: true,
            })
            .unwrap();
        let rot = c
            .rotate(KeySpec {
                count: 1,
                ncount: 1,
                transferable: true,
            })
            .unwrap();
        let commitment = Digest::from_matter(
            digest(DigestCode::Blake3_256, &rot.verkeys[0].to_qb64b()).unwrap(),
        );
        assert_eq!(commitment, icp.next_digests[0]);
        assert_ne!(rot.verkeys, icp.verkeys);
        assert_ne!(rot.next_digests, icp.next_digests);
    }

    #[test]
    fn rotate_count_must_match_committed_next_set() {
        let mut c = salty();
        c.incept(KeySpec {
            count: 1,
            ncount: 2,
            transferable: true,
        })
        .unwrap();
        let err = c
            .rotate(KeySpec {
                count: 1,
                ncount: 1,
                transferable: true,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyError::RotationCountMismatch {
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn abandoned_custodian_cannot_rotate() {
        let mut c = salty();
        c.incept(KeySpec {
            count: 1,
            ncount: 0,
            transferable: true,
        })
        .unwrap();
        assert!(matches!(
            c.rotate(KeySpec {
                count: 1,
                ncount: 1,
                transferable: true,
            }),
            Err(CustodyError::NotRotatable)
        ));
    }

    #[test]
    fn sign_produces_verifiable_indexed_signatures() {
        let mut c = salty();
        let icp = c
            .incept(KeySpec {
                count: 2,
                ncount: 0,
                transferable: false,
            })
            .unwrap();
        let sigs = c.sign(b"event bytes", None).unwrap();
        assert_eq!(sigs.len(), 2);
        for (i, sig) in sigs.iter().enumerate() {
            assert_eq!(sig.index(), u32::try_from(i).unwrap());
        }
        let keys: Vec<Verfer<'_>> = icp
            .verkeys
            .iter()
            .map(|vk| vk.as_matter().clone())
            .collect();
        let verified: Vec<u32> = cesr::crypto::verify_indexed(&keys, b"event bytes", &sigs)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(verified, [0, 1]);
    }

    #[test]
    fn sign_with_explicit_indices_and_length_mismatch() {
        let mut c = salty();
        c.incept(KeySpec {
            count: 2,
            ncount: 0,
            transferable: false,
        })
        .unwrap();
        let sigs = c.sign(b"x", Some(&[5, 9])).unwrap();
        assert_eq!(sigs[0].index(), 5);
        assert_eq!(sigs[1].index(), 9);
        assert!(matches!(
            c.sign(b"x", Some(&[0])),
            Err(CustodyError::IndicesLengthMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn params_resume_re_derives_identical_keys() {
        let mut c = salty();
        c.incept(KeySpec {
            count: 1,
            ncount: 1,
            transferable: true,
        })
        .unwrap();
        let rot = c
            .rotate(KeySpec {
                count: 1,
                ncount: 1,
                transferable: true,
            })
            .unwrap();

        let params = c.params();
        let resumed = SaltyCustodian::resume(Salt::from_raw(RAW).unwrap(), params);
        let sigs_a = c.sign(b"data", None).unwrap();
        let sigs_b = resumed.sign(b"data", None).unwrap();
        assert_eq!(sigs_a, sigs_b);
        let _ = rot;
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn derivation_paths_are_unique_per_key_index(
            ridx in 0_u64..=u64::MAX,
            kidx_a in 0_u64..=u64::MAX,
            kidx_b in 0_u64..=u64::MAX,
        ) {
            prop_assume!(kidx_a != kidx_b);
            let c = salty();
            // Hex concatenation is ambiguous across (ridx,kidx) pairs in
            // general (keripy inherits the same ambiguity); within a fixed
            // ridx the kidx must disambiguate.
            prop_assert_ne!(c.derivation_path(ridx, kidx_a), c.derivation_path(ridx, kidx_b));
        }
    }

    proptest! {
        // argon2 at Tier::Low costs ~1 s per derived key; keep case count
        // and key counts tiny so the suite stays fast.
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn spec_validation_is_total(count in 0_usize..3, ncount in 0_usize..3, transferable: bool) {
            let mut c = salty();
            let spec = KeySpec { count, ncount, transferable };
            // Must never panic; error or commitment with the exact sizes.
            if let Ok(out) = c.incept(spec) {
                prop_assert_eq!(out.verkeys.len(), count);
                prop_assert_eq!(out.next_digests.len(), ncount);
            }
        }
    }
}
