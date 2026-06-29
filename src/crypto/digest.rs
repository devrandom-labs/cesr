use blake2::{Blake2b, Blake2b512, Blake2s256, Digest as _};
use cesr_core::matter::builder::MatterBuilder;
use cesr_core::matter::code::DigestCode;
use cesr_core::primitives::Diger;
use digest::consts::U32;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

/// Computes a cryptographic digest of `data` using the algorithm specified by `code`.
///
/// # Errors
///
/// Returns a [`DigestError`](crate::error::DigestError) if building the CESR primitive fails.
pub fn digest(code: DigestCode, data: &[u8]) -> Result<Diger<'static>, crate::error::DigestError> {
    let raw = match code {
        DigestCode::Blake3_256 => blake3::hash(data).as_bytes().to_vec(),
        DigestCode::Blake3_512 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(data);
            let mut output = vec![0u8; 64];
            hasher.finalize_xof().fill(&mut output);
            output
        }
        DigestCode::Blake2b_256 => Blake2b::<U32>::digest(data).to_vec(),
        DigestCode::Blake2b_512 => Blake2b512::digest(data).to_vec(),
        DigestCode::Blake2s_256 => Blake2s256::digest(data).to_vec(),
        DigestCode::SHA2_256 => Sha256::digest(data).to_vec(),
        DigestCode::SHA2_512 => Sha512::digest(data).to_vec(),
        DigestCode::SHA3_256 => Sha3_256::digest(data).to_vec(),
        DigestCode::SHA3_512 => Sha3_512::digest(data).to_vec(),
    };

    MatterBuilder::new()
        .with_code(code)
        .with_raw(raw)
        .map_err(|e| crate::error::DigestError::BuildFailed(e.to_string()))?
        .build()
        .map_err(|e| crate::error::DigestError::BuildFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr_core::matter::code::DigestCode;

    #[test]
    fn blake3_256_digest() {
        let d = digest(DigestCode::Blake3_256, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::Blake3_256);
        assert_eq!(d.raw().len(), 32);
    }

    #[test]
    fn blake3_512_digest() {
        let d = digest(DigestCode::Blake3_512, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::Blake3_512);
        assert_eq!(d.raw().len(), 64);
    }

    #[test]
    fn blake2b_256_digest() {
        let d = digest(DigestCode::Blake2b_256, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::Blake2b_256);
        assert_eq!(d.raw().len(), 32);
    }

    #[test]
    fn blake2b_512_digest() {
        let d = digest(DigestCode::Blake2b_512, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::Blake2b_512);
        assert_eq!(d.raw().len(), 64);
    }

    #[test]
    fn blake2s_256_digest() {
        let d = digest(DigestCode::Blake2s_256, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::Blake2s_256);
        assert_eq!(d.raw().len(), 32);
    }

    #[test]
    fn sha2_256_digest() {
        let d = digest(DigestCode::SHA2_256, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::SHA2_256);
        assert_eq!(d.raw().len(), 32);
    }

    #[test]
    fn sha2_512_digest() {
        let d = digest(DigestCode::SHA2_512, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::SHA2_512);
        assert_eq!(d.raw().len(), 64);
    }

    #[test]
    fn sha3_256_digest() {
        let d = digest(DigestCode::SHA3_256, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::SHA3_256);
        assert_eq!(d.raw().len(), 32);
    }

    #[test]
    fn sha3_512_digest() {
        let d = digest(DigestCode::SHA3_512, b"hello").unwrap();
        assert_eq!(*d.code(), DigestCode::SHA3_512);
        assert_eq!(d.raw().len(), 64);
    }

    #[test]
    fn same_input_same_digest() {
        let d1 = digest(DigestCode::Blake3_256, b"deterministic").unwrap();
        let d2 = digest(DigestCode::Blake3_256, b"deterministic").unwrap();
        assert_eq!(d1.raw(), d2.raw());
    }

    #[test]
    fn different_input_different_digest() {
        let d1 = digest(DigestCode::Blake3_256, b"one").unwrap();
        let d2 = digest(DigestCode::Blake3_256, b"two").unwrap();
        assert_ne!(d1.raw(), d2.raw());
    }

    #[test]
    fn different_algo_different_digest() {
        let d1 = digest(DigestCode::Blake3_256, b"same").unwrap();
        let d2 = digest(DigestCode::SHA2_256, b"same").unwrap();
        assert_ne!(d1.raw(), d2.raw());
    }

    // ===== Known-vector conformance tests =====
    // These test vectors are universally known hash outputs from NIST, Blake3,
    // and Blake2 reference implementations.

    /// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn sha2_256_empty_string_known_vector() {
        const EXPECTED: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let d = digest(DigestCode::SHA2_256, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::SHA2_256);
    }

    /// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #[test]
    fn sha2_256_abc_known_vector() {
        const EXPECTED: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let d = digest(DigestCode::SHA2_256, b"abc").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
    }

    /// SHA-512("") = cf83e1357eefb8bd...
    #[test]
    fn sha2_512_empty_string_known_vector() {
        const EXPECTED: [u8; 64] = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        let d = digest(DigestCode::SHA2_512, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::SHA2_512);
    }

    /// SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    #[test]
    fn sha3_256_empty_string_known_vector() {
        const EXPECTED: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];
        let d = digest(DigestCode::SHA3_256, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::SHA3_256);
    }

    /// SHA3-512("") = a69f73cca23a9ac5...
    #[test]
    fn sha3_512_empty_string_known_vector() {
        const EXPECTED: [u8; 64] = [
            0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a,
            0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1,
            0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3,
            0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
            0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
        ];
        let d = digest(DigestCode::SHA3_512, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::SHA3_512);
    }

    /// Blake3-256("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
    #[test]
    fn blake3_256_empty_string_known_vector() {
        const EXPECTED: [u8; 32] = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];
        let d = digest(DigestCode::Blake3_256, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    /// Blake2b-256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
    #[test]
    fn blake2b_256_empty_string_known_vector() {
        const EXPECTED: [u8; 32] = [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ];
        let d = digest(DigestCode::Blake2b_256, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::Blake2b_256);
    }

    /// Blake2b-512("") = 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419...
    #[test]
    fn blake2b_512_empty_string_known_vector() {
        const EXPECTED: [u8; 64] = [
            0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52,
            0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17,
            0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89,
            0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
            0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
        ];
        let d = digest(DigestCode::Blake2b_512, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::Blake2b_512);
    }

    /// Blake2s-256("") = 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9
    #[test]
    fn blake2s_256_empty_string_known_vector() {
        const EXPECTED: [u8; 32] = [
            0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35,
            0x4a, 0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd,
            0x1e, 0xd0, 0xee, 0xf9,
        ];
        let d = digest(DigestCode::Blake2s_256, b"").unwrap();
        assert_eq!(d.raw(), &EXPECTED);
        assert_eq!(*d.code(), DigestCode::Blake2s_256);
    }

    // ===== Property-based tests =====

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Digesting the same data with the same algorithm always produces
            /// identical output (determinism).
            #[test]
            fn digest_deterministic_for_all_codes(
                data in proptest::collection::vec(any::<u8>(), 0..256)
            ) {
                for code in [
                    DigestCode::Blake3_256,
                    DigestCode::Blake3_512,
                    DigestCode::Blake2b_256,
                    DigestCode::Blake2b_512,
                    DigestCode::Blake2s_256,
                    DigestCode::SHA2_256,
                    DigestCode::SHA2_512,
                    DigestCode::SHA3_256,
                    DigestCode::SHA3_512,
                ] {
                    let d1 = digest(code, &data).unwrap();
                    let d2 = digest(code, &data).unwrap();
                    prop_assert_eq!(d1.raw(), d2.raw());
                    prop_assert_eq!(d1.code(), d2.code());
                }
            }

            /// The raw output length always matches the expected size for each
            /// digest algorithm.
            #[test]
            fn digest_output_size_matches_code(
                data in proptest::collection::vec(any::<u8>(), 0..256)
            ) {
                let expected_sizes = [
                    (DigestCode::Blake3_256, 32),
                    (DigestCode::Blake3_512, 64),
                    (DigestCode::Blake2b_256, 32),
                    (DigestCode::Blake2b_512, 64),
                    (DigestCode::Blake2s_256, 32),
                    (DigestCode::SHA2_256, 32),
                    (DigestCode::SHA2_512, 64),
                    (DigestCode::SHA3_256, 32),
                    (DigestCode::SHA3_512, 64),
                ];
                for (code, size) in expected_sizes {
                    let d = digest(code, &data).unwrap();
                    prop_assert_eq!(d.raw().len(), size,
                        "digest code {:?} produced {} bytes, expected {}",
                        code, d.raw().len(), size);
                    prop_assert_eq!(*d.code(), code);
                }
            }

            /// Different data should (with overwhelming probability) produce
            /// different digests. We test this for a 256-bit hash to avoid
            /// false negatives from birthday collisions.
            #[test]
            fn digest_collision_resistance(
                a in proptest::collection::vec(any::<u8>(), 1..256),
                b in proptest::collection::vec(any::<u8>(), 1..256),
            ) {
                prop_assume!(a != b);
                let da = digest(DigestCode::SHA2_256, &a).unwrap();
                let db = digest(DigestCode::SHA2_256, &b).unwrap();
                prop_assert_ne!(da.raw(), db.raw());
            }
        }
    }
}
