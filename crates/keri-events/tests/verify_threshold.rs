//! Cross-layer signature and threshold composition on packaged dependencies.

use cesr::core::indexer::code::IndexMode;
use cesr::core::matter::code::VerKeyCode;
use cesr::crypto::algo::Ed25519;
use cesr::crypto::keypair::KeyPair;
use cesr::crypto::verify_indexed;
use keri_events::SigningThreshold;

#[test]
fn verified_indices_satisfy_threshold() {
    let message = b"shared event bytes";
    let mut keys = Vec::new();
    let mut signatures = Vec::new();
    for (index, seed) in (0u32..3).zip([1u8, 2, 3]) {
        let key = KeyPair::<Ed25519>::from_seed_bytes(&[seed; 32]);
        keys.push(key.verfer(VerKeyCode::Ed25519).unwrap().into_static());
        signatures.push(key.sign_indexed(message, index, IndexMode::Both).unwrap());
    }
    let indices: Vec<u32> = verify_indexed(&keys, message, &signatures)
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(SigningThreshold::Simple(3).satisfied_by(indices.iter().copied()));
    assert!(!SigningThreshold::Simple(4).satisfied_by(indices));
}
