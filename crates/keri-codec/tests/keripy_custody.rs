//! Differential: `SaltyCustodian` incept/rotate sequence vs keripy custody
//! vectors (`scripts/keripy_custody_gen.py` at the pin in `scripts/KERIPY_PIN`).
//!
//! Same salt, same tier, same counts -> byte-identical verkeys and next-key
//! digests at every step, which is exactly the "same passcode, same AID"
//! acceptance of #93.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration test binary — unwrap/panic documents the failing invariant"
)]

use cesr::crypto::salt::{Salt, Tier};
use keri::{Custodian, KeySpec, PathConvention, SaltyCustodian};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    oracle: String,
    salt_qb64: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    op: String,
    count: usize,
    ncount: usize,
    verkeys: Vec<String>,
    digers: Vec<String>,
}

#[test]
fn keripy_custody_sequence_matches_vectors() {
    let v: Vectors =
        serde_json::from_str(include_str!("fixtures/keripy_custody_vectors.json")).unwrap();
    assert!(!v.steps.is_empty(), "oracle {} produced no steps", v.oracle);

    let salt = Salt::from_qb64(&v.salt_qb64).unwrap();
    let mut custodian = SaltyCustodian::new(salt, Tier::Low, PathConvention::Keripy);

    for (n, step) in v.steps.iter().enumerate() {
        let spec = KeySpec {
            count: step.count,
            ncount: step.ncount,
            transferable: true,
        };
        let out = match step.op.as_str() {
            "incept" => custodian.incept(spec).unwrap(),
            "rotate" => custodian.rotate(spec).unwrap(),
            other => panic!("unknown op {other:?}"),
        };
        let verkeys: Vec<String> = out.verkeys.iter().map(|k| k.to_qb64()).collect();
        let digers: Vec<String> = out.next_digests.iter().map(|d| d.to_qb64()).collect();
        assert_eq!(verkeys, step.verkeys, "step {n} verkeys");
        assert_eq!(digers, step.digers, "step {n} next digests");
    }
}
