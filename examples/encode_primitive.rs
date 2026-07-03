//! Encode a CESR primitive to qualified Base64 (qb64) text and parse it back.
//!
//! This is the lowest layer of CESR: every key, digest, signature, and
//! identifier is a `Matter` — raw bytes plus a derivation *code* that says what
//! the bytes mean. The text form (`qb64`) is that code followed by the
//! Base64URL-encoded bytes, and it round-trips: decoding the text yields the
//! original code and raw bytes exactly.
//!
//! Run with:
//! ```text
//! cargo run --example encode_primitive --features stream
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the qb64 forms it produces"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::stream::encode::matter_to_qb64;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 32 deterministic bytes stand in for a real Ed25519 public key. Encoding
    // never inspects the curve — a `Matter` is just (code, raw bytes) — so a
    // fixed pattern keeps this example reproducible with no RNG.
    let key_bytes: [u8; 32] = [
        0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d,
        0x73, 0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6, 0x3a, 0xc0, 0x48, 0xa1, 0x8b, 0x59,
        0xda, 0x29,
    ];

    // A transferable (rotatable) Ed25519 public key → `Verfer`, code "D".
    let verfer = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(&key_bytes[..])?
        .build()?;

    let verfer_qb64 = matter_to_qb64(&verfer)?;
    let verfer_text = String::from_utf8(verfer_qb64)?;
    println!("Verfer (Ed25519 public key) qb64: {verfer_text}");

    // The derivation code is load-bearing: transferable Ed25519 keys start "D".
    assert!(
        verfer_text.starts_with('D'),
        "Ed25519 transferable verfer must carry code 'D', got {verfer_text}"
    );

    // Decode the text back into a primitive and prove the round-trip: the raw
    // bytes we started with come back byte-for-byte.
    let decoded = MatterBuilder::new().from_qualified_base64(verfer_text.as_bytes())?;
    assert_eq!(
        decoded.raw(),
        &key_bytes[..],
        "decode(encode(key)) must recover the original raw bytes"
    );

    // A different primitive kind uses a different code. A Blake3-256 digest
    // (`Diger`) over the same bytes encodes with code "E".
    let diger = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(&key_bytes[..])?
        .build()?;
    let diger_text = String::from_utf8(matter_to_qb64(&diger)?)?;
    println!("Diger  (Blake3-256 digest)    qb64: {diger_text}");
    assert!(
        diger_text.starts_with('E'),
        "Blake3-256 digest must carry code 'E', got {diger_text}"
    );

    // Same 32 raw bytes, different code → different text. The code is what makes
    // a CESR primitive self-describing.
    assert_ne!(
        verfer_text, diger_text,
        "identical bytes under different codes must produce different qb64"
    );

    println!("Round-trip and code-prefix checks passed.");
    Ok(())
}
