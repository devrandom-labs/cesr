//! Generate an Ed25519 key pair, sign a message, and verify the signature.
//!
//! This is the crypto layer: `KeyPair` wraps a real signing key, `Verfer` is
//! the public key as a CESR primitive, and `Cigar` is a (non-indexed) signature
//! as a CESR primitive. A correct signature verifies; a tampered message does
//! not.
//!
//! Run with:
//! ```text
//! cargo run --example keypair_sign_verify --features crypto,stream
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the public key and signature it produces"
)]

use cesr::core::matter::code::VerKeyCode;
use cesr::stream::encode::matter_to_qb64;
use cesr::{Ed25519, KeyPair};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Fresh Ed25519 key pair (uses the OS RNG under the `std` feature).
    let keypair = KeyPair::<Ed25519>::generate()?;

    // The public key as a CESR `Verfer`. Code "D" = transferable Ed25519.
    let verfer = keypair.verfer(VerKeyCode::Ed25519)?;
    let verfer_text = String::from_utf8(matter_to_qb64(&verfer)?)?;
    println!("Public key (Verfer): {verfer_text}");
    assert!(
        verfer_text.starts_with('D'),
        "transferable Ed25519 verfer must carry code 'D'"
    );

    let message = b"CESR makes signatures self-describing.";

    // Sign, then encode the signature to its CESR text form for display.
    let signature = keypair.sign(message)?;
    let signature_text = String::from_utf8(matter_to_qb64(&signature)?)?;
    println!("Signature (Cigar):   {signature_text}");

    // The honest path: the signature verifies against the signed message.
    assert!(
        keypair.verify(message, &signature)?,
        "a signature must verify against the exact bytes that were signed"
    );

    // Flip one byte of the message; the same signature must now fail. This is
    // the property that makes signatures useful — they bind to specific bytes.
    let tampered = b"CESR makes signatures self-describing!";
    assert!(
        !keypair.verify(tampered, &signature)?,
        "a signature must NOT verify against modified bytes"
    );

    println!("Signature verified; tampered message correctly rejected.");
    Ok(())
}
