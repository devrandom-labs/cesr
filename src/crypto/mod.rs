//! CESR-compatible cryptographic signing, verification, and digest primitives.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, string::ToString, vec, vec::Vec};

/// Algorithm marker types and the `Algorithm` sealed trait.
pub mod algo;
/// Digest computation for all supported CESR hash algorithms.
pub mod digest;
/// Error types for signing, verification, key, and digest operations.
pub mod error;
/// Generic `KeyPair<A>` for Ed25519, secp256k1, and secp256r1.
pub mod keypair;
/// Standalone signature verification dispatching on `VerKeyCode` at runtime.
pub mod verify;

// Re-exports for convenience
pub use algo::{Algorithm, Ed25519, Secp256k1, Secp256r1};
pub use digest::digest;
pub use error::{CodeMismatchError, DigestError, KeyError, SignatureError};
pub use keypair::KeyPair;
pub use verify::verify;
