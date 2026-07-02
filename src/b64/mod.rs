//! CESR Base64 codec.
//!
//! URL-safe Base64 encode/decode for CESR integer and binary fields: the
//! canonical alphabet + reverse table ([`alphabet`]), the integer codec
//! ([`int`]), byte-stream encoding ([`binary`]), and character-set validation
//! ([`charset`]).

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, string::ToString, vec, vec::Vec};

/// The canonical URL-safe Base64 alphabet, reverse table, and char↔index helpers.
pub mod alphabet;
/// Base64 encoding functions for CESR binary data.
pub mod binary;
/// URL-safe Base64 character-set validation.
pub mod charset;
/// Error types for Base64 decode/encode operations.
pub mod error;
/// Base64 codec for CESR integers (both directions).
pub mod int;

pub use binary::encode_binary;
pub use charset::is_b64_url_safe_charset;
pub use int::{decode_to_int, encode_int};
