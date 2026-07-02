//! CESR Base64 codec.
//!
//! URL-safe Base64 encode/decode for CESR integer and binary fields: the
//! canonical alphabet + reverse table ([`alphabet`]), the integer codec
//! ([`encode`]/[`decode`]), and character-set validation.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, string::ToString, vec, vec::Vec};

/// The canonical URL-safe Base64 alphabet, reverse table, and char↔index helpers.
pub mod alphabet;
/// Base64 decoding functions for CESR integers and binary data.
pub mod decode;
/// Base64 encoding functions for CESR integers and binary data.
pub mod encode;
/// Error types for Base64 decode/encode operations.
pub mod error;

pub use decode::decode_to_int;
pub use encode::{encode_binary, encode_int};
