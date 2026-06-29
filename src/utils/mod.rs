//! CESR Base64 encoding/decoding utilities.
//!
//! Provides URL-safe Base64 encoding and decoding for CESR integer and binary
//! fields, plus character-set validation helpers.

/// Base64 decoding functions for CESR integers and binary data.
pub mod decode;
/// Base64 encoding functions for CESR integers and binary data.
pub mod encode;
/// Error types for Base64 decode/encode operations.
pub mod error;
/// Base64 character-set validation and conversion helpers.
pub mod utils;

pub use decode::decode_to_int;
pub use encode::{encode_binary, encode_int};
