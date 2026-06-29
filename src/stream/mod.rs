//! CESR stream parsing — counter-delimited group types and iterators.
//!
//! Parses CESR attachment groups from byte streams, supporting both V1.0 and
//! V2.0 counter code tables. All parsed groups are fully owned (`'static`).

/// Binary domain (qb2) conversion utilities.
pub mod binary;
/// Cold start detection for CESR streams.
pub mod cold;
/// Stream parsing error types.
pub mod error;
/// CESR attachment group types and parsers.
pub mod group;
/// CESR version string parsing for message framing.
pub mod message;

/// CESR qb64 encoding — counters and groups to wire format.
pub mod encode;
/// Nested group unwrapping with genus-version switching.
pub mod unwrap;
/// Compile-time version safety: sealed `Version` trait, `V1`/`V2` phantom types, `CesrEncode<V>`.
pub mod version;

#[doc(hidden)]
pub mod util;

#[doc(hidden)]
pub mod parse;

/// Tokio codec implementations for async CESR stream decoding.
#[cfg(feature = "async")]
pub mod codec;
#[cfg(feature = "async")]
pub use codec::CesrCodec;

pub use binary::{qb2_to_qb64, qb64_to_qb2};
pub use cold::ColdCode;
pub use cold::Tritet;
pub use cold::detect_tritet;
pub use encode::encode_version_string_v2;
pub use error::ParseError;
pub use group::types::CesrGroup;
pub use group::{Groups, GroupsV2, groups, groups_v2, parse_group, parse_group_v2};
pub use message::CesrMessage;
pub use message::VersionStringV2;
pub use message::parse_message;
pub use message::parse_version_string;
pub use message::parse_version_string_v2;
pub use unwrap::CesrVersion;
pub use unwrap::unwrap_generic_group;
pub use version::CesrEncode;
pub use version::V1;
pub use version::V2;
pub use version::Version;
