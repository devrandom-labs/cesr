//! Wire framing: find where a CESR message starts and ends.
//!
//! This module's one job is framing — cold-start detection, version-string
//! sizing, and counter-delimited attachment groups (V1.0 and V2.0 code
//! tables; all parsed groups are fully owned, `'static`). It slices spans
//! and parses groups; it never interprets an event body — that is the
//! `serder` module's job. Primary entry point: [`parse_message`].
//!
//! Attachment groups mirror how [`core`](crate::core) models primitives with
//! its one generic `Matter<'a, C>` carrier: `group::Group<K>` carries every
//! element-counted group and `group::Frame<K>` every quadlet-counted framing
//! group, each parameterized by a sealed kind (`GroupKind`/`FrameKind`) that
//! declares the family's counter codes and element grammar. The concrete
//! group types ([`ControllerIdxSigs`], `SealSourceCouples`, …) are type
//! aliases over those carriers, and the [`CesrEncode`] impls on the carriers
//! make encoding a V2-only group with V1 counters a compile-time error.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};

/// Cold start detection for CESR streams.
pub mod cold;
/// Stream parsing error types.
pub mod error;
/// CESR attachment groups: the generic `Group<K>`/`Frame<K>` carriers, their
/// sealed kinds, and the version dispatch.
pub mod group;
/// CESR message framing (version strings live in [`crate::core::version`]).
pub mod message;
/// qb64 <-> qb2 (text <-> binary) conversion.
pub mod qb2;

/// CESR qb64 encoding — counters and groups to wire format.
pub mod encode;
/// Nested group unwrapping with genus-version switching.
pub mod unwrap;
/// Compile-time version safety: sealed `Version` trait, `V1`/`V2` phantom types, `CesrEncode<V>`.
pub mod version;

#[doc(hidden)]
pub mod parse;

/// Tokio codec implementations for async CESR stream decoding.
#[cfg(feature = "async")]
pub mod codec;
#[cfg(feature = "async")]
pub use codec::CesrCodec;

pub use cold::ColdCode;
pub use cold::Tritet;
pub use cold::detect_tritet;
pub use encode::encode_version_string_v2;
pub use error::ParseError;
pub use group::CesrGroup;
pub use group::{ControllerIdxSigs, WitnessIdxSigs};
pub use group::{Groups, GroupsV2, groups, groups_v2, parse_group, parse_group_v2};
pub use message::CesrMessage;
pub use message::parse_message;
pub use qb2::{qb2_to_qb64, qb64_to_qb2};
pub use unwrap::unwrap_generic_group;
pub use version::CesrEncode;
pub use version::V1;
pub use version::V2;
pub use version::Version;
