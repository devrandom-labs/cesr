//! CESR (Composable Event Streaming Representation) core primitives and codes.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};

/// Counter (group) codes for V1.0 and V2.0 CESR code tables.
pub mod counter;
/// Indexed signature primitives, codes, and builders.
pub mod indexer;
/// CESR protocol version selection.
#[cfg(feature = "stream")]
pub mod version;
#[cfg(feature = "stream")]
pub use version::CesrVersion;
/// Matter primitives, codes, sizage, and builders.
pub mod matter;
/// Higher-level CESR primitive types (Verfer, Signer, Diger, etc.).
pub mod primitives;

pub use matter::Matter;
pub use primitives::{
    Cigar, Dater, Diger, Labeler, Noncer, Number, Prefixer, Saider, Seqner, Signer, Siger,
    Texter, Tholder, Verfer, Verser,
};
