//! CESR (Composable Event Streaming Representation) core primitives and codes.

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
mod utils;
