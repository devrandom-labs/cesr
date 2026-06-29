/// Builder for constructing and parsing `Indexer` primitives.
pub mod builder;
/// Indexed signature codes, mode, and lookup helpers.
pub mod code;
/// Parse and validation error types for indexed signature streams.
pub mod error;
/// `Indexer` type for indexed CESR signatures.
#[allow(
    clippy::module_inception,
    reason = "Indexer module contains the Indexer type"
)]
pub mod indexer;
/// Sizing table (`Xizage`) for indexed signature codes.
pub mod xizage;

pub use builder::IndexerBuilder;
pub use indexer::Indexer;
