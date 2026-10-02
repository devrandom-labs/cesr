#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::string::String;
use thiserror::Error;

/// Errors from keri-core domain operations.
#[derive(Debug, Error)]
pub enum KeriError {
    /// Unknown message type code.
    #[error("unknown message type code: {0}")]
    UnknownMessageType(String),
    /// Unknown config trait code.
    #[error("unknown config trait code: {0}")]
    UnknownConfigTrait(String),
    /// Unknown role code.
    #[error("unknown role code: {0}")]
    UnknownRole(String),
}

/// Structural identity rules for an inception, independent of wire encoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InceptionIdentityError {
    /// A basic prefix has exactly one controlling key.
    #[error("basic inception requires exactly one key, got {actual}")]
    BasicKeyCount {
        /// Number of declared controlling keys.
        actual: usize,
    },
    /// A basic prefix has a one-of-one signing threshold.
    #[error("basic inception requires signing threshold one")]
    BasicThreshold,
    /// The sole key's qualified value differs from the basic prefix.
    #[error("basic inception prefix does not equal its controlling key")]
    BasicKeyMismatch,
    /// A non-transferable prefix cannot commit a next authority.
    #[error("non-transferable inception cannot commit next keys")]
    NonTransferableNextKeys,
    /// A non-transferable prefix cannot name witnesses.
    #[error("non-transferable inception cannot name witnesses")]
    NonTransferableWitnesses,
    /// A non-transferable prefix cannot carry seals.
    #[error("non-transferable inception cannot carry anchors")]
    NonTransferableAnchors,
}
