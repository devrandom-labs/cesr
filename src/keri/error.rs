#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{string::String,};
use thiserror::Error;

/// Errors from keri-core domain operations.
#[derive(Debug, Error)]
pub enum KeriError {
    /// Unknown event type code.
    #[error("unknown ilk code: {0}")]
    UnknownIlk(String),
    /// Unknown config trait code.
    #[error("unknown config trait code: {0}")]
    UnknownConfigTrait(String),
    /// Unknown role code.
    #[error("unknown role code: {0}")]
    UnknownRole(String),
}
