//! Compile-time CESR version safety via phantom types.
//!
//! The sealed [`Version`] trait and its two implementors [`V1`] and [`V2`]
//! are used as type parameters on [`CesrEncode`] to guarantee at compile time
//! that a group is only encoded with a compatible counter code table.
//!
//! [`CesrEncode`]: crate::stream::encode::CesrEncode

use bytes::BytesMut;

use crate::stream::error::ParseError;

mod private {
    pub trait Sealed {}
}

/// Marker trait for CESR counter code table versions.
///
/// This trait is **sealed** — only [`V1`] and [`V2`] implement it.
/// External crates cannot add new versions.
pub trait Version: private::Sealed + 'static {}

/// CESR counter code table version 1.0.
pub enum V1 {}
impl private::Sealed for V1 {}
impl Version for V1 {}

/// CESR counter code table version 2.0.
pub enum V2 {}
impl private::Sealed for V2 {}
impl Version for V2 {}

/// Encode a CESR group into a byte buffer using version `V`'s counter codes.
///
/// Shared group types (e.g. [`ControllerIdxSigs`]) implement this for both
/// [`V1`] and [`V2`]. V2-only types (e.g. [`DatagramSegmentGroup`]) only
/// implement `CesrEncode<V2>` — attempting to encode them as V1 is a
/// **compile-time error**.
///
/// [`ControllerIdxSigs`]: crate::stream::group::types::ControllerIdxSigs
/// [`DatagramSegmentGroup`]: crate::stream::group::types::DatagramSegmentGroup
pub trait CesrEncode<V: Version> {
    /// Append this group's wire-format bytes (counter + payload) to `dst`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Malformed`] if the count does not fit in the
    /// counter's soft field, or if a V2-only group is encoded with V1 counters.
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError>;
}
