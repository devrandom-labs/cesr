//! Compile-time CESR version safety via phantom types.
//!
//! The sealed [`Version`] trait and its two implementors [`V1`] and [`V2`]
//! are used as type parameters on [`CesrEncode`] to guarantee at compile time
//! that a group is only encoded with a compatible counter code table.
//!
//! [`CesrEncode`]: crate::encode::CesrEncode

use bytes::BytesMut;

use crate::error::ParseError;
use cesr::core::version::CesrVersion;

mod private {
    pub trait Sealed {}
}

/// Marker trait for CESR counter code table versions.
///
/// This trait is **sealed** — only [`V1`] and [`V2`] implement it.
/// External crates cannot add new versions.
pub trait Version: private::Sealed + 'static {
    /// The value-level [`CesrVersion`] this marker type stands for.
    const VERSION: CesrVersion;
}

/// CESR counter code table version 1.0.
pub enum V1 {}
impl private::Sealed for V1 {}
impl Version for V1 {
    const VERSION: CesrVersion = CesrVersion::V1;
}

/// CESR counter code table version 2.0.
pub enum V2 {}
impl private::Sealed for V2 {}
impl Version for V2 {
    const VERSION: CesrVersion = CesrVersion::V2;
}

/// Encode a CESR group into a byte buffer using version `V`'s counter codes.
///
/// Shared group types (e.g. [`ControllerIdxSigs`]) implement this for both
/// [`V1`] and [`V2`]. V2-only types (e.g. [`DatagramSegmentGroup`]) only
/// implement `CesrEncode<V2>` — attempting to encode them as V1 is a
/// **compile-time error**.
///
/// [`ControllerIdxSigs`]: crate::group::ControllerIdxSigs
/// [`DatagramSegmentGroup`]: crate::group::DatagramSegmentGroup
pub trait CesrEncode<V: Version> {
    /// Append this group's wire-format bytes (counter + payload) to `dst`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Malformed`] if the count does not fit in the
    /// counter's soft field, or if a V2-only group is encoded with V1 counters.
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_marker_links_to_value_level_v1() {
        assert_eq!(<V1 as Version>::VERSION, CesrVersion::V1);
    }

    #[test]
    fn v2_marker_links_to_value_level_v2() {
        assert_eq!(<V2 as Version>::VERSION, CesrVersion::V2);
    }
}
