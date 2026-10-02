//! Binary domain (qb2) conversion — re-exported from the `cesr` primitive crate,
//! which owns all Base64-domain math. See [`cesr::b64::transcode`].
//!
//! The selected V1 JSON/text message profile has an explicit conversion
//! boundary for an externally delimited **complete attachment group**:
//!
//! 1. The caller bounds and delimits the qb2 group in its own transport. A
//!    binary cold start is not a message boundary in [`MessageFramer`](crate::MessageFramer).
//! 2. Convert that exact span with [`Qb2::encode`]. It requires a whole
//!    multiple of three binary bytes and yields qb64 text.
//! 3. Validate the text with [`CesrGroup::parse`](crate::group::CesrGroup::parse)
//!    and require an empty remainder for one group. Append that validated
//!    text group to its exact V1 JSON body, then use the typed message parser.
//!
//! This conversion is byte-equivalent for an aligned CESR group. It does not
//! identify group boundaries inside an undelimited qb2 stream, accept mixed
//! text/binary attachments, or provide a native/V2 body codec. The caller
//! should enforce its byte policy before allocating the conversion output;
//! the typed parser enforces its own `FrameLimits` afterward. The public
//! signed-message regression is `keri-codec/tests/a25_wire.rs`.

pub use cesr::b64::{Qb2, Qb64};

#[cfg(test)]
mod tests {
    use super::{Qb2, Qb64};

    #[test]
    fn reexport_paths_resolve_and_roundtrip() {
        let bin = Qb64(b"-AAB").decode().unwrap();
        assert_eq!(&Qb2(&bin).encode().unwrap(), b"-AAB");
    }
}
