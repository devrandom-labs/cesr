//! Helpers for converting CESR primitives to JSON-friendly string values.
//!
//! KERI events in JSON carry qb64-encoded CESR primitives (keys, digests, etc.)
//! as plain string fields. This module bridges `Matter<C>` → `String` and
//! provides hex formatting for sequence numbers.

use crate::core::matter::code::CesrCode;
use crate::core::matter::matter::Matter;
use crate::keri::Identifier;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec};

/// Encode a [`Matter`] primitive as a qualified Base64 (qb64) string.
///
/// qb64 output is pure ASCII (URL-safe Base64 alphabet + CESR code chars), so
/// this is infallible for any validly-constructed primitive.
#[must_use]
pub fn to_qb64_string<C: CesrCode>(matter: &Matter<'_, C>) -> String {
    matter.to_qb64()
}

/// Encode an [`Identifier`] as a qualified Base64 (qb64) string.
///
/// Dispatches to the inner `Prefixer` or `Saider` depending on the variant.
#[must_use]
pub fn identifier_to_qb64_string(id: &Identifier<'_>) -> String {
    match id {
        Identifier::Basic(prefixer) => to_qb64_string(prefixer),
        Identifier::SelfAddressing(saider) => to_qb64_string(saider),
    }
}

/// Format a witness threshold (`bt`) as a lowercase hexadecimal string
/// without leading zeros, matching keripy's `Number(num=n).numh` convention.
///
/// Event and seal sequence numbers (`s`) render through
/// [`SequenceNumber`](crate::keri::SequenceNumber)'s `Display` instead; this
/// helper's only remaining caller is the `bt` field, which stays a bare
/// `u32` (rung 3 of #171 will give it its own domain type).
///
/// Zero is rendered as `"0"`, not `""`.
#[must_use]
pub fn sn_to_hex(value: u128) -> String {
    format!("{value:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use alloc::borrow::Cow;

    #[test]
    fn verfer_to_qb64_string() {
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .expect("raw should be accepted")
            .build()
            .expect("build should succeed");

        let qb64 = to_qb64_string(&verfer);
        assert_eq!(qb64.len(), 44);
        assert!(
            qb64.starts_with('D'),
            "Ed25519 verfer qb64 should start with 'D'"
        );
    }

    #[test]
    fn saider_to_qb64_string() {
        let saider = MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .expect("raw should be accepted")
            .build()
            .expect("build should succeed");

        let qb64 = to_qb64_string(&saider);
        assert_eq!(qb64.len(), 44);
        assert!(
            qb64.starts_with('E'),
            "Blake3_256 saider qb64 should start with 'E'"
        );
    }

    #[test]
    fn sn_to_hex_zero() {
        assert_eq!(sn_to_hex(0), "0");
    }

    #[test]
    fn sn_to_hex_small() {
        assert_eq!(sn_to_hex(10), "a");
        assert_eq!(sn_to_hex(255), "ff");
    }

    #[test]
    fn sn_to_hex_large() {
        assert_eq!(sn_to_hex(4096), "1000");
    }
}
