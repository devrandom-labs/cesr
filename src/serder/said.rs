//! SAID (Self-Addressing IDentifier) computation and verification.
//!
//! A SAID is a content-addressable digest that appears in the `d` field of a
//! KERI event. To compute it, the `d` field is first filled with a placeholder
//! string of the correct length, the event is serialized, and the digest of
//! that serialization becomes the final `d` value.

use crate::core::matter::code::CesrCode;
use crate::core::matter::code::DigestCode;
use crate::core::matter::sizage::SizeType;
use crate::core::primitives::Saider;
use crate::crypto::digest::digest;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString};

use crate::serder::error::SerderError;
use crate::serder::primitives::to_qb64_string;

/// Placeholder character used to fill the `d` field before hashing.
///
/// `#` is not a valid Base64 character, so a placeholder string is
/// unambiguously distinguishable from a real SAID.
pub const DUMMY_CHAR: char = '#';

/// Generate a placeholder string of the correct qb64 length for `code`.
///
/// For `Blake3_256` the result is 44 `#` characters.
///
/// # Errors
///
/// Returns [`SerderError::DigestError`] if the code has a variable-size
/// `SizeType` (all digest codes are fixed-size, so this should never
/// occur in practice).
pub fn said_placeholder(code: DigestCode) -> Result<String, SerderError> {
    let sizage = code.get_sizage();
    let len = match *sizage.fs() {
        SizeType::Fixed(n) => usize::from(n),
        SizeType::Small | SizeType::Large => {
            return Err(SerderError::DigestError(
                "digest code has variable size, expected fixed".to_owned(),
            ));
        }
    };
    Ok(core::iter::repeat_n(DUMMY_CHAR, len).collect())
}

/// Compute a cryptographic digest of `data` and return it as a [`Saider`].
///
/// # Errors
///
/// Returns [`SerderError::DigestError`] if the underlying digest computation
/// fails.
pub fn compute_digest(data: &[u8], code: DigestCode) -> Result<Saider<'static>, SerderError> {
    digest(code, data).map_err(|e| SerderError::DigestError(e.to_string()))
}

/// Verify that the `d` field of a serialized JSON event matches a freshly
/// computed SAID.
///
/// This only replaces the `d` field with a placeholder — suitable for
/// rotation (`rot`), interaction (`ixn`), and delegated rotation (`drt`)
/// events.  For inception events where both `d` and `i` are saidive, use
/// the deserialization functions which handle double-SAID verification
/// internally.
///
/// The function:
/// 1. Parses `raw` as JSON and reads the `d` field.
/// 2. Replaces `d` with a placeholder of the correct length for `code`.
/// 3. Re-serializes the JSON and computes the digest.
/// 4. Compares the computed digest (qb64) against the original `d` value.
///
/// # Errors
///
/// Returns [`SerderError::MissingField`] if there is no `d` field,
/// [`SerderError::DigestError`] on hash failure, or [`SerderError::Json`]
/// on parse failure.
pub fn verify_said(raw: &[u8], code: DigestCode) -> Result<bool, SerderError> {
    let mut value: serde_json::Value = serde_json::from_slice(raw)?;

    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(serde_json::Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = said_placeholder(code)?;
    obj.insert("d".to_owned(), serde_json::Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = compute_digest(reser.as_bytes(), code)?;
    let computed_qb64 = to_qb64_string(&computed)?;

    Ok(original_said == computed_qb64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::code::DigestCode;

    #[test]
    fn placeholder_blake3_256_is_44_chars() {
        let ph = said_placeholder(DigestCode::Blake3_256).expect("fixed-size code");
        assert_eq!(ph.len(), 44);
        assert!(ph.chars().all(|c| c == DUMMY_CHAR));
    }

    #[test]
    fn placeholder_sha3_256_is_44_chars() {
        let ph = said_placeholder(DigestCode::SHA3_256).expect("fixed-size code");
        assert_eq!(ph.len(), 44);
        assert!(ph.chars().all(|c| c == DUMMY_CHAR));
    }

    #[test]
    fn compute_digest_produces_valid_qb64() {
        let data = b"hello KERI world";
        let saider = compute_digest(data, DigestCode::Blake3_256).expect("digest should succeed");
        let qb64 = to_qb64_string(&saider).expect("qb64 encoding");
        assert_eq!(qb64.len(), 44);
        assert!(
            qb64.starts_with('E'),
            "Blake3_256 qb64 should start with 'E'"
        );
    }

    #[test]
    fn compute_digest_deterministic() {
        let data = b"deterministic input";
        let a = compute_digest(data, DigestCode::Blake3_256).expect("digest a");
        let b = compute_digest(data, DigestCode::Blake3_256).expect("digest b");
        assert_eq!(
            to_qb64_string(&a).expect("qb64 a"),
            to_qb64_string(&b).expect("qb64 b")
        );
    }

    #[test]
    fn different_data_different_said() {
        let a = compute_digest(b"alpha", DigestCode::Blake3_256).expect("digest alpha");
        let b = compute_digest(b"bravo", DigestCode::Blake3_256).expect("digest bravo");
        assert_ne!(
            to_qb64_string(&a).expect("qb64 alpha"),
            to_qb64_string(&b).expect("qb64 bravo")
        );
    }
}
