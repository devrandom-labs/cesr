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
use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
#[cfg(test)]
use core::ops::Range;

use crate::serder::error::SerderError;
use crate::serder::primitives::to_qb64_string;

/// Placeholder character used to fill the `d` field before hashing.
///
/// `#` is not a valid Base64 character, so a placeholder string is
/// unambiguously distinguishable from a real SAID.
pub const DUMMY_CHAR: char = '#';

/// Byte form of [`DUMMY_CHAR`] for in-place span filling.
#[cfg(test)]
pub(crate) const DUMMY_BYTE: u8 = b'#';

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
    let computed_qb64 = to_qb64_string(&computed);

    Ok(original_said == computed_qb64)
}

// Test-gated until the deserialize entry points adopt span-based SAID
// verification (#142 rewire); the gate is removed when the first production
// caller lands.
#[cfg(test)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
/// Verify a SAID by span: copy `raw` once into a scratch buffer, overwrite
/// the SAID value span (and the prefix span for double-SAID events) with
/// [`DUMMY_BYTE`], hash, and compare against `said_value`.
///
/// Spans come from the canonical parser and must address the qb64 value
/// bytes exactly (quotes excluded). This replaces the historical
/// parse-mutate-re-render verification with one allocation and one hash.
///
/// # Errors
///
/// Returns [`SerderError::SaidMismatch`] if the computed digest differs,
/// [`SerderError::InvalidEventLayout`] if a span is out of bounds, or
/// [`SerderError::DigestError`] on hash failure.
pub(crate) fn verify_said_spans(
    raw: &[u8],
    said_value: &str,
    said_span: &Range<usize>,
    prefix_span: Option<&Range<usize>>,
    code: DigestCode,
) -> Result<(), SerderError> {
    let mut scratch = raw.to_vec();
    fill_span(&mut scratch, said_span)?;
    if let Some(span) = prefix_span {
        fill_span(&mut scratch, span)?;
    }
    let computed = compute_digest(&scratch, code)?;
    let computed_qb64 = to_qb64_string(&computed);
    if said_value == computed_qb64 {
        Ok(())
    } else {
        Err(SerderError::SaidMismatch {
            expected: said_value.to_owned(),
            computed: computed_qb64,
        })
    }
}

#[cfg(test)]
fn fill_span(scratch: &mut [u8], span: &Range<usize>) -> Result<(), SerderError> {
    scratch
        .get_mut(span.clone())
        .ok_or(SerderError::InvalidEventLayout("SAID span out of bounds"))?
        .fill(DUMMY_BYTE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::Seqner;
    use crate::keri::InteractionEvent;
    use crate::serder::builder::icp::InceptionBuilder;
    use crate::serder::serialize::serialize_interaction;
    use alloc::borrow::Cow;
    use alloc::vec;
    use alloc::vec::Vec;

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
        let qb64 = to_qb64_string(&saider);
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
        assert_eq!(to_qb64_string(&a), to_qb64_string(&b));
    }

    #[test]
    fn different_data_different_said() {
        let a = compute_digest(b"alpha", DigestCode::Blake3_256).expect("digest alpha");
        let b = compute_digest(b"bravo", DigestCode::Blake3_256).expect("digest bravo");
        assert_ne!(to_qb64_string(&a), to_qb64_string(&b));
    }

    fn probe_ixn_raw() -> (Vec<u8>, String) {
        let prefixer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let saider_fixture = compute_digest(b"seed", DigestCode::Blake3_256).unwrap();
        let event = InteractionEvent::new(
            prefixer.into(),
            Seqner::new(1),
            saider_fixture.clone(),
            saider_fixture,
            vec![],
        );
        let ser = serialize_interaction(&event).unwrap();
        let said = to_qb64_string(ser.said());
        (ser.as_bytes().to_vec(), said)
    }

    #[test]
    fn verify_said_spans_accepts_writer_output() {
        let (raw, said) = probe_ixn_raw();
        let start = raw
            .windows(6)
            .position(|w| w == b"\"d\":\"E")
            .expect("d field present")
            + 5;
        let span = start..start + 44;
        assert_eq!(&raw[span.clone()], said.as_bytes());
        verify_said_spans(&raw, &said, &span, None, DigestCode::Blake3_256)
            .expect("writer output must verify");
    }

    #[test]
    fn verify_said_spans_rejects_tamper() {
        let (mut raw, said) = probe_ixn_raw();
        let start = raw.windows(6).position(|w| w == b"\"d\":\"E").unwrap() + 5;
        let span = start..start + 44;
        let s_pos = raw.windows(8).position(|w| w == b",\"s\":\"1\"").unwrap();
        raw[s_pos + 6] = b'2';
        assert!(matches!(
            verify_said_spans(&raw, &said, &span, None, DigestCode::Blake3_256),
            Err(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn verify_said_spans_rejects_out_of_bounds_span() {
        let (raw, said) = probe_ixn_raw();
        let bogus = raw.len()..raw.len() + 44;
        assert!(matches!(
            verify_said_spans(&raw, &said, &bogus, None, DigestCode::Blake3_256),
            Err(SerderError::InvalidEventLayout(_))
        ));
    }

    #[test]
    fn verify_said_spans_double_said_matches_reference() {
        // For an icp whose d == i (self-addressing), filling BOTH spans must
        // reproduce the SAID the writer computed (the writer patches both
        // slots from one digest over a double-placeholder render).
        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![7u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let icp = InceptionBuilder::new().keys(vec![verfer]).build().unwrap();
        let raw = icp.as_bytes().to_vec();
        let said = to_qb64_string(icp.said());
        let d_start = raw.windows(5).position(|w| w == b"\"d\":\"").unwrap() + 5;
        let i_start = raw.windows(5).position(|w| w == b"\"i\":\"").unwrap() + 5;
        let d_span = d_start..d_start + 44;
        let i_span = i_start..i_start + 44;
        assert_eq!(&raw[d_span.clone()], said.as_bytes());
        assert_eq!(&raw[i_span.clone()], said.as_bytes());
        verify_said_spans(&raw, &said, &d_span, Some(&i_span), DigestCode::Blake3_256)
            .expect("double-SAID writer output must verify by span");
    }
}
