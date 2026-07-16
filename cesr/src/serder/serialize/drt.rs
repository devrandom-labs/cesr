//! Delegated rotation event (`drt`) serialization.

use crate::keri::DelegatedRotationEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};

use super::{EventRef, SerializedEvent, serialize_event};
use crate::serder::error::SerderError;

/// Serialize a [`DelegatedRotationEvent`] to canonical JSON with a computed SAID.
///
/// Only the `d` field is self-addressing; `i` is the existing AID prefix.
/// The delegator is established at inception and looked up from the KEL, so
/// there is no `di` field — the only difference from `rot` is the ilk (`drt`).
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_delegated_rotation(
    event: &DelegatedRotationEvent,
) -> Result<SerializedEvent, SerderError> {
    serialize_event(EventRef::DelegatedRotation(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use crate::keri::Ilk;
    use crate::keri::RotationEvent;
    use crate::keri::SigningThreshold;
    use crate::keri::sequence::SequenceNumber;
    use crate::keri::threshold_form::ThresholdForm;
    use crate::keri::toad::Toad;
    use alloc::borrow::Cow;

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verfer() -> Verfer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_diger() -> Diger<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_event() -> DelegatedRotationEvent {
        DelegatedRotationEvent::new(RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            vec![],
            Toad::from_wire(1),
            vec![],
            ThresholdForm::HexString,
        ))
    }

    #[test]
    fn serialize_drt_field_order() {
        let event = make_event();
        let result = serialize_delegated_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            &[
                "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"
            ]
        );
    }

    #[test]
    fn serialize_drt_ilk() {
        let event = make_event();
        let result = serialize_delegated_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "drt");
        assert_eq!(result.ilk(), Ilk::Drt);
    }

    #[test]
    fn serialize_drt_said_is_valid() {
        let event = make_event();
        let result = serialize_delegated_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();

        assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
        assert_eq!(d.len(), 44);

        crate::serder::said::verify_said(result.as_bytes(), DigestCode::Blake3_256)
            .expect("SAID verification should pass");
    }

    #[test]
    fn serialize_drt_prefix_is_not_saidive() {
        let event = make_event();
        let result = serialize_delegated_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_ne!(d, i, "delegated rotation prefix must not equal the SAID");
    }

    #[test]
    fn drt_wire_has_no_config_field() {
        let event = make_event();
        let out = serialize_delegated_rotation(&event).unwrap();
        let json = core::str::from_utf8(out.as_bytes()).unwrap();
        assert!(!json.contains("\"c\":"), "v1 drt must not emit a c field");
    }
}
