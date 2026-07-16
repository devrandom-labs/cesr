//! Delegated inception event (`dip`) serialization.

use crate::keri::DelegatedInceptionEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};

use super::{EventRef, SerializedEvent, serialize_event};
use crate::serder::error::SerderError;

/// Serialize a [`DelegatedInceptionEvent`] to canonical JSON with a computed SAID.
///
/// The `i` field follows the event's [`Identifier`](crate::keri::Identifier)
/// derivation exactly as for regular inceptions: self-addressing prefixes get
/// the computed SAID in both `d` and `i` (double-SAID — the only derivation
/// keripy's `delcept` produces), while a basic prefix is serialized verbatim
/// with a single-SAID `d`. The `di` field carries the delegator's prefix.
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_delegated_inception(
    event: &DelegatedInceptionEvent,
) -> Result<SerializedEvent, SerderError> {
    serialize_event(EventRef::DelegatedInception(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use crate::keri::Identifier;
    use crate::keri::Ilk;
    use crate::keri::InceptionEvent;
    use crate::keri::SigningThreshold;
    use crate::keri::sequence::SequenceNumber;
    use crate::keri::threshold_form::ThresholdForm;
    use crate::keri::toad::Toad;
    use crate::serder::primitives::identifier_to_qb64_string;
    use alloc::borrow::Cow;
    use serde_json::Value;

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

    fn make_event() -> DelegatedInceptionEvent<'static> {
        DelegatedInceptionEvent::new(
            InceptionEvent::new(
                Identifier::SelfAddressing(make_saider()),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer()],
                Toad::exact(1, 1).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            ),
            make_prefixer().into(),
        )
    }

    #[test]
    fn serialize_dip_field_order() {
        let event = make_event();
        let result = serialize_delegated_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            &[
                "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"
            ]
        );
    }

    #[test]
    fn serialize_dip_ilk() {
        let event = make_event();
        let result = serialize_delegated_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "dip");
        assert_eq!(result.ilk(), Ilk::Dip);
    }

    #[test]
    fn serialize_dip_self_addressing_prefix() {
        let event = make_event();
        let result = serialize_delegated_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_eq!(
            d, i,
            "d and i must be equal for self-addressing delegated inception events"
        );
    }

    #[test]
    fn serialize_dip_basic_prefix_verbatim_single_said() {
        // #144: the dip writer follows the Identifier variant exactly like
        // icp — a basic prefix is carried verbatim with a single-SAID `d`.
        let event = DelegatedInceptionEvent::new(
            InceptionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![],
                Toad::exact(0, 0).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            ),
            make_prefixer().into(),
        );
        let result = serialize_delegated_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_eq!(
            i,
            identifier_to_qb64_string(event.inception().prefix()),
            "basic prefix must serialize verbatim"
        );
        assert_ne!(d, i, "basic delegated inception is single-SAID");
    }

    #[test]
    fn serialize_dip_said_is_valid() {
        let event = make_event();
        let result = serialize_delegated_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();

        assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
        assert_eq!(d.len(), 44);

        let placeholder = crate::serder::said::said_placeholder(DigestCode::Blake3_256).unwrap();
        let mut verify_obj = parsed.clone();
        let obj = verify_obj.as_object_mut().unwrap();
        obj.insert("d".to_owned(), Value::String(placeholder.clone()));
        obj.insert("i".to_owned(), Value::String(placeholder));
        let reser = serde_json::to_string(&verify_obj).unwrap();
        let computed =
            crate::serder::said::compute_digest(reser.as_bytes(), DigestCode::Blake3_256).unwrap();
        let computed_qb64 = crate::serder::primitives::to_qb64_string(&computed);
        assert_eq!(d, computed_qb64, "SAID verification should pass");
    }

    #[test]
    fn serialize_dip_delegator() {
        let event = make_event();
        let result = serialize_delegated_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let di = parsed["di"].as_str().unwrap();
        assert_eq!(
            di.len(),
            44,
            "delegator prefix should be a 44-char qb64 string"
        );
    }
}
