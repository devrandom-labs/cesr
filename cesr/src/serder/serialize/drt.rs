//! Delegated rotation event (`drt`) serialization.

use crate::keri::DelegatedRotationEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};
use serde_json::{Map, Value};

use super::{
    AnchorJson, EventBody, EventRef, SerializedEvent, matters_to_json_array, seal_to_json,
    serialize_event, tholder_to_json, toad_json,
};
use crate::serder::error::SerderError;
use crate::serder::primitives::{identifier_to_qb64_string, to_qb64_string};
use crate::serder::version::VersionString;

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

/// Render the event body as canonical JSON with a zero-size version string
/// and `said_placeholder` in the `d` slot.
pub(crate) fn render_json(
    event: &DelegatedRotationEvent,
    said_placeholder: &str,
) -> Result<String, SerderError> {
    let rot = event.rotation();
    let form = rot.threshold_form();
    let prefix_qb64 = identifier_to_qb64_string(rot.prefix());
    let sn_hex = rot.sn().to_string();
    let prior_qb64 = to_qb64_string(rot.prior_event_said());
    let kt = tholder_to_json(rot.threshold(), form);
    let keys = matters_to_json_array(rot.keys());
    let nt = tholder_to_json(rot.next_threshold(), form);
    let next_keys = matters_to_json_array(rot.next_keys());
    let bt = toad_json(rot.witness_threshold(), form);
    let witness_removals = matters_to_json_array(rot.witness_removals());
    let witness_additions = matters_to_json_array(rot.witness_additions());

    let mut anchors_json = Vec::with_capacity(rot.anchors().len());
    for seal in rot.anchors() {
        anchors_json.push(seal_to_json(seal)?);
    }

    let fields = DrtFields {
        prefix: &prefix_qb64,
        sn: &sn_hex,
        prior: &prior_qb64,
        kt: &kt,
        keys: &keys,
        nt: &nt,
        next_keys: &next_keys,
        bt: &bt,
        witness_removals: &witness_removals,
        witness_additions: &witness_additions,
        anchors: &anchors_json,
    };

    let vs = VersionString::keri_json_v1().to_str()?;
    build_drt_json(&vs, said_placeholder, &fields)
}

struct DrtFields<'a> {
    prefix: &'a str,
    sn: &'a str,
    prior: &'a str,
    kt: &'a Value,
    keys: &'a Value,
    nt: &'a Value,
    next_keys: &'a Value,
    bt: &'a Value,
    witness_removals: &'a Value,
    witness_additions: &'a Value,
    anchors: &'a [AnchorJson],
}

fn build_drt_json(
    version_str: &str,
    said_value: &str,
    fields: &DrtFields<'_>,
) -> Result<String, SerderError> {
    let mut map = Map::new();
    map.insert("v".to_owned(), Value::String(version_str.to_owned()));
    map.insert("t".to_owned(), Value::String("drt".to_owned()));
    map.insert("d".to_owned(), Value::String(said_value.to_owned()));
    map.insert("i".to_owned(), Value::String(fields.prefix.to_owned()));
    map.insert("s".to_owned(), Value::String(fields.sn.to_owned()));
    map.insert("p".to_owned(), Value::String(fields.prior.to_owned()));
    map.insert("kt".to_owned(), fields.kt.clone());
    map.insert("k".to_owned(), fields.keys.clone());
    map.insert("nt".to_owned(), fields.nt.clone());
    map.insert("n".to_owned(), fields.next_keys.clone());
    map.insert("bt".to_owned(), fields.bt.clone());
    map.insert("br".to_owned(), fields.witness_removals.clone());
    map.insert("ba".to_owned(), fields.witness_additions.clone());
    let body = EventBody {
        head: &map,
        anchors: fields.anchors,
        tail: &[],
    };
    serde_json::to_string(&body).map_err(SerderError::from)
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
