//! Rotation event (`rot`) serialization.

use crate::keri::RotationEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};
use serde_json::{Map, Value};

use super::{
    AnchorJson, EventBody, EventRef, SerdeJson, SerializedEvent, matters_to_json_array,
    seal_to_json, serialize_with, tholder_to_json,
};
use crate::serder::error::SerderError;
use crate::serder::primitives::{identifier_to_qb64_string, sn_to_hex, to_qb64_string};
use crate::serder::version::VersionString;

/// Serialize a [`RotationEvent`] to canonical JSON with a computed SAID.
///
/// Only the `d` field is self-addressing; `i` is the existing AID prefix.
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_rotation(event: &RotationEvent) -> Result<SerializedEvent, SerderError> {
    serialize_with(&SerdeJson, EventRef::Rotation(event))
}

/// Render the event body as canonical JSON with a zero-size version string
/// and `said_placeholder` in the `d` slot.
pub(crate) fn render_json(
    event: &RotationEvent,
    said_placeholder: &str,
) -> Result<String, SerderError> {
    let prefix_qb64 = identifier_to_qb64_string(event.prefix());
    let sn_hex = event.sn().to_string();
    let prior_qb64 = to_qb64_string(event.prior_event_said());
    let kt = tholder_to_json(event.threshold());
    let keys = matters_to_json_array(event.keys());
    let nt = tholder_to_json(event.next_threshold());
    let next_keys = matters_to_json_array(event.next_keys());
    let bt = sn_to_hex(u128::from(event.witness_threshold().value()));
    let witness_removals = matters_to_json_array(event.witness_removals());
    let witness_additions = matters_to_json_array(event.witness_additions());

    let mut anchors_json = Vec::with_capacity(event.anchors().len());
    for seal in event.anchors() {
        anchors_json.push(seal_to_json(seal)?);
    }

    let fields = RotFields {
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
    build_rot_json(&vs, said_placeholder, &fields)
}

struct RotFields<'a> {
    prefix: &'a str,
    sn: &'a str,
    prior: &'a str,
    kt: &'a Value,
    keys: &'a Value,
    nt: &'a Value,
    next_keys: &'a Value,
    bt: &'a str,
    witness_removals: &'a Value,
    witness_additions: &'a Value,
    anchors: &'a [AnchorJson],
}

fn build_rot_json(
    version_str: &str,
    said_value: &str,
    fields: &RotFields<'_>,
) -> Result<String, SerderError> {
    let mut map = Map::new();
    map.insert("v".to_owned(), Value::String(version_str.to_owned()));
    map.insert("t".to_owned(), Value::String("rot".to_owned()));
    map.insert("d".to_owned(), Value::String(said_value.to_owned()));
    map.insert("i".to_owned(), Value::String(fields.prefix.to_owned()));
    map.insert("s".to_owned(), Value::String(fields.sn.to_owned()));
    map.insert("p".to_owned(), Value::String(fields.prior.to_owned()));
    map.insert("kt".to_owned(), fields.kt.clone());
    map.insert("k".to_owned(), fields.keys.clone());
    map.insert("nt".to_owned(), fields.nt.clone());
    map.insert("n".to_owned(), fields.next_keys.clone());
    map.insert("bt".to_owned(), Value::String(fields.bt.to_owned()));
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
    use crate::core::primitives::{Diger, Prefixer, Saider, Tholder, Verfer};
    use crate::keri::Ilk;
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

    fn make_event() -> RotationEvent {
        RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            vec![],
            Toad::from_wire(1),
            vec![],
            ThresholdForm::HexString,
        )
    }

    #[test]
    fn serialize_rot_field_order() {
        let event = make_event();
        let result = serialize_rotation(&event).unwrap();
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
    fn serialize_rot_ilk() {
        let event = make_event();
        let result = serialize_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "rot");
        assert_eq!(result.ilk(), Ilk::Rot);
    }

    #[test]
    fn serialize_rot_said_is_valid() {
        let event = make_event();
        let result = serialize_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();

        assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
        assert_eq!(d.len(), 44);

        crate::serder::said::verify_said(result.as_bytes(), DigestCode::Blake3_256)
            .expect("SAID verification should pass");
    }

    #[test]
    fn serialize_rot_version_string_size() {
        let event = make_event();
        let result = serialize_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let vs_str = parsed["v"].as_str().unwrap();
        let vs = crate::serder::version::VersionString::parse(vs_str).unwrap();
        assert_eq!(usize::try_from(vs.size).unwrap(), result.size());
        assert_eq!(result.size(), result.as_bytes().len());
    }

    #[test]
    fn serialize_rot_prefix_is_not_saidive() {
        let event = make_event();
        let result = serialize_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_ne!(d, i, "rotation prefix must not equal the SAID");
    }

    #[test]
    fn serialize_rot_prior_event_said() {
        let event = make_event();
        let result = serialize_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let p = parsed["p"].as_str().unwrap();
        assert_eq!(p.len(), 44, "prior event SAID should be 44 chars");
        assert!(p.starts_with('E'), "Blake3_256 qb64 should start with 'E'");
    }

    #[test]
    fn serialize_rot_witness_additions_removals() {
        let event = RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer(), make_prefixer()],
            vec![make_prefixer()],
            Toad::from_wire(1),
            vec![],
            ThresholdForm::HexString,
        );
        let result = serialize_rotation(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();

        let ba = parsed["ba"].as_array().unwrap();
        assert_eq!(ba.len(), 2);
        for v in ba {
            let s = v.as_str().unwrap();
            assert_eq!(s.len(), 44, "qb64 witness prefix should be 44 chars");
        }

        let br = parsed["br"].as_array().unwrap();
        assert_eq!(br.len(), 1);
        for v in br {
            let s = v.as_str().unwrap();
            assert_eq!(s.len(), 44, "qb64 witness prefix should be 44 chars");
        }
    }

    #[test]
    fn rot_wire_has_no_config_field() {
        let event = make_event();
        let out = serialize_rotation(&event).unwrap();
        let json = core::str::from_utf8(out.as_bytes()).unwrap();
        assert!(!json.contains("\"c\":"), "v1 rot must not emit a c field");
    }
}
