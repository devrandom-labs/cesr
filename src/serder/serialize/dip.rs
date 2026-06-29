//! Delegated inception event (`dip`) serialization.

use crate::core::matter::code::DigestCode;
use crate::keri::{DelegatedInceptionEvent, Ilk};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};
use serde_json::{Map, Value};

use super::{SerializedEvent, matters_to_json_array, seal_to_json, tholder_to_json};
use crate::serder::error::SerderError;
use crate::serder::primitives::{identifier_to_qb64_string, sn_to_hex, to_qb64_string};
use crate::serder::said::{compute_digest, said_placeholder};
use crate::serder::version::VersionString;

/// Serialize a [`DelegatedInceptionEvent`] to canonical JSON with a computed SAID.
///
/// Both `d` (said) and `i` (prefix) are set to the computed SAID — this is the
/// double-SAID property shared with regular inception events. The `di` field
/// carries the delegator's prefix.
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
    let digest_code = DigestCode::Blake3_256;
    let placeholder = said_placeholder(digest_code)?;

    let icp = event.inception();
    let sn_hex = sn_to_hex(icp.sn().value());
    let kt = tholder_to_json(icp.threshold());
    let keys = matters_to_json_array(icp.keys())?;
    let nt = tholder_to_json(icp.next_threshold());
    let next_keys = matters_to_json_array(icp.next_keys())?;
    let bt = sn_to_hex(u128::from(icp.witness_threshold()));
    let witnesses = matters_to_json_array(icp.witnesses())?;
    let config: Vec<Value> = icp
        .config()
        .iter()
        .map(|c| Value::String(c.code().to_owned()))
        .collect();
    let config_value = Value::Array(config);

    let mut anchors_json = Vec::with_capacity(icp.anchors().len());
    for seal in icp.anchors() {
        anchors_json.push(seal_to_json(seal)?);
    }
    let anchors_value = Value::Array(anchors_json);

    let delegator_qb64 = identifier_to_qb64_string(event.delegator())?;

    let fields = DipFields {
        sn: &sn_hex,
        kt: &kt,
        keys: &keys,
        nt: &nt,
        next_keys: &next_keys,
        bt: &bt,
        witnesses: &witnesses,
        config: &config_value,
        anchors: &anchors_value,
        delegator: &delegator_qb64,
    };

    let phase1_vs = VersionString::keri_json_v1().to_str();
    let phase1_json = build_dip_json(&phase1_vs, &placeholder, &fields)?;
    let measured_len =
        u32::try_from(phase1_json.len()).map_err(|e| SerderError::DigestError(e.to_string()))?;

    let vs_with_size = VersionString::keri_json_v1()
        .with_size(measured_len)
        .to_str();
    let phase2_json = build_dip_json(&vs_with_size, &placeholder, &fields)?;

    let said = compute_digest(phase2_json.as_bytes(), digest_code)?;
    let said_qb64 = to_qb64_string(&said)?;

    let final_json = build_dip_json(&vs_with_size, &said_qb64, &fields)?;

    let size = final_json.len();
    Ok(SerializedEvent {
        raw: final_json.into_bytes(),
        said,
        prefix: Some(compute_digest(phase2_json.as_bytes(), digest_code)?),
        ilk: Ilk::Dip,
        size,
        event: (),
    })
}

struct DipFields<'a> {
    sn: &'a str,
    kt: &'a Value,
    keys: &'a Value,
    nt: &'a Value,
    next_keys: &'a Value,
    bt: &'a str,
    witnesses: &'a Value,
    config: &'a Value,
    anchors: &'a Value,
    delegator: &'a str,
}

fn build_dip_json(
    version_str: &str,
    said_value: &str,
    fields: &DipFields<'_>,
) -> Result<String, SerderError> {
    let mut map = Map::new();
    map.insert("v".to_owned(), Value::String(version_str.to_owned()));
    map.insert("t".to_owned(), Value::String("dip".to_owned()));
    map.insert("d".to_owned(), Value::String(said_value.to_owned()));
    map.insert("i".to_owned(), Value::String(said_value.to_owned()));
    map.insert("s".to_owned(), Value::String(fields.sn.to_owned()));
    map.insert("kt".to_owned(), fields.kt.clone());
    map.insert("k".to_owned(), fields.keys.clone());
    map.insert("nt".to_owned(), fields.nt.clone());
    map.insert("n".to_owned(), fields.next_keys.clone());
    map.insert("bt".to_owned(), Value::String(fields.bt.to_owned()));
    map.insert("b".to_owned(), fields.witnesses.clone());
    map.insert("c".to_owned(), fields.config.clone());
    map.insert("a".to_owned(), fields.anchors.clone());
    map.insert("di".to_owned(), Value::String(fields.delegator.to_owned()));
    serde_json::to_string(&Value::Object(map)).map_err(SerderError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::InceptionEvent;
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

    fn make_event() -> DelegatedInceptionEvent {
        DelegatedInceptionEvent::new(
            InceptionEvent::new(
                make_prefixer().into(),
                Seqner::new(0),
                make_saider(),
                vec![make_verfer()],
                Tholder::Simple(1),
                vec![make_diger()],
                Tholder::Simple(1),
                vec![make_prefixer()],
                1,
                vec![],
                vec![],
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
        assert_eq!(d, i, "d and i must be equal for delegated inception events");
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
        let computed_qb64 = crate::serder::primitives::to_qb64_string(&computed).unwrap();
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
