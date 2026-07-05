//! Inception event (`icp`) serialization.

use crate::core::matter::code::DigestCode;
use crate::keri::{Ilk, InceptionEvent};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};
use serde_json::{Map, Value};

use super::{SerializedEvent, matters_to_json_array, seal_to_json, tholder_to_json};
use crate::serder::error::SerderError;
use crate::serder::primitives::{sn_to_hex, to_qb64_string};
use crate::serder::said::{compute_digest, said_placeholder};
use crate::serder::version::VersionString;

/// Serialize an [`InceptionEvent`] to canonical JSON with a computed SAID.
///
/// Both `d` (said) and `i` (prefix) are set to the computed SAID — this is the
/// double-SAID property of inception events where the prefix is self-addressing.
///
/// The resulting JSON has field order: `v, t, d, i, s, kt, k, nt, n, bt, b, c, a`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_inception(event: &InceptionEvent) -> Result<SerializedEvent, SerderError> {
    let digest_code = DigestCode::Blake3_256;
    let placeholder = said_placeholder(digest_code)?;

    let sn_hex = sn_to_hex(event.sn().value());
    let kt = tholder_to_json(event.threshold());
    let keys = matters_to_json_array(event.keys());
    let nt = tholder_to_json(event.next_threshold());
    let next_keys = matters_to_json_array(event.next_keys());
    let bt = sn_to_hex(u128::from(event.witness_threshold()));
    let witnesses = matters_to_json_array(event.witnesses());
    let config: Vec<Value> = event
        .config()
        .iter()
        .map(|c| Value::String(c.code().to_owned()))
        .collect();
    let config_value = Value::Array(config);

    let mut anchors_json = Vec::with_capacity(event.anchors().len());
    for seal in event.anchors() {
        anchors_json.push(seal_to_json(seal));
    }
    let anchors_value = Value::Array(anchors_json);

    let fields = IcpFields {
        sn: &sn_hex,
        kt: &kt,
        keys: &keys,
        nt: &nt,
        next_keys: &next_keys,
        bt: &bt,
        witnesses: &witnesses,
        config: &config_value,
        anchors: &anchors_value,
    };

    // Phase 1: build JSON with placeholder SAIDs and zero size to measure length
    let phase1_vs = VersionString::keri_json_v1().to_str();
    let phase1_json = build_icp_json(&phase1_vs, &placeholder, &fields)?;
    let measured_len =
        u32::try_from(phase1_json.len()).map_err(|e| SerderError::DigestError(e.to_string()))?;

    // Phase 2: rebuild with correct size in version string (same byte length)
    let vs_with_size = VersionString::keri_json_v1()
        .with_size(measured_len)
        .to_str();
    let phase2_json = build_icp_json(&vs_with_size, &placeholder, &fields)?;

    // Phase 3: compute SAID over the correctly-sized JSON
    let said = compute_digest(phase2_json.as_bytes(), digest_code)?;
    let said_qb64 = to_qb64_string(&said);

    // Phase 4: splice computed SAID into both d and i fields
    let final_json = build_icp_json(&vs_with_size, &said_qb64, &fields)?;

    let size = final_json.len();
    Ok(SerializedEvent {
        raw: final_json.into_bytes(),
        said,
        prefix: Some(compute_digest(phase2_json.as_bytes(), digest_code)?),
        ilk: Ilk::Icp,
        size,
        event: (),
    })
}

struct IcpFields<'a> {
    sn: &'a str,
    kt: &'a Value,
    keys: &'a Value,
    nt: &'a Value,
    next_keys: &'a Value,
    bt: &'a str,
    witnesses: &'a Value,
    config: &'a Value,
    anchors: &'a Value,
}

fn build_icp_json(
    version_str: &str,
    said_value: &str,
    fields: &IcpFields<'_>,
) -> Result<String, SerderError> {
    let mut map = Map::new();
    map.insert("v".to_owned(), Value::String(version_str.to_owned()));
    map.insert("t".to_owned(), Value::String("icp".to_owned()));
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
    serde_json::to_string(&Value::Object(map)).map_err(SerderError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::ConfigTrait;
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

    fn make_event() -> InceptionEvent {
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
        )
    }

    #[test]
    fn serialize_icp_field_order() {
        let event = make_event();
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            &[
                "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"
            ]
        );
    }

    #[test]
    fn serialize_icp_ilk() {
        let event = make_event();
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "icp");
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn serialize_icp_self_addressing_prefix() {
        let event = make_event();
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_eq!(d, i, "d and i must be equal for inception events");
    }

    #[test]
    fn serialize_icp_said_is_valid() {
        let event = make_event();
        let result = serialize_inception(&event).unwrap();
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
    fn serialize_icp_version_string_size() {
        let event = make_event();
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let vs_str = parsed["v"].as_str().unwrap();
        let vs = crate::serder::version::VersionString::parse(vs_str).unwrap();
        assert_eq!(usize::try_from(vs.size).unwrap(), result.size());
        assert_eq!(result.size(), result.as_bytes().len());
    }

    #[test]
    fn serialize_icp_simple_threshold() {
        let event = make_event();
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["kt"].as_str().unwrap(), "1");
    }

    #[test]
    fn serialize_icp_weighted_threshold() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer()],
            Tholder::Weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 3), (1, 3), (1, 3)]]),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![],
            vec![],
        );
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let kt = &parsed["kt"];
        assert!(kt.is_array(), "weighted threshold should be an array");
        let outer = kt.as_array().unwrap();
        assert_eq!(outer.len(), 2);
        let clause0 = outer[0].as_array().unwrap();
        assert_eq!(clause0.len(), 2);
        assert_eq!(clause0[0].as_str().unwrap(), "1/2");
        assert_eq!(clause0[1].as_str().unwrap(), "1/2");
        let clause1 = outer[1].as_array().unwrap();
        assert_eq!(clause1.len(), 3);
        assert_eq!(clause1[0].as_str().unwrap(), "1/3");
    }

    #[test]
    fn serialize_icp_keys_and_witnesses() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer()],
            Tholder::Simple(1),
            vec![make_diger(), make_diger(), make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer(), make_prefixer()],
            1,
            vec![],
            vec![],
        );
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();

        let k = parsed["k"].as_array().unwrap();
        assert_eq!(k.len(), 2);
        for v in k {
            let s = v.as_str().unwrap();
            assert_eq!(s.len(), 44, "qb64 key should be 44 chars");
        }

        let n = parsed["n"].as_array().unwrap();
        assert_eq!(n.len(), 3);
        for v in n {
            let s = v.as_str().unwrap();
            assert_eq!(s.len(), 44, "qb64 digest should be 44 chars");
        }

        let b = parsed["b"].as_array().unwrap();
        assert_eq!(b.len(), 2);
        for v in b {
            let s = v.as_str().unwrap();
            assert_eq!(s.len(), 44, "qb64 witness prefix should be 44 chars");
        }
    }

    #[test]
    fn serialize_icp_config_traits() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![ConfigTrait::EstOnly],
            vec![],
        );
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let c = parsed["c"].as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].as_str().unwrap(), "EO");
    }
}
