//! Inception event (`icp`) serialization.

use crate::keri::InceptionEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};

use super::{EventRef, SerializedEvent, serialize_event};
use crate::serder::error::SerderError;

/// Serialize an [`InceptionEvent`] to canonical JSON with a computed SAID.
///
/// The `i` field follows the event's [`Identifier`](crate::keri::Identifier)
/// derivation: for a
/// self-addressing prefix both `d` and `i` are set to the computed SAID
/// (the double-SAID property); for a basic-derivation prefix `i` is the
/// public key serialized verbatim and only `d` carries the SAID, computed
/// with `i` left intact (single-SAID), matching keripy's `makify`.
///
/// The resulting JSON has field order: `v, t, d, i, s, kt, k, nt, n, bt, b, c, a`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_inception(event: &InceptionEvent) -> Result<SerializedEvent, SerderError> {
    serialize_event(EventRef::Inception(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use crate::keri::ConfigTrait;
    use crate::keri::Identifier;
    use crate::keri::Ilk;
    use crate::keri::sequence::SequenceNumber;
    use crate::keri::threshold_form::ThresholdForm;
    use crate::keri::toad::Toad;
    use crate::keri::{SigningThreshold, WeightedThreshold};
    use crate::serder::primitives::to_qb64_string;
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

    fn make_event() -> InceptionEvent {
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
        )
    }

    fn make_basic_event() -> InceptionEvent {
        InceptionEvent::new(
            make_prefixer().into(),
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
        assert_eq!(
            d, i,
            "d and i must be equal for self-addressing inception events"
        );
    }

    #[test]
    fn serialize_icp_basic_prefix_verbatim_single_said() {
        // #144: a basic-derivation inception carries its public key in `i`
        // and computes the SAID over the event with only `d` dummied.
        let event = make_basic_event();
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();

        assert_eq!(
            i,
            to_qb64_string(event.prefix().as_prefixer().unwrap()),
            "basic prefix must serialize verbatim"
        );
        assert_ne!(d, i, "basic inception is single-SAID");

        let placeholder = crate::serder::said::said_placeholder(DigestCode::Blake3_256).unwrap();
        let mut verify_obj = parsed.clone();
        let obj = verify_obj.as_object_mut().unwrap();
        obj.insert("d".to_owned(), Value::String(placeholder));
        let reser = serde_json::to_string(&verify_obj).unwrap();
        let computed =
            crate::serder::said::compute_digest(reser.as_bytes(), DigestCode::Blake3_256).unwrap();
        assert_eq!(
            d,
            crate::serder::primitives::to_qb64_string(&computed),
            "single-SAID must verify with `i` left intact"
        );
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
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer()],
            SigningThreshold::Weighted(
                WeightedThreshold::from_nested(vec![
                    vec![(1, 2), (1, 2)],
                    vec![(1, 3), (1, 3), (1, 3)],
                ])
                .unwrap(),
            ),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
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
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger(), make_diger(), make_diger()],
            SigningThreshold::Simple(1),
            vec![make_prefixer(), make_prefixer()],
            Toad::exact(1, 2).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
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
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![],
            ThresholdForm::HexString,
        );
        let result = serialize_inception(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let c = parsed["c"].as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].as_str().unwrap(), "EO");
    }
}
