//! Interaction event (`ixn`) serialization.

use crate::keri::InteractionEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};
use serde_json::{Map, Value};

use super::{EventRef, SerdeJson, SerializedEvent, seal_to_json, serialize_with};
use crate::serder::error::SerderError;
use crate::serder::primitives::{identifier_to_qb64_string, sn_to_hex, to_qb64_string};
use crate::serder::version::VersionString;

/// Serialize an [`InteractionEvent`] to canonical JSON with a computed SAID.
///
/// The resulting JSON has field order: `v, t, d, i, s, p, a`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_interaction(event: &InteractionEvent) -> Result<SerializedEvent, SerderError> {
    serialize_with(&SerdeJson, EventRef::Interaction(event))
}

/// Render the event body as canonical JSON with a zero-size version string
/// and `said_placeholder` in the `d` slot.
pub(crate) fn render_json(
    event: &InteractionEvent,
    said_placeholder: &str,
) -> Result<String, SerderError> {
    let prefix_qb64 = identifier_to_qb64_string(event.prefix());
    let sn_hex = sn_to_hex(event.sn().value());
    let prior_qb64 = to_qb64_string(event.prior_event_said());

    let mut anchors_json = Vec::with_capacity(event.anchors().len());
    for seal in event.anchors() {
        anchors_json.push(seal_to_json(seal));
    }
    let anchors_value = Value::Array(anchors_json);

    let fields = IxnFields {
        prefix: &prefix_qb64,
        sn: &sn_hex,
        prior: &prior_qb64,
        anchors: &anchors_value,
    };

    let vs = VersionString::keri_json_v1().to_str()?;
    build_ixn_json(&vs, said_placeholder, &fields)
}

struct IxnFields<'a> {
    prefix: &'a str,
    sn: &'a str,
    prior: &'a str,
    anchors: &'a Value,
}

fn build_ixn_json(
    version_str: &str,
    said_value: &str,
    fields: &IxnFields<'_>,
) -> Result<String, SerderError> {
    let mut map = Map::new();
    map.insert("v".to_owned(), Value::String(version_str.to_owned()));
    map.insert("t".to_owned(), Value::String("ixn".to_owned()));
    map.insert("d".to_owned(), Value::String(said_value.to_owned()));
    map.insert("i".to_owned(), Value::String(fields.prefix.to_owned()));
    map.insert("s".to_owned(), Value::String(fields.sn.to_owned()));
    map.insert("p".to_owned(), Value::String(fields.prior.to_owned()));
    map.insert("a".to_owned(), fields.anchors.clone());
    serde_json::to_string(&Value::Object(map)).map_err(SerderError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Prefixer, Saider, Seqner};
    use crate::keri::Ilk;
    use crate::keri::Seal;
    use crate::serder::version::VERSION_SIZE_MAX;
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

    fn make_event() -> InteractionEvent {
        InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![],
        )
    }

    #[test]
    fn serialize_ixn_field_order() {
        let event = make_event();
        let result = serialize_interaction(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        assert_eq!(keys, &["v", "t", "d", "i", "s", "p", "a"]);
    }

    #[test]
    fn serialize_ixn_ilk() {
        let event = make_event();
        let result = serialize_interaction(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "ixn");
        assert_eq!(result.ilk(), Ilk::Ixn);
    }

    #[test]
    fn serialize_ixn_rejects_event_beyond_version_size_capacity() {
        // Bug probe: an event whose JSON exceeds the six-hex-digit size field
        // (16 MiB - 1) previously rendered a widened version string, silently
        // corrupting the frame instead of returning an error.
        let anchors: Vec<Seal> = (0..340_000)
            .map(|_| Seal::Digest { d: make_saider() })
            .collect();
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            anchors,
        );
        let result = serialize_interaction(&event);
        assert!(matches!(
            result,
            Err(SerderError::VersionStringOverflow {
                field: "size",
                max: VERSION_SIZE_MAX,
            })
        ));
    }

    #[test]
    fn serialize_ixn_version_string_size_matches() {
        let event = make_event();
        let result = serialize_interaction(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let vs_str = parsed["v"].as_str().unwrap();
        let vs = VersionString::parse(vs_str).unwrap();
        assert_eq!(usize::try_from(vs.size).unwrap(), result.size());
        assert_eq!(result.size(), result.as_bytes().len());
    }

    #[test]
    fn serialize_ixn_said_is_valid() {
        let event = make_event();
        let result = serialize_interaction(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();

        assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
        assert_eq!(d.len(), 44);

        crate::serder::said::verify_said(result.as_bytes(), DigestCode::Blake3_256)
            .expect("SAID verification should pass");
    }

    #[test]
    fn serialize_ixn_with_digest_seal() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(3),
            make_saider(),
            make_saider(),
            vec![Seal::Digest { d: make_saider() }],
        );
        let result = serialize_interaction(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let anchors = parsed["a"].as_array().unwrap();
        assert_eq!(anchors.len(), 1);
        assert!(anchors[0].get("d").is_some(), "seal should have 'd' field");
    }
}
