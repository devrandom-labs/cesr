//! Interaction event (`ixn`) serialization.

use crate::keri::InteractionEvent;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec, vec::Vec};

use super::{EventRef, SerializedEvent, serialize_event};
use crate::serder::error::SerderError;

/// Serialize an [`InteractionEvent`] to canonical JSON with a computed SAID.
///
/// The resulting JSON has field order: `v, t, d, i, s, p, a`.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize_interaction(event: &InteractionEvent) -> Result<SerializedEvent, SerderError> {
    serialize_event(EventRef::Interaction(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Prefixer, Saider};
    use crate::keri::Ilk;
    use crate::keri::Seal;
    use crate::keri::sequence::SequenceNumber;
    use crate::serder::version::{VERSION_SIZE_MAX, VersionString};
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
            SequenceNumber::new(1),
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
            SequenceNumber::new(1),
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
            SequenceNumber::new(3),
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
