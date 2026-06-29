//! Serde traits for method-syntax serialization and deserialization of KERI events.

use crate::keri::{
    DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent, KeriEvent,
    RotationEvent,
};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;

use crate::serder::error::SerderError;
use crate::serder::serialize::SerializedEvent;

/// Serialize a KERI event to canonical JSON with computed SAID.
pub trait KeriSerialize: Sized {
    /// Serialize this event to canonical JSON bytes with a computed SAID.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] if CESR primitive encoding or digest
    /// computation fails.
    fn serialize(&self) -> Result<SerializedEvent, SerderError>;
}

/// Deserialize a KERI event from canonical JSON bytes with SAID verification.
pub trait KeriDeserialize: Sized {
    /// Deserialize from canonical JSON bytes, verifying the SAID.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] if JSON parsing fails, required fields are
    /// missing, or the SAID does not verify.
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError>;
}

impl KeriSerialize for InceptionEvent {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        crate::serder::serialize::serialize_inception(self)
    }
}

impl KeriDeserialize for InceptionEvent {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_inception(raw)
    }
}

impl KeriSerialize for RotationEvent {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        crate::serder::serialize::serialize_rotation(self)
    }
}

impl KeriDeserialize for RotationEvent {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_rotation(raw)
    }
}

impl KeriSerialize for InteractionEvent {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        crate::serder::serialize::serialize_interaction(self)
    }
}

impl KeriDeserialize for InteractionEvent {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_interaction(raw)
    }
}

impl KeriSerialize for DelegatedInceptionEvent {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        crate::serder::serialize::serialize_delegated_inception(self)
    }
}

impl KeriDeserialize for DelegatedInceptionEvent {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_delegated_inception(raw)
    }
}

impl KeriSerialize for DelegatedRotationEvent {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        crate::serder::serialize::serialize_delegated_rotation(self)
    }
}

impl KeriDeserialize for DelegatedRotationEvent {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_delegated_rotation(raw)
    }
}

impl KeriSerialize for KeriEvent {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        crate::serder::serialize::serialize(self)
    }
}

impl KeriDeserialize for KeriEvent {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_event(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::Ilk;
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

    #[test]
    fn serialize_inception_trait() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn deserialize_inception_trait() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = event.serialize().unwrap();
        let recovered = InceptionEvent::deserialize(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.sn().value(), 0);
        assert_eq!(recovered.keys().len(), 1);
    }

    #[test]
    fn serialize_rotation_trait() {
        let event = RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        );
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Rot);
    }

    #[test]
    fn serialize_interaction_trait() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![],
        );
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Ixn);
    }

    #[test]
    fn keri_event_serialize_trait() {
        let event = KeriEvent::Inception(InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        ));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn keri_event_roundtrip() {
        let event = KeriEvent::Inception(InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        ));
        let serialized = event.serialize().unwrap();
        let recovered = KeriEvent::deserialize(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.ilk(), Ilk::Icp);
    }
}
