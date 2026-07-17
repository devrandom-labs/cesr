//! The (de)serialization traits: the sole serde surface for KERI events.
//!
//! [`KeriSerialize`] and [`KeriDeserialize`] are implemented for every KEL
//! event type and for the [`KeriEvent`](cesr::keri::KeriEvent) sum. The
//! write-path impls live in [`serialize`](crate::serialize) (over
//! the single canonical JSON writer) and the read-path impls in
//! [`deserialize`](crate::deserialize) (over the strict canonical
//! parser with in-place SAID verification).

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;

use crate::error::SerderError;
use crate::serialize::SerializedEvent;

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
///
/// Implemented for the `'static` event instantiations; parsing borrows
/// internally and detaches via `into_static` (near-free — decoded payloads
/// are already owned).
pub trait KeriDeserialize: Sized {
    /// Deserialize from canonical JSON bytes, verifying the SAID.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] if JSON parsing fails, required fields are
    /// missing, or the SAID does not verify.
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use cesr::keri::Ilk;
    use cesr::keri::SigningThreshold;
    use cesr::keri::sequence::SequenceNumber;
    use cesr::keri::threshold_form::ThresholdForm;
    use cesr::keri::toad::Toad;
    use cesr::keri::{InceptionEvent, InteractionEvent, KeriEvent, RotationEvent};

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
        );
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn deserialize_inception_trait() {
        let event = InceptionEvent::new(
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
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            vec![],
            Toad::from_wire(0),
            vec![],
            ThresholdForm::HexString,
        );
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Rot);
    }

    #[test]
    fn serialize_interaction_trait() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
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
        ));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn keri_event_roundtrip() {
        let event = KeriEvent::Inception(InceptionEvent::new(
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
        ));
        let serialized = event.serialize().unwrap();
        let recovered = KeriEvent::deserialize(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.ilk(), Ilk::Icp);
    }
}
