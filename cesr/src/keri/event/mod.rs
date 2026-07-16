use crate::keri::ilk::Ilk;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;

/// Delegated inception and rotation events.
pub mod delegation;
/// Inception event.
pub mod inception;
/// Interaction event.
pub mod interaction;
/// Rotation event.
pub mod rotation;

pub use delegation::{DelegatedInceptionEvent, DelegatedRotationEvent};
pub use inception::InceptionEvent;
pub use interaction::InteractionEvent;
pub use rotation::RotationEvent;

/// A unified KERI event encompassing all event types.
pub enum KeriEvent<'a> {
    /// An inception event that creates a new identifier.
    Inception(InceptionEvent<'a>),
    /// A rotation event that rotates keys for an identifier.
    Rotation(RotationEvent<'a>),
    /// An interaction event that anchors data without key changes.
    Interaction(InteractionEvent<'a>),
    /// A delegated inception event.
    DelegatedInception(DelegatedInceptionEvent<'a>),
    /// A delegated rotation event.
    DelegatedRotation(DelegatedRotationEvent<'a>),
}

impl KeriEvent<'_> {
    /// Returns the [`Ilk`] corresponding to this event variant.
    #[must_use]
    pub const fn ilk(&self) -> Ilk {
        match self {
            Self::Inception(_) => Ilk::Icp,
            Self::Rotation(_) => Ilk::Rot,
            Self::Interaction(_) => Ilk::Ixn,
            Self::DelegatedInception(_) => Ilk::Dip,
            Self::DelegatedRotation(_) => Ilk::Drt,
        }
    }

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> KeriEvent<'static> {
        match self {
            Self::Inception(e) => KeriEvent::Inception(e.into_static()),
            Self::Rotation(e) => KeriEvent::Rotation(e.into_static()),
            Self::Interaction(e) => KeriEvent::Interaction(e.into_static()),
            Self::DelegatedInception(e) => KeriEvent::DelegatedInception(e.into_static()),
            Self::DelegatedRotation(e) => KeriEvent::DelegatedRotation(e.into_static()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use alloc::borrow::Cow;

    fn make_prefixer() -> crate::core::primitives::Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> crate::core::primitives::Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verfer() -> crate::core::primitives::Verfer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_diger() -> crate::core::primitives::Diger<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_inception() -> InceptionEvent<'static> {
        use crate::keri::SigningThreshold;
        use crate::keri::config::ConfigTrait;
        use crate::keri::sequence::SequenceNumber;
        use crate::keri::threshold_form::ThresholdForm;
        use crate::keri::toad::Toad;

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
            vec![ConfigTrait::EstOnly],
            vec![],
            ThresholdForm::HexString,
        )
    }

    fn make_interaction() -> InteractionEvent<'static> {
        use crate::keri::sequence::SequenceNumber;

        InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![],
        )
    }

    #[test]
    fn keri_event_ilk() {
        let event = KeriEvent::Inception(make_inception());
        assert_eq!(event.ilk(), Ilk::Icp);
    }

    #[test]
    fn keri_event_ilk_interaction() {
        let event = KeriEvent::Interaction(make_interaction());
        assert_eq!(event.ilk(), Ilk::Ixn);
    }

    #[test]
    fn keri_event_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<KeriEvent<'static>>();
    }

    /// Compile-time probe: covariance (see the rung-6 spec amendment).
    #[test]
    fn keri_event_is_covariant() {
        fn coerce<'short>(e: &'short KeriEvent<'static>) -> &'short KeriEvent<'short> {
            e
        }
        let event = KeriEvent::Inception(make_inception());
        let _ = coerce(&event);
    }
}
