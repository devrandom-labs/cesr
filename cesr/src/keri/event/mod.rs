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
pub enum KeriEvent {
    /// An inception event that creates a new identifier.
    Inception(InceptionEvent),
    /// A rotation event that rotates keys for an identifier.
    Rotation(RotationEvent),
    /// An interaction event that anchors data without key changes.
    Interaction(InteractionEvent),
    /// A delegated inception event.
    DelegatedInception(DelegatedInceptionEvent),
    /// A delegated rotation event.
    DelegatedRotation(DelegatedRotationEvent),
}

impl KeriEvent {
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

    fn make_inception() -> InceptionEvent {
        use crate::core::primitives::{Seqner, Tholder};
        use crate::keri::config::ConfigTrait;
        use crate::keri::toad::Toad;

        InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![],
        )
    }

    fn make_interaction() -> InteractionEvent {
        use crate::core::primitives::Seqner;

        InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
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
        assert_send_sync_static::<KeriEvent>();
    }
}
