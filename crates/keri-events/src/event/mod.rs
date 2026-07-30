use crate::identifier::Identifier;
use crate::message_type::MessageType;
use crate::primitive::Said;
use crate::seal::Seal;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;
use cesr::core::primitives::Number;

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

impl<'a> KeriEvent<'a> {
    /// Returns the [`MessageType`] corresponding to this event variant.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Inception(_) => InceptionEvent::MESSAGE_TYPE,
            Self::Rotation(_) => RotationEvent::MESSAGE_TYPE,
            Self::Interaction(_) => InteractionEvent::MESSAGE_TYPE,
            Self::DelegatedInception(_) => DelegatedInceptionEvent::MESSAGE_TYPE,
            Self::DelegatedRotation(_) => DelegatedRotationEvent::MESSAGE_TYPE,
        }
    }

    /// Sequence number, uniform across variants.
    #[must_use]
    pub const fn sn(&self) -> Number {
        match self {
            Self::Inception(e) => e.sn(),
            Self::Rotation(e) => e.sn(),
            Self::Interaction(e) => e.sn(),
            Self::DelegatedInception(e) => e.inception().sn(),
            Self::DelegatedRotation(e) => e.rotation().sn(),
        }
    }

    /// SAID, uniform across variants.
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        match self {
            Self::Inception(e) => e.said(),
            Self::Rotation(e) => e.said(),
            Self::Interaction(e) => e.said(),
            Self::DelegatedInception(e) => e.inception().said(),
            Self::DelegatedRotation(e) => e.rotation().said(),
        }
    }

    /// Identifier prefix, uniform across variants.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'a> {
        match self {
            Self::Inception(e) => e.prefix(),
            Self::Rotation(e) => e.prefix(),
            Self::Interaction(e) => e.prefix(),
            Self::DelegatedInception(e) => e.inception().prefix(),
            Self::DelegatedRotation(e) => e.rotation().prefix(),
        }
    }

    /// Anchored seals (the `a` field), uniform across variants.
    #[must_use]
    pub fn anchors(&self) -> &[Seal<'a>] {
        match self {
            Self::Inception(e) => e.anchors(),
            Self::Rotation(e) => e.anchors(),
            Self::Interaction(e) => e.anchors(),
            Self::DelegatedInception(e) => e.inception().anchors(),
            Self::DelegatedRotation(e) => e.rotation().anchors(),
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
    use crate::primitive::{BasicPrefix, Digest, Said, VerifyingKey};
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};

    fn make_prefixer() -> BasicPrefix<'static> {
        BasicPrefix::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_saider() -> Said<'static> {
        Said::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_verfer() -> VerifyingKey<'static> {
        VerifyingKey::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_diger() -> Digest<'static> {
        Digest::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_inception() -> InceptionEvent<'static> {
        use crate::SigningThreshold;
        use crate::config::ConfigTrait;
        use crate::threshold_form::ThresholdForm;
        use crate::toad::Toad;
        use cesr::core::primitives::Number;

        InceptionEvent::new(
            make_prefixer().into(),
            Number::new(0),
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
        use cesr::core::primitives::Number;

        InteractionEvent::new(
            make_prefixer().into(),
            Number::new(1),
            make_saider(),
            make_saider(),
            vec![],
        )
    }

    #[test]
    fn keri_event_message_type() {
        let event = KeriEvent::Inception(make_inception());
        assert_eq!(event.message_type(), MessageType::Icp);
    }

    #[test]
    fn keri_event_message_type_interaction() {
        let event = KeriEvent::Interaction(make_interaction());
        assert_eq!(event.message_type(), MessageType::Ixn);
    }

    #[test]
    fn keri_event_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<KeriEvent<'static>>();
    }

    #[test]
    fn keri_event_unified_accessors() {
        let icp = make_inception();
        let (sn, said, prefix) = (icp.sn(), icp.said().clone(), icp.prefix().clone());
        let event = KeriEvent::Inception(icp);
        assert_eq!(event.sn(), sn);
        assert_eq!(event.said(), &said);
        assert_eq!(event.prefix(), &prefix);
        assert!(event.anchors().is_empty());
    }

    #[test]
    fn keri_event_unified_accessors_delegated() {
        let inner = make_inception();
        let sn = inner.sn();
        let dip = DelegatedInceptionEvent::new(inner, Identifier::Basic(make_prefixer()));
        let event = KeriEvent::DelegatedInception(dip);
        assert_eq!(event.sn(), sn);
        assert_eq!(event.message_type(), MessageType::Dip);
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
