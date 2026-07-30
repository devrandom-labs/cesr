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

    /// Position of the event-seal matching `delegated`'s `(i, s, d)` within
    /// this event's seals, counted over the event-seal subsequence (keripy
    /// filters seals to `SealEvent` fields and takes `.index` within the
    /// filtered sequence — eventing.py:3455-3463). `None` when this event
    /// does not anchor `delegated`.
    #[must_use]
    pub fn anchor_position(&self, delegated: &KeriEvent<'_>) -> Option<usize> {
        let target: (&Identifier<'_>, u128, &Said<'_>) =
            (delegated.prefix(), delegated.sn().value(), delegated.said());
        self.anchors()
            .iter()
            .filter_map(|seal| match seal {
                Seal::Event { i, s, d } => Some((i, s.value(), d)),
                _ => None,
            })
            .position(|(i, s, d)| i == target.0 && s == target.1 && d == target.2)
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
    use alloc::vec::Vec;
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
        make_saider_filled(0)
    }

    fn make_saider_filled(fill: u8) -> Said<'static> {
        Said::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![fill; 32]))
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
        make_interaction_with_anchors(vec![])
    }

    fn make_interaction_with_anchors(anchors: Vec<Seal<'static>>) -> InteractionEvent<'static> {
        use cesr::core::primitives::Number;

        InteractionEvent::new(
            make_prefixer().into(),
            Number::new(1),
            make_saider(),
            make_saider(),
            anchors,
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

    #[test]
    fn anchor_position_finds_the_matching_event_seal() {
        let delegated = KeriEvent::Inception(make_inception());
        let seal = Seal::Event {
            i: delegated.prefix().clone(),
            s: delegated.sn(),
            d: delegated.said().clone(),
        };
        // wrong-digest event seal: counted by the subsequence, never matched
        let event_decoy = Seal::Event {
            i: delegated.prefix().clone(),
            s: delegated.sn(),
            d: make_saider_filled(7),
        };
        // non-event seal: filtered out BEFORE indexing (keripy filtered-
        // subsequence semantics) — it must not shift the position
        let digest_decoy = Seal::Digest {
            d: make_saider_filled(9),
        };
        let anchoring = KeriEvent::Interaction(make_interaction_with_anchors(vec![
            digest_decoy,
            event_decoy,
            seal,
        ]));
        assert_eq!(anchoring.anchor_position(&delegated), Some(1));

        let unrelated = KeriEvent::Interaction(make_interaction_with_anchors(vec![]));
        assert_eq!(unrelated.anchor_position(&delegated), None);
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
