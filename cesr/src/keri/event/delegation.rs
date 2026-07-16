use crate::keri::event::inception::InceptionEvent;
use crate::keri::event::rotation::RotationEvent;
use crate::keri::identifier::Identifier;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;

/// A delegated inception event — creates an identifier under a delegator's authority.
pub struct DelegatedInceptionEvent<'a> {
    inception: InceptionEvent<'a>,
    delegator: Identifier<'a>,
}

impl<'a> DelegatedInceptionEvent<'a> {
    /// Creates a new delegated inception event.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(inception: InceptionEvent<'a>, delegator: Identifier<'a>) -> Self {
        Self {
            inception,
            delegator,
        }
    }

    /// The underlying inception event.
    #[must_use]
    pub const fn inception(&self) -> &InceptionEvent<'a> {
        &self.inception
    }

    /// Prefix of the delegating identifier.
    #[must_use]
    pub const fn delegator(&self) -> &Identifier<'a> {
        &self.delegator
    }

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> DelegatedInceptionEvent<'static> {
        DelegatedInceptionEvent {
            inception: self.inception.into_static(),
            delegator: self.delegator.into_static(),
        }
    }
}

/// A delegated rotation event — rotates keys under a delegator's authority.
///
/// Unlike `DelegatedInceptionEvent`, the delegator prefix is not stored here.
/// It is established at inception and can be looked up from the KEL.
pub struct DelegatedRotationEvent<'a> {
    rotation: RotationEvent<'a>,
}

impl<'a> DelegatedRotationEvent<'a> {
    /// Creates a new delegated rotation event.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(rotation: RotationEvent<'a>) -> Self {
        Self { rotation }
    }

    /// The underlying rotation event.
    #[must_use]
    pub const fn rotation(&self) -> &RotationEvent<'a> {
        &self.rotation
    }

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> DelegatedRotationEvent<'static> {
        DelegatedRotationEvent {
            rotation: self.rotation.into_static(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use crate::keri::SigningThreshold;
    use crate::keri::sequence::SequenceNumber;
    use crate::keri::threshold_form::ThresholdForm;
    use crate::keri::toad::Toad;
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
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
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

    fn make_inception() -> InceptionEvent<'static> {
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
            vec![],
            vec![],
            ThresholdForm::HexString,
        )
    }

    fn make_rotation() -> RotationEvent<'static> {
        RotationEvent::new(
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
            Toad::exact(0, 0).unwrap(),
            vec![],
            ThresholdForm::HexString,
        )
    }

    #[test]
    fn construct_delegated_inception() {
        let event = DelegatedInceptionEvent::new(make_inception(), make_prefixer().into());

        assert_eq!(event.inception().sn().value(), 0);
        assert_eq!(
            *event.delegator().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
    }

    #[test]
    fn construct_delegated_rotation() {
        let event = DelegatedRotationEvent::new(make_rotation());

        assert_eq!(event.rotation().sn().value(), 1);
    }

    #[test]
    fn delegated_inception_accessor_methods() {
        let event = DelegatedInceptionEvent::new(make_inception(), make_prefixer().into());

        assert_eq!(event.inception().sn().value(), 0);
        assert_eq!(
            *event.delegator().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
    }

    #[test]
    fn delegated_rotation_accessor_methods() {
        let event = DelegatedRotationEvent::new(make_rotation());

        assert_eq!(event.rotation().sn().value(), 1);
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<DelegatedInceptionEvent<'static>>();
        assert_send_sync_static::<DelegatedRotationEvent<'static>>();
    }

    /// Compile-time probe: covariance (see the rung-6 spec amendment).
    #[test]
    fn delegated_events_are_covariant() {
        fn coerce_dip<'short>(
            e: &'short DelegatedInceptionEvent<'static>,
        ) -> &'short DelegatedInceptionEvent<'short> {
            e
        }
        fn coerce_drt<'short>(
            e: &'short DelegatedRotationEvent<'static>,
        ) -> &'short DelegatedRotationEvent<'short> {
            e
        }
        let dip = DelegatedInceptionEvent::new(make_inception(), make_prefixer().into());
        let _ = coerce_dip(&dip);
        let drt = DelegatedRotationEvent::new(make_rotation());
        let _ = coerce_drt(&drt);
    }
}
