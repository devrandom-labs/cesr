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
pub struct DelegatedInceptionEvent {
    inception: InceptionEvent,
    delegator: Identifier<'static>,
}

impl DelegatedInceptionEvent {
    /// Creates a new delegated inception event.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(inception: InceptionEvent, delegator: Identifier<'static>) -> Self {
        Self {
            inception,
            delegator,
        }
    }

    /// The underlying inception event.
    #[must_use]
    pub const fn inception(&self) -> &InceptionEvent {
        &self.inception
    }

    /// Prefix of the delegating identifier.
    #[must_use]
    pub const fn delegator(&self) -> &Identifier<'static> {
        &self.delegator
    }
}

/// A delegated rotation event — rotates keys under a delegator's authority.
///
/// Unlike `DelegatedInceptionEvent`, the delegator prefix is not stored here.
/// It is established at inception and can be looked up from the KEL.
pub struct DelegatedRotationEvent {
    rotation: RotationEvent,
}

impl DelegatedRotationEvent {
    /// Creates a new delegated rotation event.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(rotation: RotationEvent) -> Self {
        Self { rotation }
    }

    /// The underlying rotation event.
    #[must_use]
    pub const fn rotation(&self) -> &RotationEvent {
        &self.rotation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
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

    fn make_inception() -> InceptionEvent {
        InceptionEvent::new(
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
        )
    }

    fn make_rotation() -> RotationEvent {
        RotationEvent::new(
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
        assert_send_sync_static::<DelegatedInceptionEvent>();
        assert_send_sync_static::<DelegatedRotationEvent>();
    }
}
