#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use cesr::core::primitives::Saider;

use crate::identifier::Identifier;
use crate::seal::Seal;
use crate::sequence::SequenceNumber;

/// An interaction event that anchors data without changing keys.
pub struct InteractionEvent<'a> {
    prefix: Identifier<'a>,
    sn: SequenceNumber,
    said: Saider<'a>,
    prior_event_said: Saider<'a>,
    anchors: Vec<Seal<'a>>,
}

impl<'a> InteractionEvent<'a> {
    /// Creates a new interaction event from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(
        prefix: Identifier<'a>,
        sn: SequenceNumber,
        said: Saider<'a>,
        prior_event_said: Saider<'a>,
        anchors: Vec<Seal<'a>>,
    ) -> Self {
        Self {
            prefix,
            sn,
            said,
            prior_event_said,
            anchors,
        }
    }

    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'a> {
        &self.prefix
    }

    /// Sequence number.
    #[must_use]
    pub const fn sn(&self) -> SequenceNumber {
        self.sn
    }

    /// Self-addressing identifier digest.
    #[must_use]
    pub const fn said(&self) -> &Saider<'a> {
        &self.said
    }

    /// Digest of the prior event.
    #[must_use]
    pub const fn prior_event_said(&self) -> &Saider<'a> {
        &self.prior_event_said
    }

    /// Anchored seals binding external data.
    #[must_use]
    pub fn anchors(&self) -> &[Seal<'a>] {
        &self.anchors
    }

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> InteractionEvent<'static> {
        InteractionEvent {
            prefix: self.prefix.into_static(),
            sn: self.sn,
            said: self.said.into_static(),
            prior_event_said: self.prior_event_said.into_static(),
            anchors: self.anchors.into_iter().map(Seal::into_static).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::Prefixer;

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

    #[test]
    fn construct_and_access_fields() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(2),
            make_saider(),
            make_saider(),
            vec![Seal::Digest { d: make_saider() }],
        );

        assert_eq!(
            *event.prefix().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
        assert_eq!(event.sn().value(), 2);
        assert_eq!(*event.said().code(), DigestCode::Blake3_256);
        assert_eq!(*event.prior_event_said().code(), DigestCode::Blake3_256);
        assert_eq!(event.anchors().len(), 1);
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<InteractionEvent<'static>>();
    }

    /// Compile-time probe: covariance (see the rung-6 spec amendment).
    #[test]
    fn interaction_event_is_covariant() {
        fn coerce<'short>(
            e: &'short InteractionEvent<'static>,
        ) -> &'short InteractionEvent<'short> {
            e
        }
        let event = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(2),
            make_saider(),
            make_saider(),
            vec![],
        );
        let _ = coerce(&event);
    }
}
