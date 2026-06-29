use cesr_core::primitives::{Saider, Seqner};

use crate::identifier::Identifier;
use crate::seal::Seal;

/// An interaction event that anchors data without changing keys.
pub struct InteractionEvent {
    prefix: Identifier<'static>,
    sn: Seqner,
    said: Saider<'static>,
    prior_event_said: Saider<'static>,
    anchors: Vec<Seal>,
}

impl InteractionEvent {
    /// Creates a new interaction event from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(
        prefix: Identifier<'static>,
        sn: Seqner,
        said: Saider<'static>,
        prior_event_said: Saider<'static>,
        anchors: Vec<Seal>,
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
    pub const fn prefix(&self) -> &Identifier<'static> {
        &self.prefix
    }

    /// Sequence number.
    #[must_use]
    pub const fn sn(&self) -> &Seqner {
        &self.sn
    }

    /// Self-addressing identifier digest.
    #[must_use]
    pub const fn said(&self) -> &Saider<'static> {
        &self.said
    }

    /// Digest of the prior event.
    #[must_use]
    pub const fn prior_event_said(&self) -> &Saider<'static> {
        &self.prior_event_said
    }

    /// Anchored seals binding external data.
    #[must_use]
    pub fn anchors(&self) -> &[Seal] {
        &self.anchors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr_core::matter::builder::MatterBuilder;
    use cesr_core::matter::code::{DigestCode, VerKeyCode};
    use cesr_core::primitives::Prefixer;
    use std::borrow::Cow;

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
            Seqner::new(2),
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
        assert_send_sync_static::<InteractionEvent>();
    }
}
