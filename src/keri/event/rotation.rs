#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{vec, vec::Vec,};
use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};

use crate::keri::config::ConfigTrait;
use crate::keri::identifier::Identifier;
use crate::keri::seal::Seal;

/// A rotation event that changes keys for an existing KERI identifier.
pub struct RotationEvent {
    prefix: Identifier<'static>,
    sn: Seqner,
    said: Saider<'static>,
    prior_event_said: Saider<'static>,
    keys: Vec<Verfer<'static>>,
    threshold: Tholder,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Tholder,
    witness_additions: Vec<Prefixer<'static>>,
    witness_removals: Vec<Prefixer<'static>>,
    witness_threshold: u32,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal>,
}

impl RotationEvent {
    /// Creates a new rotation event from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the full field set"
    )]
    pub const fn new(
        prefix: Identifier<'static>,
        sn: Seqner,
        said: Saider<'static>,
        prior_event_said: Saider<'static>,
        keys: Vec<Verfer<'static>>,
        threshold: Tholder,
        next_keys: Vec<Diger<'static>>,
        next_threshold: Tholder,
        witness_additions: Vec<Prefixer<'static>>,
        witness_removals: Vec<Prefixer<'static>>,
        witness_threshold: u32,
        config: Vec<ConfigTrait>,
        anchors: Vec<Seal>,
    ) -> Self {
        Self {
            prefix,
            sn,
            said,
            prior_event_said,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witness_additions,
            witness_removals,
            witness_threshold,
            config,
            anchors,
        }
    }

    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'static> {
        &self.prefix
    }

    /// Sequence number (must be > 0).
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

    /// New signing keys.
    #[must_use]
    pub fn keys(&self) -> &[Verfer<'static>] {
        &self.keys
    }

    /// Signing threshold for new keys.
    #[must_use]
    pub const fn threshold(&self) -> &Tholder {
        &self.threshold
    }

    /// Digests of next rotation key set.
    #[must_use]
    pub fn next_keys(&self) -> &[Diger<'static>] {
        &self.next_keys
    }

    /// Signing threshold for next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &Tholder {
        &self.next_threshold
    }

    /// Witnesses added in this rotation.
    #[must_use]
    pub fn witness_additions(&self) -> &[Prefixer<'static>] {
        &self.witness_additions
    }

    /// Witnesses removed in this rotation.
    #[must_use]
    pub fn witness_removals(&self) -> &[Prefixer<'static>] {
        &self.witness_removals
    }

    /// Witness agreement threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }

    /// Configuration traits constraining identifier behavior.
    #[must_use]
    pub fn config(&self) -> &[ConfigTrait] {
        &self.config
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
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
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

    #[test]
    fn construct_and_access_fields() {
        let event = RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            vec![],
            1,
            vec![],
            vec![],
        );

        assert_eq!(
            *event.prefix().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
        assert_eq!(event.sn().value(), 1);
        assert_eq!(*event.said().code(), DigestCode::Blake3_256);
        assert_eq!(*event.prior_event_said().code(), DigestCode::Blake3_256);
        assert_eq!(event.keys().len(), 1);
        assert!(event.threshold().satisfy(1));
        assert_eq!(event.next_keys().len(), 1);
        assert!(event.next_threshold().satisfy(1));
        assert_eq!(event.witness_additions().len(), 1);
        assert!(event.witness_removals().is_empty());
        assert_eq!(event.witness_threshold(), 1);
        assert!(event.config().is_empty());
        assert!(event.anchors().is_empty());
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<RotationEvent>();
    }
}
