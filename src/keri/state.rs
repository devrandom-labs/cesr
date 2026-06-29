use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};

use crate::keri::config::ConfigTrait;
use crate::keri::ilk::Ilk;

/// Computed key state for a KERI identifier at a given point in the KEL.
pub struct KeyState {
    prefix: Prefixer<'static>,
    sn: Seqner,
    latest_said: Saider<'static>,
    latest_ilk: Ilk,
    keys: Vec<Verfer<'static>>,
    threshold: Tholder,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Tholder,
    witnesses: Vec<Prefixer<'static>>,
    witness_threshold: u32,
    config: Vec<ConfigTrait>,
    delegator: Option<Prefixer<'static>>,
    transferable: bool,
}

impl KeyState {
    /// Creates a new key state from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the full field set"
    )]
    pub const fn new(
        prefix: Prefixer<'static>,
        sn: Seqner,
        latest_said: Saider<'static>,
        latest_ilk: Ilk,
        keys: Vec<Verfer<'static>>,
        threshold: Tholder,
        next_keys: Vec<Diger<'static>>,
        next_threshold: Tholder,
        witnesses: Vec<Prefixer<'static>>,
        witness_threshold: u32,
        config: Vec<ConfigTrait>,
        delegator: Option<Prefixer<'static>>,
        transferable: bool,
    ) -> Self {
        Self {
            prefix,
            sn,
            latest_said,
            latest_ilk,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witnesses,
            witness_threshold,
            config,
            delegator,
            transferable,
        }
    }

    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Prefixer<'static> {
        &self.prefix
    }

    /// Sequence number of the latest event.
    #[must_use]
    pub const fn sn(&self) -> &Seqner {
        &self.sn
    }

    /// SAID of the latest event.
    #[must_use]
    pub const fn latest_said(&self) -> &Saider<'static> {
        &self.latest_said
    }

    /// Ilk of the latest event.
    #[must_use]
    pub const fn latest_ilk(&self) -> &Ilk {
        &self.latest_ilk
    }

    /// Current signing keys.
    #[must_use]
    pub fn keys(&self) -> &[Verfer<'static>] {
        &self.keys
    }

    /// Signing threshold for current keys.
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

    /// Current witness prefixes.
    #[must_use]
    pub fn witnesses(&self) -> &[Prefixer<'static>] {
        &self.witnesses
    }

    /// Witness agreement threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }

    /// Active configuration traits.
    #[must_use]
    pub fn config(&self) -> &[ConfigTrait] {
        &self.config
    }

    /// Delegator prefix, if this is a delegated identifier.
    #[must_use]
    pub const fn delegator(&self) -> Option<&Prefixer<'static>> {
        self.delegator.as_ref()
    }

    /// Whether the identifier supports key rotation.
    #[must_use]
    pub const fn transferable(&self) -> bool {
        self.transferable
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
    fn construct_from_inception_data() {
        let state = KeyState::new(
            make_prefixer(),
            Seqner::new(0),
            make_saider(),
            Ilk::Icp,
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![],
            None,
            true,
        );

        assert_eq!(state.sn().value(), 0);
        assert_eq!(*state.latest_ilk(), Ilk::Icp);
        assert_eq!(state.keys().len(), 1);
        assert!(state.threshold().satisfy(1));
        assert_eq!(state.next_keys().len(), 1);
        assert_eq!(state.witnesses().len(), 1);
        assert_eq!(state.witness_threshold(), 1);
        assert!(state.config().is_empty());
        assert!(state.delegator().is_none());
        assert!(state.transferable());
    }

    #[test]
    fn construct_delegated_state() {
        let state = KeyState::new(
            make_prefixer(),
            Seqner::new(0),
            make_saider(),
            Ilk::Dip,
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            Some(make_prefixer()),
            true,
        );

        assert_eq!(*state.latest_ilk(), Ilk::Dip);
        assert!(state.delegator().is_some());
    }

    #[test]
    fn accessor_methods() {
        let state = KeyState::new(
            make_prefixer(),
            Seqner::new(0),
            make_saider(),
            Ilk::Icp,
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![],
            Some(make_prefixer()),
            true,
        );

        assert_eq!(*state.prefix().code(), VerKeyCode::Ed25519);
        assert_eq!(state.sn().value(), 0);
        assert_eq!(*state.latest_said().code(), DigestCode::Blake3_256);
        assert_eq!(*state.latest_ilk(), Ilk::Icp);
        assert_eq!(state.keys().len(), 1);
        assert!(state.threshold().satisfy(1));
        assert_eq!(state.next_keys().len(), 1);
        assert!(state.next_threshold().satisfy(1));
        assert_eq!(state.witnesses().len(), 1);
        assert_eq!(state.witness_threshold(), 1);
        assert!(state.config().is_empty());
        assert!(state.delegator().is_some());
        assert!(state.transferable());
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<KeyState>();
    }
}
