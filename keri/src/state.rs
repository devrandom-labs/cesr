//! Computed key state for a KERI identifier at a point in its KEL.
use alloc::vec::Vec;

use cesr::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use cesr::keri::{ConfigTrait, Identifier, Ilk};

/// `(sn, said)` of the last establishment event (keripy `lastEst`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentRef {
    /// Sequence number of the last establishment event.
    pub sn: Seqner,
    /// SAID of the last establishment event.
    pub said: Saider<'static>,
}

/// Computed key state. Owns its data outright: every field holds owned
/// `'static` primitives, because state must outlive any single input event.
///
/// A future zero-copy pass (#129) will reintroduce a borrowing lifetime once
/// events themselves borrow from the stream buffer.
#[derive(Debug, Clone)]
pub struct KeyState {
    pub(crate) prefix: Identifier<'static>,
    pub(crate) sn: Seqner,
    pub(crate) latest_said: Saider<'static>,
    pub(crate) latest_ilk: Ilk,
    pub(crate) keys: Vec<Verfer<'static>>,
    pub(crate) threshold: Tholder,
    pub(crate) next_keys: Vec<Diger<'static>>,
    pub(crate) next_threshold: Tholder,
    pub(crate) witnesses: Vec<Prefixer<'static>>,
    pub(crate) witness_threshold: u32,
    pub(crate) config: Vec<ConfigTrait>,
    pub(crate) delegator: Option<Prefixer<'static>>,
    pub(crate) transferable: bool,
    pub(crate) last_est: EstablishmentRef,
}

impl KeyState {
    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'static> {
        &self.prefix
    }
    /// Sequence number of the latest applied event.
    #[must_use]
    pub const fn sn(&self) -> &Seqner {
        &self.sn
    }
    /// SAID of the latest applied event.
    #[must_use]
    pub const fn latest_said(&self) -> &Saider<'static> {
        &self.latest_said
    }
    /// Ilk of the latest applied event.
    #[must_use]
    pub const fn latest_ilk(&self) -> Ilk {
        self.latest_ilk
    }
    /// Current signing keys.
    #[must_use]
    pub fn keys(&self) -> &[Verfer<'static>] {
        &self.keys
    }
    /// Current signing threshold.
    #[must_use]
    pub const fn threshold(&self) -> &Tholder {
        &self.threshold
    }
    /// Committed next-key digests.
    #[must_use]
    pub fn next_keys(&self) -> &[Diger<'static>] {
        &self.next_keys
    }
    /// Threshold for the next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &Tholder {
        &self.next_threshold
    }
    /// Current witness prefixes.
    #[must_use]
    pub fn witnesses(&self) -> &[Prefixer<'static>] {
        &self.witnesses
    }
    /// Witness threshold (TOAD).
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }
    /// Configuration traits in effect.
    #[must_use]
    pub fn config(&self) -> &[ConfigTrait] {
        &self.config
    }
    /// Delegator prefix, if this identifier is delegated.
    #[must_use]
    pub const fn delegator(&self) -> Option<&Prefixer<'static>> {
        self.delegator.as_ref()
    }
    /// Whether the identifier is transferable (rotatable).
    #[must_use]
    pub const fn transferable(&self) -> bool {
        self.transferable
    }
    /// `(sn, said)` of the last establishment event.
    #[must_use]
    pub const fn last_establishment(&self) -> &EstablishmentRef {
        &self.last_est
    }

    /// `true` if this state has the `EstOnly` config trait.
    #[must_use]
    pub fn is_establishment_only(&self) -> bool {
        self.config
            .iter()
            .any(|c| matches!(c, ConfigTrait::EstOnly))
    }
}
