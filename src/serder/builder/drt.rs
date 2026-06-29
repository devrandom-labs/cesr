//! Delegated rotation event (`drt`) builder with compile-time required field
//! enforcement.

use std::marker::PhantomData;

use cesr_core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use keri_core::{ConfigTrait, DelegatedRotationEvent, RotationEvent, Seal};

use super::icp::{dummy_saider, majority, validate_threshold};
use crate::error::SerderError;
use crate::serialize::SerializedEvent;

/// Type state: prefix not yet provided.
pub struct NeedsPrefix;

/// Type state: prior event SAID not yet provided.
pub struct NeedsPriorSaid;

/// Type state: keys not yet provided.
pub struct NeedsKeys;

/// Type state: all required fields provided, ready to build.
pub struct Ready;

/// Builder for delegated rotation events with compile-time required field
/// enforcement.
///
/// Required fields: `prefix`, `prior_event_said`, `keys`.
/// All other fields have smart defaults.
///
/// # Examples
///
/// ```ignore
/// let result = DelegatedRotationBuilder::new()
///     .prefix(prefixer)
///     .prior_event_said(saider)
///     .keys(vec![verfer])
///     .build()?;
/// ```
#[must_use]
pub struct DelegatedRotationBuilder<State = NeedsPrefix> {
    prefix: Option<Prefixer<'static>>,
    prior_event_said: Option<Saider<'static>>,
    keys: Vec<Verfer<'static>>,
    sn: Option<u128>,
    threshold: Option<Tholder>,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Option<Tholder>,
    witness_removals: Vec<Prefixer<'static>>,
    witness_additions: Vec<Prefixer<'static>>,
    witness_threshold: Option<u32>,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal>,
    _state: PhantomData<State>,
}

impl DelegatedRotationBuilder<NeedsPrefix> {
    /// Create a new delegated rotation builder awaiting the identifier prefix.
    pub const fn new() -> Self {
        Self {
            prefix: None,
            prior_event_said: None,
            keys: Vec::new(),
            sn: None,
            threshold: None,
            next_keys: Vec::new(),
            next_threshold: None,
            witness_removals: Vec::new(),
            witness_additions: Vec::new(),
            witness_threshold: None,
            config: Vec::new(),
            anchors: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Set the identifier prefix (required).
    pub fn prefix(self, prefix: Prefixer<'static>) -> DelegatedRotationBuilder<NeedsPriorSaid> {
        DelegatedRotationBuilder {
            prefix: Some(prefix),
            prior_event_said: self.prior_event_said,
            keys: self.keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            _state: PhantomData,
        }
    }
}

impl Default for DelegatedRotationBuilder<NeedsPrefix> {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatedRotationBuilder<NeedsPriorSaid> {
    /// Set the prior event SAID (required).
    pub fn prior_event_said(self, said: Saider<'static>) -> DelegatedRotationBuilder<NeedsKeys> {
        DelegatedRotationBuilder {
            prefix: self.prefix,
            prior_event_said: Some(said),
            keys: self.keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            _state: PhantomData,
        }
    }
}

impl DelegatedRotationBuilder<NeedsKeys> {
    /// Set the new signing keys (required).
    pub fn keys(self, keys: Vec<Verfer<'static>>) -> DelegatedRotationBuilder<Ready> {
        DelegatedRotationBuilder {
            prefix: self.prefix,
            prior_event_said: self.prior_event_said,
            keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            _state: PhantomData,
        }
    }
}

impl DelegatedRotationBuilder<Ready> {
    /// Override the sequence number (default: 1, must be >= 1).
    pub const fn sn(mut self, sn: u128) -> Self {
        self.sn = Some(sn);
        self
    }

    /// Override the signing threshold (default: majority of keys).
    pub fn threshold(mut self, threshold: Tholder) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set the next (pre-rotated) key digests (default: empty).
    pub fn next_keys(mut self, next_keys: Vec<Diger<'static>>) -> Self {
        self.next_keys = next_keys;
        self
    }

    /// Override the next key threshold (default: majority of next keys).
    pub fn next_threshold(mut self, next_threshold: Tholder) -> Self {
        self.next_threshold = Some(next_threshold);
        self
    }

    /// Set witnesses to remove (default: empty).
    pub fn witness_removals(mut self, witness_removals: Vec<Prefixer<'static>>) -> Self {
        self.witness_removals = witness_removals;
        self
    }

    /// Set witnesses to add (default: empty).
    pub fn witness_additions(mut self, witness_additions: Vec<Prefixer<'static>>) -> Self {
        self.witness_additions = witness_additions;
        self
    }

    /// Override the witness threshold (default: 0).
    pub const fn witness_threshold(mut self, witness_threshold: u32) -> Self {
        self.witness_threshold = Some(witness_threshold);
        self
    }

    /// Set configuration traits (default: empty).
    pub fn config(mut self, config: Vec<ConfigTrait>) -> Self {
        self.config = config;
        self
    }

    /// Set anchored seals (default: empty).
    pub fn anchors(mut self, anchors: Vec<Seal>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Build the delegated rotation event, applying smart defaults and
    /// validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::Validation`] if:
    /// - `keys` is empty
    /// - `sn` is 0
    /// - Simple threshold exceeds the number of keys
    /// - Next threshold exceeds the number of next keys (when non-empty)
    pub fn build(self) -> Result<SerializedEvent, SerderError> {
        if self.keys.is_empty() {
            return Err(SerderError::Validation("keys must not be empty".to_owned()));
        }

        let sn = self.sn.unwrap_or(1);
        if sn == 0 {
            return Err(SerderError::Validation(
                "delegated rotation sn must be >= 1".to_owned(),
            ));
        }

        let threshold = self
            .threshold
            .unwrap_or_else(|| Tholder::Simple(majority(self.keys.len())));

        validate_threshold(&threshold, self.keys.len(), "signing")?;

        let next_threshold = self.next_threshold.unwrap_or_else(|| {
            if self.next_keys.is_empty() {
                Tholder::Simple(0)
            } else {
                Tholder::Simple(majority(self.next_keys.len()))
            }
        });

        if !self.next_keys.is_empty() {
            validate_threshold(&next_threshold, self.next_keys.len(), "next signing")?;
        }

        let witness_threshold = self.witness_threshold.unwrap_or(0);

        let prefix = self
            .prefix
            .ok_or_else(|| SerderError::Validation("prefix is required".to_owned()))?;
        let prior_event_said = self
            .prior_event_said
            .ok_or_else(|| SerderError::Validation("prior_event_said is required".to_owned()))?;

        let rotation = RotationEvent::new(
            prefix.into(),
            Seqner::new(sn),
            dummy_saider()?,
            prior_event_said,
            self.keys,
            threshold,
            self.next_keys,
            next_threshold,
            self.witness_additions,
            self.witness_removals,
            witness_threshold,
            self.config,
            self.anchors,
        );

        let event = DelegatedRotationEvent::new(rotation);

        crate::serialize::drt::serialize_delegated_rotation(&event)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use std::borrow::Cow;

    use cesr_core::matter::builder::MatterBuilder;
    use cesr_core::matter::code::{DigestCode, VerKeyCode};
    use cesr_core::primitives::{Diger, Prefixer, Saider, Verfer};

    use super::*;

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

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![3u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![4u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn build_minimal_delegated_rotation() {
        let result = DelegatedRotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        assert_eq!(result.ilk(), keri_core::Ilk::Drt);
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "drt");
        assert_eq!(parsed["s"].as_str().unwrap(), "1");
    }

    #[test]
    fn build_with_all_options() {
        let result = DelegatedRotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer(), make_verfer()])
            .sn(2)
            .threshold(Tholder::Simple(1))
            .next_keys(vec![make_diger()])
            .next_threshold(Tholder::Simple(1))
            .witness_additions(vec![make_prefixer()])
            .witness_removals(vec![make_prefixer()])
            .witness_threshold(1)
            .config(vec![])
            .anchors(vec![])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "drt");
        assert_eq!(parsed["s"].as_str().unwrap(), "2");
        assert_eq!(parsed["kt"].as_str().unwrap(), "1");
    }

    #[test]
    fn threshold_default_majority() {
        let result = DelegatedRotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["kt"].as_str().unwrap(), "2");
    }

    #[test]
    fn roundtrip() {
        let serialized = DelegatedRotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .next_keys(vec![make_diger()])
            .build()
            .unwrap();

        let recovered =
            crate::deserialize::deserialize_delegated_rotation(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.rotation().sn().value(), 1);
        assert_eq!(recovered.rotation().keys().len(), 1);
        assert_eq!(recovered.rotation().next_keys().len(), 1);
    }

    #[test]
    fn sn_zero_rejected() {
        let result = DelegatedRotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .sn(0)
            .build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("sn must be >= 1"));
    }

    #[test]
    fn empty_keys_rejected() {
        let result = DelegatedRotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![])
            .build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("keys must not be empty"));
    }

    #[test]
    fn default_impl() {
        let builder = DelegatedRotationBuilder::default();
        let result = builder
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .build()
            .unwrap();
        assert_eq!(result.ilk(), keri_core::Ilk::Drt);
    }
}
