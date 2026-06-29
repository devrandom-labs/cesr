//! Delegated inception event (`dip`) builder with compile-time required field
//! enforcement.

use std::marker::PhantomData;

use crate::core::primitives::{Diger, Prefixer, Seqner, Tholder, Verfer};
use crate::keri::{ConfigTrait, DelegatedInceptionEvent, InceptionEvent, Seal};

use super::icp::{dummy_prefixer, dummy_saider, majority, validate_threshold};
use crate::error::SerderError;
use crate::serialize::SerializedEvent;

/// Type state: keys not yet provided.
pub struct NeedsKeys;

/// Type state: delegator not yet provided.
pub struct NeedsDelegator;

/// Type state: all required fields provided, ready to build.
pub struct Ready;

/// Builder for delegated inception events with compile-time required field
/// enforcement.
///
/// Required fields: `keys`, `delegator`.
/// All other fields have smart defaults matching keripy's `delcept()`.
///
/// # Examples
///
/// ```ignore
/// let result = DelegatedInceptionBuilder::new()
///     .keys(vec![verfer])
///     .delegator(prefixer)
///     .build()?;
/// ```
#[must_use]
pub struct DelegatedInceptionBuilder<State = NeedsKeys> {
    keys: Vec<Verfer<'static>>,
    delegator: Option<Prefixer<'static>>,
    threshold: Option<Tholder>,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Option<Tholder>,
    witnesses: Vec<Prefixer<'static>>,
    witness_threshold: Option<u32>,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal>,
    _state: PhantomData<State>,
}

impl DelegatedInceptionBuilder<NeedsKeys> {
    /// Create a new delegated inception builder awaiting signing keys.
    pub const fn new() -> Self {
        Self {
            keys: Vec::new(),
            delegator: None,
            threshold: None,
            next_keys: Vec::new(),
            next_threshold: None,
            witnesses: Vec::new(),
            witness_threshold: None,
            config: Vec::new(),
            anchors: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Set the signing keys (required).
    pub fn keys(self, keys: Vec<Verfer<'static>>) -> DelegatedInceptionBuilder<NeedsDelegator> {
        DelegatedInceptionBuilder {
            keys,
            delegator: self.delegator,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witnesses: self.witnesses,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            _state: PhantomData,
        }
    }
}

impl Default for DelegatedInceptionBuilder<NeedsKeys> {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatedInceptionBuilder<NeedsDelegator> {
    /// Set the delegator prefix (required).
    pub fn delegator(self, delegator: Prefixer<'static>) -> DelegatedInceptionBuilder<Ready> {
        DelegatedInceptionBuilder {
            keys: self.keys,
            delegator: Some(delegator),
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witnesses: self.witnesses,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            _state: PhantomData,
        }
    }
}

impl DelegatedInceptionBuilder<Ready> {
    /// Override the signing threshold (default: majority of keys).
    pub fn threshold(mut self, threshold: Tholder) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set the next (pre-rotated) key digests (default: empty / non-transferable).
    pub fn next_keys(mut self, next_keys: Vec<Diger<'static>>) -> Self {
        self.next_keys = next_keys;
        self
    }

    /// Override the next key threshold (default: majority of next keys).
    pub fn next_threshold(mut self, next_threshold: Tholder) -> Self {
        self.next_threshold = Some(next_threshold);
        self
    }

    /// Set witness prefixes (default: empty).
    pub fn witnesses(mut self, witnesses: Vec<Prefixer<'static>>) -> Self {
        self.witnesses = witnesses;
        self
    }

    /// Override the witness threshold (default: `ample(witnesses.len())`).
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

    /// Build the delegated inception event, applying smart defaults and
    /// validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::Validation`] if:
    /// - `keys` is empty
    /// - Simple threshold exceeds the number of keys
    /// - Next threshold exceeds the number of next keys (when non-empty)
    pub fn build(self) -> Result<SerializedEvent, SerderError> {
        if self.keys.is_empty() {
            return Err(SerderError::Validation("keys must not be empty".to_owned()));
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

        let witness_threshold = self
            .witness_threshold
            .unwrap_or_else(|| crate::ample::ample(self.witnesses.len()));

        let delegator = self
            .delegator
            .ok_or_else(|| SerderError::Validation("delegator is required".to_owned()))?;

        let inception = InceptionEvent::new(
            dummy_prefixer()?.into(),
            Seqner::new(0),
            dummy_saider()?,
            self.keys,
            threshold,
            self.next_keys,
            next_threshold,
            self.witnesses,
            witness_threshold,
            self.config,
            self.anchors,
        );

        let event = DelegatedInceptionEvent::new(inception, delegator.into());

        crate::serialize::dip::serialize_delegated_inception(&event)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use std::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Verfer};

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

    #[test]
    fn build_minimal_delegated_inception() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_prefixer())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Dip);
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "dip");
        assert_eq!(parsed["s"].as_str().unwrap(), "0");
        assert!(parsed.get("di").is_some());
    }

    #[test]
    fn build_with_all_options() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer()])
            .delegator(make_prefixer())
            .threshold(Tholder::Simple(1))
            .next_keys(vec![make_diger()])
            .next_threshold(Tholder::Simple(1))
            .witnesses(vec![make_prefixer()])
            .witness_threshold(1)
            .config(vec![ConfigTrait::EstOnly])
            .anchors(vec![])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "dip");
        assert_eq!(parsed["kt"].as_str().unwrap(), "1");
        let k = parsed["k"].as_array().unwrap();
        assert_eq!(k.len(), 2);
    }

    #[test]
    fn threshold_default_majority() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .delegator(make_prefixer())
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["kt"].as_str().unwrap(), "2");
    }

    #[test]
    fn roundtrip() {
        let serialized = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_prefixer())
            .next_keys(vec![make_diger()])
            .build()
            .unwrap();

        let recovered =
            crate::deserialize::deserialize_delegated_inception(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.inception().sn().value(), 0);
        assert_eq!(recovered.inception().keys().len(), 1);
        assert_eq!(recovered.inception().next_keys().len(), 1);
    }

    #[test]
    fn self_addressing_prefix() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_prefixer())
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_eq!(d, i, "d and i must be equal for delegated inception");
    }

    #[test]
    fn empty_keys_rejected() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![])
            .delegator(make_prefixer())
            .build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("keys must not be empty"));
    }

    #[test]
    fn default_impl() {
        let builder = DelegatedInceptionBuilder::default();
        let result = builder
            .keys(vec![make_verfer()])
            .delegator(make_prefixer())
            .build()
            .unwrap();
        assert_eq!(result.ilk(), crate::keri::Ilk::Dip);
    }
}
