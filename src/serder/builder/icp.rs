//! Inception event (`icp`) builder with compile-time required field enforcement.

use std::borrow::Cow;
use std::marker::PhantomData;

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{DigestCode, VerKeyCode};
use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use crate::keri::{ConfigTrait, InceptionEvent, Seal};

use crate::error::SerderError;
use crate::serialize::SerializedEvent;

/// Type state: keys not yet provided.
pub struct NeedsKeys;

/// Type state: all required fields provided, ready to build.
pub struct Ready;

/// Builder for inception events with compile-time required field enforcement.
///
/// Only `keys` is required. All other fields have smart defaults matching
/// keripy's `incept()` function.
///
/// # Examples
///
/// ```ignore
/// let result = InceptionBuilder::new()
///     .keys(vec![verfer])
///     .build()?;
/// ```
#[must_use]
pub struct InceptionBuilder<State = NeedsKeys> {
    keys: Vec<Verfer<'static>>,
    threshold: Option<Tholder>,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Option<Tholder>,
    witnesses: Vec<Prefixer<'static>>,
    witness_threshold: Option<u32>,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal>,
    _state: PhantomData<State>,
}

pub(crate) fn dummy_saider() -> Result<Saider<'static>, SerderError> {
    MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
        .map_err(|e| SerderError::Validation(e.to_string()))?
        .build()
        .map_err(|e| SerderError::Validation(e.to_string()))
}

pub(crate) fn dummy_prefixer() -> Result<Prefixer<'static>, SerderError> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
        .map_err(|e| SerderError::Validation(e.to_string()))?
        .build()
        .map_err(|e| SerderError::Validation(e.to_string()))
}

pub(crate) fn majority(n: usize) -> u64 {
    let m = 1.max(n.div_ceil(2));
    // SAFETY: usize to u64 is lossless on all supported platforms (64-bit)
    u64::try_from(m).unwrap_or(u64::MAX)
}

impl InceptionBuilder<NeedsKeys> {
    /// Create a new inception builder awaiting signing keys.
    pub const fn new() -> Self {
        Self {
            keys: Vec::new(),
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
    pub fn keys(self, keys: Vec<Verfer<'static>>) -> InceptionBuilder<Ready> {
        InceptionBuilder {
            keys,
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

impl Default for InceptionBuilder<NeedsKeys> {
    fn default() -> Self {
        Self::new()
    }
}

impl InceptionBuilder<Ready> {
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

    /// Build the inception event, applying smart defaults and validating fields.
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

        let event = InceptionEvent::new(
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

        crate::serialize::icp::serialize_inception(&event)
    }
}

pub(crate) fn validate_threshold(
    threshold: &Tholder,
    key_count: usize,
    label: &str,
) -> Result<(), SerderError> {
    match threshold {
        Tholder::Simple(n) => {
            if *n < 1 {
                return Err(SerderError::Validation(format!(
                    "{label} threshold must be >= 1"
                )));
            }
            let n_usize = usize::try_from(*n)
                .map_err(|_| SerderError::Validation(format!("{label} threshold too large")))?;
            if n_usize > key_count {
                return Err(SerderError::Validation(format!(
                    "{label} threshold ({n}) exceeds key count ({key_count})"
                )));
            }
        }
        Tholder::Weighted(clauses) => {
            let total_weights: usize = clauses.iter().map(Vec::len).sum();
            if total_weights > key_count {
                return Err(SerderError::Validation(format!(
                    "{label} weighted threshold has {total_weights} weights but only {key_count} keys"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use std::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Verfer};

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
    fn build_minimal_inception() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Icp);
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "icp");
        assert_eq!(parsed["s"].as_str().unwrap(), "0");
    }

    #[test]
    fn build_with_all_options() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer()])
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
        assert_eq!(parsed["t"].as_str().unwrap(), "icp");
        assert_eq!(parsed["kt"].as_str().unwrap(), "1");
        let k = parsed["k"].as_array().unwrap();
        assert_eq!(k.len(), 2);
        let n = parsed["n"].as_array().unwrap();
        assert_eq!(n.len(), 1);
        let b = parsed["b"].as_array().unwrap();
        assert_eq!(b.len(), 1);
        let c = parsed["c"].as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].as_str().unwrap(), "EO");
    }

    #[test]
    fn threshold_default_majority() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["kt"].as_str().unwrap(), "2");
    }

    #[test]
    fn next_threshold_default_majority() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .next_keys(vec![make_diger(), make_diger(), make_diger()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["nt"].as_str().unwrap(), "2");
    }

    #[test]
    fn witness_threshold_default_ample() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witnesses(vec![make_prefixer(), make_prefixer(), make_prefixer()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["bt"].as_str().unwrap(), "2");
    }

    #[test]
    fn empty_next_keys_zero_threshold() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["nt"].as_str().unwrap(), "0");
        let n = parsed["n"].as_array().unwrap();
        assert!(n.is_empty());
    }

    #[test]
    fn roundtrip() {
        let serialized = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .next_keys(vec![make_diger()])
            .build()
            .unwrap();

        let recovered = crate::deserialize::deserialize_inception(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.sn().value(), 0);
        assert_eq!(recovered.keys().len(), 1);
        assert_eq!(recovered.next_keys().len(), 1);
    }

    #[test]
    fn said_is_valid() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        let d = parsed["d"].as_str().unwrap();
        let i = parsed["i"].as_str().unwrap();
        assert_eq!(d, i, "d and i must be equal for inception events");
        assert!(d.starts_with('E'));
        assert_eq!(d.len(), 44);
    }

    #[test]
    fn empty_keys_rejected() {
        let result = InceptionBuilder::new().keys(vec![]).build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("keys must not be empty"));
    }

    #[test]
    fn threshold_exceeds_keys_rejected() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(Tholder::Simple(5))
            .build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("exceeds key count"));
    }

    #[test]
    fn sn_always_zero() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["s"].as_str().unwrap(), "0");
    }

    #[test]
    fn default_impl() {
        let builder = InceptionBuilder::default();
        let result = builder.keys(vec![make_verfer()]).build().unwrap();
        assert_eq!(result.ilk(), crate::keri::Ilk::Icp);
    }
}
