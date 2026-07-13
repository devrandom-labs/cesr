//! Delegated inception event (`dip`) builder with compile-time required field
//! enforcement.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::ToString, vec, vec::Vec};
use core::marker::PhantomData;

use crate::core::matter::code::DigestCode;
use crate::core::primitives::{Diger, Prefixer, Tholder, Verfer};
use crate::keri::sequence::SequenceNumber;
use crate::keri::threshold_form::ThresholdForm;
use crate::keri::toad::Toad;
use crate::keri::{ConfigTrait, DelegatedInceptionEvent, Identifier, InceptionEvent, Seal};

use super::icp::{dummy_saider, majority, validate_threshold};
use super::witness::validate_distinct;
use crate::serder::error::SerderError;
use crate::serder::serialize::SerializedEvent;

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
    delegator: Option<Identifier<'static>>,
    threshold: Option<Tholder>,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Option<Tholder>,
    witnesses: Vec<Prefixer<'static>>,
    witness_threshold: Option<u32>,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal>,
    said_code: DigestCode,
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
            said_code: DigestCode::Blake3_256,
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
            said_code: self.said_code,
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
    /// Set the delegator prefix (required). Accepts a basic (`Prefixer`) or self-addressing (`Saider`) delegator, or an `Identifier` directly.
    pub fn delegator(
        self,
        delegator: impl Into<Identifier<'static>>,
    ) -> DelegatedInceptionBuilder<Ready> {
        DelegatedInceptionBuilder {
            keys: self.keys,
            delegator: Some(delegator.into()),
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witnesses: self.witnesses,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            said_code: self.said_code,
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

    /// Override the witness threshold (default: `Toad::ample(witnesses.len())`).
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

    /// Override the SAID digest code used for `d` and the self-addressing
    /// prefix `i` (default: Blake3-256), mirroring keripy's
    /// `delcept(code=...)`.
    pub const fn said_code(mut self, code: DigestCode) -> Self {
        self.said_code = code;
        self
    }

    /// Build the delegated inception event, applying smart defaults and
    /// validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::EmptyKeys`] if `keys` is empty.
    ///
    /// Returns [`SerderError::SigningThresholdOutOfRange`] if the simple
    /// threshold exceeds the number of keys, or the next threshold exceeds
    /// the number of next keys (when non-empty).
    ///
    /// Returns [`SerderError::DuplicatePrefixes`] if `witnesses` contains
    /// duplicates.
    ///
    /// Returns [`SerderError::MissingBuilderField`] if `delegator` was not set.
    ///
    /// Returns [`SerderError::Toad`] if the witness threshold is out of bounds
    /// (`1..=len(witnesses)`, or nonzero with no witnesses).
    pub fn build(self) -> Result<SerializedEvent, SerderError> {
        if self.keys.is_empty() {
            return Err(SerderError::EmptyKeys("keys"));
        }

        let threshold = match self.threshold {
            Some(explicit) => explicit,
            None => Tholder::Simple(majority(self.keys.len())?),
        };

        validate_threshold(&threshold, self.keys.len(), "signing")?;

        let next_threshold = match self.next_threshold {
            Some(explicit) => explicit,
            None if self.next_keys.is_empty() => Tholder::Simple(0),
            None => Tholder::Simple(majority(self.next_keys.len())?),
        };

        if !self.next_keys.is_empty() {
            validate_threshold(&next_threshold, self.next_keys.len(), "next signing")?;
        }

        validate_distinct(&self.witnesses, "witnesses")?;

        let witness_threshold = match self.witness_threshold {
            Some(explicit) => Toad::exact(explicit, self.witnesses.len())?,
            None => Toad::ample(self.witnesses.len())?,
        };

        let delegator = self
            .delegator
            .ok_or(SerderError::MissingBuilderField("delegator"))?;

        let inception = InceptionEvent::new(
            Identifier::SelfAddressing(dummy_saider(self.said_code)?),
            SequenceNumber::new(0),
            dummy_saider(self.said_code)?,
            self.keys,
            threshold,
            self.next_keys,
            next_threshold,
            self.witnesses,
            witness_threshold,
            self.config,
            self.anchors,
            ThresholdForm::HexString,
        );

        let event = DelegatedInceptionEvent::new(inception, delegator);

        crate::serder::serialize::dip::serialize_delegated_inception(&event)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Verfer};
    use crate::keri::toad::ToadError;

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

    fn make_said_delegator() -> crate::core::primitives::Saider<'static> {
        crate::core::matter::builder::MatterBuilder::new()
            .with_code(crate::core::matter::code::DigestCode::Blake3_256)
            .with_raw(vec![6u8; 32])
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn build_dip_with_self_addressing_delegator() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_said_delegator())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Dip);
        let parsed =
            crate::serder::deserialize::deserialize_delegated_inception(result.as_bytes()).unwrap();
        assert!(
            parsed.delegator().as_saider().is_some(),
            "delegator must decode as self-addressing"
        );
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
    fn said_code_selects_digest_for_said_and_prefix() {
        // #148: keripy's delcept(code=...) accepts any DigDex code; dip is
        // self-addressing-only, so i == d must hold under the chosen code.
        for code in [DigestCode::SHA3_256, DigestCode::Blake2b_256] {
            let result = DelegatedInceptionBuilder::new()
                .keys(vec![make_verfer()])
                .delegator(make_prefixer())
                .said_code(code)
                .build()
                .unwrap();
            assert_eq!(*result.said().code(), code);
            crate::serder::said::verify_said(result.as_bytes(), code)
                .expect("SAID must verify under the selected code");

            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(
                parsed["d"], parsed["i"],
                "dip keeps i == d under the selected code"
            );

            let recovered =
                crate::serder::deserialize::deserialize_delegated_inception(result.as_bytes())
                    .unwrap();
            assert_eq!(
                *recovered.inception().said().code(),
                code,
                "read path must infer the selected code"
            );
        }
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
            crate::serder::deserialize::deserialize_delegated_inception(serialized.as_bytes())
                .unwrap();
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
        assert!(matches!(result, Err(SerderError::EmptyKeys("keys"))));
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

    #[test]
    fn duplicate_witnesses_rejected() {
        // keripy delcept() shares incept()'s duplicate-witness check
        // (validation.jsonl incept/dup_wits)
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_said_delegator())
            .witnesses(vec![make_prefixer(), make_prefixer()])
            .build();
        assert!(matches!(
            result,
            Err(SerderError::DuplicatePrefixes("witnesses"))
        ));
    }

    #[test]
    fn toad_exceeding_witness_count_rejected() {
        // keripy delcept(): "Invalid toad ... for wits" (incept/toad_gt_wits)
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_said_delegator())
            .witnesses(vec![make_prefixer()])
            .witness_threshold(2)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("toad above the witness count must be rejected");
        };
        assert_eq!((toad, witnesses), (2, 1));
    }

    #[test]
    fn toad_zero_with_witnesses_rejected() {
        // keripy delcept(): toad < 1 with wits (incept/toad_zero_with_wits)
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_said_delegator())
            .witnesses(vec![make_prefixer()])
            .witness_threshold(0)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("zero toad alongside witnesses must be rejected");
        };
        assert_eq!((toad, witnesses), (0, 1));
    }

    #[test]
    fn toad_nonzero_without_witnesses_rejected() {
        // keripy delcept(): toad != 0 with no wits (incept/toad_nonzero_no_wits)
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_said_delegator())
            .witness_threshold(1)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("nonzero toad with no witnesses must be rejected");
        };
        assert_eq!((toad, witnesses), (1, 0));
    }
}
