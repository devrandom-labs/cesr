//! Inception event (`icp`) builder with compile-time required field enforcement.

#[cfg(test)]
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};
use core::marker::PhantomData;

#[cfg(test)]
use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::DigestCode;
#[cfg(test)]
use crate::core::matter::code::VerKeyCode;
use crate::core::primitives::{Diger, Prefixer, Saider, Tholder, Verfer};
use crate::keri::sequence::SequenceNumber;
use crate::keri::threshold_form::ThresholdForm;
use crate::keri::toad::Toad;
use crate::keri::{ConfigTrait, Identifier, InceptionEvent, Seal};

use super::witness::validate_distinct;
use crate::serder::error::SerderError;
use crate::serder::said::compute_digest;
use crate::serder::serialize::SerializedEvent;

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
    said_code: DigestCode,
    _state: PhantomData<State>,
}

/// A placeholder [`Saider`] under `code`, sized correctly for any digest
/// code. Its value is never emitted — the writer dummies the SAID slot and
/// backpatches the computed digest — only its code steers the computation.
pub(crate) fn dummy_saider(code: DigestCode) -> Result<Saider<'static>, SerderError> {
    compute_digest(&[], code)
}

#[cfg(test)]
pub(crate) fn dummy_prefixer() -> Result<Prefixer<'static>, SerderError> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
        .map_err(|e| SerderError::PlaceholderPrimitive { source: e.into() })?
        .build()
        .map_err(|e| SerderError::PlaceholderPrimitive { source: e })
}

/// Default signing threshold: simple majority of `n` keys, `max(1, ceil(n / 2))`.
///
/// Port of keripy's default `sith`/`nsith` (`eventing.py:459` / `:471`,
/// keripy `de59bc7d`).
///
/// # Errors
///
/// Returns [`SerderError::MajorityOverflow`] when the majority does not fit
/// `u64` (unreachable on targets where `usize` is 64 bits or narrower).
pub(crate) fn majority(n: usize) -> Result<u64, SerderError> {
    let m = 1.max(n.div_ceil(2));
    u64::try_from(m).map_err(|_| SerderError::MajorityOverflow { keys: n })
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
            said_code: DigestCode::Blake3_256,
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
            said_code: self.said_code,
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
    /// `incept(code=...)`.
    pub const fn said_code(mut self, code: DigestCode) -> Self {
        self.said_code = code;
        self
    }

    /// Build the inception event, applying smart defaults and validating fields.
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

        let event = InceptionEvent::new(
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

        crate::serder::serialize::icp::serialize_inception(&event)
    }
}

pub(crate) fn validate_threshold(
    threshold: &Tholder,
    key_count: usize,
    field: &'static str,
) -> Result<(), SerderError> {
    threshold
        .check_well_formed(key_count)
        .map_err(|source| SerderError::SigningThresholdOutOfRange { field, source })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, ThresholdError, Verfer};
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

    fn make_prefixer_tag(tag: u8) -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![tag; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    /// Expectations match keripy's default signing threshold
    /// `max(1, ceil(len(keys) / 2))` (`eventing.py:459`, keripy `de59bc7d`;
    /// same shape at `:471` for `nsith`).
    #[test]
    fn majority_matches_keripy_default_threshold_table() {
        let expected: [(usize, u64); 14] = [
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (6, 3),
            (7, 4),
            (8, 4),
            (9, 5),
            (10, 5),
            (11, 6),
            (12, 6),
            (13, 7),
        ];
        for (n, want) in expected {
            assert_eq!(majority(n).unwrap(), want, "majority({n})");
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn majority_succeeds_at_usize_boundary() {
        assert_eq!(majority(usize::MAX).unwrap(), u64::MAX / 2 + 1);
        assert_eq!(majority(usize::MAX - 1).unwrap(), u64::MAX / 2);
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
            .witnesses(vec![
                make_prefixer_tag(3),
                make_prefixer_tag(4),
                make_prefixer_tag(5),
            ])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["bt"].as_str().unwrap(), "3");
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

        let recovered =
            crate::serder::deserialize::deserialize_inception(serialized.as_bytes()).unwrap();
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
    fn said_code_selects_digest_for_said_and_prefix() {
        // #148: keripy's incept(code=...) accepts any DigDex code for the
        // SAID/prefix; the builder must round-trip non-default codes with
        // the double-SAID property intact under the chosen code.
        for code in [DigestCode::SHA3_256, DigestCode::Blake2b_256] {
            let result = InceptionBuilder::new()
                .keys(vec![make_verfer()])
                .said_code(code)
                .build()
                .unwrap();
            assert_eq!(*result.said().code(), code);
            crate::serder::said::verify_said(result.as_bytes(), code)
                .expect("SAID must verify under the selected code");

            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(
                parsed["d"], parsed["i"],
                "double-SAID must hold under the selected code"
            );

            let recovered =
                crate::serder::deserialize::deserialize_inception(result.as_bytes()).unwrap();
            assert_eq!(
                *recovered.said().code(),
                code,
                "read path must infer the selected code"
            );
        }
    }

    #[test]
    fn empty_keys_rejected() {
        let result = InceptionBuilder::new().keys(vec![]).build();
        assert!(matches!(result, Err(SerderError::EmptyKeys("keys"))));
    }

    #[test]
    fn threshold_exceeds_keys_rejected() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(Tholder::Simple(5))
            .build();
        let Err(SerderError::SigningThresholdOutOfRange { field, source }) = result else {
            panic!("expected error");
        };
        assert_eq!(field, "signing");
        assert_eq!(
            source,
            ThresholdError::ExceedsKeyCount {
                required: 5,
                key_count: 1
            }
        );
    }

    #[test]
    fn empty_weighted_clause_list_rejected() {
        // Regression: the builder previously accepted `kt:[]` (an empty weighted
        // clause-list); it now shares Tholder::check_well_formed with the fold.
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(Tholder::Weighted(vec![]))
            .build();
        let Err(SerderError::SigningThresholdOutOfRange { field, source }) = result else {
            panic!("expected error");
        };
        assert_eq!(field, "signing");
        assert_eq!(source, ThresholdError::EmptyClauseList);
    }

    #[test]
    fn empty_weighted_clause_rejected() {
        // Regression: the builder previously accepted a weighted threshold with an
        // empty clause (`[[]]`), which the fold rejects.
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(Tholder::Weighted(vec![vec![]]))
            .build();
        let Err(SerderError::SigningThresholdOutOfRange { field, source }) = result else {
            panic!("expected error");
        };
        assert_eq!(field, "signing");
        assert_eq!(source, ThresholdError::EmptyClause);
    }

    #[test]
    fn weighted_threshold_builds_end_to_end() {
        // #149 acceptance: a valid weighted threshold ("1/2, 1/2, 1/2" over
        // 3 keys) must build, serialize as the fraction list, and round-trip.
        //
        // Single-clause weighted kt serializes as a flat fraction list, not a
        // nested list-of-clauses: `tholder_to_json` (serder/serialize.rs)
        // unwraps a lone clause and nests only for 2+ clauses, matching
        // keripy's Tholder.sith.
        let serialized = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .threshold(Tholder::Weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]))
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(serialized.as_bytes()).unwrap();
        assert_eq!(parsed["kt"], serde_json::json!(["1/2", "1/2", "1/2"]));

        let recovered =
            crate::serder::deserialize::deserialize_inception(serialized.as_bytes()).unwrap();
        assert_eq!(
            *recovered.threshold(),
            Tholder::Weighted(vec![vec![(1, 2), (1, 2), (1, 2)]])
        );
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

    #[test]
    fn duplicate_witnesses_rejected() {
        // keripy incept(): "Invalid wits = ..., has duplicates" (validation.jsonl incept/dup_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witnesses(vec![make_prefixer(), make_prefixer()])
            .build();
        assert!(matches!(
            result,
            Err(SerderError::DuplicatePrefixes("witnesses"))
        ));
    }

    #[test]
    fn toad_exceeding_witness_count_rejected() {
        // keripy incept(): "Invalid toad ... for wits" (incept/toad_gt_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
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
        // keripy incept(): toad < 1 with wits (incept/toad_zero_with_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
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
        // keripy incept(): toad != 0 with no wits (incept/toad_nonzero_no_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witness_threshold(1)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("nonzero toad with no witnesses must be rejected");
        };
        assert_eq!((toad, witnesses), (1, 0));
    }
}
