//! Rotation event (`rot`) builder with compile-time required field enforcement.

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, vec::Vec};
#[cfg(all(feature = "alloc", test))]
use alloc::{string::ToString, vec};
use core::marker::PhantomData;

use crate::core::matter::code::DigestCode;
use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use crate::keri::toad::Toad;
use crate::keri::{Identifier, RotationEvent, Seal};

use super::icp::{dummy_saider, majority, validate_threshold};
use super::witness::validate_rotation_witnesses;
use crate::serder::error::SerderError;
use crate::serder::serialize::SerializedEvent;

/// Type state: prefix not yet provided.
pub struct NeedsPrefix;

/// Type state: prior event SAID not yet provided.
pub struct NeedsPriorSaid;

/// Type state: keys not yet provided.
pub struct NeedsKeys;

/// Type state: prior witness set not yet provided.
pub struct NeedsPriorWitnesses;

/// Type state: all required fields provided, ready to build.
pub struct Ready;

/// Builder for rotation events with compile-time required field enforcement.
///
/// Required fields: `prefix`, `prior_event_said`, `keys`, `prior_witnesses`.
/// All other fields have smart defaults.
///
/// # Examples
///
/// ```ignore
/// let result = RotationBuilder::new()
///     .prefix(prefixer)
///     .prior_event_said(saider)
///     .keys(vec![verfer])
///     .prior_witnesses(vec![])
///     .build()?;
/// ```
#[must_use]
pub struct RotationBuilder<State = NeedsPrefix> {
    prefix: Option<Identifier<'static>>,
    prior_event_said: Option<Saider<'static>>,
    keys: Vec<Verfer<'static>>,
    sn: Option<u128>,
    threshold: Option<Tholder>,
    next_keys: Vec<Diger<'static>>,
    next_threshold: Option<Tholder>,
    witness_removals: Vec<Prefixer<'static>>,
    witness_additions: Vec<Prefixer<'static>>,
    prior_witnesses: Vec<Prefixer<'static>>,
    witness_threshold: Option<u32>,
    anchors: Vec<Seal>,
    said_code: DigestCode,
    _state: PhantomData<State>,
}

impl RotationBuilder<NeedsPrefix> {
    /// Create a new rotation builder awaiting the identifier prefix.
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
            prior_witnesses: Vec::new(),
            witness_threshold: None,
            anchors: Vec::new(),
            said_code: DigestCode::Blake3_256,
            _state: PhantomData,
        }
    }

    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(self, prefix: impl Into<Identifier<'static>>) -> RotationBuilder<NeedsPriorSaid> {
        RotationBuilder {
            prefix: Some(prefix.into()),
            prior_event_said: self.prior_event_said,
            keys: self.keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            prior_witnesses: self.prior_witnesses,
            witness_threshold: self.witness_threshold,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
        }
    }
}

impl Default for RotationBuilder<NeedsPrefix> {
    fn default() -> Self {
        Self::new()
    }
}

impl RotationBuilder<NeedsPriorSaid> {
    /// Set the prior event SAID (required).
    pub fn prior_event_said(self, said: Saider<'static>) -> RotationBuilder<NeedsKeys> {
        RotationBuilder {
            prefix: self.prefix,
            prior_event_said: Some(said),
            keys: self.keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            prior_witnesses: self.prior_witnesses,
            witness_threshold: self.witness_threshold,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
        }
    }
}

impl RotationBuilder<NeedsKeys> {
    /// Set the new signing keys (required).
    pub fn keys(self, keys: Vec<Verfer<'static>>) -> RotationBuilder<NeedsPriorWitnesses> {
        RotationBuilder {
            prefix: self.prefix,
            prior_event_said: self.prior_event_said,
            keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            prior_witnesses: self.prior_witnesses,
            witness_threshold: self.witness_threshold,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
        }
    }
}

impl RotationBuilder<NeedsPriorWitnesses> {
    /// Set the prior witness set the removals/additions rotate (required —
    /// pass an empty `Vec` for an identifier with no current witnesses).
    ///
    /// Validation-only input mirroring keripy `rotate(wits=...)`: the prior
    /// set never appears in the serialized event, but the cut/add set
    /// relations and the default witness threshold are functions of it.
    pub fn prior_witnesses(
        self,
        prior_witnesses: Vec<Prefixer<'static>>,
    ) -> RotationBuilder<Ready> {
        RotationBuilder {
            prefix: self.prefix,
            prior_event_said: self.prior_event_said,
            keys: self.keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            prior_witnesses,
            witness_threshold: self.witness_threshold,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
        }
    }
}

impl RotationBuilder<Ready> {
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

    /// Override the witness threshold (default: `Toad::ample` of the post-rotation witness set).
    pub const fn witness_threshold(mut self, witness_threshold: u32) -> Self {
        self.witness_threshold = Some(witness_threshold);
        self
    }

    /// Set anchored seals (default: empty).
    pub fn anchors(mut self, anchors: Vec<Seal>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Override the SAID digest code used for `d` (default: Blake3-256),
    /// mirroring keripy's `rotate(code=...)`.
    pub const fn said_code(mut self, code: DigestCode) -> Self {
        self.said_code = code;
        self
    }

    /// Build the rotation event, applying smart defaults and validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::Validation`] if:
    /// - `keys` is empty
    /// - `sn` is 0
    /// - Simple threshold exceeds the number of keys
    /// - Next threshold exceeds the number of next keys (when non-empty)
    /// - `prior_witnesses`, `witness_removals`, or `witness_additions` contain duplicates
    /// - A removal is not a prior witness, or an addition already is one
    ///
    /// Returns [`SerderError::Toad`] if the witness threshold is out of
    /// bounds for the post-rotation witness set.
    pub fn build(self) -> Result<SerializedEvent, SerderError> {
        if self.keys.is_empty() {
            return Err(SerderError::Validation("keys must not be empty".to_owned()));
        }

        let sn = self.sn.unwrap_or(1);
        if sn == 0 {
            return Err(SerderError::Validation(
                "rotation sn must be >= 1".to_owned(),
            ));
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

        let witness_count = validate_rotation_witnesses(
            &self.prior_witnesses,
            &self.witness_removals,
            &self.witness_additions,
        )?;
        let witness_threshold = match self.witness_threshold {
            Some(explicit) => Toad::exact(explicit, witness_count)?,
            None => Toad::ample(witness_count)?,
        };

        let prefix = self
            .prefix
            .ok_or_else(|| SerderError::Validation("prefix is required".to_owned()))?;
        let prior_event_said = self
            .prior_event_said
            .ok_or_else(|| SerderError::Validation("prior_event_said is required".to_owned()))?;

        let event = RotationEvent::new(
            prefix,
            Seqner::new(sn),
            dummy_saider(self.said_code)?,
            prior_event_said,
            self.keys,
            threshold,
            self.next_keys,
            next_threshold,
            self.witness_additions,
            self.witness_removals,
            witness_threshold,
            self.anchors,
        );

        crate::serder::serialize::rot::serialize_rotation(&event)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
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

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![4u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn build_minimal_rotation() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Rot);
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "rot");
        assert_eq!(parsed["s"].as_str().unwrap(), "1");
    }

    #[test]
    fn said_code_selects_digest() {
        // #148: keripy's rotate() computes the SAID under any DigDex code.
        for code in [DigestCode::SHA3_256, DigestCode::Blake2b_256] {
            let result = RotationBuilder::new()
                .prefix(make_prefixer())
                .prior_event_said(make_saider())
                .keys(vec![make_verfer()])
                .prior_witnesses(vec![])
                .said_code(code)
                .build()
                .unwrap();
            assert_eq!(*result.said().code(), code);
            crate::serder::said::verify_said(result.as_bytes(), code)
                .expect("SAID must verify under the selected code");
            let recovered =
                crate::serder::deserialize::deserialize_rotation(result.as_bytes()).unwrap();
            assert_eq!(
                *recovered.said().code(),
                code,
                "read path must infer the selected code"
            );
        }
    }

    #[test]
    fn build_with_all_options() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer(), make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(6)])
            .witness_removals(vec![make_prefixer_tag(5)])
            .witness_threshold(1)
            .sn(3)
            .threshold(Tholder::Simple(1))
            .next_keys(vec![make_diger()])
            .next_threshold(Tholder::Simple(1))
            .anchors(vec![])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "rot");
        assert_eq!(parsed["s"].as_str().unwrap(), "3");
        assert_eq!(parsed["kt"].as_str().unwrap(), "1");
    }

    #[test]
    fn threshold_default_majority() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .prior_witnesses(vec![])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["kt"].as_str().unwrap(), "2");
    }

    #[test]
    fn roundtrip() {
        let serialized = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .next_keys(vec![make_diger()])
            .build()
            .unwrap();

        let recovered =
            crate::serder::deserialize::deserialize_rotation(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.sn().value(), 1);
        assert_eq!(recovered.keys().len(), 1);
        assert_eq!(recovered.next_keys().len(), 1);
    }

    #[test]
    fn sn_zero_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .sn(0)
            .build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("sn must be >= 1"));
    }

    #[test]
    fn empty_keys_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![])
            .prior_witnesses(vec![])
            .build();
        let Err(err) = result else {
            panic!("expected error");
        };
        assert!(err.to_string().contains("keys must not be empty"));
    }

    #[test]
    fn build_rotation_with_self_addressing_prefix() {
        let result = RotationBuilder::new()
            .prefix(make_saider())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Rot);
        let parsed = crate::serder::deserialize::deserialize_rotation(result.as_bytes()).unwrap();
        assert!(
            parsed.prefix().as_saider().is_some(),
            "rotation prefix must decode as self-addressing"
        );
    }

    #[test]
    fn default_impl() {
        let builder = RotationBuilder::default();
        let result = builder
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .build()
            .unwrap();
        assert_eq!(result.ilk(), crate::keri::Ilk::Rot);
    }

    #[test]
    fn duplicate_prior_witnesses_rejected() {
        // keripy rotate(): "Invalid wits = ..., has duplicates" (validation.jsonl rotate/dup_wits_prior)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5), make_prefixer_tag(5)])
            .witness_threshold(2)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate prior witnesses must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn duplicate_witness_removals_rejected() {
        // keripy rotate(): "Invalid cuts = ..., has duplicates" (rotate/dup_cuts)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(5), make_prefixer_tag(5)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate removals must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn duplicate_witness_additions_rejected() {
        // keripy rotate(): "Invalid adds = ..., has duplicates" (rotate/dup_adds)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .witness_additions(vec![make_prefixer_tag(6), make_prefixer_tag(6)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate additions must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn removal_not_prior_witness_rejected() {
        // keripy rotate(): "Invalid cuts = ..., not all members in wits" (rotate/cut_not_in_wits)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(9)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("removing a non-witness must be rejected");
        };
        assert!(msg.contains("prior witnesses"), "unexpected message: {msg}");
    }

    #[test]
    fn addition_already_prior_witness_rejected() {
        // keripy rotate(): "Intersecting wits and adds" (rotate/add_already_in_wits)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(5)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("re-adding a prior witness must be rejected");
        };
        assert!(msg.contains("already"), "unexpected message: {msg}");
    }

    #[test]
    fn overlapping_removal_and_addition_rejected() {
        // keripy rotate(): "Intersecting cuts and adds" (rotate/cut_add_intersect).
        // The overlapping member must be a prior witness (else cuts ⊆ wits fires
        // first), so the adds ∩ wits check rejects it — same terminal Err as keripy.
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(5)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("cutting and adding the same witness must be rejected");
        };
        assert!(msg.contains("already"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_exceeding_new_witness_set_rejected() {
        // keripy rotate(): "Invalid toad ... for wits" against the post-rotation set (rotate/toad_gt_new_wits)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(6)])
            .witness_threshold(2)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("toad above the post-rotation witness count must be rejected");
        };
        assert_eq!((toad, witnesses), (2, 1));
    }

    #[test]
    fn toad_zero_with_witnesses_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_threshold(0)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("zero toad alongside a non-empty witness set must be rejected");
        };
        assert_eq!((toad, witnesses), (0, 1));
    }

    #[test]
    fn toad_nonzero_without_witnesses_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .witness_threshold(1)
            .build();
        let Err(SerderError::Toad(ToadError::OutOfRange { toad, witnesses })) = result else {
            panic!("nonzero toad with no witnesses must be rejected");
        };
        assert_eq!((toad, witnesses), (1, 0));
    }

    #[test]
    fn toad_defaults_to_ample_of_post_rotation_set() {
        // 4 prior − 1 cut + 2 adds = 5 witnesses → ample(5) = 4 (keripy test_ample table).
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![
                make_prefixer_tag(1),
                make_prefixer_tag(2),
                make_prefixer_tag(3),
                make_prefixer_tag(4),
            ])
            .witness_removals(vec![make_prefixer_tag(1)])
            .witness_additions(vec![make_prefixer_tag(5), make_prefixer_tag(6)])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["bt"].as_str().unwrap(), "4");
        let br = parsed["br"].as_array().unwrap();
        assert_eq!(br.len(), 1);
        let ba = parsed["ba"].as_array().unwrap();
        assert_eq!(ba.len(), 2);
    }

    #[test]
    fn witness_change_roundtrip() {
        let serialized = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(1), make_prefixer_tag(2)])
            .witness_removals(vec![make_prefixer_tag(1)])
            .witness_additions(vec![make_prefixer_tag(3)])
            .build()
            .unwrap();

        let recovered =
            crate::serder::deserialize::deserialize_rotation(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.witness_removals().len(), 1);
        assert_eq!(recovered.witness_additions().len(), 1);
        assert_eq!(recovered.witness_threshold().value(), 2);
    }
}
