//! Rotation event (`rot`) builder with compile-time required field enforcement.

#[cfg(all(feature = "alloc", test))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::{Diger, Prefixer, Saider, Verfer};
use keri_events::SigningThreshold;
use keri_events::sequence::SequenceNumber;
use keri_events::threshold_form::ThresholdForm;
use keri_events::{Identifier, RotationEvent, Seal};

use super::establishment::KeyConfiguration;
use super::witness::WitnessRotation;
use super::{EventBuilderState, dummy_saider};
use crate::error::SerderError;
use crate::serialize::SerializedEvent;
use crate::traits::KeriSerialize;

/// Type state: prefix not yet provided.
pub struct NeedsPrefix;

impl EventBuilderState for NeedsPrefix {}

/// Type state: prior event SAID not yet provided.
pub struct NeedsPriorSaid {
    prefix: Identifier<'static>,
}

impl EventBuilderState for NeedsPriorSaid {}

/// Type state: keys not yet provided.
pub struct NeedsKeys {
    prefix: Identifier<'static>,
    prior_event_said: Saider<'static>,
}

impl EventBuilderState for NeedsKeys {}

/// Type state: prior witness set not yet provided.
pub struct NeedsPriorWitnesses {
    prefix: Identifier<'static>,
    prior_event_said: Saider<'static>,
    key_configuration: KeyConfiguration,
}

impl EventBuilderState for NeedsPriorWitnesses {}

/// Type state: all required fields provided, ready to build.
pub struct Ready {
    prefix: Identifier<'static>,
    prior_event_said: Saider<'static>,
    key_configuration: KeyConfiguration,
    witness_rotation: WitnessRotation,
    sn: u128,
    anchors: Vec<Seal<'static>>,
    said_code: DigestCode,
}

impl EventBuilderState for Ready {}

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
pub struct RotationBuilder<State = NeedsPrefix>
where
    State: EventBuilderState,
{
    state: State,
}

impl RotationBuilder<NeedsPrefix> {
    /// Create a new rotation builder awaiting the identifier prefix.
    pub const fn new() -> Self {
        Self { state: NeedsPrefix }
    }

    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(self, prefix: impl Into<Identifier<'static>>) -> RotationBuilder<NeedsPriorSaid> {
        RotationBuilder {
            state: NeedsPriorSaid {
                prefix: prefix.into(),
            },
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
        let NeedsPriorSaid { prefix } = self.state;
        RotationBuilder {
            state: NeedsKeys {
                prefix,
                prior_event_said: said,
            },
        }
    }
}

impl RotationBuilder<NeedsKeys> {
    /// Set the new signing keys (required).
    pub fn keys(self, keys: Vec<Verfer<'static>>) -> RotationBuilder<NeedsPriorWitnesses> {
        let NeedsKeys {
            prefix,
            prior_event_said,
        } = self.state;
        RotationBuilder {
            state: NeedsPriorWitnesses {
                prefix,
                prior_event_said,
                key_configuration: KeyConfiguration::new(keys),
            },
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
        let NeedsPriorWitnesses {
            prefix,
            prior_event_said,
            key_configuration,
        } = self.state;
        RotationBuilder {
            state: Ready {
                prefix,
                prior_event_said,
                key_configuration,
                witness_rotation: WitnessRotation::new(prior_witnesses),
                sn: 1,
                anchors: Vec::new(),
                said_code: DigestCode::Blake3_256,
            },
        }
    }
}

impl RotationBuilder<Ready> {
    /// Override the sequence number (default: 1, must be >= 1).
    pub const fn sn(mut self, sn: u128) -> Self {
        self.state.sn = sn;
        self
    }

    /// Override the signing threshold (default: majority of keys).
    pub fn threshold(mut self, threshold: SigningThreshold) -> Self {
        self.state.key_configuration.threshold = Some(threshold);
        self
    }

    /// Set the next (pre-rotated) key digests (default: empty).
    pub fn next_keys(mut self, next_keys: Vec<Diger<'static>>) -> Self {
        self.state.key_configuration.next_keys = next_keys;
        self
    }

    /// Override the next key threshold (default: majority of next keys).
    pub fn next_threshold(mut self, next_threshold: SigningThreshold) -> Self {
        self.state.key_configuration.next_threshold = Some(next_threshold);
        self
    }

    /// Set witnesses to remove (default: empty).
    pub fn witness_removals(mut self, witness_removals: Vec<Prefixer<'static>>) -> Self {
        self.state.witness_rotation.removals = witness_removals;
        self
    }

    /// Set witnesses to add (default: empty).
    pub fn witness_additions(mut self, witness_additions: Vec<Prefixer<'static>>) -> Self {
        self.state.witness_rotation.additions = witness_additions;
        self
    }

    /// Override the witness threshold (default: `Toad::ample` of the post-rotation witness set).
    pub const fn witness_threshold(mut self, witness_threshold: u32) -> Self {
        self.state.witness_rotation.threshold = Some(witness_threshold);
        self
    }

    /// Set anchored seals (default: empty).
    pub fn anchors(mut self, anchors: Vec<Seal<'static>>) -> Self {
        self.state.anchors = anchors;
        self
    }

    /// Override the SAID digest code used for `d` (default: Blake3-256),
    /// mirroring keripy's `rotate(code=...)`.
    pub const fn said_code(mut self, code: DigestCode) -> Self {
        self.state.said_code = code;
        self
    }

    /// Render numeric `kt`/`nt`/`bt` as JSON integers (keripy `intive=True`)
    /// instead of hex strings.
    pub const fn threshold_form(mut self, form: ThresholdForm) -> Self {
        self.state.key_configuration.threshold_form = form;
        self
    }

    /// Build the rotation event, applying smart defaults and validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::EmptyKeys`] if `keys` is empty.
    ///
    /// Returns [`SerderError::SnBelowMinimum`] if `sn` is 0.
    ///
    /// Returns [`SerderError::SigningThresholdOutOfRange`] if the simple
    /// threshold exceeds the number of keys, or the next threshold exceeds
    /// the number of next keys (when non-empty).
    ///
    /// Returns [`SerderError::DuplicatePrefixes`] if `prior_witnesses`,
    /// `witness_removals`, or `witness_additions` contain duplicates.
    ///
    /// Returns [`SerderError::CutNotPriorWitness`] if a removal is not a
    /// prior witness, or [`SerderError::AddAlreadyWitness`] if an
    /// addition already is one.
    ///
    /// Returns [`SerderError::Toad`] if the witness threshold is out of
    /// bounds for the post-rotation witness set.
    pub fn build(self) -> Result<SerializedEvent, SerderError> {
        let Ready {
            prefix,
            prior_event_said,
            key_configuration,
            witness_rotation,
            sn,
            anchors,
            said_code,
        } = self.state;

        if sn == 0 {
            return Err(SerderError::SnBelowMinimum("rotation"));
        }

        let authority = key_configuration.validate()?;
        let witnesses = witness_rotation.validate()?;

        let event = RotationEvent::new(
            prefix,
            SequenceNumber::new(sn),
            dummy_saider(said_code)?,
            prior_event_said,
            authority.keys,
            authority.threshold,
            authority.next_keys,
            authority.next_threshold,
            witnesses.additions,
            witnesses.removals,
            witnesses.threshold,
            anchors,
            authority.threshold_form,
        );

        event.serialize()
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use keri_events::toad::ToadError;

    use super::*;
    use crate::traits::KeriDeserialize;

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

        assert_eq!(result.ilk(), keri_events::Ilk::Rot);
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
            crate::said::verify_said(result.as_bytes(), code)
                .expect("SAID must verify under the selected code");
            let recovered = RotationEvent::deserialize(result.as_bytes()).unwrap();
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
            .threshold(SigningThreshold::Simple(1))
            .next_keys(vec![make_diger()])
            .next_threshold(SigningThreshold::Simple(1))
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

        let recovered = RotationEvent::deserialize(serialized.as_bytes()).unwrap();
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
        assert!(matches!(
            result,
            Err(SerderError::SnBelowMinimum("rotation"))
        ));
    }

    #[test]
    fn empty_keys_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![])
            .prior_witnesses(vec![])
            .build();
        assert!(matches!(result, Err(SerderError::EmptyKeys("keys"))));
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

        assert_eq!(result.ilk(), keri_events::Ilk::Rot);
        let parsed = RotationEvent::deserialize(result.as_bytes()).unwrap();
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
        assert_eq!(result.ilk(), keri_events::Ilk::Rot);
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
        assert!(matches!(
            result,
            Err(SerderError::DuplicatePrefixes("prior witnesses"))
        ));
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
        assert!(matches!(
            result,
            Err(SerderError::DuplicatePrefixes("witness removals"))
        ));
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
        assert!(matches!(
            result,
            Err(SerderError::DuplicatePrefixes("witness additions"))
        ));
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
        assert!(matches!(result, Err(SerderError::CutNotPriorWitness)));
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
        assert!(matches!(result, Err(SerderError::AddAlreadyWitness)));
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
        assert!(matches!(result, Err(SerderError::AddAlreadyWitness)));
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

        let recovered = RotationEvent::deserialize(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.witness_removals().len(), 1);
        assert_eq!(recovered.witness_additions().len(), 1);
        assert_eq!(recovered.witness_threshold().value(), 2);
    }
}
