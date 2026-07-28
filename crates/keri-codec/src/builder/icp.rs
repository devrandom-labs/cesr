//! Inception event (`icp`) builder with compile-time required field enforcement.

#[cfg(all(feature = "alloc", test))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::Number;
use keri_events::SigningThreshold;
use keri_events::primitive::{BasicPrefix, Digest, Said, VerifyingKey};
use keri_events::threshold_form::ThresholdForm;
use keri_events::{ConfigTrait, DelegatedInceptionEvent, Identifier, InceptionEvent, Seal};

use super::establishment::KeyConfiguration;
use super::sealed::Sealed;
use super::witness::WitnessConfiguration;
use super::{Direct, EventBuilderState, dummy_saider};
#[cfg(test)]
use crate::error::BuilderError;
use crate::error::CodecError;
use crate::serialize::SerializedEvent;
use crate::traits::Serialize;

/// Type state: keys not yet provided.
#[doc(hidden)]
pub struct NeedsKeys;

impl Sealed for NeedsKeys {}

/// Type state: all required fields provided, ready to build.
#[doc(hidden)]
pub struct Ready {
    key_configuration: KeyConfiguration,
    witness_configuration: WitnessConfiguration,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal<'static>>,
    said_code: DigestCode,
}

impl Sealed for Ready {}

/// Delegated-kind marker carrying the delegator prefix: seals the inception
/// in a [`DelegatedInceptionEvent`], emitting the `dip` tag and its `di`
/// field.
#[doc(hidden)]
pub struct Delegated {
    delegator: Identifier<'static>,
}

impl Sealed for Delegated {}

/// Which wire tag the finished inception seals under: `icp` (direct) or
/// `dip` (delegated). Sealed — the two kinds are a closed set. `pub`
/// because it bounds the public builder struct, same pattern as
/// [`EventBuilderState`].
pub trait InceptionKind: Sealed {
    /// Wrap the validated inception in its event type and serialize it.
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError>;
}

impl InceptionKind for Direct {
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError> {
        inception.serialize()
    }
}

impl InceptionKind for Delegated {
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError> {
        DelegatedInceptionEvent::new(inception, self.delegator).serialize()
    }
}

/// One type-state chain for both inception flavors, parameterized over the
/// sealed [`InceptionKind`] marker; the delegated kind carries the delegator
/// supplied at construction. Construct through the [`InceptionBuilder`]
/// (direct, `icp`) or [`DelegatedInceptionBuilder`] (delegated, `dip`)
/// aliases — an alias pins `Kind`, which lets inherent-method resolution see
/// a single `new` candidate (two inherent `new`s on one nominal are
/// ambiguous, E0034; a defaulted `Kind` on the struct is not applied in
/// expression position, E0283).
#[must_use]
pub struct InceptionChain<State = NeedsKeys, Kind = Direct>
where
    State: EventBuilderState,
    Kind: InceptionKind,
{
    state: State,
    kind: Kind,
}

/// Builder for inception events with compile-time required field enforcement.
///
/// Only `keys` is required for a direct inception; [`DelegatedInceptionBuilder`]
/// takes the delegator up front at `new`. All other fields have smart
/// defaults matching keripy's `incept()` function.
///
/// # Examples
///
/// ```ignore
/// let result = InceptionBuilder::new()
///     .keys(vec![verfer])
///     .build()?;
/// ```
pub type InceptionBuilder<State = NeedsKeys> = InceptionChain<State, Direct>;

/// Builder for delegated inception events (`dip`): the same chain, defaults,
/// and validation as [`InceptionBuilder`]; the delegator is supplied up
/// front and the final wrap adds the `di` field.
///
/// # Examples
///
/// ```ignore
/// let result = DelegatedInceptionBuilder::new(delegator)
///     .keys(vec![verfer])
///     .build()?;
/// ```
pub type DelegatedInceptionBuilder<State = NeedsKeys> = InceptionChain<State, Delegated>;

impl InceptionChain<NeedsKeys, Direct> {
    /// Create a new inception builder awaiting signing keys.
    pub const fn new() -> Self {
        Self {
            state: NeedsKeys,
            kind: Direct,
        }
    }
}

impl Default for InceptionChain<NeedsKeys, Direct> {
    fn default() -> Self {
        Self::new()
    }
}

impl InceptionChain<NeedsKeys, Delegated> {
    /// Create a new delegated inception builder; the delegator prefix is
    /// required up front. Accepts a basic (`Prefixer`) or self-addressing
    /// (`Saider`) delegator, or an `Identifier` directly.
    pub fn new(delegator: impl Into<Identifier<'static>>) -> Self {
        Self {
            state: NeedsKeys,
            kind: Delegated {
                delegator: delegator.into(),
            },
        }
    }
}

impl<K: InceptionKind> InceptionChain<NeedsKeys, K> {
    /// Set the signing keys (required).
    pub fn keys(self, keys: Vec<VerifyingKey<'static>>) -> InceptionChain<Ready, K> {
        InceptionChain {
            state: Ready {
                key_configuration: KeyConfiguration::new(keys),
                witness_configuration: WitnessConfiguration::new(),
                config: Vec::new(),
                anchors: Vec::new(),
                said_code: DigestCode::Blake3_256,
            },
            kind: self.kind,
        }
    }
}

impl<K: InceptionKind> InceptionChain<Ready, K> {
    /// Override the signing threshold (default: majority of keys).
    pub fn threshold(mut self, threshold: SigningThreshold) -> Self {
        self.state.key_configuration.threshold = Some(threshold);
        self
    }

    /// Set the next (pre-rotated) key digests (default: empty / non-transferable).
    pub fn next_keys(mut self, next_keys: Vec<Digest<'static>>) -> Self {
        self.state.key_configuration.next_keys = next_keys;
        self
    }

    /// Override the next key threshold (default: majority of next keys).
    pub fn next_threshold(mut self, next_threshold: SigningThreshold) -> Self {
        self.state.key_configuration.next_threshold = Some(next_threshold);
        self
    }

    /// Set witness prefixes (default: empty).
    pub fn witnesses(mut self, witnesses: Vec<BasicPrefix<'static>>) -> Self {
        self.state.witness_configuration.witnesses = witnesses;
        self
    }

    /// Override the witness threshold (default: `Toad::ample(witnesses.len())`).
    pub const fn witness_threshold(mut self, witness_threshold: u32) -> Self {
        self.state.witness_configuration.threshold = Some(witness_threshold);
        self
    }

    /// Set configuration traits (default: empty).
    pub fn config(mut self, config: Vec<ConfigTrait>) -> Self {
        self.state.config = config;
        self
    }

    /// Set anchored seals (default: empty).
    pub fn anchors(mut self, anchors: Vec<Seal<'static>>) -> Self {
        self.state.anchors = anchors;
        self
    }

    /// Override the SAID digest code used for `d` and the self-addressing
    /// prefix `i` (default: Blake3-256), mirroring keripy's
    /// `incept(code=...)`.
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

    /// Build the inception event, applying smart defaults and validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::EmptyKeys`] if `keys` is empty.
    ///
    /// Returns [`BuilderError::SigningThresholdOutOfRange`] if the simple
    /// threshold exceeds the number of keys, or the next threshold exceeds
    /// the number of next keys (when non-empty).
    ///
    /// Returns [`BuilderError::DuplicatePrefixes`] if `witnesses` contains
    /// duplicates.
    ///
    /// Returns [`BuilderError::Toad`] if the witness threshold is out of bounds
    /// (`1..=len(witnesses)`, or nonzero with no witnesses).
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let Ready {
            key_configuration,
            witness_configuration,
            config,
            anchors,
            said_code,
        } = self.state;

        let authority = key_configuration.validate()?;
        let (witnesses, witness_threshold) = witness_configuration.validate()?;

        let inception = InceptionEvent::new(
            Identifier::SelfAddressing(Said::from_matter(dummy_saider(said_code)?)),
            Number::new(0),
            Said::from_matter(dummy_saider(said_code)?),
            authority.keys,
            authority.threshold,
            authority.next_keys,
            authority.next_threshold,
            witnesses,
            witness_threshold,
            config,
            anchors,
            authority.threshold_form,
        );

        self.kind.seal(inception)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use keri_events::primitive::{Digest, VerifyingKey};
    use keri_events::{SigningThresholdError, WeightedThreshold};

    fn weighted(clauses: alloc::vec::Vec<alloc::vec::Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }
    use keri_events::toad::ToadError;

    use super::*;
    use crate::traits::Deserialize;

    fn make_verfer() -> VerifyingKey<'static> {
        VerifyingKey::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_diger() -> Digest<'static> {
        Digest::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_prefixer() -> BasicPrefix<'static> {
        BasicPrefix::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![3u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_prefixer_tag(tag: u8) -> BasicPrefix<'static> {
        BasicPrefix::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![tag; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_said_delegator() -> Said<'static> {
        Said::from_matter(
            cesr::core::matter::builder::MatterBuilder::new()
                .with_code(cesr::core::matter::code::DigestCode::Blake3_256)
                .with_raw(vec![6u8; 32])
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    #[test]
    fn build_minimal_inception() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        assert_eq!(result.message_type(), keri_events::MessageType::Icp);
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "icp");
        assert_eq!(parsed["s"].as_str().unwrap(), "0");
    }

    #[test]
    fn build_with_all_options() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer()])
            .threshold(SigningThreshold::Simple(1))
            .next_keys(vec![make_diger()])
            .next_threshold(SigningThreshold::Simple(1))
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

        let recovered = InceptionEvent::deserialize(serialized.as_bytes()).unwrap();
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
            crate::said::verify_said_raw(result.as_bytes())
                .expect("SAID must verify under the selected code");

            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(
                parsed["d"], parsed["i"],
                "double-SAID must hold under the selected code"
            );

            let recovered = InceptionEvent::deserialize(result.as_bytes()).unwrap();
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
        assert!(matches!(
            result,
            Err(CodecError::Builder(BuilderError::EmptyKeys("keys")))
        ));
    }

    #[test]
    fn threshold_exceeds_keys_rejected() {
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(SigningThreshold::Simple(5))
            .build();
        let Err(CodecError::Builder(BuilderError::SigningThresholdOutOfRange { field, source })) =
            result
        else {
            panic!("expected error");
        };
        assert_eq!(field, "signing");
        assert_eq!(
            source,
            SigningThresholdError::ExceedsKeyCount {
                required: 5,
                key_count: 1
            }
        );
    }

    #[test]
    fn empty_weighted_clause_list_rejected() {
        // Regression: the builder previously accepted `kt:[]` (an empty weighted
        // clause-list); it now shares SigningThreshold::check_well_formed with the fold.
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(weighted(vec![]))
            .build();
        let Err(CodecError::Builder(BuilderError::SigningThresholdOutOfRange { field, source })) =
            result
        else {
            panic!("expected error");
        };
        assert_eq!(field, "signing");
        assert_eq!(source, SigningThresholdError::EmptyClauseList);
    }

    #[test]
    fn empty_weighted_clause_rejected() {
        // Regression: the builder previously accepted a weighted threshold with an
        // empty clause (`[[]]`), which the fold rejects.
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(weighted(vec![vec![]]))
            .build();
        let Err(CodecError::Builder(BuilderError::SigningThresholdOutOfRange { field, source })) =
            result
        else {
            panic!("expected error");
        };
        assert_eq!(field, "signing");
        assert_eq!(source, SigningThresholdError::EmptyClause);
    }

    #[test]
    fn weighted_threshold_builds_end_to_end() {
        // #149 acceptance: a valid weighted threshold ("1/2, 1/2, 1/2" over
        // 3 keys) must build, serialize as the fraction list, and round-trip.
        //
        // Single-clause weighted kt serializes as a flat fraction list, not a
        // nested list-of-clauses: `ThresholdField::encode` (codec/threshold.rs)
        // flattens a lone clause and nests only for 2+ clauses, matching
        // keripy's Tholder.sith.
        let serialized = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .threshold(weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]))
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(serialized.as_bytes()).unwrap();
        assert_eq!(parsed["kt"], serde_json::json!(["1/2", "1/2", "1/2"]));

        let recovered = InceptionEvent::deserialize(serialized.as_bytes()).unwrap();
        assert_eq!(
            *recovered.threshold(),
            weighted(vec![vec![(1, 2), (1, 2), (1, 2)]])
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
        assert_eq!(result.message_type(), keri_events::MessageType::Icp);
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
            Err(CodecError::Builder(BuilderError::DuplicatePrefixes(
                "witnesses"
            )))
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
        let Err(CodecError::Builder(BuilderError::Toad(ToadError::OutOfRange { toad, witnesses }))) =
            result
        else {
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
        let Err(CodecError::Builder(BuilderError::Toad(ToadError::OutOfRange { toad, witnesses }))) =
            result
        else {
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
        let Err(CodecError::Builder(BuilderError::Toad(ToadError::OutOfRange { toad, witnesses }))) =
            result
        else {
            panic!("nonzero toad with no witnesses must be rejected");
        };
        assert_eq!((toad, witnesses), (1, 0));
    }

    /// #168: `.threshold_form(Integer)` renders `kt`/`nt`/`bt` as bare JSON
    /// integers (keripy `intive=True`). A 3-key (default signing threshold 2),
    /// 3-witness icp with `bt = 1` must emit `"kt":2` and `"bt":1` unquoted.
    #[test]
    fn builder_integer_form_emits_unquoted_numeric_thresholds() {
        let built = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .witnesses(vec![
                make_prefixer_tag(4),
                make_prefixer_tag(5),
                make_prefixer_tag(6),
            ])
            .witness_threshold(1)
            .threshold_form(ThresholdForm::Integer)
            .build()
            .expect("intive icp builds");
        let json = alloc::string::String::from_utf8_lossy(built.as_bytes());
        assert!(
            json.contains(r#""kt":2,"#),
            "kt must render as an unquoted integer: {json}"
        );
        assert!(
            json.contains(r#""bt":1,"#),
            "bt must render as an unquoted integer: {json}"
        );
        assert!(
            !json.contains(r#""kt":"2""#),
            "kt must not render as a hex string under Integer form: {json}"
        );
    }

    /// #168: keripy's `MaxIntThold = 2^32 - 1` means an integer-form signing
    /// threshold above `u32::MAX` would fall back to hex; cesr models that as
    /// an explicit build-time rejection rather than a silent form change.
    #[test]
    fn builder_integer_form_rejects_threshold_above_max_int_thold() {
        let over = u64::from(u32::MAX) + 1;
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .threshold(SigningThreshold::Simple(over))
            .threshold_form(ThresholdForm::Integer)
            .build();
        let Err(CodecError::Builder(BuilderError::IntegerFormOverflow { value })) = result else {
            panic!("integer-form threshold above MaxIntThold must be rejected");
        };
        assert_eq!(value, over);
    }

    /// Delegated (`dip`) kind: only what the Delegated seal path can observe —
    /// tag, `di` field, wrap, and the dip read path. Validation invariants
    /// are Kind-independent (one generic `build()`) and tested once above.
    mod delegated {
        use super::*;

        #[test]
        fn build_dip_with_self_addressing_delegator() {
            let result = DelegatedInceptionBuilder::new(make_said_delegator())
                .keys(vec![make_verfer()])
                .build()
                .unwrap();

            assert_eq!(result.message_type(), keri_events::MessageType::Dip);
            let parsed = DelegatedInceptionEvent::deserialize(result.as_bytes()).unwrap();
            assert!(
                parsed.delegator().as_saider().is_some(),
                "delegator must decode as self-addressing"
            );
        }

        #[test]
        fn build_minimal_delegated_inception() {
            let result = DelegatedInceptionBuilder::new(make_prefixer())
                .keys(vec![make_verfer()])
                .build()
                .unwrap();

            assert_eq!(result.message_type(), keri_events::MessageType::Dip);
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
                let result = DelegatedInceptionBuilder::new(make_prefixer())
                    .keys(vec![make_verfer()])
                    .said_code(code)
                    .build()
                    .unwrap();
                assert_eq!(*result.said().code(), code);
                crate::said::verify_said_raw(result.as_bytes())
                    .expect("SAID must verify under the selected code");

                let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
                assert_eq!(
                    parsed["d"], parsed["i"],
                    "dip keeps i == d under the selected code"
                );

                let recovered = DelegatedInceptionEvent::deserialize(result.as_bytes()).unwrap();
                assert_eq!(
                    *recovered.inception().said().code(),
                    code,
                    "read path must infer the selected code"
                );
            }
        }

        #[test]
        fn build_with_all_options() {
            let result = DelegatedInceptionBuilder::new(make_prefixer())
                .keys(vec![make_verfer(), make_verfer()])
                .threshold(SigningThreshold::Simple(1))
                .next_keys(vec![make_diger()])
                .next_threshold(SigningThreshold::Simple(1))
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
        fn roundtrip() {
            let serialized = DelegatedInceptionBuilder::new(make_prefixer())
                .keys(vec![make_verfer()])
                .next_keys(vec![make_diger()])
                .build()
                .unwrap();

            let recovered = DelegatedInceptionEvent::deserialize(serialized.as_bytes()).unwrap();
            assert_eq!(recovered.inception().sn().value(), 0);
            assert_eq!(recovered.inception().keys().len(), 1);
            assert_eq!(recovered.inception().next_keys().len(), 1);
        }

        #[test]
        fn self_addressing_prefix() {
            let result = DelegatedInceptionBuilder::new(make_prefixer())
                .keys(vec![make_verfer()])
                .build()
                .unwrap();

            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();
            assert_eq!(d, i, "d and i must be equal for delegated inception");
        }
    }
}
