//! Interaction event (`ixn`) builder with compile-time required field enforcement.

#[cfg(all(feature = "alloc", test))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::Saider;
use keri_events::sequence::SequenceNumber;
use keri_events::{Identifier, InteractionEvent, Seal};

use super::{EventBuilderState, dummy_saider};
use crate::error::{BuilderError, CodecError};
use crate::serialize::SerializedEvent;
use crate::traits::Serialize;

/// Type state: prefix not yet provided.
pub struct NeedsPrefix;

impl EventBuilderState for NeedsPrefix {}

/// Type state: prior event SAID not yet provided.
pub struct NeedsPriorSaid {
    prefix: Identifier<'static>,
}

impl EventBuilderState for NeedsPriorSaid {}

/// Type state: all required fields provided, ready to build.
pub struct Ready {
    prefix: Identifier<'static>,
    prior_event_said: Saider<'static>,
    sn: u128,
    anchors: Vec<Seal<'static>>,
    said_code: DigestCode,
}

impl EventBuilderState for Ready {}

/// Builder for interaction events with compile-time required field enforcement.
///
/// Required fields: `prefix`, `prior_event_said`.
/// Optional fields: `sn` (default: 1), `anchors` (default: empty).
///
/// # Examples
///
/// ```ignore
/// let result = InteractionBuilder::new()
///     .prefix(prefixer)
///     .prior_event_said(saider)
///     .build()?;
/// ```
#[must_use]
pub struct InteractionBuilder<State = NeedsPrefix>
where
    State: EventBuilderState,
{
    state: State,
}

impl InteractionBuilder<NeedsPrefix> {
    /// Create a new interaction builder awaiting the identifier prefix.
    pub const fn new() -> Self {
        Self { state: NeedsPrefix }
    }

    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(
        self,
        prefix: impl Into<Identifier<'static>>,
    ) -> InteractionBuilder<NeedsPriorSaid> {
        InteractionBuilder {
            state: NeedsPriorSaid {
                prefix: prefix.into(),
            },
        }
    }
}

impl Default for InteractionBuilder<NeedsPrefix> {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractionBuilder<NeedsPriorSaid> {
    /// Set the prior event SAID (required).
    pub fn prior_event_said(self, said: Saider<'static>) -> InteractionBuilder<Ready> {
        let NeedsPriorSaid { prefix } = self.state;
        InteractionBuilder {
            state: Ready {
                prefix,
                prior_event_said: said,
                sn: 1,
                anchors: Vec::new(),
                said_code: DigestCode::Blake3_256,
            },
        }
    }
}

impl InteractionBuilder<Ready> {
    /// Override the sequence number (default: 1, must be >= 1).
    pub const fn sn(mut self, sn: u128) -> Self {
        self.state.sn = sn;
        self
    }

    /// Set anchored seals (default: empty).
    pub fn anchors(mut self, anchors: Vec<Seal<'static>>) -> Self {
        self.state.anchors = anchors;
        self
    }

    /// Override the SAID digest code used for `d` (default: Blake3-256),
    /// mirroring keripy's `interact(code=...)`.
    pub const fn said_code(mut self, code: DigestCode) -> Self {
        self.state.said_code = code;
        self
    }

    /// Build the interaction event, applying smart defaults and validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::SnBelowMinimum`] if `sn` is 0.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let Ready {
            prefix,
            prior_event_said,
            sn,
            anchors,
            said_code,
        } = self.state;

        if sn == 0 {
            return Err(BuilderError::SnBelowMinimum("interaction").into());
        }

        let event = InteractionEvent::new(
            prefix,
            SequenceNumber::new(sn),
            dummy_saider(said_code)?,
            prior_event_said,
            anchors,
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
    use cesr::core::primitives::{Prefixer, Saider};

    use super::*;
    use crate::traits::Deserialize;

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
    fn build_minimal_interaction() {
        let result = InteractionBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), keri_events::Ilk::Ixn);
        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "ixn");
        assert_eq!(parsed["s"].as_str().unwrap(), "1");
    }

    #[test]
    fn build_with_all_options() {
        let result = InteractionBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .sn(5)
            .anchors(vec![Seal::Digest { d: make_saider() }])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), "ixn");
        assert_eq!(parsed["s"].as_str().unwrap(), "5");
        let a = parsed["a"].as_array().unwrap();
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn roundtrip() {
        let serialized = InteractionBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .anchors(vec![Seal::Digest { d: make_saider() }])
            .build()
            .unwrap();

        let recovered = InteractionEvent::deserialize(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.sn().value(), 1);
        assert_eq!(recovered.anchors().len(), 1);
    }

    #[test]
    fn said_code_selects_digest() {
        // #148: keripy's interact() computes the SAID under any DigDex code.
        for code in [DigestCode::SHA3_256, DigestCode::Blake2b_256] {
            let result = InteractionBuilder::new()
                .prefix(make_prefixer())
                .prior_event_said(make_saider())
                .said_code(code)
                .build()
                .unwrap();
            assert_eq!(*result.said().code(), code);
            crate::said::verify_said_raw(result.as_bytes())
                .expect("SAID must verify under the selected code");
            let recovered = InteractionEvent::deserialize(result.as_bytes()).unwrap();
            assert_eq!(
                *recovered.said().code(),
                code,
                "read path must infer the selected code"
            );
        }
    }

    #[test]
    fn sn_zero_rejected() {
        let result = InteractionBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .sn(0)
            .build();
        assert!(matches!(
            result,
            Err(CodecError::Builder(BuilderError::SnBelowMinimum(
                "interaction"
            )))
        ));
    }

    #[test]
    fn build_interaction_with_self_addressing_prefix() {
        let result = InteractionBuilder::new()
            .prefix(make_saider())
            .prior_event_said(make_saider())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), keri_events::Ilk::Ixn);
        let parsed = InteractionEvent::deserialize(result.as_bytes()).unwrap();
        assert!(
            parsed.prefix().as_saider().is_some(),
            "interaction prefix must decode as self-addressing"
        );
    }

    #[test]
    fn default_impl() {
        let builder = InteractionBuilder::default();
        let result = builder
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .build()
            .unwrap();
        assert_eq!(result.ilk(), keri_events::Ilk::Ixn);
    }
}
