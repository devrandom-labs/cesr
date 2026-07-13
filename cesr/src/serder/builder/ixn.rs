//! Interaction event (`ixn`) builder with compile-time required field enforcement.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, string::ToString, vec, vec::Vec};
use core::marker::PhantomData;

use crate::core::matter::code::DigestCode;
use crate::core::primitives::{Saider, Seqner};
use crate::keri::{Identifier, InteractionEvent, Seal};

use super::icp::dummy_saider;
use crate::serder::error::SerderError;
use crate::serder::serialize::SerializedEvent;

/// Type state: prefix not yet provided.
pub struct NeedsPrefix;

/// Type state: prior event SAID not yet provided.
pub struct NeedsPriorSaid;

/// Type state: all required fields provided, ready to build.
pub struct Ready;

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
pub struct InteractionBuilder<State = NeedsPrefix> {
    prefix: Option<Identifier<'static>>,
    prior_event_said: Option<Saider<'static>>,
    sn: Option<u128>,
    anchors: Vec<Seal>,
    said_code: DigestCode,
    _state: PhantomData<State>,
}

impl InteractionBuilder<NeedsPrefix> {
    /// Create a new interaction builder awaiting the identifier prefix.
    pub const fn new() -> Self {
        Self {
            prefix: None,
            prior_event_said: None,
            sn: None,
            anchors: Vec::new(),
            said_code: DigestCode::Blake3_256,
            _state: PhantomData,
        }
    }

    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(
        self,
        prefix: impl Into<Identifier<'static>>,
    ) -> InteractionBuilder<NeedsPriorSaid> {
        InteractionBuilder {
            prefix: Some(prefix.into()),
            prior_event_said: self.prior_event_said,
            sn: self.sn,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
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
        InteractionBuilder {
            prefix: self.prefix,
            prior_event_said: Some(said),
            sn: self.sn,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
        }
    }
}

impl InteractionBuilder<Ready> {
    /// Override the sequence number (default: 1, must be >= 1).
    pub const fn sn(mut self, sn: u128) -> Self {
        self.sn = Some(sn);
        self
    }

    /// Set anchored seals (default: empty).
    pub fn anchors(mut self, anchors: Vec<Seal>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Override the SAID digest code used for `d` (default: Blake3-256),
    /// mirroring keripy's `interact(code=...)`.
    pub const fn said_code(mut self, code: DigestCode) -> Self {
        self.said_code = code;
        self
    }

    /// Build the interaction event, applying smart defaults and validating fields.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::SnBelowMinimum`] if `sn` is 0.
    ///
    /// Returns [`SerderError::MissingBuilderField`] if `prefix` or
    /// `prior_event_said` was not set.
    pub fn build(self) -> Result<SerializedEvent, SerderError> {
        let sn = self.sn.unwrap_or(1);
        if sn == 0 {
            return Err(SerderError::SnBelowMinimum("interaction"));
        }

        let prefix = self
            .prefix
            .ok_or(SerderError::MissingBuilderField("prefix"))?;
        let prior_event_said = self
            .prior_event_said
            .ok_or(SerderError::MissingBuilderField("prior_event_said"))?;

        let event = InteractionEvent::new(
            prefix,
            Seqner::new(sn),
            dummy_saider(self.said_code)?,
            prior_event_said,
            self.anchors,
        );

        crate::serder::serialize::ixn::serialize_interaction(&event)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Prefixer, Saider};

    use super::*;

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

        assert_eq!(result.ilk(), crate::keri::Ilk::Ixn);
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

        let recovered =
            crate::serder::deserialize::deserialize_interaction(serialized.as_bytes()).unwrap();
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
            crate::serder::said::verify_said(result.as_bytes(), code)
                .expect("SAID must verify under the selected code");
            let recovered =
                crate::serder::deserialize::deserialize_interaction(result.as_bytes()).unwrap();
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
            Err(SerderError::SnBelowMinimum("interaction"))
        ));
    }

    #[test]
    fn build_interaction_with_self_addressing_prefix() {
        let result = InteractionBuilder::new()
            .prefix(make_saider())
            .prior_event_said(make_saider())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Ixn);
        let parsed =
            crate::serder::deserialize::deserialize_interaction(result.as_bytes()).unwrap();
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
        assert_eq!(result.ilk(), crate::keri::Ilk::Ixn);
    }
}
