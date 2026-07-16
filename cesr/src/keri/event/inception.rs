use crate::core::matter::matter::Matter;
use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
use crate::keri::SigningThreshold;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};

use crate::keri::config::ConfigTrait;
use crate::keri::identifier::Identifier;
use crate::keri::seal::Seal;
use crate::keri::sequence::SequenceNumber;
use crate::keri::threshold_form::ThresholdForm;
use crate::keri::toad::Toad;

/// An inception event that creates a new KERI identifier.
pub struct InceptionEvent<'a> {
    prefix: Identifier<'a>,
    sn: SequenceNumber,
    said: Saider<'a>,
    keys: Vec<Verfer<'a>>,
    threshold: SigningThreshold,
    next_keys: Vec<Diger<'a>>,
    next_threshold: SigningThreshold,
    witnesses: Vec<Prefixer<'a>>,
    witness_threshold: Toad,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal<'a>>,
    threshold_form: ThresholdForm,
}

impl<'a> InceptionEvent<'a> {
    /// Creates a new inception event from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the full field set"
    )]
    pub const fn new(
        prefix: Identifier<'a>,
        sn: SequenceNumber,
        said: Saider<'a>,
        keys: Vec<Verfer<'a>>,
        threshold: SigningThreshold,
        next_keys: Vec<Diger<'a>>,
        next_threshold: SigningThreshold,
        witnesses: Vec<Prefixer<'a>>,
        witness_threshold: Toad,
        config: Vec<ConfigTrait>,
        anchors: Vec<Seal<'a>>,
        threshold_form: ThresholdForm,
    ) -> Self {
        Self {
            prefix,
            sn,
            said,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witnesses,
            witness_threshold,
            config,
            anchors,
            threshold_form,
        }
    }

    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'a> {
        &self.prefix
    }

    /// Sequence number (always 0 for inception).
    #[must_use]
    pub const fn sn(&self) -> SequenceNumber {
        self.sn
    }

    /// Self-addressing identifier digest.
    #[must_use]
    pub const fn said(&self) -> &Saider<'a> {
        &self.said
    }

    /// Current signing keys.
    #[must_use]
    pub fn keys(&self) -> &[Verfer<'a>] {
        &self.keys
    }

    /// Signing threshold for current keys.
    #[must_use]
    pub const fn threshold(&self) -> &SigningThreshold {
        &self.threshold
    }

    /// Digests of next rotation key set.
    #[must_use]
    pub fn next_keys(&self) -> &[Diger<'a>] {
        &self.next_keys
    }

    /// Signing threshold for next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &SigningThreshold {
        &self.next_threshold
    }

    /// Witness prefixes.
    #[must_use]
    pub fn witnesses(&self) -> &[Prefixer<'a>] {
        &self.witnesses
    }

    /// Witness agreement threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> Toad {
        self.witness_threshold
    }

    /// Configuration traits constraining identifier behavior.
    #[must_use]
    pub fn config(&self) -> &[ConfigTrait] {
        &self.config
    }

    /// Anchored seals binding external data.
    #[must_use]
    pub fn anchors(&self) -> &[Seal<'a>] {
        &self.anchors
    }

    /// Wire encoding of the numeric threshold fields (keripy `intive`).
    #[must_use]
    pub const fn threshold_form(&self) -> ThresholdForm {
        self.threshold_form
    }

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> InceptionEvent<'static> {
        InceptionEvent {
            prefix: self.prefix.into_static(),
            sn: self.sn,
            said: self.said.into_static(),
            keys: self.keys.into_iter().map(Matter::into_static).collect(),
            threshold: self.threshold,
            next_keys: self
                .next_keys
                .into_iter()
                .map(Matter::into_static)
                .collect(),
            next_threshold: self.next_threshold,
            witnesses: self
                .witnesses
                .into_iter()
                .map(Matter::into_static)
                .collect(),
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors.into_iter().map(Seal::into_static).collect(),
            threshold_form: self.threshold_form,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use alloc::borrow::Cow;

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

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

    #[test]
    fn construct_and_access_fields() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![],
            ThresholdForm::HexString,
        );

        assert_eq!(
            *event.prefix().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
        assert_eq!(event.sn().value(), 0);
        assert_eq!(*event.said().code(), DigestCode::Blake3_256);
        assert_eq!(event.keys().len(), 1);
        assert!(event.threshold().satisfied_by([0]));
        assert_eq!(event.next_keys().len(), 1);
        assert!(event.next_threshold().satisfied_by([0]));
        assert_eq!(event.witnesses().len(), 1);
        assert_eq!(event.witness_threshold().value(), 1);
        assert_eq!(event.config(), &[ConfigTrait::EstOnly]);
        assert!(event.anchors().is_empty());
        assert_eq!(event.threshold_form(), ThresholdForm::HexString);
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<InceptionEvent<'static>>();
    }

    /// Compile-time probe: the event must stay covariant in its lifetime
    /// (a `&Event<'static>` coerces to `&Event<'short>`). Vec lists keep
    /// this true; a `Cow<'a, [T<'a>]>` field would break it — see the
    /// rung-6 spec amendment.
    #[test]
    fn inception_event_is_covariant() {
        fn coerce<'short>(e: &'short InceptionEvent<'static>) -> &'short InceptionEvent<'short> {
            e
        }
        let event = InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        );
        let _ = coerce(&event);
    }
}
