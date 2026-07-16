use crate::core::matter::matter::Matter;
use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
use crate::keri::SigningThreshold;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};

use crate::keri::identifier::Identifier;
use crate::keri::seal::Seal;
use crate::keri::sequence::SequenceNumber;
use crate::keri::threshold_form::ThresholdForm;
use crate::keri::toad::Toad;

/// A rotation event that changes keys for an existing KERI identifier.
pub struct RotationEvent<'a> {
    prefix: Identifier<'a>,
    sn: SequenceNumber,
    said: Saider<'a>,
    prior_event_said: Saider<'a>,
    keys: Vec<Verfer<'a>>,
    threshold: SigningThreshold,
    next_keys: Vec<Diger<'a>>,
    next_threshold: SigningThreshold,
    witness_additions: Vec<Prefixer<'a>>,
    witness_removals: Vec<Prefixer<'a>>,
    witness_threshold: Toad,
    anchors: Vec<Seal<'a>>,
    threshold_form: ThresholdForm,
}

impl<'a> RotationEvent<'a> {
    /// Creates a new rotation event from all constituent fields.
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
        prior_event_said: Saider<'a>,
        keys: Vec<Verfer<'a>>,
        threshold: SigningThreshold,
        next_keys: Vec<Diger<'a>>,
        next_threshold: SigningThreshold,
        witness_additions: Vec<Prefixer<'a>>,
        witness_removals: Vec<Prefixer<'a>>,
        witness_threshold: Toad,
        anchors: Vec<Seal<'a>>,
        threshold_form: ThresholdForm,
    ) -> Self {
        Self {
            prefix,
            sn,
            said,
            prior_event_said,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witness_additions,
            witness_removals,
            witness_threshold,
            anchors,
            threshold_form,
        }
    }

    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'a> {
        &self.prefix
    }

    /// Sequence number (must be > 0).
    #[must_use]
    pub const fn sn(&self) -> SequenceNumber {
        self.sn
    }

    /// Self-addressing identifier digest.
    #[must_use]
    pub const fn said(&self) -> &Saider<'a> {
        &self.said
    }

    /// Digest of the prior event.
    #[must_use]
    pub const fn prior_event_said(&self) -> &Saider<'a> {
        &self.prior_event_said
    }

    /// New signing keys.
    #[must_use]
    pub fn keys(&self) -> &[Verfer<'a>] {
        &self.keys
    }

    /// Signing threshold for new keys.
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

    /// Witnesses added in this rotation.
    #[must_use]
    pub fn witness_additions(&self) -> &[Prefixer<'a>] {
        &self.witness_additions
    }

    /// Witnesses removed in this rotation.
    #[must_use]
    pub fn witness_removals(&self) -> &[Prefixer<'a>] {
        &self.witness_removals
    }

    /// Witness agreement threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> Toad {
        self.witness_threshold
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
    pub fn into_static(self) -> RotationEvent<'static> {
        RotationEvent {
            prefix: self.prefix.into_static(),
            sn: self.sn,
            said: self.said.into_static(),
            prior_event_said: self.prior_event_said.into_static(),
            keys: self.keys.into_iter().map(Matter::into_static).collect(),
            threshold: self.threshold,
            next_keys: self
                .next_keys
                .into_iter()
                .map(Matter::into_static)
                .collect(),
            next_threshold: self.next_threshold,
            witness_additions: self
                .witness_additions
                .into_iter()
                .map(Matter::into_static)
                .collect(),
            witness_removals: self
                .witness_removals
                .into_iter()
                .map(Matter::into_static)
                .collect(),
            witness_threshold: self.witness_threshold,
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
        let event = RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            vec![],
            Toad::exact(1, 1).unwrap(),
            vec![],
            ThresholdForm::HexString,
        );

        assert_eq!(
            *event.prefix().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
        assert_eq!(event.sn().value(), 1);
        assert_eq!(*event.said().code(), DigestCode::Blake3_256);
        assert_eq!(*event.prior_event_said().code(), DigestCode::Blake3_256);
        assert_eq!(event.keys().len(), 1);
        assert!(event.threshold().satisfied_by([0]));
        assert_eq!(event.next_keys().len(), 1);
        assert!(event.next_threshold().satisfied_by([0]));
        assert_eq!(event.witness_additions().len(), 1);
        assert!(event.witness_removals().is_empty());
        assert_eq!(event.witness_threshold().value(), 1);
        assert!(event.anchors().is_empty());
        assert_eq!(event.threshold_form(), ThresholdForm::HexString);
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<RotationEvent<'static>>();
    }

    /// Compile-time probe: covariance (see the rung-6 spec amendment).
    #[test]
    fn rotation_event_is_covariant() {
        fn coerce<'short>(e: &'short RotationEvent<'static>) -> &'short RotationEvent<'short> {
            e
        }
        let event = RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            ThresholdForm::HexString,
        );
        let _ = coerce(&event);
    }
}
