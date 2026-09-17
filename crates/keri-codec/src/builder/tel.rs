//! TEL (registry event log) builders mirroring keripy's registry-event
//! factories (`src/keri/vdr/eventing.py`, keripy `de59bc7d`): `incept`,
//! `rotate`, `issue`, `revoke`, `backerIssue`, and `backerRevoke`.
//!
//! Unlike the KEL establishment builders' type-state chains, the TEL
//! factories' required fields are few and per-ilk, so each builder takes
//! them in `new` (mirroring the factory's positional parameters) and the
//! remaining fields are setters with keripy's defaults. Two determinism
//! departures from keripy's kwargs, both mandated: the registry `nonce`
//! and the `dt` timestamps are REQUIRED — keripy defaults them to
//! wall-clock values (`Salter().qb64`, `nowIso8601()`), which would break
//! byte-identical corpus replay.
//!
//! Every builder validates the factory's laws (sequence domains, backer
//! set relations, toad bounds, the NB configuration rule) and returns the
//! [`SerializedEvent`] — the SAID is computed by the shared generic SAD
//! writer, not here. All SAIDs derive under keripy's default
//! [`DigestCode::Blake3_256`]; parsed events re-serialize under their own
//! wire code.

#[cfg(feature = "alloc")]
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::{Noncer, Number};
use keri_events::Identifier;
use keri_events::TelEvent;
use keri_events::primitive::{BasicPrefix, Said};
use keri_events::tel::{
    BackedIssue, BackedRevoke, Issue, RegistryInception, RegistryRotation, Revoke,
};
use keri_events::toad::Toad;
use keri_events::{ConfigTrait, Seal};

use super::dummy_saider;
use crate::error::{BuilderError, CodecError, SaidError};
use crate::serialize::SerializedEvent;
use crate::traits::Serialize;

/// The digest code every TEL builder derives under: keripy's registry
/// factories use the `Saider.saidify` default (`MtrDex.Blake3_256`) —
/// the factories expose no code parameter.
const TEL_SAID_CODE: DigestCode = DigestCode::Blake3_256;

/// A fresh placeholder SAID under the TEL factory code — its value is
/// never emitted; the generic writer dummies the slot and splices the
/// computed digest.
fn placeholder_said() -> Result<Said<'static>, SaidError> {
    Ok(Said::from_matter(dummy_saider(TEL_SAID_CODE)?))
}

/// Backer-set laws shared by the `vcp`/`vrt` builders (keripy `incept`
/// prologue and `rotate` set relations): duplicate-free inputs, cuts drawn
/// from the prior set, additions disjoint from it, cuts/adds disjoint from
/// each other.
fn validate_backer_relations(
    cuts: &[BasicPrefix<'_>],
    additions: &[BasicPrefix<'_>],
    prior: &[BasicPrefix<'_>],
) -> Result<(), BuilderError> {
    for (list, label) in [(cuts, "cuts"), (additions, "additions")] {
        if list.is_empty() {
            continue;
        }
        let mut seen = Vec::new();
        for prefix in list {
            if seen.contains(prefix) {
                return Err(BuilderError::DuplicatePrefixes(label));
            }
            seen.push(prefix.clone());
        }
    }
    for cut in cuts {
        if !prior.contains(cut) {
            return Err(BuilderError::CutNotPriorWitness);
        }
    }
    for addition in additions {
        if prior.contains(addition) {
            return Err(BuilderError::AddAlreadyWitness);
        }
    }
    for cut in cuts {
        if additions.contains(cut) {
            return Err(BuilderError::DuplicatePrefixes("cuts and additions"));
        }
    }
    Ok(())
}

/// Registry inception (`vcp`) builder — keripy `incept`
/// (`vdr/eventing.py:51-126`).
///
/// Required: the issuing identifier (`ii`) and the registry `nonce`
/// (determinism mandate — keripy defaults it to random). Optional:
/// configuration traits (default empty) and the backer set with its
/// threshold (default none; the threshold must be 0 exactly when the
/// backer set is empty, per [`Toad`]'s law).
///
/// # Examples
///
/// ```
/// use cesr::core::matter::builder::MatterBuilder;
/// use cesr::core::matter::code::NoncerCode;
/// use keri_codec::RegistryInceptionBuilder;
/// use keri_events::Identifier;
/// use keri_events::primitive::BasicPrefix;
/// use std::borrow::Cow;
///
/// let issuer = Identifier::Basic(BasicPrefix::from_matter(
///     MatterBuilder::new()
///         .with_code(cesr::core::matter::code::VerKeyCode::Ed25519N)
///         .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
///         .unwrap()
///         .build()
///         .unwrap(),
/// ));
/// let nonce = MatterBuilder::new()
///     .with_code(NoncerCode::Salt128)
///     .with_raw(Cow::<[u8]>::Owned(vec![0u8; 16]))
///     .unwrap()
///     .build()
///     .unwrap();
/// let event = RegistryInceptionBuilder::new(issuer, nonce)
///     .build()
///     .unwrap();
/// assert_eq!(event.message_type(), keri_events::MessageType::Vcp);
/// ```
#[must_use]
pub struct RegistryInceptionBuilder {
    issuer: Identifier<'static>,
    nonce: Noncer<'static>,
    config: Vec<ConfigTrait>,
    backers: Vec<BasicPrefix<'static>>,
    backer_threshold: u32,
}

impl RegistryInceptionBuilder {
    /// Starts a registry inception for `issuer` with the registry `nonce`.
    pub const fn new(issuer: Identifier<'static>, nonce: Noncer<'static>) -> Self {
        Self {
            issuer,
            nonce,
            config: Vec::new(),
            backers: Vec::new(),
            backer_threshold: 0,
        }
    }

    /// Sets the configuration traits (keripy `cnfg`).
    pub fn config(mut self, config: Vec<ConfigTrait>) -> Self {
        self.config = config;
        self
    }

    /// Sets the backer set (`b`) and its threshold (`bt`).
    pub fn backers(mut self, backers: Vec<BasicPrefix<'static>>, backer_threshold: u32) -> Self {
        self.backers = backers;
        self.backer_threshold = backer_threshold;
        self
    }

    /// Validates the factory laws and serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::DuplicatePrefixes`] on duplicate backers,
    /// [`BuilderError::NoBackersWithBackers`] when the NB configuration
    /// trait meets a non-empty backer set, or [`BuilderError::Toad`] when
    /// the threshold is out of bounds for the backer set.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        if self.config.contains(&ConfigTrait::NoBackers) && !self.backers.is_empty() {
            return Err(BuilderError::NoBackersWithBackers.into());
        }
        validate_backer_relations(&[], &[], &self.backers)?;
        let backer_threshold =
            Toad::exact(self.backer_threshold, self.backers.len()).map_err(BuilderError::from)?;
        // keripy `incept`: the registry identity IS the vcp SAID (i == d at
        // the default code), so the domain event stores no separate `i`.
        let event = TelEvent::RegistryInception(RegistryInception::new(
            placeholder_said()?,
            self.issuer,
            self.config,
            backer_threshold,
            self.backers,
            self.nonce,
        ));
        event.serialize()
    }
}

/// Registry rotation (`vrt`) builder — keripy `rotate`
/// (`vdr/eventing.py:128-260`).
///
/// Required: the registry identifier (`i`), the prior TEL event's SAID
/// (`p`), the prior backer set the cuts/additions rotate (the factory's
/// `baks` parameter — the membership laws are checked against it), and
/// the sequence number (`s`, must be ≥ 1 — the factory raises below it).
/// Optional: backer cuts/additions and the post-rotation threshold
/// (from-wire form; the fold validates it against the computed set).
#[must_use]
pub struct RegistryRotationBuilder {
    registry: Said<'static>,
    prior: Said<'static>,
    prior_backers: Vec<BasicPrefix<'static>>,
    sn: u128,
    backer_threshold: u32,
    backer_cuts: Vec<BasicPrefix<'static>>,
    backer_additions: Vec<BasicPrefix<'static>>,
}

impl RegistryRotationBuilder {
    /// Starts a registry rotation of `registry` from the event `prior`,
    /// with `prior_backers` as the backer set before the rotation.
    pub const fn new(
        registry: Said<'static>,
        prior: Said<'static>,
        prior_backers: Vec<BasicPrefix<'static>>,
        sn: u128,
    ) -> Self {
        Self {
            registry,
            prior,
            prior_backers,
            sn,
            backer_threshold: 0,
            backer_cuts: Vec::new(),
            backer_additions: Vec::new(),
        }
    }

    /// Sets the backer threshold (`bt`, from-wire form).
    pub const fn backer_threshold(mut self, backer_threshold: u32) -> Self {
        self.backer_threshold = backer_threshold;
        self
    }

    /// Sets the backer cuts (`br`) and additions (`ba`).
    pub fn backer_rotation(
        mut self,
        cuts: Vec<BasicPrefix<'static>>,
        additions: Vec<BasicPrefix<'static>>,
    ) -> Self {
        self.backer_cuts = cuts;
        self.backer_additions = additions;
        self
    }

    /// Validates the factory laws and serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::SnBelowMinimum`] when `sn` is 0,
    /// [`BuilderError::DuplicatePrefixes`] on duplicate or overlapping
    /// cuts/additions, [`BuilderError::CutNotPriorWitness`] when a cut is
    /// not a prior backer, or [`BuilderError::AddAlreadyWitness`] when an
    /// addition already is one.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        if self.sn < 1 {
            return Err(BuilderError::SnBelowMinimum("vrt").into());
        }
        validate_backer_relations(
            &self.backer_cuts,
            &self.backer_additions,
            &self.prior_backers,
        )?;
        let event = TelEvent::RegistryRotation(RegistryRotation::new(
            placeholder_said()?,
            self.registry,
            self.prior,
            Number::new(self.sn),
            Toad::from_wire(self.backer_threshold),
            self.backer_cuts,
            self.backer_additions,
        ));
        event.serialize()
    }
}

/// Credential issue (`iss`) builder — keripy `issue`
/// (`vdr/eventing.py:262-300`).
///
/// Required: the credential's SAID (`i`, keripy `vcdig`), the governing
/// registry (`ri`), and the issuance timestamp `dt` (determinism mandate
/// — keripy defaults to `nowIso8601()`).
#[must_use]
pub struct IssueBuilder {
    credential_said: Said<'static>,
    registry_said: Said<'static>,
    datetime: Cow<'static, str>,
}

impl IssueBuilder {
    /// Starts a credential issue into `registry_said` at `datetime`.
    pub fn new(
        credential_said: Said<'static>,
        registry_said: Said<'static>,
        datetime: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            credential_said,
            registry_said,
            datetime: datetime.into(),
        }
    }

    /// Serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] on digest or version-string failure.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let event = TelEvent::Issue(Issue::new(
            placeholder_said()?,
            self.credential_said,
            self.registry_said,
            self.datetime,
        ));
        event.serialize()
    }
}

/// Credential revoke (`rev`) builder — keripy `revoke`
/// (`vdr/eventing.py:302-345`).
///
/// Required: the credential's SAID (`i`), the governing registry (`ri`),
/// the prior TEL event's SAID (`p` — the previous `iss`/`rev`), and the
/// revocation timestamp `dt`. The sequence number is the factory's
/// pinned 1.
#[must_use]
pub struct RevokeBuilder {
    credential_said: Said<'static>,
    registry_said: Said<'static>,
    prior: Said<'static>,
    datetime: Cow<'static, str>,
}

impl RevokeBuilder {
    /// Starts a credential revocation chaining to `prior`.
    pub fn new(
        credential_said: Said<'static>,
        registry_said: Said<'static>,
        prior: Said<'static>,
        datetime: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            credential_said,
            registry_said,
            prior,
            datetime: datetime.into(),
        }
    }

    /// Serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] on digest or version-string failure.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let event = TelEvent::Revoke(Revoke::new(
            placeholder_said()?,
            self.credential_said,
            self.registry_said,
            self.prior,
            self.datetime,
        ));
        event.serialize()
    }
}

/// Backed credential issue (`bis`) builder — keripy `backerIssue`
/// (`vdr/eventing.py:347-400`).
///
/// Required: the credential's SAID (`i`), the registry identifier (`ii`),
/// the `ra` anchor — the backed TEL event's coordinate as a
/// [`Seal::Event`] — and the backing timestamp `dt`.
#[must_use]
pub struct BackedIssueBuilder {
    credential_said: Said<'static>,
    registry_said: Said<'static>,
    anchor: Seal<'static>,
    datetime: Cow<'static, str>,
}

impl BackedIssueBuilder {
    /// Starts a backed issue anchored at `anchor`.
    pub fn new(
        credential_said: Said<'static>,
        registry_said: Said<'static>,
        anchor: Seal<'static>,
        datetime: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            credential_said,
            registry_said,
            anchor,
            datetime: datetime.into(),
        }
    }

    /// Serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::NonEventBackerAnchor`] when the anchor is
    /// not the event-seal shape, or [`CodecError`] on digest failure.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let event = TelEvent::BackedIssue(BackedIssue::new(
            placeholder_said()?,
            self.credential_said,
            self.registry_said,
            self.anchor,
            self.datetime,
        ));
        event.serialize()
    }
}

/// Backed credential revoke (`brv`) builder — keripy `backerRevoke`
/// (`vdr/eventing.py:402-445`).
///
/// Required: the credential's SAID (`i`), the prior TEL event's SAID
/// (`p`), the `ra` anchor ([`Seal::Event`]), and the timestamp `dt`.
#[must_use]
pub struct BackedRevokeBuilder {
    credential_said: Said<'static>,
    prior: Said<'static>,
    anchor: Seal<'static>,
    datetime: Cow<'static, str>,
}

impl BackedRevokeBuilder {
    /// Starts a backed revocation anchored at `anchor`.
    pub fn new(
        credential_said: Said<'static>,
        prior: Said<'static>,
        anchor: Seal<'static>,
        datetime: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            credential_said,
            prior,
            anchor,
            datetime: datetime.into(),
        }
    }

    /// Serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::NonEventBackerAnchor`] when the anchor is
    /// not the event-seal shape, or [`CodecError`] on digest failure.
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let event = TelEvent::BackedRevoke(BackedRevoke::new(
            placeholder_said()?,
            self.credential_said,
            self.prior,
            self.anchor,
            self.datetime,
        ));
        event.serialize()
    }
}
