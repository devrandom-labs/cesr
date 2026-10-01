//! Pure TEL registry and credential state transition logic.
//!
//! The host supplies accepted KEL events, issuer state and historical
//! registry evidence; this crate performs no retrieval, persistence,
//! scheduling or effects.
//!
//! Pinned keripy `Tever`/`Tevery` (`de59bc7d834955c5b0273c62f6b8b6a0df150dc3`)
//! and the PTEL draft require every `vcp`, `vrt`, `iss`, `rev`, `bis` and `brv`
//! to be anchored by an accepted issuer KEL event. The TEL `-G` source couple
//! gives that KEL event's `(sn, SAID)`; its sole event seal names the TEL
//! `(i, s, d)`. Issuer signatures on the TEL body are not required. Backed
//! events also require indexed receipts from the backer set at their `ra`
//! registry-management coordinate.
//!
//! Missing facts yield [`Disposition::Awaiting`](crate::Disposition::Awaiting)
//! so hosts can re-drive; supplied contradictory facts are terminal. See
//! `docs/audits/2026-09-29-a07-oracle.py` for executable pinned-reference
//! cases.
use alloc::borrow::Cow;
use alloc::vec::Vec;

use cesr::core::primitives::{Number, Siger};
use keri_events::{
    BasicPrefix, ConfigTrait, Identifier, KeriEvent, RegistryRotation, Said, Seal,
    SigningThreshold, TelEvent, Toad,
};

use crate::error::{RegistryRejection, RegistryStructuralError, WitnessSetError};
use crate::state::KeyState;
use crate::verification::Verifier;

/// A TEL event as the fold consumes it: the typed event, its exact body bytes,
/// source KEL coordinate, and any indexed controller or backer signatures.
///
/// The wire adapter [`SignedTel::from`] lifts this from a parsed
/// [`keri_codec::TelMessage`]; hosts with an out-of-band transport build it
/// through [`Self::from_host_asserted_parts`], asserting that the event was
/// parsed from exactly the supplied bytes. That assertion is also required
/// when rehydrating an accepted record from host storage.
///
/// ```compile_fail
/// # use keri::SignedTel;
/// # use keri_events::TelEvent;
/// fn forge<'e>(event: &'e TelEvent<'e>, bytes: &'e [u8]) -> SignedTel<'e> {
///     SignedTel { event, signed_bytes: bytes, sigs: Vec::new() }
/// }
/// ```
#[derive(Clone)]
pub struct SignedTel<'e> {
    /// The typed TEL event.
    pub(crate) event: &'e TelEvent<'e>,
    /// The exact canonical bytes the signatures commit to.
    pub(crate) signed_bytes: &'e [u8],
    /// The indexed signatures over [`Self::signed_bytes`].
    pub(crate) sigs: Cow<'e, [Siger<'e>]>,
    /// `-G` KEL source couple, as received or retained by the host.
    pub(crate) source: Option<TelAnchorCoordinate<'e>>,
    /// `-B` indexed backer receipts over the TEL body.
    pub(crate) backer_sigs: Cow<'e, [Siger<'e>]>,
    /// Accepted KEL event at `source`, supplied by the host after lookup.
    pub(crate) accepted_anchor: Option<AcceptedTelAnchor<'e>>,
}

/// A host assertion that this KEL event has been accepted at its coordinate.
///
/// Only the data needed for TEL authentication is retained; the fold still
/// checks it against the `-G` source and the TEL event's exact seal.
#[derive(Clone)]
pub struct AcceptedTelAnchor<'e> {
    prefix: Identifier<'e>,
    sn: Number,
    said: Said<'e>,
    seals: Vec<Seal<'e>>,
}

impl<'e> AcceptedTelAnchor<'e> {
    /// Extract an already accepted KEL event from host storage.
    #[must_use]
    pub fn from_host_accepted_event(event: &KeriEvent<'e>) -> Self {
        Self {
            prefix: event.prefix().clone(),
            sn: event.sn(),
            said: event.said().clone(),
            seals: event.anchors().to_vec(),
        }
    }
}

/// The KEL event coordinate carried by a TEL `-G` source couple.
///
/// The issuer prefix is derived from accepted registry state; the host must
/// supply the accepted event at exactly this sequence number and SAID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelAnchorCoordinate<'e> {
    sn: Number,
    said: Said<'e>,
}

impl<'e> TelAnchorCoordinate<'e> {
    /// Construct a source coordinate retained by a host codec/storage layer.
    #[must_use]
    pub const fn new(sn: Number, said: Said<'e>) -> Self {
        Self { sn, said }
    }

    /// Source KEL sequence number.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// Source KEL event SAID.
    #[must_use]
    pub const fn said(&self) -> &Said<'e> {
        &self.said
    }
}

impl<'e> SignedTel<'e> {
    /// Construct from an event/body pair whose provenance the host asserts.
    ///
    /// This does not compare the event with its bytes. Use it only with an
    /// out-of-band parser that bound the two, or with a host-accepted record
    /// whose binding is preserved by storage. The registry fold verifies
    /// signatures over `signed_bytes` but cannot infer the event's origin.
    #[must_use]
    pub const fn from_host_asserted_parts(
        event: &'e TelEvent<'e>,
        signed_bytes: &'e [u8],
        sigs: Vec<Siger<'e>>,
    ) -> Self {
        Self {
            event,
            signed_bytes,
            sigs: Cow::Owned(sigs),
            source: None,
            backer_sigs: Cow::Borrowed(&[]),
            accepted_anchor: None,
        }
    }

    /// Attach the `-G` source coordinate preserved by a host parser/store.
    #[must_use]
    pub fn with_source(mut self, source: TelAnchorCoordinate<'e>) -> Self {
        self.source = Some(source);
        self
    }

    /// Attach `-B` indexed backer receipts preserved by a host parser/store.
    #[must_use]
    pub fn with_backer_sigs(mut self, sigs: Vec<Siger<'e>>) -> Self {
        self.backer_sigs = Cow::Owned(sigs);
        self
    }

    /// Supply the KEL event that the host has already accepted at `source`.
    /// The fold checks its issuer, sn, SAID and sole TEL seal. The accepted
    /// status itself is a host assertion; never use an unaccepted KEL event.
    #[must_use]
    pub fn with_host_accepted_anchor(mut self, event: &KeriEvent<'e>) -> Self {
        self.accepted_anchor = Some(AcceptedTelAnchor::from_host_accepted_event(event));
        self
    }

    /// The `-G` source coordinate, if supplied.
    #[must_use]
    pub const fn source(&self) -> Option<&TelAnchorCoordinate<'e>> {
        self.source.as_ref()
    }

    /// The `-B` indexed backer receipts.
    #[must_use]
    pub fn backer_sigs(&self) -> &[Siger<'e>] {
        self.backer_sigs.as_ref()
    }

    /// The host-asserted accepted KEL event, if supplied.
    #[must_use]
    pub const fn accepted_anchor(&self) -> Option<&AcceptedTelAnchor<'e>> {
        self.accepted_anchor.as_ref()
    }

    /// The TEL event paired with the supplied bytes.
    #[must_use]
    pub const fn event(&self) -> &'e TelEvent<'e> {
        self.event
    }

    /// Exact bytes presented to signature verification.
    #[must_use]
    pub const fn signed_bytes(&self) -> &'e [u8] {
        self.signed_bytes
    }

    /// Indexed signatures attached to the event.
    #[must_use]
    pub fn sigs(&self) -> &[Siger<'e>] {
        self.sigs.as_ref()
    }
}

/// The signing evidence the caller supplies alongside a TEL event.
///
/// The fold never resolves identities itself — it classifies what the caller
/// hands it. Missing evidence can be retried; a supplied evidence class that
/// contradicts the event's ilk is terminal.
#[derive(Clone, Copy)]
pub enum TelEvidence<'e> {
    /// No issuer or backer state is available yet; the host may re-drive
    /// after resolving the relevant registry/issuer record.
    Missing,
    /// Issuer KEL evidence: the issuer's accepted key state and, optionally,
    /// the accepted KEL event sealing this TEL event. The latter may instead
    /// be attached to [`SignedTel`] via
    /// [`SignedTel::with_host_accepted_anchor`].
    Issuer {
        /// The issuer's current key state.
        state: &'e KeyState<'e>,
        /// The accepted KEL event anchoring this TEL event, if supplied here.
        anchor: Option<&'e KeriEvent<'e>>,
    },
    /// Current management-head backer evidence. No caller-supplied key state
    /// is needed: `-B` receipts verify against the recorded ordered backers.
    Backer,
    /// Historical management state at the backed event's `ra` coordinate.
    /// The host supplies an accepted registry snapshot, which the fold
    /// checks against the complete `(registry, sn, SAID)` seal.
    BackerAt {
        /// The accepted management state named by `ra`.
        management: &'e RegistryState,
    },
}

/// The pure derivation over a credential's recorded chain head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The registry records a chain for the credential whose head is the
    /// issuance event — no revocation observed.
    Issued,
    /// The chain's head is a revocation event.
    Revoked,
    /// The registry has no chain for the credential — never issued here (or
    /// issued under a different registry id).
    Unknown,
}

/// Owned head of one credential TEL.
///
/// It is independent of every other credential under the same registry. The
/// host keys and persists this value by
/// `(registry, credential)` and supplies the governing registry state for
/// each transition. Its primitives own their bytes, so source events may be
/// released after acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialState {
    registry: Said<'static>,
    credential: Said<'static>,
    sn: Number,
    head: Said<'static>,
}

impl CredentialState {
    /// Validate the first `iss` or `bis` for a credential using accepted
    /// management and issuer/backer evidence.
    ///
    /// # Errors
    /// Returns [`RegistryRejection`] for a wrong event kind, registry,
    /// flavor, anchor, backer receipt or inception sequence.
    pub fn incept(
        registry: &RegistryState,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<Self, RegistryRejection> {
        let (credential, sn, head) = match signed.event {
            TelEvent::Issue(iss) => {
                if iss.registry_said() != registry.id() {
                    return Err(RegistryRejection::InconsistentRegistry);
                }
                if !registry.is_backerless() {
                    return Err(RegistryStructuralError::SimpleEventOnBackerRegistry.into());
                }
                registry.authenticate_issuer(signed, evidence)?;
                (iss.credential_said(), iss.sn(), iss.said())
            }
            TelEvent::BackedIssue(bis) => {
                if bis.registry_said() != registry.id() {
                    return Err(RegistryRejection::InconsistentRegistry);
                }
                if registry.is_backerless() {
                    return Err(RegistryStructuralError::BackedEventOnBackerlessRegistry.into());
                }
                RegistryState::verify_kel_anchor(
                    signed,
                    registry.issuer(),
                    signed.accepted_anchor.as_ref(),
                )?;
                let (backers, toad) = registry.resolve_backer_authority(bis.anchor(), evidence)?;
                RegistryState::authenticate_backer(signed, backers, toad)?;
                (bis.credential_said(), bis.sn(), bis.said())
            }
            _ => return Err(RegistryStructuralError::NotCredentialInception.into()),
        };
        if sn.value() != 0 {
            return Err(RegistryRejection::OutOfOrder {
                expected: 0,
                actual: sn.value(),
            });
        }
        Ok(Self {
            registry: registry.id.clone().into_static(),
            credential: credential.clone().into_static(),
            sn,
            head: head.clone().into_static(),
        })
    }

    /// Validate and apply the next `rev` or `brv`. All fallible checks
    /// precede mutation, so rejection leaves the retained head unchanged.
    ///
    /// # Errors
    /// Returns [`RegistryRejection`] for wrong routing, evidence or chain
    /// coordinates, with its disposition classifying host redrive.
    pub fn ingest_mut(
        &mut self,
        registry: &RegistryState,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<(), RegistryRejection> {
        if &self.registry != registry.id() {
            return Err(RegistryRejection::InconsistentRegistry);
        }
        let (credential, sn, head, prior) = match signed.event {
            TelEvent::Revoke(rev) => {
                if rev.registry_said() != registry.id() {
                    return Err(RegistryRejection::InconsistentRegistry);
                }
                if !registry.is_backerless() {
                    return Err(RegistryStructuralError::SimpleEventOnBackerRegistry.into());
                }
                registry.authenticate_issuer(signed, evidence)?;
                (rev.credential_said(), rev.sn(), rev.said(), rev.prior())
            }
            TelEvent::BackedRevoke(brv) => {
                if !RegistryState::anchor_names_registry(brv.anchor(), registry.id()) {
                    return Err(RegistryRejection::InconsistentRegistry);
                }
                if registry.is_backerless() {
                    return Err(RegistryStructuralError::BackedEventOnBackerlessRegistry.into());
                }
                RegistryState::verify_kel_anchor(
                    signed,
                    registry.issuer(),
                    signed.accepted_anchor.as_ref(),
                )?;
                let (backers, toad) = registry.resolve_backer_authority(brv.anchor(), evidence)?;
                RegistryState::authenticate_backer(signed, backers, toad)?;
                (brv.credential_said(), brv.sn(), brv.said(), brv.prior())
            }
            _ => return Err(RegistryStructuralError::NotCredentialTransition.into()),
        };
        if credential != &self.credential {
            return Err(RegistryRejection::InconsistentCredential);
        }
        let expected = self
            .sn
            .value()
            .checked_add(1)
            .ok_or(RegistryStructuralError::SequenceNumberOverflow)?;
        if sn.value() != expected {
            return Err(RegistryRejection::OutOfOrder {
                expected,
                actual: sn.value(),
            });
        }
        if prior != &self.head {
            return Err(RegistryRejection::PriorDigestMismatch);
        }
        self.sn = sn;
        self.head = head.clone().into_static();
        Ok(())
    }

    /// Registry whose management TEL governs this credential.
    #[must_use]
    pub const fn registry(&self) -> &Said<'static> {
        &self.registry
    }

    /// Identifier of this credential TEL.
    #[must_use]
    pub const fn credential(&self) -> &Said<'static> {
        &self.credential
    }

    /// Sequence number of its accepted head.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// SAID of its accepted head.
    #[must_use]
    pub const fn head(&self) -> &Said<'static> {
        &self.head
    }

    /// Status derived from its accepted issuance or revocation head.
    #[must_use]
    pub const fn status(&self) -> CredentialStatus {
        if self.sn.value() == 0 {
            CredentialStatus::Issued
        } else {
            CredentialStatus::Revoked
        }
    }
}

/// Owned management-TEL head.
///
/// It contains registry identity, issuer, sequence and backer configuration,
/// with no credential heads. Hosts retain this value
/// under its registry id and retain historical clones by `(id, sn, SAID)` for
/// backed credential events whose `ra` names an earlier management event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryState {
    /// The registry's identity: the `vcp`'s SAID (`i == d`).
    id: Said<'static>,
    /// The issuer whose accepted KEL anchors the registry's TEL events.
    issuer: Identifier<'static>,
    /// The management chain's current sequence number.
    sn: Number,
    /// The management chain's current event digest (the head's SAID).
    latest: Said<'static>,
    /// The `vcp`'s configuration traits.
    config: Vec<ConfigTrait>,
    /// The backer threshold (toad) governing indexed `-B` receipts.
    backer_threshold: Toad,
    /// The current backer set, after all applied rotations.
    backers: Vec<BasicPrefix<'static>>,
}

impl RegistryState {
    /// The `vcp` transition: seed a registry from its inception event,
    /// authenticated by an accepted issuer KEL anchor.
    ///
    /// Mirrors keripy's `incept` factory plus the `Tevery` first-seen path
    /// (`vdr/eventing.py:89` for the trait/backer agreement): the vcp's SAID
    /// becomes the registry id, the backer set and threshold are recorded
    /// verbatim, and no credential chains exist yet.
    ///
    /// # Errors
    ///
    /// [`RegistryRejection::InconsistentIssuer`] when the supplied state
    /// names another issuer; [`RegistryRejection::MissingAnchor`] when the
    /// source or its accepted KEL event has not arrived;
    /// [`RegistryRejection::Structural`](`RegistryRejection::Structural`) for
    /// the trait/backer disagreement;
    /// [`RegistryRejection::BackerThreshold`] for a threshold outside the
    /// domain law; [`RegistryRejection::MissingBackerReceipts`] when a backed
    /// inception has too few valid `-B` receipts.
    pub fn incept(
        signed: &SignedTel<'_>,
        issuer: &KeyState<'_>,
    ) -> Result<Self, RegistryRejection> {
        let TelEvent::RegistryInception(vcp) = signed.event else {
            return Err(RegistryStructuralError::NotRegistryInception.into());
        };
        // The accepted KEL anchor must belong to the registry's issuer.
        if issuer.prefix() != vcp.issuer() {
            return Err(RegistryRejection::InconsistentIssuer);
        }
        // The NB trait must agree with the seeded backer set (keripy incept
        // factory). The TEL parser does not enforce this, so the fold does.
        if vcp.config().contains(&ConfigTrait::NoBackers) && !vcp.backers().is_empty() {
            return Err(RegistryStructuralError::NoBackersWithBackers.into());
        }
        keri_events::member_set::MemberSet::check_members(vcp.backers(), "backers")
            .map_err(WitnessSetError::from)?;
        // The seeded threshold satisfies the domain law (from-wire defense in
        // depth; the parser enforces the same law for in-event backer sets).
        Self::check_backer_threshold(vcp.backers().len(), vcp.backer_threshold())?;
        Self::verify_kel_anchor(signed, vcp.issuer(), signed.accepted_anchor.as_ref())?;
        if !vcp.backers().is_empty() {
            Self::authenticate_backer(signed, vcp.backers(), vcp.backer_threshold())?;
        }
        Ok(Self {
            id: vcp.said().clone().into_static(),
            issuer: vcp.issuer().clone().into_static(),
            sn: vcp.sn(),
            latest: vcp.said().clone().into_static(),
            config: vcp.config().clone(),
            backer_threshold: vcp.backer_threshold(),
            backers: vcp
                .backers()
                .iter()
                .cloned()
                .map(BasicPrefix::into_static)
                .collect(),
        })
    }

    /// Fold the first TEL event when issuer evidence may still be missing.
    /// Absence is retryable; a supplied state naming another issuer is a
    /// terminal contradiction.
    ///
    /// # Errors
    /// Returns [`RegistryRejection::MissingIssuer`] for absent evidence,
    /// or the same verification/structural errors as [`Self::incept`].
    pub fn incept_with_evidence(
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<Self, RegistryRejection> {
        match evidence {
            TelEvidence::Issuer { state, .. } => Self::incept(signed, state),
            TelEvidence::Missing => Err(RegistryRejection::MissingIssuer),
            TelEvidence::Backer | TelEvidence::BackerAt { .. } => {
                Err(RegistryRejection::InconsistentIssuer)
            }
        }
    }

    /// Validate and apply one `vrt` management event. A rejection leaves
    /// every field unchanged; credential events use [`CredentialState`].
    ///
    /// # Errors
    ///
    /// Returns [`RegistryRejection`] with a typed disposition.
    pub fn ingest_mut(
        &mut self,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<(), RegistryRejection> {
        match signed.event {
            TelEvent::RegistryInception(_) => Err(RegistryRejection::DuplicateInception),
            TelEvent::RegistryRotation(vrt) => self.rotate_mut(vrt, signed, evidence),
            _ => Err(RegistryStructuralError::NotManagementRotation.into()),
        }
    }

    /// The registry's identity: the `vcp`'s SAID (`i == d`).
    #[must_use]
    pub const fn id(&self) -> &Said<'static> {
        &self.id
    }

    /// The issuer that signs the registry's management chain.
    #[must_use]
    pub const fn issuer(&self) -> &Identifier<'static> {
        &self.issuer
    }

    /// The management chain's current sequence number.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// The management chain's current event digest.
    #[must_use]
    pub const fn latest(&self) -> &Said<'static> {
        &self.latest
    }

    /// The `vcp`'s configuration traits.
    #[must_use]
    pub fn config(&self) -> &[ConfigTrait] {
        &self.config
    }

    /// Whether the registry is backerless (the `NB` trait is set) — the
    /// flavor that routes `iss`/`rev` against `bis`/`brv`.
    #[must_use]
    pub fn is_backerless(&self) -> bool {
        self.config.contains(&ConfigTrait::NoBackers)
    }

    /// The current backer set, after all applied rotations.
    #[must_use]
    pub fn backers(&self) -> &[BasicPrefix<'static>] {
        &self.backers
    }

    /// The backer threshold (toad) governing backer signatures.
    #[must_use]
    pub const fn backer_threshold(&self) -> Toad {
        self.backer_threshold
    }

    /// The `vrt` transition — keripy's `rotate` (`vdr/eventing.py:960-1035`):
    /// routing, flavor, chain position, prior digest, anchor verification,
    /// signatures, then the backer cut/add algebra and threshold law.
    fn rotate_mut(
        &mut self,
        vrt: &RegistryRotation<'_>,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<(), RegistryRejection> {
        // Routing: the rotation must govern this registry.
        if vrt.registry() != &self.id {
            return Err(RegistryRejection::InconsistentRegistry);
        }
        // Flavor: a backerless registry has no backers to rotate (keripy
        // rotate).
        if self.is_backerless() {
            return Err(RegistryStructuralError::RotationOnBackerlessRegistry.into());
        }
        // Chain position: sn = current + 1.
        let expected = self
            .sn
            .value()
            .checked_add(1)
            .ok_or(RegistryRejection::Structural(
                RegistryStructuralError::SequenceNumberOverflow,
            ))?;
        if vrt.sn().value() != expected {
            return Err(RegistryRejection::OutOfOrder {
                expected,
                actual: vrt.sn().value(),
            });
        }
        // Prior digest: p = the current head.
        if vrt.prior() != &self.latest {
            return Err(RegistryRejection::PriorDigestMismatch);
        }
        // Anchor evidence: the accepted KEL event seals the rotation. The
        // issuer's key state must be this registry's issuer's.
        let (state, anchor) = match *evidence {
            TelEvidence::Issuer { state, anchor } => (state, anchor),
            TelEvidence::Missing => return Err(RegistryRejection::MissingIssuer),
            TelEvidence::Backer { .. } | TelEvidence::BackerAt { .. } => {
                return Err(RegistryRejection::InconsistentIssuer);
            }
        };
        if state.prefix() != &self.issuer {
            return Err(RegistryRejection::InconsistentIssuer);
        }
        if let Some(event) = anchor {
            let accepted = AcceptedTelAnchor::from_host_accepted_event(event);
            Self::verify_kel_anchor(signed, &self.issuer, Some(&accepted))?;
        } else {
            Self::verify_kel_anchor(signed, &self.issuer, signed.accepted_anchor.as_ref())?;
        }
        // Backer cut/add algebra against the current set, then the threshold
        // law against the RESOLVED set.
        let backers = resolve_backers(self, vrt)?;
        Self::check_backer_threshold(backers.len(), vrt.backer_threshold())?;
        if !backers.is_empty() {
            Self::authenticate_backer(signed, &backers, vrt.backer_threshold())?;
        }
        self.sn = vrt.sn();
        self.latest = vrt.said().clone().into_static();
        self.backers = backers;
        self.backer_threshold = vrt.backer_threshold();
        Ok(())
    }

    /// The issuer KEL authentication path: match the accepted issuer event,
    /// source coordinate and sole seal against the TEL event.
    fn authenticate_issuer(
        &self,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<(), RegistryRejection> {
        let (state, anchor) = match *evidence {
            TelEvidence::Issuer { state, anchor } => (state, anchor),
            TelEvidence::Missing => return Err(RegistryRejection::MissingIssuer),
            TelEvidence::Backer { .. } | TelEvidence::BackerAt { .. } => {
                return Err(RegistryRejection::InconsistentIssuer);
            }
        };
        if state.prefix() != &self.issuer {
            return Err(RegistryRejection::InconsistentIssuer);
        }
        anchor.map_or_else(
            || Self::verify_kel_anchor(signed, &self.issuer, signed.accepted_anchor.as_ref()),
            |event| {
                let accepted = AcceptedTelAnchor::from_host_accepted_event(event);
                Self::verify_kel_anchor(signed, &self.issuer, Some(&accepted))
            },
        )
    }

    /// Verify `-B` signatures against the management event's backer list.
    fn authenticate_backer(
        signed: &SignedTel<'_>,
        backers: &[BasicPrefix<'_>],
        toad: Toad,
    ) -> Result<(), RegistryRejection> {
        let threshold = SigningThreshold::Simple(u64::from(toad.value()));
        match Verifier::with_keys(
            backers,
            &threshold,
            signed.signed_bytes,
            &signed.backer_sigs,
        ) {
            Ok(_) => Ok(()),
            Err(crate::error::Rejection::MissingSignatures { verified }) => {
                Err(RegistryRejection::MissingBackerReceipts {
                    valid: verified,
                    required: toad.value(),
                })
            }
            Err(err) => Err(RegistryRejection::Signatures(err)),
        }
    }

    /// Resolve the historical management state named by the complete `ra`
    /// coordinate. With no retained snapshot, only the current head can
    /// serve as evidence; an older coordinate awaits host-supplied history.
    fn resolve_backer_authority<'a>(
        &'a self,
        anchor: &Seal<'_>,
        evidence: &'a TelEvidence<'_>,
    ) -> Result<(&'a [BasicPrefix<'static>], Toad), RegistryRejection> {
        let Seal::Event { i, s, d } = anchor else {
            return Err(RegistryRejection::InconsistentManagement);
        };
        if !Self::seal_names_registry(i, &self.id) {
            return Err(RegistryRejection::InconsistentRegistry);
        }
        let (backers, toad) = match evidence {
            TelEvidence::BackerAt { management } => {
                if management.id() != &self.id
                    || management.issuer() != &self.issuer
                    || management.config() != self.config()
                    || management.sn() != *s
                    || management.latest() != d
                {
                    return Err(RegistryRejection::InconsistentManagement);
                }
                (management.backers(), management.backer_threshold())
            }
            TelEvidence::Backer => {
                if s.value() != self.sn.value() || d != &self.latest {
                    return Err(RegistryRejection::UnresolvedAnchor { sn: s.value() });
                }
                (self.backers(), self.backer_threshold)
            }
            TelEvidence::Missing => {
                return Err(RegistryRejection::UnresolvedAnchor { sn: s.value() });
            }
            TelEvidence::Issuer { .. } => return Err(RegistryRejection::InconsistentIssuer),
        };
        keri_events::member_set::MemberSet::check_members(backers, "backers")
            .map_err(WitnessSetError::from)?;
        Self::check_backer_threshold(backers.len(), toad)?;
        Ok((backers, toad))
    }

    /// Whether the anchor's registry id names `id` — the routing half of the
    /// backer anchor law.
    fn anchor_names_registry(anchor: &Seal<'_>, id: &Said<'_>) -> bool {
        match anchor {
            Seal::Event { i, .. } => Self::seal_names_registry(i, id),
            _ => false,
        }
    }

    fn seal_names_registry(i: &Identifier<'_>, id: &Said<'_>) -> bool {
        matches!(i, Identifier::SelfAddressing(said) if said == id)
    }

    /// Match a TEL event to the exact accepted issuer KEL coordinate carried
    /// by its `-G` source couple and to the KEL event's sole TEL seal.
    fn verify_kel_anchor(
        signed: &SignedTel<'_>,
        issuer: &Identifier<'_>,
        candidate: Option<&AcceptedTelAnchor<'_>>,
    ) -> Result<(), RegistryRejection> {
        let Some(source) = signed.source.as_ref() else {
            return Err(RegistryRejection::MissingAnchor);
        };
        let Some(anchor) = candidate else {
            return Err(RegistryRejection::MissingAnchor);
        };
        let event = signed.event;
        let event_id = match event {
            TelEvent::RegistryInception(vcp) => vcp.said(),
            TelEvent::RegistryRotation(vrt) => vrt.registry(),
            TelEvent::Issue(iss) => iss.credential_said(),
            TelEvent::Revoke(rev) => rev.credential_said(),
            TelEvent::BackedIssue(bis) => bis.credential_said(),
            TelEvent::BackedRevoke(brv) => brv.credential_said(),
        };
        if &anchor.prefix != issuer
            || anchor.sn != source.sn
            || anchor.said != source.said
            || !matches!(
                anchor.seals.as_slice(),
                [Seal::Event { i: Identifier::SelfAddressing(i), s, d }]
                    if i == event_id && s == &event.sn() && d == event.said()
            )
        {
            return Err(RegistryRejection::InconsistentAnchor);
        }
        Ok(())
    }

    /// The threshold domain law for a backer set: 0 iff the set is empty,
    /// else 1..=count.
    fn check_backer_threshold(count: usize, toad: Toad) -> Result<(), RegistryRejection> {
        Toad::exact(toad.value(), count).map(|_| ())?;
        Ok(())
    }
}

/// The backer cut/add algebra against the current set — the registry mirror
/// of the key-event fold's witness algebra: every removal must be a current
/// backer and disjoint from the additions, and no addition may already be
/// present.
fn resolve_backers(
    prior: &RegistryState,
    vrt: &RegistryRotation<'_>,
) -> Result<Vec<BasicPrefix<'static>>, WitnessSetError> {
    let removals = vrt.backer_cuts();
    let additions = vrt.backer_additions();
    keri_events::member_set::MemberSet::check_deltas(
        removals,
        additions,
        "backer cuts",
        "backer additions",
    )?;
    for removal in removals {
        if !prior.backers().contains(removal) {
            return Err(WitnessSetError::RemovalNotCurrent);
        }
    }
    for addition in additions {
        if prior.backers().contains(addition) {
            return Err(WitnessSetError::AdditionAlreadyPresent);
        }
    }
    Ok(
        KeyState::updated_members(prior.backers(), removals, additions)
            .map(|member| member.clone().into_static())
            .collect(),
    )
}
