//! The registry-state fold: TEL (Transaction Event Log) registry and
//! credential lifecycle (P5).
//!
//! [`RegistryState`] mirrors [`KeyState`](crate::KeyState) for the registry
//! side of KERI: a pure, borrowed state that consumes signed TEL events
//! against caller-supplied evidence and computes the COMPLETE next state —
//! or rejects with [`RegistryRejection`] and preserves the previous state
//! exactly (the caller keeps custody on rejection; see
//! [`KeyState::ingest`](crate::KeyState::ingest) for the same law on the key
//! event side).
//!
//! # The fold table
//!
//! | ilk | guard (in evaluation order) | next state |
//! |-----|------------------------------|------------|
//! | `vcp` | not yet governing this registry; the evidence is the issuer's own key state; the `NB` trait agrees with the seeded backer set; the seeded threshold satisfies the domain law | seeds identity `= d` (the vcp's SAID), issuer, backer set/threshold |
//! | `vrt` | `i` is this registry; the registry is not backerless; `sn` = current + 1; `p` = head digest; the issuer's current key state; an accepted KEL event whose anchors carry an event seal naming `(i, s, d)` of the rotation; signatures verify | advances the management chain, applies backer cut/add deltas, records the new threshold |
//! | `iss` | `ri` is this registry; the registry is backerless; the credential chain is unoccupied and `sn` = 0; the issuer's current key state; signatures verify | records the credential chain head |
//! | `rev` | `ri` is this registry; the registry is backerless; `sn` = current credential head + 1; `p` = credential head digest; the issuer's current key state; signatures verify | advances the credential chain head |
//! | `bis` | `ii` is this registry; the registry is NOT backerless; the credential chain is unoccupied and `sn` = 0; the `ra` event seal names this registry's current management head; the endorser's key state is a current backer; signatures verify | records the credential chain head |
//! | `brv` | the `ra` event seal names this registry; the registry is NOT backerless; `sn` = current credential head + 1; `p` = credential head digest; the `ra` seal names the current management head; the endorser's key state is a current backer; signatures verify | advances the credential chain head |
//!
//! Credential status is a pure derivation from the recorded chain
//! ([`RegistryState::vcstate`]): issued, revoked, or unknown when the
//! registry has no chain for the credential.
//!
//! # Rejection taxonomy
//!
//! [`RegistryRejection::disposition`] maps every rejection to keripy's
//! `Tevery` dispositions (pin `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`):
//! sequence gaps await prior events (the `.ooes` escrow), occupied sequence
//! numbers are contested (the duplicity path), and everything else — missing
//! registry/issuer/anchor, digest mismatches, backer-algebra and threshold
//! violations, failed signatures, structural disagreements — is terminal.
//!
//! # Evidence model
//!
//! The fold is pure computation over caller-supplied data: it never queries
//! a key-event log or registry store. What the caller must supply depends on
//! the event's ilk — [`TelEvidence::Issuer`] for issuer-signed events (with
//! the accepted KEL anchor event for a `vrt`), [`TelEvidence::Backer`] for
//! backer-signed events. This mirrors [`KeyState`]'s split between the fold
//! and the evidence the host's stream, query, or escrow produces.
//!
//! # keripy anchors and deliberate divergences
//!
//! The transitions mirror keripy's `vdr/eventing.py` factories at the pin:
//! `incept`, `rotate`, `issue`, `revoke`, `backerIssue`, `backerRevoke`
//! (guard order), `verifyAnchor` (digest-only seal comparison,
//! :1410-1437), and `getBackerState`'s escrow-on-missing-anchor
//! (:1255-1266). Deliberate divergences, each grounded in the blueprint's
//! fold table:
//!
//! * **Backer anchors resolve against the current management head.** keripy's
//!   `getBackerState` reads the backer set recorded in the anchored event;
//!   this fold keeps only the current management state, so a backer event is
//!   accepted exactly when its `ra` seal names the current head — and the
//!   endorsement is verified against the CURRENT backer set and threshold
//!   (keripy derives verification keys from the anchored event's recorded
//!   list, so a non-backer's signature can never verify there either; the
//!   current-head rule additionally rejects stale endorsements keripy would
//!   accept, the stricter reading of the blueprint's fold table).
//! * **The toad domain law is enforced for resolved backer sets.** keripy's
//!   `rotate` only bounds the threshold above; the fold uses the
//!   [`Toad::exact`] law (0 iff empty, else 1..=count) for both the seeded
//!   and the resolved set.
//! * **The zero-threshold corner is unreachable.** A registry with a
//!   backerless/nontransferable backer set cannot sign a backer event, so
//!   the pure fold rejects unverifiable endorsements where keripy would
//!   accept a zero-threshold one.
//! * **The vcp carries no KEL-anchor guard.** The blueprint mandates the
//!   anchor guard for rotations only; a vcp is authenticated by its issuer's
//!   signatures alone.
use alloc::borrow::Cow;
use alloc::vec::Vec;

use cesr::core::primitives::{Number, Siger};
use keri_events::{
    BackedIssue, BackedRevoke, BasicPrefix, ConfigTrait, Identifier, Issue, KeriEvent,
    RegistryRotation, Revoke, Said, Seal, SigningThreshold, TelEvent, Toad, VerifyingKey,
};

use crate::authority::Authority;
use crate::error::{RegistryRejection, RegistryStructuralError, WitnessSetError};
use crate::state::KeyState;

/// A signed TEL event as the fold consumes it: the typed event, the exact
/// canonical bytes that were signed, and the indexed signatures over them.
///
/// The wire adapter [`SignedTel::from`] lifts this from a parsed
/// [`keri_codec::TelMessage`]; hosts with an out-of-band transport build it
/// directly.
#[derive(Debug, Clone)]
pub struct SignedTel<'e> {
    /// The typed TEL event.
    pub event: &'e TelEvent<'e>,
    /// The exact canonical bytes the signatures commit to.
    pub signed_bytes: &'e [u8],
    /// The indexed signatures over [`Self::signed_bytes`].
    pub sigs: Vec<Siger<'e>>,
}

/// The signing evidence the caller supplies alongside a TEL event.
///
/// The fold never resolves identities itself — it classifies what the caller
/// hands it. Supplying the wrong class for the event's ilk is itself a
/// rejection ([`RegistryRejection::MissingIssuer`]), mirroring keripy's
/// "invalid ... evt against ... registry" guards.
#[derive(Clone, Copy)]
pub enum TelEvidence<'e> {
    /// Issuer-signed evidence: the issuer's current key state. The `anchor`
    /// is required for a rotation — the accepted KEL event whose anchors
    /// carry the rotation's event seal — and absent otherwise.
    Issuer {
        /// The issuer's current key state.
        state: &'e KeyState<'e>,
        /// The accepted KEL event anchoring the TEL event, when the ilk
        /// requires one (a `vrt`).
        anchor: Option<&'e KeriEvent<'e>>,
    },
    /// Backer-signed evidence. No caller-supplied key state is needed: the
    /// endorsement verifies against the RECORDED backer keys (basic-prefix
    /// derivation makes each `b` entry its own verifying key).
    Backer,
}

/// The pure derivation over a credential's recorded chain:
/// [`RegistryState::vcstate`].
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

/// The registry-state fold's output state: the registry's identity, issuer,
/// management chain, backer configuration, and per-credential chains.
///
/// Borrowed event data (ids, digests) ties the state to the events that
/// produced it, exactly as [`KeyState`] borrows its key-event payloads; hosts
/// that need ownership clone into their own storage (or use the snapshot
/// pattern [`KeyStateSnapshot`](crate::KeyStateSnapshot) establishes for the
/// key-event side).
///
/// # Examples
///
/// The fold's shape mirrors [`KeyState::try_fold`]: consume the current
/// state, compute the complete next state, or reject with the previous state
/// intact.
///
/// ```ignore
/// let state = RegistryState::incept(&vcp_signed, &issuer_state)?;
/// let state = state.ingest(&iss_signed, &TelEvidence::Issuer { state: &issuer, anchor: None })?;
/// assert_eq!(state.vcstate(&credential), CredentialStatus::Issued);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryState<'e> {
    /// The registry's identity: the `vcp`'s SAID (`i == d`).
    id: &'e Said<'e>,
    /// The issuer that signs the registry's management chain.
    issuer: &'e Identifier<'e>,
    /// The management chain's current sequence number.
    sn: Number,
    /// The management chain's current event digest (the head's SAID).
    latest: &'e Said<'e>,
    /// The `vcp`'s configuration traits.
    config: &'e [ConfigTrait],
    /// The backer threshold (toad) governing backer signatures.
    backer_threshold: Toad,
    /// The current backer set, after all applied rotations.
    backers: Cow<'e, [BasicPrefix<'e>]>,
    /// Per-credential chains, one head per known credential.
    credentials: Cow<'e, [CredentialChain<'e>]>,
}

/// One credential's chain head: the credential's SAID plus the head event's
/// sequence number and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialChain<'e> {
    credential: &'e Said<'e>,
    head_sn: Number,
    head: &'e Said<'e>,
}

impl<'e> RegistryState<'e> {
    /// The `vcp` transition: seed a registry from its inception event,
    /// authenticated by the issuer's key state.
    ///
    /// Mirrors keripy's `incept` factory plus the `Tevery` first-seen path
    /// (`vdr/eventing.py:89` for the trait/backer agreement): the vcp's SAID
    /// becomes the registry id, the backer set and threshold are recorded
    /// verbatim, and no credential chains exist yet.
    ///
    /// # Errors
    ///
    /// [`RegistryRejection::MissingIssuer`] when the evidence is not the
    /// inception's issuer's own key state;
    /// [`RegistryRejection::Structural`](`RegistryRejection::Structural`) for
    /// the trait/backer disagreement;
    /// [`RegistryRejection::BackerThreshold`] for a threshold outside the
    /// domain law; [`RegistryRejection::Signatures`] when the issuer's
    /// signatures do not verify.
    pub fn incept(
        signed: &SignedTel<'e>,
        issuer: &'e KeyState<'e>,
    ) -> Result<Self, RegistryRejection> {
        let TelEvent::RegistryInception(vcp) = signed.event else {
            return Err(RegistryStructuralError::NotRegistryInception.into());
        };
        // The seed event must be signed by the registry's own issuer: the
        // evidence's prefix is the only authority that may establish it.
        if issuer.prefix() != vcp.issuer() {
            return Err(RegistryRejection::MissingIssuer);
        }
        // The NB trait must agree with the seeded backer set (keripy incept
        // factory). The TEL parser does not enforce this, so the fold does.
        if vcp.config().contains(&ConfigTrait::NoBackers) && !vcp.backers().is_empty() {
            return Err(RegistryStructuralError::NoBackersWithBackers.into());
        }
        // The seeded threshold satisfies the domain law (from-wire defense in
        // depth; the parser enforces the same law for in-event backer sets).
        Self::check_backer_threshold(vcp.backers().len(), vcp.backer_threshold())?;
        Authority::new(issuer.keys(), issuer.threshold())
            .verify(signed.signed_bytes, &signed.sigs)?;
        Ok(Self {
            id: vcp.said(),
            issuer: vcp.issuer(),
            sn: vcp.sn(),
            latest: vcp.said(),
            config: vcp.config().as_slice(),
            backer_threshold: vcp.backer_threshold(),
            backers: Cow::Borrowed(vcp.backers().as_slice()),
            credentials: Cow::Borrowed(&[]),
        })
    }

    /// The `vrt`/`iss`/`rev`/`bis`/`brv` transitions: consume this state and
    /// a signed TEL event, compute the complete next state.
    ///
    /// A rejection returns [`Err`] with the previous state untouched — the
    /// caller keeps custody — and a [`RegistryRejection`] whose
    /// [`disposition`](RegistryRejection::disposition) says whether re-drive
    /// with more evidence can succeed (keripy's escrow), the sequence number
    /// is contested (duplicity), or the event is dead (terminal).
    ///
    /// # Errors
    ///
    /// [`RegistryRejection`] per the fold table; a `vcp` here is
    /// [`RegistryRejection::DuplicateInception`] (the registry already
    /// governs its own inception).
    pub fn ingest(
        self,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<Self, RegistryRejection> {
        match signed.event {
            TelEvent::RegistryInception(_) => Err(RegistryRejection::DuplicateInception),
            TelEvent::RegistryRotation(vrt) => self.rotate(vrt, signed, evidence),
            TelEvent::Issue(iss) => self.issue(iss, signed, evidence),
            TelEvent::BackedIssue(bis) => self.backed_issue(bis, signed, evidence),
            TelEvent::Revoke(rev) => self.revoke(rev, signed, evidence),
            TelEvent::BackedRevoke(brv) => self.backed_revoke(brv, signed, evidence),
        }
    }

    /// The registry's identity: the `vcp`'s SAID (`i == d`).
    #[must_use]
    pub const fn id(&self) -> &Said<'_> {
        self.id
    }

    /// The issuer that signs the registry's management chain.
    #[must_use]
    pub const fn issuer(&self) -> &Identifier<'_> {
        self.issuer
    }

    /// The management chain's current sequence number.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// The management chain's current event digest.
    #[must_use]
    pub const fn latest(&self) -> &Said<'_> {
        self.latest
    }

    /// The `vcp`'s configuration traits.
    #[must_use]
    pub const fn config(&self) -> &[ConfigTrait] {
        self.config
    }

    /// Whether the registry is backerless (the `NB` trait is set) — the
    /// flavor that routes `iss`/`rev` against `bis`/`brv`.
    #[must_use]
    pub fn is_backerless(&self) -> bool {
        self.config.contains(&ConfigTrait::NoBackers)
    }

    /// The current backer set, after all applied rotations.
    #[must_use]
    pub fn backers(&self) -> &[BasicPrefix<'e>] {
        &self.backers
    }

    /// The backer threshold (toad) governing backer signatures.
    #[must_use]
    pub const fn backer_threshold(&self) -> Toad {
        self.backer_threshold
    }

    /// The pure status derivation: the credential's chain head decides.
    ///
    /// Mirrors keripy's `vcstate` semantics at the pin: a chain headed by the
    /// issuance is `Issued`, a chain headed by a revocation is `Revoked`, and
    /// no chain is `Unknown`.
    #[must_use]
    pub fn vcstate(&self, credential: &Said<'_>) -> CredentialStatus {
        match self
            .credentials
            .iter()
            .find(|chain| chain.credential == credential)
        {
            // One chain entry per credential: the head sn is 0 for the
            // issuance and the revocation's sn once a revocation advanced it.
            Some(chain) if chain.head_sn.value() == 0 => CredentialStatus::Issued,
            Some(_) => CredentialStatus::Revoked,
            None => CredentialStatus::Unknown,
        }
    }

    /// The `vrt` transition — keripy's `rotate` (`vdr/eventing.py:960-1035`):
    /// routing, flavor, chain position, prior digest, anchor verification,
    /// signatures, then the backer cut/add algebra and threshold law.
    fn rotate(
        self,
        vrt: &'e RegistryRotation<'e>,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<Self, RegistryRejection> {
        // Routing: the rotation must govern this registry.
        if vrt.registry() != self.id {
            return Err(RegistryRejection::MissingRegistry);
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
        if vrt.prior() != self.latest {
            return Err(RegistryRejection::PriorDigestMismatch);
        }
        // Anchor evidence: the accepted KEL event seals the rotation. The
        // issuer's key state must be this registry's issuer's.
        let (state, anchor) = match *evidence {
            TelEvidence::Issuer { state, anchor } => (state, anchor),
            TelEvidence::Backer { .. } => return Err(RegistryRejection::MissingIssuer),
        };
        if state.prefix() != self.issuer {
            return Err(RegistryRejection::MissingIssuer);
        }
        let Some(anchoring) = anchor else {
            return Err(RegistryRejection::MissingAnchor);
        };
        if !Self::anchors_rotation(anchoring, vrt) {
            return Err(RegistryRejection::MissingAnchor);
        }
        // Authentication through the shared authority path.
        Authority::new(state.keys(), state.threshold())
            .verify(signed.signed_bytes, &signed.sigs)?;
        // Backer cut/add algebra against the current set, then the threshold
        // law against the RESOLVED set.
        let backers = resolve_backers(&self, vrt)?;
        Self::check_backer_threshold(backers.len(), vrt.backer_threshold())?;
        Ok(self.rotated(vrt, backers))
    }

    /// The `iss` transition — keripy's `issue` (`vdr/eventing.py:1060-1080`):
    /// routing, flavor, issuer authentication, then the unoccupied-chain
    /// record.
    fn issue(
        mut self,
        iss: &'e Issue<'e>,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<Self, RegistryRejection> {
        if iss.registry_said() != self.id {
            return Err(RegistryRejection::MissingRegistry);
        }
        if !self.is_backerless() {
            return Err(RegistryStructuralError::SimpleEventOnBackerRegistry.into());
        }
        self.authenticate_issuer(signed, evidence)?;
        self.record_chain_event(iss.credential_said(), iss.sn(), iss.said(), None)?;
        Ok(self)
    }

    /// The `rev` transition — keripy's `revoke`
    /// (`vdr/eventing.py:1120-1156`): routing, flavor, issuer authentication,
    /// then chain position, prior digest, and the head advance.
    fn revoke(
        mut self,
        rev: &'e Revoke<'e>,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<Self, RegistryRejection> {
        if rev.registry_said() != self.id {
            return Err(RegistryRejection::MissingRegistry);
        }
        if !self.is_backerless() {
            return Err(RegistryStructuralError::SimpleEventOnBackerRegistry.into());
        }
        self.authenticate_issuer(signed, evidence)?;
        self.record_chain_event(
            rev.credential_said(),
            rev.sn(),
            rev.said(),
            Some(rev.prior()),
        )?;
        Ok(self)
    }

    /// The `bis` transition — keripy's `backerIssue`
    /// (`vdr/eventing.py:1080-1118`): routing, flavor, anchor resolution,
    /// backer authentication, then the unoccupied-chain record.
    fn backed_issue(
        mut self,
        bis: &'e BackedIssue<'e>,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<Self, RegistryRejection> {
        if bis.registry_said() != self.id {
            return Err(RegistryRejection::MissingRegistry);
        }
        if self.is_backerless() {
            return Err(RegistryStructuralError::BackedEventOnBackerlessRegistry.into());
        }
        self.check_backer_anchor(bis.anchor())?;
        self.authenticate_backer(signed, evidence)?;
        self.record_chain_event(bis.credential_said(), bis.sn(), bis.said(), None)?;
        Ok(self)
    }

    /// The `brv` transition — keripy's `backerRevoke`
    /// (`vdr/eventing.py:1156-1200`): routing through the anchor (a `brv`
    /// carries no `ii`), flavor, anchor resolution, backer authentication,
    /// then chain position, prior digest, and the head advance.
    fn backed_revoke(
        mut self,
        brv: &'e BackedRevoke<'e>,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<Self, RegistryRejection> {
        // Routing: the ra anchor's registry id is the only registry reference
        // a brv carries (keripy's registryKey = ra.i).
        if !Self::anchor_names_registry(brv.anchor(), self.id) {
            return Err(RegistryRejection::MissingRegistry);
        }
        if self.is_backerless() {
            return Err(RegistryStructuralError::BackedEventOnBackerlessRegistry.into());
        }
        self.check_backer_anchor(brv.anchor())?;
        self.authenticate_backer(signed, evidence)?;
        self.record_chain_event(
            brv.credential_said(),
            brv.sn(),
            brv.said(),
            Some(brv.prior()),
        )?;
        Ok(self)
    }

    /// The per-credential chain law, applied: an inceptive event
    /// (`iss`/`bis`, sn 0) occupies an unrecorded chain; a receptive event
    /// (`rev`/`brv`, sn + 1) advances the recorded head in place — one chain
    /// entry per credential, which is what [`RegistryState::vcstate`] reads.
    /// Every rejection precedes the mutation, so a rejected event leaves the
    /// state untouched.
    fn record_chain_event(
        &mut self,
        credential: &'e Said<'e>,
        sn: Number,
        head: &'e Said<'e>,
        prior: Option<&'e Said<'e>>,
    ) -> Result<(), RegistryRejection> {
        let credentials = self.credentials.to_mut();
        match credentials
            .iter_mut()
            .find(|chain| chain.credential == credential)
        {
            // Receptive event: chain position, then the prior digest, then
            // the in-place head advance.
            Some(chain) => {
                let expected =
                    chain
                        .head_sn
                        .value()
                        .checked_add(1)
                        .ok_or(RegistryRejection::Structural(
                            RegistryStructuralError::SequenceNumberOverflow,
                        ))?;
                if sn.value() != expected {
                    return Err(RegistryRejection::OutOfOrder {
                        expected,
                        actual: sn.value(),
                    });
                }
                if prior != Some(chain.head) {
                    return Err(RegistryRejection::PriorDigestMismatch);
                }
                chain.head_sn = sn;
                chain.head = head;
                Ok(())
            }
            // Inceptive event: the chain must be unrecorded.
            None if sn.value() == 0 && prior.is_none() => {
                credentials.push(CredentialChain {
                    credential,
                    head_sn: sn,
                    head,
                });
                Ok(())
            }
            None => Err(RegistryRejection::OutOfOrder {
                expected: 0,
                actual: sn.value(),
            }),
        }
    }

    /// The issuer-signed authentication path: the evidence must be the
    /// registry's issuer's own key state, then the signatures verify over the
    /// exact signed span through the shared authority path.
    fn authenticate_issuer(
        &self,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<(), RegistryRejection> {
        let state = match *evidence {
            TelEvidence::Issuer { state, .. } => state,
            TelEvidence::Backer { .. } => return Err(RegistryRejection::MissingIssuer),
        };
        if state.prefix() != self.issuer {
            return Err(RegistryRejection::MissingIssuer);
        }
        Authority::new(state.keys(), state.threshold())
            .verify(signed.signed_bytes, &signed.sigs)?;
        Ok(())
    }

    /// The backer-signed authentication path: the endorsement signatures
    /// verify against the RECORDED backer keys — basic-prefix derivation
    /// makes each `b` entry its own verifying key, so a non-backer's
    /// signature can never verify (keripy derives verification keys from the
    /// recorded backer list) — at the current backer threshold, through the
    /// shared authority path.
    fn authenticate_backer(
        &self,
        signed: &SignedTel<'e>,
        evidence: &TelEvidence<'e>,
    ) -> Result<(), RegistryRejection> {
        // The endorsement path is backer-governed: issuer-class evidence
        // mislabels the signing authority.
        if matches!(evidence, TelEvidence::Issuer { .. }) {
            return Err(RegistryRejection::MissingIssuer);
        }
        let keys: Vec<VerifyingKey<'_>> = self
            .backers
            .iter()
            .map(|backer| VerifyingKey::from_matter(backer.as_matter().clone()))
            .collect();
        let threshold = SigningThreshold::Simple(u64::from(self.backer_threshold.value()));
        Authority::new(&keys, &threshold)
            .verify(signed.signed_bytes, &signed.sigs)
            .map_err(RegistryRejection::Signatures)?;
        Ok(())
    }

    /// The backer anchor law: the `ra` event seal must name this registry and
    /// its CURRENT management head. keripy's `getBackerState` reads the
    /// anchored event's recorded backer set, escrowing when absent
    /// (`vdr/eventing.py:1255-1266`); this fold validates against the current
    /// head, the only management state it keeps — see the module divergence
    /// notes.
    fn check_backer_anchor(&self, anchor: &Seal<'_>) -> Result<(), RegistryRejection> {
        match anchor {
            Seal::Event { i, s, d } => {
                if !Self::seal_names_registry(i, self.id) {
                    return Err(RegistryRejection::MissingRegistry);
                }
                if s.value() != self.sn.value() || d != self.latest {
                    return Err(RegistryRejection::UnresolvedAnchor { sn: s.value() });
                }
                Ok(())
            }
            // The parser rejects non-event ra anchors (corpus token
            // `anchor_shape`); this arm classifies the typed enum's other
            // variants defensively.
            _ => Err(RegistryRejection::MissingAnchor),
        }
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

    /// The rotation's anchor law (the TEL analog of the delegation path): the
    /// accepted KEL event must carry an event seal naming the rotation's
    /// `(i, s, d)` — keripy `verifyAnchor`'s seal check, digest comparison
    /// only (`vdr/eventing.py:1410-1437`).
    fn anchors_rotation(anchor: &KeriEvent<'_>, vrt: &RegistryRotation<'_>) -> bool {
        anchor.anchors().iter().any(|seal| match seal {
            Seal::Event { i, s, d } => {
                Self::seal_names_registry(i, vrt.registry())
                    && s.value() == vrt.sn().value()
                    && d == vrt.said()
            }
            _ => false,
        })
    }

    /// The threshold domain law for a backer set: 0 iff the set is empty,
    /// else 1..=count.
    fn check_backer_threshold(count: usize, toad: Toad) -> Result<(), RegistryRejection> {
        Toad::exact(toad.value(), count).map(|_| ())?;
        Ok(())
    }

    /// The `vrt` apply step: advance the management chain, replace the backer
    /// set with the resolved one, record the new threshold.
    fn rotated(self, vrt: &'e RegistryRotation<'e>, backers: Vec<BasicPrefix<'e>>) -> Self {
        Self {
            sn: vrt.sn(),
            latest: vrt.said(),
            backers: Cow::Owned(backers),
            backer_threshold: vrt.backer_threshold(),
            ..self
        }
    }
}

/// The backer cut/add algebra against the current set — the registry mirror
/// of the key-event fold's witness algebra: every removal must be a current
/// backer and disjoint from the additions, and no addition may already be
/// present.
fn resolve_backers<'e>(
    prior: &RegistryState<'e>,
    vrt: &RegistryRotation<'e>,
) -> Result<Vec<BasicPrefix<'e>>, WitnessSetError> {
    let removals = vrt.backer_cuts();
    let additions = vrt.backer_additions();
    for removal in removals {
        if !prior.backers().iter().any(|backer| backer == removal) {
            return Err(WitnessSetError::RemovalNotCurrent);
        }
        if additions.iter().any(|addition| addition == removal) {
            return Err(WitnessSetError::CutAddOverlap);
        }
    }
    let mut resolved: Vec<BasicPrefix<'_>> = prior
        .backers()
        .iter()
        .filter(|backer| !removals.iter().any(|removal| removal == *backer))
        .cloned()
        .collect();
    for addition in additions {
        if resolved.iter().any(|backer| backer == addition) {
            return Err(WitnessSetError::AdditionAlreadyPresent);
        }
        resolved.push(addition.clone());
    }
    Ok(resolved)
}
