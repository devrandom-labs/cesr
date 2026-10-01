//! Registry-state fold integration tests (P5): the fold table's every row,
//! driven through **real** signed TEL events built by the public codec
//! builders, real Ed25519 issuer/backer signatures, and the hostile
//! wire-only shapes the parse layer does not harden against (the
//! [`common`] forge technique).
//!
//! Every rejection test asserts the two guarantees that make the fold
//! custodial (the repo's law): the verdict names the taxonomy variant the
//! brief maps to keripy's `Tevery` dispositions (pin
//! `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`, `vdr/eventing.py`), and the
//! current state reads exactly as it did before the rejected ingest — no
//! partial mutation. Out-of-order sn and missing registry/issuer/anchor
//! evidence await re-drive; stale sn and duplicate inception are contested.
//!
//! Setup is fallible and flows through `?`; there is no `unwrap`/`expect`
//! in fixtures — deliberate-rejection assertions use `matches!`.
mod common;

use cesr::core::counter::CounterCodeV1;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, NoncerCode, NumberCode};
use cesr::core::primitives::{Noncer, Number, Siger};
use cesr::crypto::digest;
use cesr_stream::group::ControllerIdxSigs;
use keri::state::KeyState;
use keri::{
    CredentialState, CredentialStatus, Disposition, EvidenceKind, ExchangeError, RegistryRejection,
    RegistryState as ManagementState, RegistryStructuralError, SignedTel, TelEvidence,
    WitnessSetError,
};
use keri_codec::{
    BackedIssueBuilder, BackedRevokeBuilder, CodecError, Deserialize, DeserializeError, Exn,
    IssueBuilder, Message, RegistryInceptionBuilder, RegistryRotationBuilder, RevokeBuilder,
    Serialize, TelMessage,
};
use keri_events::{
    BasicPrefix, ConfigTrait, Identifier, MemberSetError, RegistryInception, RegistryRotation,
    Said, Seal, TelEvent, Toad, ToadError,
};
use serde::Deserialize as JsonDeserialize;
use std::num::NonZeroUsize;
use std::{collections::HashMap, ops::Deref};

use common::{
    Fallible, Key, genesis, interaction, interaction_anchoring, plain_rotation, prefix_of,
    reseal_icp, reseal_spans, seed,
};

/// Integration-only host store used to retain the existing TEL verdict matrix
/// while the public core owns only a management head and one credential head.
/// The map is intentionally outside `keri`; direct A12 tests below call the
/// canonical per-credential API without going through this adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryState {
    management: ManagementState,
    credentials: HashMap<String, CredentialState>,
}

impl Deref for RegistryState {
    type Target = ManagementState;

    fn deref(&self) -> &Self::Target {
        &self.management
    }
}

impl RegistryState {
    fn incept(signed: &SignedTel<'_>, issuer: &KeyState<'_>) -> Result<Self, RegistryRejection> {
        Ok(Self {
            management: ManagementState::incept(signed, issuer)?,
            credentials: HashMap::new(),
        })
    }

    fn incept_with_evidence(
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<Self, RegistryRejection> {
        Ok(Self {
            management: ManagementState::incept_with_evidence(signed, evidence)?,
            credentials: HashMap::new(),
        })
    }

    fn fold_optional(
        prior: Option<Self>,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<Self, RegistryRejection> {
        match prior {
            Some(mut state) => {
                state.ingest_mut(signed, evidence)?;
                Ok(state)
            }
            None if matches!(signed.event(), TelEvent::RegistryInception(_)) => {
                Self::incept_with_evidence(signed, evidence)
            }
            None => Err(RegistryRejection::MissingRegistry),
        }
    }

    fn ingest(
        mut self,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<Self, RegistryRejection> {
        self.ingest_mut(signed, evidence)?;
        Ok(self)
    }

    fn ingest_mut(
        &mut self,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
    ) -> Result<(), RegistryRejection> {
        match signed.event() {
            TelEvent::RegistryInception(_) => Err(RegistryRejection::DuplicateInception),
            TelEvent::RegistryRotation(_) => self.management.ingest_mut(signed, evidence),
            TelEvent::Issue(issue) => self.issue(signed, evidence, issue.credential_said()),
            TelEvent::BackedIssue(issue) => self.issue(signed, evidence, issue.credential_said()),
            TelEvent::Revoke(revoke) => {
                self.revoke(signed, evidence, revoke.credential_said(), revoke.sn())
            }
            TelEvent::BackedRevoke(revoke) => {
                self.revoke(signed, evidence, revoke.credential_said(), revoke.sn())
            }
        }
    }

    fn issue(
        &mut self,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
        credential: &Said<'_>,
    ) -> Result<(), RegistryRejection> {
        let candidate = CredentialState::incept(&self.management, signed, evidence)?;
        let key = credential.to_qb64();
        if self.credentials.contains_key(&key) {
            return Err(RegistryRejection::OutOfOrder {
                expected: 1,
                actual: 0,
            });
        }
        self.credentials.insert(key, candidate);
        Ok(())
    }

    fn revoke(
        &mut self,
        signed: &SignedTel<'_>,
        evidence: &TelEvidence<'_>,
        credential: &Said<'_>,
        sn: Number,
    ) -> Result<(), RegistryRejection> {
        let Some(head) = self.credentials.get_mut(&credential.to_qb64()) else {
            return Err(RegistryRejection::OutOfOrder {
                expected: 0,
                actual: sn.value(),
            });
        };
        head.ingest_mut(&self.management, signed, evidence)
    }

    fn vcstate(&self, credential: &Said<'_>) -> CredentialStatus {
        self.credentials
            .get(&credential.to_qb64())
            .map_or(CredentialStatus::Unknown, CredentialState::status)
    }

    fn management_evidence(&self) -> ManagementState {
        self.management.clone()
    }
}

/// The datetime `iss`/`rev`/`bis`/`brv` factories demand.
const DATETIME: &str = "2026-09-18T00:00:00+00:00";

/// The checked-in keripy-shaped signed exn corpus (the apply route's first
/// vector supplies the envelope shape the exn test splices its own sender
/// into).
const SIGNED_EXN: &str = include_str!("corpus/ipex/signed.jsonl");

// ── TEL fixtures ────────────────────────────────────────────────────────────

/// A parsed TEL event plus its exact wire bytes and SAID: the [`SignedTel`]
/// inputs.
struct Tel {
    event: TelEvent<'static>,
    bytes: Vec<u8>,
    said: Said<'static>,
}

impl Tel {
    /// Borrow event, bytes, and signatures into a fold input.
    const fn signed<'a>(&'a self, sigs: Vec<Siger<'a>>) -> SignedTel<'a> {
        SignedTel::from_host_asserted_parts(&self.event, self.bytes.as_slice(), sigs)
    }

    /// A host-accepted issuer KEL event at the `-G` coordinate, with a sole
    /// TEL seal. Individual fold tests use this to isolate the transition
    /// under test; the end-to-end matrix uses a real KEL chain instead.
    fn signed_anchored<'a>(
        &'a self,
        issuer_icp: &common::Event,
        sigs: Vec<Siger<'a>>,
    ) -> Fallible<SignedTel<'a>> {
        let anchor = tel_anchor_kel(issuer_icp, 1, self)?;
        let backed = matches!(
            self.event,
            TelEvent::BackedIssue(_) | TelEvent::BackedRevoke(_)
        );
        let mut signed = self
            .signed(if backed { Vec::new() } else { sigs.clone() })
            .with_source(keri::TelAnchorCoordinate::new(
                Number::new(1),
                anchor.said.clone(),
            ))
            .with_host_accepted_anchor(&anchor.parsed);
        if backed {
            signed = signed.with_backer_sigs(sigs);
        }
        Ok(signed)
    }
}

fn tel_anchor_kel(prior: &common::Event, sn: u128, tel: &Tel) -> Fallible<common::Event> {
    let tel_id = match &tel.event {
        TelEvent::RegistryInception(vcp) => vcp.said(),
        TelEvent::RegistryRotation(vrt) => vrt.registry(),
        TelEvent::Issue(iss) => iss.credential_said(),
        TelEvent::Revoke(rev) => rev.credential_said(),
        TelEvent::BackedIssue(bis) => bis.credential_said(),
        TelEvent::BackedRevoke(brv) => brv.credential_said(),
    };
    interaction_anchoring(
        prior,
        sn,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(tel_id.clone().into_static()),
            s: tel.event.sn(),
            d: tel.said.clone(),
        }],
    )
}

fn incept_anchored<'a>(
    vcp: &'a Tel,
    icp: &common::Event,
    issuer_state: &'a KeyState<'a>,
    issuer: &Key,
    backer: Option<&Key>,
) -> Fallible<RegistryState> {
    let mut signed = vcp.signed_anchored(icp, vec![issuer.sign(&vcp.bytes, 0)?])?;
    if let Some(receipt_signer) = backer {
        signed = signed.with_backer_sigs(vec![receipt_signer.sign(&vcp.bytes, 0)?]);
    }
    Ok(RegistryState::incept(&signed, issuer_state)?)
}

/// Seal a built TEL event: round-trip the builder output through the public
/// parse path (which verifies the SAID) and bundle wire bytes + SAID.
fn tel(ser: &keri_codec::SerializedEvent) -> Fallible<Tel> {
    let bytes = ser.as_bytes().to_vec();
    Ok(Tel {
        event: TelEvent::deserialize(&bytes, keri_codec::JsonLimits::new(4096, 64))?.into_static(),
        bytes,
        said: ser.said().clone().into_static(),
    })
}

/// A fresh 128-bit salt: one fixed byte repeated, so distinct fixtures pass
/// distinct bytes and get distinct registry SAIDs.
fn nonce(byte: u8) -> Fallible<Noncer<'static>> {
    Ok(MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(std::borrow::Cow::Owned(vec![byte; 16]))?
        .build()?)
}

/// A backerless `vcp` (`NB` trait) whose issuer is `issuer` (the issuer
/// AID its genesis ICP established) — the fold seed.
fn vcp_nb(issuer: &Identifier<'static>) -> Fallible<Tel> {
    tel(&RegistryInceptionBuilder::new(issuer.clone(), nonce(0x11)?)
        .config(vec![ConfigTrait::NoBackers])
        .build()?)
}

/// A `vcp` with an explicit backer set and threshold (no `NB`).
fn vcp_backers(issuer: &Identifier<'static>, backers: &[&Key], bt: u32) -> Fallible<Tel> {
    let prefixes: Vec<BasicPrefix<'static>> = backers.iter().copied().map(prefix_of).collect();
    tel(&RegistryInceptionBuilder::new(issuer.clone(), nonce(0x22)?)
        .backers(prefixes, bt)
        .build()?)
}

#[test]
fn a12_owned_management_survives_source_event_drop() -> Fallible<()> {
    let (issuer, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let registry: ManagementState = {
        let vcp = vcp_nb(&icp.prefix)?;
        let signed = vcp.signed_anchored(&icp, vec![])?;
        ManagementState::incept(&signed, &issuer_state)?
    };
    assert_eq!(registry.issuer(), &icp.prefix);
    assert!(registry.is_backerless());
    Ok(())
}

#[test]
fn a12_independent_credential_heads_retry_and_revoke() -> Fallible<()> {
    let (issuer, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let registry = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let first = credential_said(b"a12-first")?;
    let second = credential_said(b"a12-second")?;
    let second_issue = iss(&second, &vcp.said)?;
    let second_signed = second_issue.signed_anchored(&icp, vec![])?;
    let mut first_head = {
        let first_issue = iss(&first, &vcp.said)?;
        let first_signed = first_issue.signed_anchored(&icp, vec![])?;
        CredentialState::incept(&registry, &first_signed, &issuer_evidence(&issuer_state))?
    };
    let second_head =
        CredentialState::incept(&registry, &second_signed, &issuer_evidence(&issuer_state))?;
    assert_eq!(first_head.status(), CredentialStatus::Issued);
    assert_eq!(second_head.status(), CredentialStatus::Issued);

    let revoke = rev(&first, &vcp.said, first_head.head())?;
    let accepted = revoke.signed_anchored(&icp, vec![])?;
    let missing = revoke.signed(vec![]).with_source(
        accepted
            .source()
            .ok_or("anchored fixture lost its source")?
            .clone(),
    );
    assert!(matches!(
        first_head.ingest_mut(&registry, &missing, &issuer_evidence(&issuer_state)),
        Err(RegistryRejection::MissingAnchor)
    ));
    assert_eq!(first_head.status(), CredentialStatus::Issued);
    first_head.ingest_mut(&registry, &accepted, &issuer_evidence(&issuer_state))?;
    assert_eq!(first_head.status(), CredentialStatus::Revoked);
    assert_eq!(second_head.status(), CredentialStatus::Issued);
    assert_eq!(first_head.registry(), registry.id());
    assert_eq!(first_head.credential(), &first);
    Ok(())
}

#[test]
fn a12_historical_management_evidence_is_bound_to_backed_credential() -> Fallible<()> {
    let (issuer, next, old_backer, new_backer) =
        (Key::new()?, Key::new()?, Key::witness()?, Key::witness()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_backers(&icp.prefix, &[&old_backer], 1)?;
    let mut registry = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&old_backer))?;
    let historical = registry.clone();
    let rotation = vrt(
        &vcp.said,
        &vcp.said,
        &[&old_backer],
        &[&old_backer],
        &[&new_backer],
        1,
    )?;
    registry.ingest_mut(
        &rotation
            .signed_anchored(&icp, vec![])?
            .with_backer_sigs(vec![new_backer.sign(&rotation.bytes, 0)?]),
        &issuer_evidence(&issuer_state),
    )?;
    let credential = credential_said(b"a12-historical")?;
    let issuance = bis(&credential, &vcp.said, &vcp.said)?;
    let signed = issuance.signed_anchored(&icp, vec![old_backer.sign(&issuance.bytes, 0)?])?;
    assert!(matches!(
        CredentialState::incept(
            &registry,
            &signed,
            &TelEvidence::BackerAt {
                management: &registry
            }
        ),
        Err(RegistryRejection::InconsistentManagement)
    ));
    let mut head = CredentialState::incept(
        &registry,
        &signed,
        &TelEvidence::BackerAt {
            management: &historical,
        },
    )?;
    let revocation = brv(&credential, &issuance.said, &vcp.said, &vcp.said)?;
    let signed_revoke =
        revocation.signed_anchored(&icp, vec![old_backer.sign(&revocation.bytes, 0)?])?;
    head.ingest_mut(
        &registry,
        &signed_revoke,
        &TelEvidence::BackerAt {
            management: &historical,
        },
    )?;
    assert_eq!(head.status(), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn a12_credential_transition_checks_registry_and_chain_identity() -> Fallible<()> {
    let (issuer, next, foreign_issuer, foreign_next) =
        (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let registry = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let foreign_icp = genesis(&foreign_issuer, &foreign_next)?;
    let foreign_state = seed(&foreign_icp, &foreign_issuer)?;
    let other_registry_inception = vcp_nb(&foreign_icp.prefix)?;
    let foreign_registry = incept_anchored(
        &other_registry_inception,
        &foreign_icp,
        &foreign_state,
        &foreign_issuer,
        None,
    )?;
    let first = credential_said(b"a12-binding-first")?;
    let second = credential_said(b"a12-binding-second")?;
    let issuance = iss(&first, &vcp.said)?;
    let signed = issuance.signed_anchored(&icp, vec![])?;
    assert!(matches!(
        CredentialState::incept(&foreign_registry, &signed, &issuer_evidence(&foreign_state)),
        Err(RegistryRejection::InconsistentRegistry)
    ));
    let mut head = CredentialState::incept(&registry, &signed, &issuer_evidence(&issuer_state))?;
    let wrong_credential = rev(&second, &vcp.said, &issuance.said)?;
    assert!(matches!(
        head.ingest_mut(
            &registry,
            &wrong_credential.signed_anchored(&icp, vec![])?,
            &issuer_evidence(&issuer_state)
        ),
        Err(RegistryRejection::InconsistentCredential)
    ));
    assert_eq!(head.status(), CredentialStatus::Issued);
    Ok(())
}

#[test]
fn a11_registry_retries_missing_anchor_on_the_same_owned_state() -> Fallible<()> {
    let (issuer, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let mut state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let credential = credential_said(b"a11-retry")?;
    let issuance = iss(&credential, &vcp.said)?;
    let accepted = issuance.signed_anchored(&icp, vec![])?;
    let missing = issuance.signed(vec![]).with_source(
        accepted
            .source()
            .ok_or("anchored fixture lost its source")?
            .clone(),
    );
    let original_head = state.latest().to_qb64b();

    assert!(matches!(
        state.ingest_mut(&missing, &issuer_evidence(&issuer_state)),
        Err(RegistryRejection::MissingAnchor)
    ));
    assert_eq!(state.latest().to_qb64b(), original_head);
    assert_eq!(state.vcstate(&credential), CredentialStatus::Unknown);

    state.ingest_mut(&accepted, &issuer_evidence(&issuer_state))?;
    assert_eq!(state.vcstate(&credential), CredentialStatus::Issued);
    assert!(matches!(
        state.ingest_mut(&accepted, &issuer_evidence(&issuer_state)),
        Err(RegistryRejection::OutOfOrder { .. })
    ));
    assert_eq!(state.vcstate(&credential), CredentialStatus::Issued);
    Ok(())
}

#[test]
fn a11_registry_rotation_rejects_late_receipt_without_advancing() -> Fallible<()> {
    let (issuer, next, old_backer, new_backer) =
        (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_backers(&icp.prefix, &[&old_backer], 1)?;
    let mut state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&old_backer))?;
    let rotation = vrt(
        &vcp.said,
        &vcp.said,
        &[&old_backer],
        &[&old_backer],
        &[&new_backer],
        1,
    )?;
    let signed = rotation.signed_anchored(&icp, vec![])?;
    let rejected = signed
        .clone()
        .with_backer_sigs(vec![old_backer.sign(&rotation.bytes, 0)?]);
    assert!(matches!(
        state.ingest_mut(&rejected, &issuer_evidence(&issuer_state)),
        Err(RegistryRejection::MissingBackerReceipts {
            valid: 0,
            required: 1
        })
    ));
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.backers(), &[prefix_of(&old_backer)]);

    let accepted = signed.with_backer_sigs(vec![new_backer.sign(&rotation.bytes, 0)?]);
    state.ingest_mut(&accepted, &issuer_evidence(&issuer_state))?;
    assert_eq!(state.sn().value(), 1);
    assert_eq!(state.backers(), &[prefix_of(&new_backer)]);
    Ok(())
}

#[test]
fn duplicate_backer_vcp_wire_and_fold_are_rejected() -> Fallible<()> {
    let (issuer, next, backer) = (Key::new()?, Key::new()?, Key::witness()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let valid = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let TelEvent::RegistryInception(vcp) = &valid.event else {
        return Err("vcp fixture parsed as another event".into());
    };
    let duplicate = prefix_of(&backer);
    let malformed = TelEvent::RegistryInception(RegistryInception::new_unchecked(
        vcp.said().clone(),
        vcp.issuer().clone(),
        vcp.config().clone(),
        Toad::exact(2, 2)?,
        vec![duplicate.clone(), duplicate],
        vcp.nonce().clone(),
    ));
    let serialized = malformed.serialize()?;
    assert!(matches!(
        TelEvent::deserialize(serialized.as_bytes(), keri_codec::JsonLimits::new(4096, 64)),
        Err(CodecError::Deserialize(DeserializeError::MemberSet(
            MemberSetError::Duplicate { set: "backers" }
        )))
    ));
    let signed = SignedTel::from_host_asserted_parts(
        &malformed,
        serialized.as_bytes(),
        vec![issuer.sign(serialized.as_bytes(), 0)?],
    );
    assert!(matches!(
        RegistryState::incept(&signed, &issuer_state),
        Err(RegistryRejection::BackerSet(WitnessSetError::Membership(
            MemberSetError::Duplicate { set: "backers" }
        )))
    ));
    Ok(())
}

/// A `vrt` for `registry` chaining onto `prior`, whose cut/add deltas are
/// validated against `prior_backers` (the builder's own laws).
#[allow(
    clippy::too_many_arguments,
    reason = "test fixture mirrors the six wire fields of a vrt"
)]
fn vrt(
    registry: &Said<'static>,
    prior: &Said<'static>,
    prior_backers: &[&Key],
    cuts: &[&Key],
    adds: &[&Key],
    bt: u32,
) -> Fallible<Tel> {
    tel(&RegistryRotationBuilder::new(
        registry.clone(),
        prior.clone(),
        prior_backers.iter().copied().map(prefix_of).collect(),
        1,
    )
    .backer_threshold(bt)
    .backer_rotation(
        cuts.iter().copied().map(prefix_of).collect(),
        adds.iter().copied().map(prefix_of).collect(),
    )
    .build()?)
}

/// An `iss` into `registry` for `credential` (sn 0, no `p`).
fn iss(credential: &Said<'static>, registry: &Said<'static>) -> Fallible<Tel> {
    tel(&IssueBuilder::new(credential.clone(), registry.clone(), DATETIME).build()?)
}

/// A `rev` chaining onto the issued chain head `prior`.
fn rev(
    credential: &Said<'static>,
    registry: &Said<'static>,
    prior: &Said<'static>,
) -> Fallible<Tel> {
    tel(&RevokeBuilder::new(
        credential.clone(),
        registry.clone(),
        prior.clone(),
        DATETIME,
    )
    .build()?)
}

/// A `bis` for `credential` whose `ra` anchor names the registry's
/// management event at `(registry, 0, management_said)`.
fn bis(
    credential: &Said<'static>,
    registry: &Said<'static>,
    management: &Said<'static>,
) -> Fallible<Tel> {
    tel(&BackedIssueBuilder::new(
        credential.clone(),
        registry.clone(),
        Seal::Event {
            i: Identifier::SelfAddressing(registry.clone()),
            s: Number::new(0),
            d: management.clone(),
        },
        DATETIME,
    )
    .build()?)
}

/// A `brv` chaining onto `prior`, anchored at the registry's management
/// event.
fn brv(
    credential: &Said<'static>,
    prior: &Said<'static>,
    registry: &Said<'static>,
    management: &Said<'static>,
) -> Fallible<Tel> {
    tel(&BackedRevokeBuilder::new(
        credential.clone(),
        prior.clone(),
        Seal::Event {
            i: Identifier::SelfAddressing(registry.clone()),
            s: Number::new(0),
            d: management.clone(),
        },
        DATETIME,
    )
    .build()?)
}

/// A credential SAID for test chains (deterministic per label).
fn credential_said(label: &[u8]) -> Fallible<Said<'static>> {
    Ok(Said::from_matter(digest(DigestCode::Blake3_256, label)?))
}

/// A real V1 attachment frame with the TEL `-G` source couple and optional
/// `-B` indexed backer receipt, as pinned keripy's `messagize` emits it.
fn tel_source_frame(
    tel: &Tel,
    anchor_sn: u128,
    anchor: &Said<'_>,
    backer: Option<&Siger<'_>>,
) -> Fallible<Vec<u8>> {
    fn counter(code: CounterCodeV1, count: u32) -> Fallible<Vec<u8>> {
        let soft_size = NonZeroUsize::new(code.soft_size()).ok_or("zero counter soft size")?;
        let soft = cesr::b64::encode_int(count, soft_size);
        Ok(format!("{}{}", code.as_str(), soft).into_bytes())
    }
    let mut groups = counter(CounterCodeV1::SealSourceCouples, 1)?;
    let seqner = MatterBuilder::new()
        .with_code(NumberCode::Short)
        .with_raw(std::borrow::Cow::Owned(
            u16::try_from(anchor_sn)?.to_be_bytes().to_vec(),
        ))?
        .build()?;
    groups.extend_from_slice(&seqner.to_qb64b());
    groups.extend_from_slice(&anchor.to_qb64b());
    if let Some(siger) = backer {
        groups.extend_from_slice(&counter(CounterCodeV1::WitnessIdxSigs, 1)?);
        groups.extend_from_slice(siger.to_qb64().as_bytes());
    }
    assert_eq!(groups.len() % 4, 0);
    let mut wire = tel.bytes.clone();
    wire.extend_from_slice(&counter(
        CounterCodeV1::AttachmentGroup,
        u32::try_from(groups.len() / 4)?,
    )?);
    wire.extend_from_slice(&groups);
    Ok(wire)
}

fn parse_tel(wire: &[u8]) -> Fallible<Box<TelMessage<'_>>> {
    let (Message::Tel(msg), rest) = Message::parse(wire, common::message_limits())? else {
        return Err("frame did not route to TEL".into());
    };
    if !rest.is_empty() {
        return Err("TEL frame left unconsumed bytes".into());
    }
    Ok(msg)
}

fn assert_awaiting_kel_anchor(result: Result<RegistryState, RegistryRejection>) -> Fallible<()> {
    let error = result
        .err()
        .ok_or("missing accepted KEL anchor was accepted")?;
    assert!(matches!(error, RegistryRejection::MissingAnchor), "{error}");
    assert_eq!(
        error.disposition(),
        Disposition::Awaiting(EvidenceKind::KelAnchor)
    );
    Ok(())
}

#[test]
fn framed_backerless_tel_chain_uses_each_kel_source() -> Fallible<()> {
    // Backerless branch: vcp -> iss -> rev, each with a successive issuer
    // KEL interaction and a real `-V/-G` TEL frame.
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let kel1 = tel_anchor_kel(&icp, 1, &vcp)?;
    let wire_vcp = tel_source_frame(&vcp, 1, &kel1.said, None)?;
    let msg_vcp = parse_tel(&wire_vcp)?;
    assert_awaiting_kel_anchor(RegistryState::incept(
        &SignedTel::from(msg_vcp.as_ref()),
        &issuer_state,
    ))?;
    let state = RegistryState::incept(
        &SignedTel::from(msg_vcp.as_ref()).with_host_accepted_anchor(&kel1.parsed),
        &issuer_state,
    )?;

    let credential = credential_said(b"six-ilk-simple")?;
    let issuance = iss(&credential, &vcp.said)?;
    let kel2 = tel_anchor_kel(&kel1, 2, &issuance)?;
    let wire_iss = tel_source_frame(&issuance, 2, &kel2.said, None)?;
    let msg_iss = parse_tel(&wire_iss)?;
    assert_awaiting_kel_anchor(state.clone().ingest(
        &SignedTel::from(msg_iss.as_ref()),
        &issuer_evidence(&issuer_state),
    ))?;
    let after_issue = state.ingest(
        &SignedTel::from(msg_iss.as_ref()).with_host_accepted_anchor(&kel2.parsed),
        &issuer_evidence(&issuer_state),
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);

    let revocation = rev(&credential, &vcp.said, &issuance.said)?;
    let kel3 = tel_anchor_kel(&kel2, 3, &revocation)?;
    let wire_rev = tel_source_frame(&revocation, 3, &kel3.said, None)?;
    let msg_rev = parse_tel(&wire_rev)?;
    assert_awaiting_kel_anchor(after_issue.clone().ingest(
        &SignedTel::from(msg_rev.as_ref()),
        &issuer_evidence(&issuer_state),
    ))?;
    let revoked = after_issue.ingest(
        &SignedTel::from(msg_rev.as_ref()).with_host_accepted_anchor(&kel3.parsed),
        &issuer_evidence(&issuer_state),
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn framed_backed_tel_chain_uses_historical_receipts() -> Fallible<()> {
    // Backed branch: vcp -> vrt -> bis -> brv. The credential events use
    // historical vcp backer A after vrt replaces A with B.
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let a = Key::witness()?;
    let b = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&a], 1)?;
    let kel1 = tel_anchor_kel(&icp, 1, &vcp)?;
    let vcp_receipt = a.sign(&vcp.bytes, 0)?;
    let wire_vcp = tel_source_frame(&vcp, 1, &kel1.said, Some(&vcp_receipt))?;
    let msg_vcp = parse_tel(&wire_vcp)?;
    let transient = SignedTel::from(msg_vcp.as_ref());
    assert_eq!(
        transient.backer_sigs().as_ptr(),
        msg_vcp.backer_sigs().as_ptr()
    );
    assert_awaiting_kel_anchor(RegistryState::incept(
        &SignedTel::from(msg_vcp.as_ref()),
        &issuer_state,
    ))?;
    let state = RegistryState::incept(
        &SignedTel::from(msg_vcp.as_ref()).with_host_accepted_anchor(&kel1.parsed),
        &issuer_state,
    )?;
    let historical = state.management_evidence();

    let rotation = vrt(&vcp.said, &vcp.said, &[&a], &[&a], &[&b], 1)?;
    let kel2 = tel_anchor_kel(&kel1, 2, &rotation)?;
    let vrt_receipt = b.sign(&rotation.bytes, 0)?;
    let wire_vrt = tel_source_frame(&rotation, 2, &kel2.said, Some(&vrt_receipt))?;
    let msg_vrt = parse_tel(&wire_vrt)?;
    assert_awaiting_kel_anchor(state.clone().ingest(
        &SignedTel::from(msg_vrt.as_ref()),
        &issuer_evidence(&issuer_state),
    ))?;
    let rotated = state.ingest(
        &SignedTel::from(msg_vrt.as_ref()).with_host_accepted_anchor(&kel2.parsed),
        &issuer_evidence(&issuer_state),
    )?;
    assert!(rotated.backers().contains(&prefix_of(&b)));

    let credential = credential_said(b"six-ilk-backed")?;
    let issuance = bis(&credential, &vcp.said, &vcp.said)?;
    let kel3 = tel_anchor_kel(&kel2, 3, &issuance)?;
    let bis_receipt = a.sign(&issuance.bytes, 0)?;
    let wire_bis = tel_source_frame(&issuance, 3, &kel3.said, Some(&bis_receipt))?;
    let msg_bis = parse_tel(&wire_bis)?;
    assert_awaiting_kel_anchor(rotated.clone().ingest(
        &SignedTel::from(msg_bis.as_ref()),
        &TelEvidence::BackerAt {
            management: &historical,
        },
    ))?;
    let after_issue = rotated.ingest(
        &SignedTel::from(msg_bis.as_ref()).with_host_accepted_anchor(&kel3.parsed),
        &TelEvidence::BackerAt {
            management: &historical,
        },
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);

    let revocation = brv(&credential, &issuance.said, &vcp.said, &vcp.said)?;
    let kel4 = tel_anchor_kel(&kel3, 4, &revocation)?;
    let brv_receipt = a.sign(&revocation.bytes, 0)?;
    let wire_brv = tel_source_frame(&revocation, 4, &kel4.said, Some(&brv_receipt))?;
    let msg_brv = parse_tel(&wire_brv)?;
    assert_awaiting_kel_anchor(after_issue.clone().ingest(
        &SignedTel::from(msg_brv.as_ref()),
        &TelEvidence::BackerAt {
            management: &historical,
        },
    ))?;
    let revoked = after_issue.ingest(
        &SignedTel::from(msg_brv.as_ref()).with_host_accepted_anchor(&kel4.parsed),
        &TelEvidence::BackerAt {
            management: &historical,
        },
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn framed_tel_redrives_after_issuer_key_rotation_and_prior_event() -> Fallible<()> {
    let first_key = Key::new()?;
    let revealed_key = Key::new()?;
    let following_key = Key::new()?;
    let icp = genesis(&first_key, &revealed_key)?;
    let issuer_initial = seed(&icp, &first_key)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let kel1 = tel_anchor_kel(&icp, 1, &vcp)?;
    let vcp_frame = tel_source_frame(&vcp, 1, &kel1.said, None)?;
    let vcp_msg = parse_tel(&vcp_frame)?;
    let registry = RegistryState::incept(
        &SignedTel::from(vcp_msg.as_ref()).with_host_accepted_anchor(&kel1.parsed),
        &issuer_initial,
    )?;

    let after_kel1 = issuer_initial
        .clone()
        .ingest(&kel1.signed(vec![first_key.sign(&kel1.bytes, 0)?]))?;
    let kel2 = plain_rotation(&kel1, 2, &revealed_key, &following_key)?;
    let current_issuer =
        after_kel1.ingest(&kel2.signed(vec![revealed_key.sign_dual(&kel2.bytes, 0, 0)?]))?;
    assert_eq!(current_issuer.sn().value(), 2);

    let credential = credential_said(b"issuer-key-rotation-redrive")?;
    let issuance = iss(&credential, &vcp.said)?;
    let kel3 = tel_anchor_kel(&kel2, 3, &issuance)?;
    let issue_frame = tel_source_frame(&issuance, 3, &kel3.said, None)?;
    let issue_msg = parse_tel(&issue_frame)?;
    let revocation = rev(&credential, &vcp.said, &issuance.said)?;
    let kel4 = tel_anchor_kel(&kel3, 4, &revocation)?;
    let revoke_frame = tel_source_frame(&revocation, 4, &kel4.said, None)?;
    let revoke_msg = parse_tel(&revoke_frame)?;

    let premature = registry.clone().ingest(
        &SignedTel::from(revoke_msg.as_ref()).with_host_accepted_anchor(&kel4.parsed),
        &issuer_evidence(&current_issuer),
    );
    assert!(matches!(
        premature,
        Err(RegistryRejection::OutOfOrder {
            expected: 0,
            actual: 1
        })
    ));
    assert_eq!(
        premature
            .err()
            .ok_or("expected out-of-order event")?
            .disposition(),
        Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 0 })
    );
    let after_issue = registry.ingest(
        &SignedTel::from(issue_msg.as_ref()).with_host_accepted_anchor(&kel3.parsed),
        &issuer_evidence(&current_issuer),
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);
    assert_awaiting_kel_anchor(after_issue.clone().ingest(
        &SignedTel::from(revoke_msg.as_ref()),
        &issuer_evidence(&current_issuer),
    ))?;
    let after_revoke = after_issue.ingest(
        &SignedTel::from(revoke_msg.as_ref()).with_host_accepted_anchor(&kel4.parsed),
        &issuer_evidence(&current_issuer),
    )?;
    assert_eq!(after_revoke.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn tel_kel_anchor_rejects_wrong_issuer_sn_said_and_seal_cardinality() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let correct = tel_anchor_kel(&icp, 1, &vcp)?;
    let wrong_seal = interaction_anchoring(
        &icp,
        1,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(vcp.said.clone()),
            s: Number::new(0),
            d: credential_said(b"wrong-tel-digest")?,
        }],
    )?;
    let duplicate_seal = Seal::Event {
        i: Identifier::SelfAddressing(vcp.said.clone()),
        s: Number::new(0),
        d: vcp.said.clone(),
    };
    let multiple = interaction_anchoring(&icp, 1, vec![duplicate_seal.clone(), duplicate_seal])?;
    let foreign = Key::new()?;
    let foreign_icp = genesis(&foreign, &Key::new()?)?;
    let foreign_kel = tel_anchor_kel(&foreign_icp, 1, &vcp)?;

    for (anchor, source_sn, source_said) in [
        (&correct, 2, correct.said.clone()),
        (&correct, 1, credential_said(b"wrong-kel-said")?),
        (&wrong_seal, 1, wrong_seal.said.clone()),
        (&multiple, 1, multiple.said.clone()),
        (&foreign_kel, 1, foreign_kel.said.clone()),
    ] {
        let signed = vcp
            .signed(vec![])
            .with_source(keri::TelAnchorCoordinate::new(
                Number::new(source_sn),
                source_said,
            ))
            .with_host_accepted_anchor(&anchor.parsed);
        let error = RegistryState::incept(&signed, &issuer_state).unwrap_err();
        assert!(matches!(error, RegistryRejection::InconsistentAnchor));
        assert_eq!(error.disposition(), Disposition::Terminal);
    }
    Ok(())
}

#[test]
fn backed_ra_requires_matching_registry_sn_and_management_said() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let backer = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&backer))?;
    let historical = state.management_evidence();
    let credential = credential_said(b"wrong-historical-coordinate")?;
    let foreign_registry = credential_said(b"foreign-registry")?;
    let mut malformed_cases = Vec::new();
    for (registry, sn, said, expected_registry_error) in [
        (foreign_registry, 0, vcp.said.clone(), true),
        (vcp.said.clone(), 1, vcp.said.clone(), false),
        (
            vcp.said.clone(),
            0,
            credential_said(b"wrong-management-said")?,
            false,
        ),
    ] {
        let malformed = tel(&BackedIssueBuilder::new(
            credential.clone(),
            vcp.said.clone(),
            Seal::Event {
                i: Identifier::SelfAddressing(registry),
                s: Number::new(sn),
                d: said,
            },
            DATETIME,
        )
        .build()?)?;
        malformed_cases.push((malformed, expected_registry_error));
    }
    for (malformed, expected_registry_error) in &malformed_cases {
        let signed = malformed.signed_anchored(&icp, vec![backer.sign(&malformed.bytes, 0)?])?;
        let error = state
            .clone()
            .ingest(
                &signed,
                &TelEvidence::BackerAt {
                    management: &historical,
                },
            )
            .unwrap_err();
        assert!(
            matches!(
                error,
                RegistryRejection::InconsistentRegistry if *expected_registry_error
            ) || matches!(
                error,
                RegistryRejection::InconsistentManagement if !*expected_registry_error
            )
        );
        assert_eq!(error.disposition(), Disposition::Terminal);
    }
    Ok(())
}

#[test]
fn tel_public_wire_accepts_source_couple_and_backer_receipt() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let backer = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let anchor = interaction_anchoring(
        &icp,
        1,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(vcp.said.clone()),
            s: Number::new(0),
            d: vcp.said.clone(),
        }],
    )?;
    let receipt = backer.sign(&vcp.bytes, 0)?;
    let wire = tel_source_frame(&vcp, 1, &anchor.said, Some(&receipt))?;
    let (Message::Tel(parsed), rest) = Message::parse(&wire, common::message_limits())? else {
        return Err("framed vcp did not route to TEL".into());
    };
    assert!(rest.is_empty());
    assert_eq!(parsed.body(), vcp.bytes);
    assert_eq!(parsed.event(), &vcp.event);
    let source = parsed.source().ok_or("TEL source couple was dropped")?;
    assert_eq!(source.sn().value(), 1);
    assert_eq!(source.said(), &anchor.said);
    assert_eq!(parsed.backer_sigs().len(), 1);
    assert_eq!(parsed.backer_sigs()[0].to_qb64(), receipt.to_qb64());
    let signed = SignedTel::from(parsed.as_ref());
    assert_eq!(
        signed
            .source()
            .ok_or("source lost at fold boundary")?
            .sn()
            .value(),
        1
    );
    assert_eq!(signed.backer_sigs().len(), 1);
    Ok(())
}

#[test]
fn framed_vcp_source_requires_the_exact_accepted_kel_event() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let seal = Seal::Event {
        i: Identifier::SelfAddressing(vcp.said.clone()),
        s: Number::new(0),
        d: vcp.said.clone(),
    };
    let accepted_kel = interaction_anchoring(&icp, 1, vec![seal])?;
    let wire = tel_source_frame(&vcp, 1, &accepted_kel.said, None)?;
    let (Message::Tel(msg), rest) = Message::parse(&wire, common::message_limits())? else {
        return Err("vcp frame did not route to TEL".into());
    };
    assert!(rest.is_empty());

    let without_host_kel = SignedTel::from(msg.as_ref());
    let absent = RegistryState::incept(&without_host_kel, &issuer_state);
    assert!(matches!(absent, Err(RegistryRejection::MissingAnchor)));
    assert_eq!(
        absent.unwrap_err().disposition(),
        Disposition::Awaiting(EvidenceKind::KelAnchor)
    );

    let wrong_kel = interaction(&icp, 1)?;
    let inconsistent = RegistryState::incept(
        &SignedTel::from(msg.as_ref()).with_host_accepted_anchor(&wrong_kel.parsed),
        &issuer_state,
    );
    assert!(matches!(
        inconsistent,
        Err(RegistryRejection::InconsistentAnchor)
    ));
    assert_eq!(
        inconsistent.unwrap_err().disposition(),
        Disposition::Terminal
    );

    let accepted = RegistryState::incept(
        &SignedTel::from(msg.as_ref()).with_host_accepted_anchor(&accepted_kel.parsed),
        &issuer_state,
    )?;
    assert_eq!(accepted.id(), &vcp.said);
    Ok(())
}

#[test]
fn framed_bis_backer_receipt_reaches_fold_without_controller_signature() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let backer = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&backer))?;
    let credential = credential_said(b"framed-backed-credential")?;
    let issuance = bis(&credential, &vcp.said, &vcp.said)?;
    let seal = Seal::Event {
        i: Identifier::SelfAddressing(credential.clone()),
        s: Number::new(0),
        d: issuance.said.clone(),
    };
    let kel = interaction_anchoring(&icp, 1, vec![seal])?;
    let receipt = backer.sign(&issuance.bytes, 0)?;
    let wire = tel_source_frame(&issuance, 1, &kel.said, Some(&receipt))?;
    let (Message::Tel(msg), rest) = Message::parse(&wire, common::message_limits())? else {
        return Err("bis frame did not route to TEL".into());
    };
    assert!(rest.is_empty());
    assert!(msg.sigs().is_empty());
    assert_eq!(msg.backer_sigs().len(), 1);
    let signed = SignedTel::from(msg.as_ref()).with_host_accepted_anchor(&kel.parsed);
    let accepted = state.ingest(&signed, &TelEvidence::Backer)?;
    assert_eq!(accepted.vcstate(&credential), CredentialStatus::Issued);
    Ok(())
}

#[test]
fn bis_uses_historical_backers_after_management_rotation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let old_backer = Key::witness()?;
    let new_backer = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&old_backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&old_backer))?;
    let historical = state.management_evidence();
    let rotation = vrt(
        &vcp.said,
        &vcp.said,
        &[&old_backer],
        &[&old_backer],
        &[&new_backer],
        1,
    )?;
    let rotated = state.ingest(
        &rotation
            .signed_anchored(&icp, vec![])?
            .with_backer_sigs(vec![new_backer.sign(&rotation.bytes, 0)?]),
        &issuer_evidence(&issuer_state),
    )?;
    assert!(!rotated.backers().contains(&prefix_of(&old_backer)));
    assert_eq!(historical.sn().value(), 0);
    assert_eq!(historical.latest(), &vcp.said);
    assert_eq!(historical.backer_threshold().value(), 1);
    assert_eq!(historical.backers(), &[prefix_of(&old_backer)]);
    let later = rotated.management_evidence();
    assert_eq!(later.sn().value(), 1);
    assert_eq!(later.latest(), &rotation.said);
    assert_eq!(later.backers(), &[prefix_of(&new_backer)]);

    let credential = credential_said(b"historical-backers")?;
    let issuance = bis(&credential, &vcp.said, &vcp.said)?;
    let signed = issuance.signed_anchored(&icp, vec![old_backer.sign(&issuance.bytes, 0)?])?;
    let missing_history = rotated.clone().ingest(&signed, &TelEvidence::Backer);
    assert!(matches!(
        missing_history,
        Err(RegistryRejection::UnresolvedAnchor { sn: 0 })
    ));
    assert_eq!(
        missing_history.unwrap_err().disposition(),
        Disposition::Awaiting(EvidenceKind::TelAnchor { sn: 0 })
    );
    let contradictory = rotated
        .clone()
        .ingest(&signed, &TelEvidence::BackerAt { management: &later });
    assert!(matches!(
        contradictory,
        Err(RegistryRejection::InconsistentManagement)
    ));
    assert_eq!(
        contradictory.unwrap_err().disposition(),
        Disposition::Terminal
    );
    let after_issue = rotated.ingest(
        &signed,
        &TelEvidence::BackerAt {
            management: &historical,
        },
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);
    let revocation = brv(&credential, &issuance.said, &vcp.said, &vcp.said)?;
    let signed_revoke =
        revocation.signed_anchored(&icp, vec![old_backer.sign(&revocation.bytes, 0)?])?;
    let revoked = after_issue.ingest(
        &signed_revoke,
        &TelEvidence::BackerAt {
            management: &historical,
        },
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn signed_backed_revocation_rejects_credential_said_in_registry_anchor() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let backer = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&backer))?;
    let management = state.management_evidence();
    let credential = credential_said(b"wrong-registry-anchor")?;
    let issuance = bis(&credential, &vcp.said, &vcp.said)?;
    let signed_issue = issuance.signed_anchored(&icp, vec![backer.sign(&issuance.bytes, 0)?])?;
    let credential_state = state.ingest(
        &signed_issue,
        &TelEvidence::BackerAt {
            management: &management,
        },
    )?;
    let wrong = brv(&credential, &issuance.said, &vcp.said, &issuance.said)?;
    let signed_wrong = wrong.signed_anchored(&icp, vec![backer.sign(&wrong.bytes, 0)?])?;
    assert!(matches!(
        credential_state.clone().ingest(
            &signed_wrong,
            &TelEvidence::BackerAt {
                management: &management,
            },
        ),
        Err(RegistryRejection::InconsistentManagement)
    ));
    assert_eq!(
        credential_state.vcstate(&credential),
        CredentialStatus::Issued
    );
    Ok(())
}

#[test]
fn backed_management_events_wait_for_post_event_backer_receipts() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let first_backer = Key::witness()?;
    let next_backer = Key::witness()?;
    let vcp = vcp_backers(&icp.prefix, &[&first_backer], 1)?;
    let signed_vcp = vcp.signed_anchored(&icp, vec![])?;
    let pending_vcp = RegistryState::incept(&signed_vcp, &issuer_state);
    assert!(matches!(
        pending_vcp,
        Err(RegistryRejection::MissingBackerReceipts {
            valid: 0,
            required: 1
        })
    ));
    let state = RegistryState::incept(
        &signed_vcp.with_backer_sigs(vec![first_backer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let rotation = vrt(
        &vcp.said,
        &vcp.said,
        &[&first_backer],
        &[&first_backer],
        &[&next_backer],
        1,
    )?;
    let signed_vrt = rotation.signed_anchored(&icp, vec![])?;
    let pending_vrt = state
        .clone()
        .ingest(&signed_vrt, &issuer_evidence(&issuer_state));
    assert!(matches!(
        pending_vrt,
        Err(RegistryRejection::MissingBackerReceipts {
            valid: 0,
            required: 1
        })
    ));
    let rotated = state.ingest(
        &signed_vrt.with_backer_sigs(vec![next_backer.sign(&rotation.bytes, 0)?]),
        &issuer_evidence(&issuer_state),
    )?;
    assert!(rotated.backers().contains(&prefix_of(&next_backer)));
    Ok(())
}

#[test]
fn signed_vcp_without_accepted_kel_anchor_awaits_anchor() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let result = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    );
    assert!(matches!(result, Err(RegistryRejection::MissingAnchor)));
    assert!(matches!(
        result.unwrap_err().disposition(),
        Disposition::Awaiting(_)
    ));
    Ok(())
}

#[test]
fn signed_iss_without_accepted_kel_anchor_awaits_anchor() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let issuance = iss(&credential_said(b"unanchored")?, &vcp.said)?;
    let result = state.ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
        &issuer_evidence(&issuer_state),
    );
    assert!(matches!(result, Err(RegistryRejection::MissingAnchor)));
    Ok(())
}

#[test]
fn missing_registry_and_issuer_evidence_can_be_redriven() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let signed_vcp = vcp.signed_anchored(&icp, vec![])?;
    let absent_issuer = RegistryState::fold_optional(None, &signed_vcp, &TelEvidence::Missing);
    assert!(matches!(
        absent_issuer,
        Err(RegistryRejection::MissingIssuer)
    ));
    assert_eq!(
        absent_issuer.unwrap_err().disposition(),
        Disposition::Awaiting(EvidenceKind::IssuerState)
    );

    let state = RegistryState::fold_optional(
        None,
        &signed_vcp,
        &TelEvidence::Issuer {
            state: &issuer_state,
            anchor: None,
        },
    )?;
    let credential = credential_said(b"delayed-registry")?;
    let issuance = iss(&credential, &vcp.said)?;
    let signed_iss = issuance.signed_anchored(&icp, vec![])?;
    let absent_registry =
        RegistryState::fold_optional(None, &signed_iss, &issuer_evidence(&issuer_state));
    assert!(matches!(
        absent_registry,
        Err(RegistryRejection::MissingRegistry)
    ));
    assert_eq!(
        absent_registry.unwrap_err().disposition(),
        Disposition::Awaiting(EvidenceKind::RegistryState)
    );
    let accepted =
        RegistryState::fold_optional(Some(state), &signed_iss, &issuer_evidence(&issuer_state))?;
    assert_eq!(accepted.vcstate(&credential), CredentialStatus::Issued);
    Ok(())
}

/// The issuer-signed evidence class (no KEL anchor — the `iss`/`rev` path).
const fn issuer_evidence<'e>(state: &'e KeyState<'e>) -> TelEvidence<'e> {
    TelEvidence::Issuer {
        state,
        anchor: None,
    }
}

/// The management anchor for a `vrt`: an interaction in the issuer's KEL
/// whose seals carry the rotation's event seal.
fn anchored_rotation(
    icp: &common::Event,
    registry: &Said<'static>,
    rotation: &Tel,
) -> Fallible<common::Event> {
    interaction_anchoring(
        icp,
        1,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(registry.clone()),
            s: Number::new(1),
            d: rotation.said.clone(),
        }],
    )
}

/// The state-preservation guarantee every rejection test asserts: after a
/// rejected ingest the current state reads exactly as the captured `before`.
fn assert_intact(before: &RegistryState, state: &RegistryState) -> Fallible<()> {
    assert_eq!(
        before.sn().value(),
        state.sn().value(),
        "rejected ingest moved the management chain"
    );
    assert_eq!(
        before.latest(),
        state.latest(),
        "rejected ingest moved the head"
    );
    assert_eq!(
        before.backers(),
        state.backers(),
        "rejected ingest moved the backer set"
    );
    let probe = credential_said(b"status-probe")?;
    assert_eq!(
        before.vcstate(&probe),
        state.vcstate(&probe),
        "rejected ingest changed credential status"
    );
    Ok(())
}

// ── vcp: registry inception ─────────────────────────────────────────────────

/// Fold table, row `vcp`: the registry is seeded from its own inception —
/// id = the vcp SAID (`i == d`), issuer = `i`, management chain at sn 0,
/// backer set from `b` (empty under `NB`), credentials empty (keripy
/// `initializeRegistryState`).
#[test]
fn vcp_seeds_registry_fold() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;

    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;

    assert_eq!(
        state.id(),
        &vcp.said,
        "registry id is the vcp SAID (i == d)"
    );
    assert_eq!(
        state.issuer(),
        &icp.prefix,
        "the issuer is the AID its ICP established"
    );
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.latest(), &vcp.said);
    assert!(state.is_backerless());
    assert!(state.backers().is_empty());
    assert_eq!(
        state.vcstate(&credential_said(b"none")?),
        CredentialStatus::Unknown,
        "a fresh registry records no credential chains"
    );
    Ok(())
}

/// Fold table, row `vcp` (backered): a non-`NB` inception seeds the backer
/// fold — the exact backer set and threshold the vcp carries (keripy
/// `incept` backer branch).
#[test]
fn vcp_with_backers_seeds_backer_fold() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let b2 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1, &b2], 1)?;

    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b1))?;

    assert!(!state.is_backerless());
    assert_eq!(state.backers().len(), 2);
    assert!(state.backers().contains(&prefix_of(&b1)));
    assert!(state.backers().contains(&prefix_of(&b2)));
    Ok(())
}

#[test]
fn accepted_backer_rotation_preserves_survivor_then_addition_order() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let (b0, b1, b2, b3, b4) = (
        Key::witness()?,
        Key::witness()?,
        Key::witness()?,
        Key::witness()?,
        Key::witness()?,
    );
    let vcp = vcp_backers(&icp.prefix, &[&b0, &b1, &b2], 1)?;
    let mut state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b0))?;
    let rotation = vrt(
        &vcp.said,
        &vcp.said,
        &[&b0, &b1, &b2],
        &[&b1],
        &[&b3, &b4],
        1,
    )?;
    state.ingest_mut(
        &rotation
            .signed_anchored(&icp, vec![])?
            .with_backer_sigs(vec![b0.sign(&rotation.bytes, 0)?]),
        &issuer_evidence(&issuer_state),
    )?;
    assert_eq!(
        state.backers(),
        &[
            prefix_of(&b0),
            prefix_of(&b2),
            prefix_of(&b3),
            prefix_of(&b4)
        ]
    );
    Ok(())
}

/// keripy `incept` trait law, fold level: an `NB` registry with a nonempty
/// backer set is rejected. `NB` plus backers is not a parse-hardening
/// vector, so the shape is forged at the wire level (the public builder
/// refuses it) and re-sealed — then the fold must still reject: the last
/// line of defense is the fold, not the parser.
#[test]
fn nb_registry_with_backers_rejected_without_partial_mutation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let backer = Key::new()?;
    let nb = vcp_nb(&icp.prefix)?;

    // Forge: NB config with a nonempty backer list, resealed (d == i).
    let mut raw = String::from_utf8(nb.bytes.clone())?;
    let fragment = format!(
        "\"c\":[\"NB\"],\"bt\":\"1\",\"b\":[\"{}\"]",
        String::from_utf8(prefix_of(&backer).to_qb64b())?
    );
    raw = raw.replace("\"c\":[\"NB\"],\"bt\":\"0\",\"b\":[]", &fragment);
    assert_ne!(
        raw.as_bytes(),
        nb.bytes.as_slice(),
        "forge splice must have matched the canonical shape"
    );
    // The splice grew the body — patch the version string's six-digit size
    // field to the new length (hex-encoded, keripy versioner format; the
    // parser checks the declared size against the actual byte count) before
    // resealing.
    let underscore = raw.as_bytes()[6..]
        .iter()
        .position(|byte| *byte == b'_')
        .ok_or("version string has no size delimiter")?
        + 6;
    let new_size = format!("{:06X}", raw.len());
    raw.replace_range(underscore - 6..underscore, &new_size);
    let (sealed, said) = reseal_icp(raw.into_bytes())?;
    let forged = Tel {
        event: TelEvent::deserialize(&sealed, keri_codec::JsonLimits::new(4096, 64))?.into_static(),
        bytes: sealed,
        said,
    };

    let verdict = RegistryState::incept(
        &forged.signed(vec![issuer.sign(&forged.bytes, 0)?]),
        &issuer_state,
    );
    assert!(matches!(
        verdict,
        Err(RegistryRejection::Structural(
            RegistryStructuralError::NoBackersWithBackers
        ))
    ));
    Ok(())
}

/// keripy Tevery likely-duplicitous branch, fold level: ingesting a second
/// `vcp` for a registry the fold already governs CONTESTS (the host fetches
/// the recorded event and judges by SAID), and the incumbent state is
/// untouched.
#[test]
fn duplicate_vcp_is_contested_without_partial_mutation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let before = state.clone();

    let replay = vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]);
    let evidence = issuer_evidence(&issuer_state);
    match state.clone().ingest(&replay, &evidence) {
        Err(err @ RegistryRejection::DuplicateInception) => {
            assert_eq!(err.disposition(), Disposition::Contested);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected duplicity rejection".into()),
    }
    assert_intact(&before, &state)?;
    Ok(())
}

// ── vrt: management rotation ────────────────────────────────────────────────

/// Fold table, row `vrt` (happy): sn 1, `p` = current head, seal resolvable
/// in the issuer's KEL, backer cut/add algebra — the fold resolves the
/// rotated set (keripy `rotate`).
#[test]
fn vrt_fold_rotates_backers_through_kel_anchor() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let b2 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b1))?;

    let rotation = vrt(&vcp.said, &vcp.said, &[&b1], &[&b1], &[&b2], 1)?;
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &rotation)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };

    let rotated = state.ingest(
        &rotation
            .signed_anchored(&icp, vec![])?
            .with_backer_sigs(vec![b2.sign(&rotation.bytes, 0)?]),
        &evidence,
    )?;

    assert_eq!(rotated.sn().value(), 1);
    assert_eq!(rotated.latest(), &rotation.said);
    assert!(rotated.backers().contains(&prefix_of(&b2)));
    assert!(!rotated.backers().contains(&prefix_of(&b1)));
    Ok(())
}

#[test]
fn vrt_cannot_use_foreign_kel_anchor_as_issuer_evidence() -> Fallible<()> {
    let (issuer, issuer_next, foreign, foreign_next, backer) = (
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
    );
    let icp = genesis(&issuer, &issuer_next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&backer))?;
    let rotation = vrt(&vcp.said, &vcp.said, &[&backer], &[], &[], 1)?;
    let foreign_icp = genesis(&foreign, &foreign_next)?;
    let foreign_anchor = anchored_rotation(&foreign_icp, &vcp.said, &rotation)?;
    assert_ne!(foreign_anchor.prefix, icp.prefix);
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&foreign_anchor.parsed),
    };
    assert!(matches!(
        state.ingest(
            &rotation.signed_anchored(&icp, vec![issuer.sign(&rotation.bytes, 0)?])?,
            &evidence
        ),
        Err(RegistryRejection::InconsistentAnchor)
    ));
    Ok(())
}

#[test]
fn duplicate_backer_cut_vrt_wire_and_fold_are_rejected() -> Fallible<()> {
    let (issuer, next, backer, replacement) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&backer))?;
    let valid = vrt(
        &vcp.said,
        &vcp.said,
        &[&backer],
        &[&backer],
        &[&replacement],
        1,
    )?;
    let TelEvent::RegistryRotation(body) = &valid.event else {
        return Err("vrt fixture parsed as another event".into());
    };
    let cut = prefix_of(&backer);
    let malformed = TelEvent::RegistryRotation(RegistryRotation::new_unchecked(
        body.said().clone(),
        body.registry().clone(),
        body.prior().clone(),
        body.sn(),
        body.backer_threshold(),
        vec![cut.clone(), cut],
        body.backer_additions().clone(),
    ));
    let serialized = malformed.serialize()?;
    assert!(matches!(
        TelEvent::deserialize(serialized.as_bytes(), keri_codec::JsonLimits::new(4096, 64)),
        Err(CodecError::Deserialize(DeserializeError::MemberSet(
            MemberSetError::Duplicate { set: "backer cuts" }
        )))
    ));
    let hostile = Tel {
        event: TelEvent::RegistryRotation(RegistryRotation::new_unchecked(
            serialized.said().clone().into_static(),
            body.registry().clone(),
            body.prior().clone(),
            body.sn(),
            body.backer_threshold(),
            vec![prefix_of(&backer), prefix_of(&backer)],
            body.backer_additions().clone(),
        )),
        bytes: serialized.as_bytes().to_vec(),
        said: serialized.said().clone().into_static(),
    };
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &hostile)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };
    let result = state.ingest(
        &hostile.signed_anchored(&icp, vec![issuer.sign(&hostile.bytes, 0)?])?,
        &evidence,
    );
    assert!(
        matches!(
            &result,
            Err(RegistryRejection::BackerSet(WitnessSetError::Membership(
                MemberSetError::Duplicate { set: "backer cuts" }
            )))
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn vrt_zero_toad_rejected_against_resolved_backers() -> Fallible<()> {
    let (issuer, next, backer) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_backers(&icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&backer))?;
    let valid = vrt(&vcp.said, &vcp.said, &[&backer], &[], &[], 1)?;
    let TelEvent::RegistryRotation(body) = &valid.event else {
        return Err("vrt fixture parsed as another event".into());
    };
    let bad_threshold = Toad::from_wire(0);
    let malformed = TelEvent::RegistryRotation(RegistryRotation::new_unchecked(
        body.said().clone(),
        body.registry().clone(),
        body.prior().clone(),
        body.sn(),
        bad_threshold,
        vec![],
        vec![],
    ));
    let serialized = malformed.serialize()?;
    let parsed =
        TelEvent::deserialize(serialized.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let hostile = Tel {
        event: parsed.into_static(),
        bytes: serialized.as_bytes().to_vec(),
        said: serialized.said().clone().into_static(),
    };
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &hostile)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };
    assert!(matches!(
        state.ingest(
            &hostile.signed_anchored(&icp, vec![issuer.sign(&hostile.bytes, 0)?])?,
            &evidence
        ),
        Err(RegistryRejection::BackerThreshold(ToadError::OutOfRange {
            toad: 0,
            witnesses: 1
        }))
    ));
    Ok(())
}

/// Fold table, row `vrt`, escrow branch: sn 2 with no sn-1 event is a GAP —
/// `Awaiting(PriorEvents)` (keripy's `.ooes` escrow: the event is NOT dead,
/// it waits), and nothing is applied.
#[test]
fn vrt_out_of_order_escrowed_without_partial_mutation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b1))?;
    let before = state.clone();

    // The fold never sees the sn-1 parent: present only the sn-2 descendant.
    let one = vrt(&vcp.said, &vcp.said, &[&b1], &[], &[], 1)?;
    let two = tel(&RegistryRotationBuilder::new(
        vcp.said.clone(),
        one.said.clone(),
        vec![prefix_of(&b1)],
        2,
    )
    .backer_threshold(1)
    .build()?)?;
    let evidence = issuer_evidence(&issuer_state);
    match state.clone().ingest(
        &two.signed_anchored(&icp, vec![issuer.sign(&two.bytes, 0)?])?,
        &evidence,
    ) {
        Err(
            err @ RegistryRejection::OutOfOrder {
                expected: 1,
                actual: 2,
            },
        ) => {
            assert_eq!(
                err.disposition(),
                Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 1 })
            );
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected escrow rejection".into()),
    }
    assert_intact(&before, &state)?;
    Ok(())
}

/// Fold table, row `vrt`, contested branch: a stale sn is NOT a gap — the
/// chain already passed that point, so the disposition is `Contested`
/// (keripy routes the occupied sn to the duplicity path).
#[test]
fn vrt_stale_sn_contested() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let b2 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b1))?;

    // Advance the chain one step so sn 1 is behind the head.
    let one = vrt(&vcp.said, &vcp.said, &[&b1], &[], &[], 1)?;
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &one)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };
    let rotated = state.ingest(
        &one.signed_anchored(&icp, vec![])?
            .with_backer_sigs(vec![b1.sign(&one.bytes, 0)?]),
        &evidence,
    )?;

    // A DIFFERENT sn-1 rotation — stale, so contested.
    let stale_vrt = vrt(&vcp.said, &vcp.said, &[&b1], &[&b1], &[&b2], 1)?;
    match rotated.ingest(
        &stale_vrt.signed_anchored(&icp, vec![issuer.sign(&stale_vrt.bytes, 0)?])?,
        &evidence,
    ) {
        Err(
            err @ RegistryRejection::OutOfOrder {
                expected: 2,
                actual: 1,
            },
        ) => {
            assert_eq!(err.disposition(), Disposition::Contested);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected contested rejection".into()),
    }
    Ok(())
}

/// Fold table, row `vrt`, terminal branch: `p` not naming the current head
/// rejects as a prior-digest mismatch — the chain would fork (keripy drops
/// for the prior-digest violation).
#[test]
fn vrt_prior_digest_mismatch_rejected_without_partial_mutation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b1))?;
    let before = state.clone();

    // sn 1 but `p` chains to a foreign digest instead of the vcp head.
    let forked = vrt(
        &vcp.said,
        &credential_said(b"not-the-head")?,
        &[&b1],
        &[],
        &[],
        1,
    )?;
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &forked)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };
    match state.clone().ingest(
        &forked.signed_anchored(&icp, vec![issuer.sign(&forked.bytes, 0)?])?,
        &evidence,
    ) {
        Err(err @ RegistryRejection::PriorDigestMismatch) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected terminal rejection".into()),
    }
    assert_intact(&before, &state)?;
    Ok(())
}

/// Fold table, row `vrt`, terminal branch: the supplied accepted issuer KEL
/// event lacks the TEL seal. This contradicts the `-G` source coordinate;
/// missing KEL evidence would instead await re-drive.
#[test]
fn vrt_unanchored_rejected_without_partial_mutation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1], 1)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, Some(&b1))?;
    let before = state.clone();

    let rotation = vrt(&vcp.said, &vcp.said, &[&b1], &[], &[], 1)?;
    // Anchor a DIFFERENT interaction — the rotation's seal is nowhere.
    let unrelated = interaction(&icp, 1)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&unrelated.parsed),
    };
    match state.clone().ingest(
        &rotation
            .signed(vec![issuer.sign(&rotation.bytes, 0)?])
            .with_source(keri::TelAnchorCoordinate::new(
                Number::new(1),
                unrelated.said.clone(),
            )),
        &evidence,
    ) {
        Err(err @ RegistryRejection::InconsistentAnchor) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected anchor rejection".into()),
    }
    assert_intact(&before, &state)?;
    Ok(())
}

/// keripy `rotate` trait law, fold level: rotations are disallowed for an
/// `NB` registry — the backerless fold has no backer set to rotate.
#[test]
fn vrt_on_nb_registry_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;

    let rotation = vrt(&vcp.said, &vcp.said, &[], &[], &[], 0)?;
    let verdict = state.ingest(
        &rotation.signed_anchored(&icp, vec![issuer.sign(&rotation.bytes, 0)?])?,
        &issuer_evidence(&issuer_state),
    );
    assert!(matches!(
        verdict,
        Err(RegistryRejection::Structural(
            RegistryStructuralError::RotationOnBackerlessRegistry
        ))
    ));
    Ok(())
}

// ── iss: credential issuance ────────────────────────────────────────────────

/// Fold table, row `iss`: sn 0, no `p`, `ri` naming this registry — chains
/// the credential, and the vcstate read derives `Issued`.
#[test]
fn iss_fold_chains_credential_and_status_reads_issued() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;

    let credential = credential_said(b"credential-one")?;
    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.ingest(
        &issuance.signed_anchored(&icp, vec![issuer.sign(&issuance.bytes, 0)?])?,
        &issuer_evidence(&issuer_state),
    )?;

    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);
    Ok(())
}

/// Fold table, row `iss`: the contested branch. The wire grammar itself
/// enforces `iss` sn 0 (`TelSequenceDomain` at parse time), so the fold's
/// gap-escrow branch for `iss` is defense-in-depth unreachable via public
/// wire paths — escrow coverage lives on the `vrt` row. A replayed `iss` at
/// sn 0 after the chain advanced contests.
#[test]
fn iss_ordering_dispositions() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let evidence = issuer_evidence(&issuer_state);

    // A replayed iss on an EXISTING chain — the sn is occupied, contested.
    let first = credential_said(b"credential-first")?;
    let first_iss = iss(&first, &vcp.said)?;
    let after_issue = state.ingest(
        &first_iss.signed_anchored(&icp, vec![issuer.sign(&first_iss.bytes, 0)?])?,
        &evidence,
    )?;
    let replay = iss(&first, &vcp.said)?;
    match after_issue.ingest(
        &replay.signed_anchored(&icp, vec![issuer.sign(&replay.bytes, 0)?])?,
        &evidence,
    ) {
        Err(
            err @ RegistryRejection::OutOfOrder {
                expected: 1,
                actual: 0,
            },
        ) => {
            assert_eq!(err.disposition(), Disposition::Contested);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected contested".into()),
    }
    Ok(())
}

/// Fold table, row `iss`, terminal branch: `ri` naming an unknown registry —
/// the fold cannot even route the event (keripy `MissingRegistryError`).
#[test]
fn iss_unknown_registry_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;

    let elsewhere = credential_said(b"elsewhere-registry")?;
    let credential = credential_said(b"orphan")?;
    let issuance = iss(&credential, &elsewhere)?;
    match state.ingest(
        &issuance.signed_anchored(&icp, vec![issuer.sign(&issuance.bytes, 0)?])?,
        &issuer_evidence(&issuer_state),
    ) {
        Err(err @ RegistryRejection::InconsistentRegistry) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected terminal rejection".into()),
    }
    Ok(())
}

/// Fold table, row `iss`, terminal branch: signing evidence that does not
/// carry the registry's issuer prefix — keripy `MissingIssuerError` class.
#[test]
fn iss_foreign_issuer_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let impostor = Key::new()?;
    let issuer_icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&issuer_icp, &issuer)?;
    let vcp = vcp_nb(&issuer_icp.prefix)?;
    let state = incept_anchored(&vcp, &issuer_icp, &issuer_state, &issuer, None)?;

    let credential = credential_said(b"impostor-credential")?;
    let issuance = iss(&credential, &vcp.said)?;
    let impostor_icp = genesis(&impostor, &Key::new()?)?;
    let impostor_state = seed(&impostor_icp, &impostor)?;
    let verdict = state.ingest(
        &issuance.signed_anchored(&issuer_icp, vec![impostor.sign(&issuance.bytes, 0)?])?,
        &issuer_evidence(&impostor_state),
    );
    match verdict {
        Err(err @ RegistryRejection::InconsistentIssuer) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected terminal rejection".into()),
    }
    Ok(())
}

// ── rev: credential revocation ──────────────────────────────────────────────

/// Fold table, rows `iss`→`rev`: the revoke chains onto the issued head at
/// sn 1 (`p` = the iss SAID) and the vcstate read flips to `Revoked`.
#[test]
fn rev_chain_flips_status_to_revoked() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let evidence = issuer_evidence(&issuer_state);

    let credential = credential_said(b"credential-revoked")?;
    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.ingest(
        &issuance.signed_anchored(&icp, vec![issuer.sign(&issuance.bytes, 0)?])?,
        &evidence,
    )?;

    let revocation = rev(&credential, &vcp.said, &issuance.said)?;
    let revoked = after_issue.ingest(
        &revocation.signed_anchored(&icp, vec![issuer.sign(&revocation.bytes, 0)?])?,
        &evidence,
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

/// Fold table, row `rev`, terminal branch: `p` not naming the chain head —
/// the revocation cannot chain (keripy drops for the prior-digest
/// violation).
#[test]
fn rev_wrong_prior_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let evidence = issuer_evidence(&issuer_state);

    let credential = credential_said(b"credential-wrong-prior")?;
    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.ingest(
        &issuance.signed_anchored(&icp, vec![issuer.sign(&issuance.bytes, 0)?])?,
        &evidence,
    )?;

    let revocation = rev(&credential, &vcp.said, &credential_said(b"not-the-head")?)?;
    match after_issue.ingest(
        &revocation.signed_anchored(&icp, vec![issuer.sign(&revocation.bytes, 0)?])?,
        &evidence,
    ) {
        Err(err @ RegistryRejection::PriorDigestMismatch) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected terminal rejection".into()),
    }
    Ok(())
}

// ── bis / brv: backed registries ────────────────────────────────────────────

/// Fold table, rows `bis`/`brv`: on a backed registry, issuance and
/// revocation are BACKER ENDORSEMENTS — the `ra` anchor must resolve against
/// the registry's own TEL (the management head) and the signature must verify
/// against the recorded backer keys.
#[test]
fn bis_and_brv_fold_through_backer_endorsements() -> Fallible<()> {
    let issuer = Key::new()?;
    let backer = Key::new()?;
    let issuer_icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&issuer_icp, &issuer)?;
    let vcp = vcp_backers(&issuer_icp.prefix, &[&backer], 1)?;
    let state = incept_anchored(&vcp, &issuer_icp, &issuer_state, &issuer, Some(&backer))?;
    let evidence = TelEvidence::Backer;

    let credential = credential_said(b"credential-backed")?;
    let endorsement = bis(&credential, &vcp.said, &vcp.said)?;
    let endorsed = state.ingest(
        &endorsement.signed_anchored(&issuer_icp, vec![backer.sign(&endorsement.bytes, 0)?])?,
        &evidence,
    )?;
    assert_eq!(endorsed.vcstate(&credential), CredentialStatus::Issued);

    // The backed revocation chains onto the endorsement's chain head and
    // flips the derived status.
    let revocation = brv(&credential, &endorsement.said, &vcp.said, &vcp.said)?;
    let revoked = endorsed.ingest(
        &revocation.signed_anchored(&issuer_icp, vec![backer.sign(&revocation.bytes, 0)?])?,
        &evidence,
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

/// An unrelated backer's invalid receipt contributes zero valid indices;
/// the event waits for a real backer receipt and succeeds on re-drive.
#[test]
fn bis_unrecognized_backer_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let recognized = Key::new()?;
    let impostor = Key::new()?;
    let issuer_icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&issuer_icp, &issuer)?;
    let vcp = vcp_backers(&issuer_icp.prefix, &[&recognized], 1)?;
    let state = incept_anchored(&vcp, &issuer_icp, &issuer_state, &issuer, Some(&recognized))?;

    let credential = credential_said(b"credential-impostor")?;
    let endorsement = bis(&credential, &vcp.said, &vcp.said)?;
    let verdict = state.clone().ingest(
        &endorsement.signed_anchored(&issuer_icp, vec![impostor.sign(&endorsement.bytes, 0)?])?,
        &TelEvidence::Backer,
    );
    match verdict {
        Err(
            err @ RegistryRejection::MissingBackerReceipts {
                valid: 0,
                required: 1,
            },
        ) => {
            assert_eq!(
                err.disposition(),
                Disposition::Awaiting(EvidenceKind::BackerReceipts {
                    valid: 0,
                    required: 1
                })
            );
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected missing backer receipt".into()),
    }
    let accepted = state.ingest(
        &endorsement.signed_anchored(&issuer_icp, vec![recognized.sign(&endorsement.bytes, 0)?])?,
        &TelEvidence::Backer,
    )?;
    assert_eq!(accepted.vcstate(&credential), CredentialStatus::Issued);
    Ok(())
}

/// Fold table, rows `bis`/`brv`: on an `NB` registry, backer issue/revoke
/// events are disallowed — endorsements only make sense with backers
/// (keripy's "invalid backer issue evt against backerless registry").
#[test]
fn bis_on_nb_registry_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let backer = Key::new()?;
    let issuer_icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&issuer_icp, &issuer)?;
    let vcp = vcp_nb(&issuer_icp.prefix)?;
    let state = incept_anchored(&vcp, &issuer_icp, &issuer_state, &issuer, None)?;

    let credential = credential_said(b"credential-nb")?;
    let endorsement = bis(&credential, &vcp.said, &vcp.said)?;
    let verdict = state.ingest(
        &endorsement.signed_anchored(&issuer_icp, vec![backer.sign(&endorsement.bytes, 0)?])?,
        &TelEvidence::Backer,
    );
    match verdict {
        Err(
            err @ RegistryRejection::Structural(
                RegistryStructuralError::BackedEventOnBackerlessRegistry,
            ),
        ) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected terminal rejection".into()),
    }
    Ok(())
}

// ── vcstate derivation ──────────────────────────────────────────────────────

/// The status derivation is a PURE read over the chain: unknown before any
/// event, issued at the iss head, revoked after the rev — and the read never
/// mutates the state it reads.
#[test]
fn credential_status_derivation_is_pure() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;
    let evidence = issuer_evidence(&issuer_state);

    let credential = credential_said(b"status-derivation")?;
    assert_eq!(
        state.vcstate(&credential),
        CredentialStatus::Unknown,
        "no chain: unknown"
    );

    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.clone().ingest(
        &issuance.signed_anchored(&icp, vec![issuer.sign(&issuance.bytes, 0)?])?,
        &evidence,
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);

    let revocation = rev(&credential, &vcp.said, &issuance.said)?;
    let revoked = after_issue.ingest(
        &revocation.signed_anchored(&icp, vec![issuer.sign(&revocation.bytes, 0)?])?,
        &evidence,
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    assert_eq!(
        state.vcstate(&credential),
        CredentialStatus::Unknown,
        "the read is pure: the ORIGINAL state is untouched"
    );
    Ok(())
}

// ── the signed wire path ────────────────────────────────────────────────────

/// TEL issuer authorization comes from the accepted KEL anchor. An issuer
/// signature is not required on the TEL body; a tampered body still fails
/// parse-level SAID verification before the fold sees it.
#[test]
fn tel_anchor_authorizes_without_issuer_signature_and_body_is_exact() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = incept_anchored(&vcp, &icp, &issuer_state, &issuer, None)?;

    let credential = credential_said(b"adapter")?;
    let issuance = iss(&credential, &vcp.said)?;

    // A tampered body fails the parse-level SAID check before the fold.
    let mut tampered = issuance.bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] = tampered[last].wrapping_add(1);
    assert!(
        TelEvent::deserialize(&tampered, keri_codec::JsonLimits::new(4096, 64)).is_err(),
        "a tampered body must not parse"
    );

    // A matching accepted KEL anchor is sufficient with no TEL signature.
    let after_issue = state.ingest(
        &issuance.signed_anchored(&icp, vec![])?,
        &issuer_evidence(&issuer_state),
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);
    Ok(())
}

/// The exn ingest path: an exchange envelope whose declared sender is this
/// key state's identifier verifies through the shared authority path over
/// the exact signed body, and any other key state rejects it with the
/// dedicated sender-mismatch error. The envelope is the checked-in
/// keripy-shaped apply vector with the sender spliced and re-sealed — the
/// codec has no exn write path yet (the corpus is the write path's stand-in).
#[test]
fn exn_verification_happy_and_sender_mismatch() -> Fallible<()> {
    #[derive(JsonDeserialize)]
    struct ExnVector {
        raw: String,
    }

    let sender = Key::new()?;
    let sender_icp = genesis(&sender, &Key::new()?)?;
    let sender_state = seed(&sender_icp, &sender)?;

    // The corpus vector: splice the local sender's self-addressing AID over
    // the envelope's 44-char basic-prefix issuer (same fixed length), re-seal
    // the SAID, and re-render canonical bytes.
    let first_line = SIGNED_EXN
        .lines()
        .next()
        .ok_or("signed exn corpus is empty")?;
    let vector: ExnVector = serde_json::from_str(first_line)?;
    let raw = vector.raw.into_bytes();
    // The corpus issuer is an Ed25519 basic prefix ('D…') — a fixed-length
    // qb64 identifier but NOT a SAID, so the plain window splice applies;
    // said_span's Blake3 guard stays reserved for the reseal below.
    let issuer_key = b"\"i\":\"";
    let issuer_start = raw
        .windows(issuer_key.len())
        .position(|window| window == issuer_key)
        .ok_or("exn is missing an issuer field")?
        + issuer_key.len();
    let sender_said = sender_icp
        .prefix
        .as_saider()
        .ok_or("exn senders are self-addressing identifiers")?;
    let replacement = sender_said.to_qb64b();
    let issuer_span = issuer_start..issuer_start + replacement.len();
    assert!(
        raw.get(issuer_span.clone())
            .is_some_and(|span| !span.contains(&b'"')),
        "issuer prefixes are fixed-length qb64"
    );
    let mut patched = raw;
    patched[issuer_span].copy_from_slice(&replacement);
    let (sealed, _) = reseal_spans(patched, &[b"\"d\":\""])?;
    let exn = Exn::deserialize(&sealed, keri_codec::JsonLimits::new(4096, 64))?.into_static();

    // Sign with the sender's current keys and frame through the write spine.
    let serialized = exn.serialize()?;
    let siger = sender.sign(serialized.as_bytes(), 0)?;
    let framed = serialized.frame_v1(&ControllerIdxSigs::from_indexed_signatures(&[siger])?)?;
    let (message, rest) = Message::parse(&framed, common::message_limits())?;
    assert!(rest.is_empty(), "framed exn leaves no remainder");
    let Message::Exn(lane) = &message else {
        return Err("exn must parse as an exn carrier".into());
    };

    // The sender's key state verifies its own envelope.
    let verified = sender_state.verify_exn(lane)?;
    assert_eq!(
        verified.sigs().len(),
        1,
        "one indexed signature verified over the exact body span"
    );

    // A DIFFERENT key state rejects the sender outright.
    let receiver = Key::new()?;
    let receiver_icp = genesis(&receiver, &Key::new()?)?;
    let receiver_state = seed(&receiver_icp, &receiver)?;
    assert!(matches!(
        receiver_state.verify_exn(lane),
        Err(ExchangeError::SenderMismatch)
    ));
    Ok(())
}
