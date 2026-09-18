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
//! partial mutation. Out-of-order sn escrows as
//! [`Awaiting`](keri::Disposition::Awaiting)([`PriorEvents`](keri::EvidenceKind::PriorEvents)),
//! a stale sn contests, missing registry/issuer/anchor are terminal, and a
//! duplicate inception contests.
//!
//! Setup is fallible and flows through `?`; there is no `unwrap`/`expect`
//! in fixtures — deliberate-rejection assertions use `matches!`.
mod common;

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, NoncerCode};
use cesr::core::primitives::{Noncer, Number, Siger};
use cesr::crypto::digest;
use cesr_stream::group::ControllerIdxSigs;
use keri::state::KeyState;
use keri::{
    CredentialStatus, Disposition, EvidenceKind, ExchangeError, RegistryRejection, RegistryState,
    RegistryStructuralError, Rejection, SignedTel, TelEvidence,
};
use keri_codec::{
    BackedIssueBuilder, BackedRevokeBuilder, Deserialize, Exn, IssueBuilder, Message,
    RegistryInceptionBuilder, RegistryRotationBuilder, RevokeBuilder, Serialize,
};
use keri_events::{BasicPrefix, ConfigTrait, Identifier, Said, Seal, TelEvent};
use serde::Deserialize as JsonDeserialize;

use common::{
    Fallible, Key, genesis, interaction, interaction_anchoring, prefix_of, reseal_icp,
    reseal_spans, seed,
};

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
        SignedTel {
            event: &self.event,
            signed_bytes: self.bytes.as_slice(),
            sigs,
        }
    }
}

/// Seal a built TEL event: round-trip the builder output through the public
/// parse path (which verifies the SAID) and bundle wire bytes + SAID.
fn tel(ser: &keri_codec::SerializedEvent) -> Fallible<Tel> {
    let bytes = ser.as_bytes().to_vec();
    Ok(Tel {
        event: TelEvent::deserialize(&bytes)?.into_static(),
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
fn assert_intact(before: &RegistryState<'_>, state: &RegistryState<'_>) -> Fallible<()> {
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

    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

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

    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    assert!(!state.is_backerless());
    assert_eq!(state.backers().len(), 2);
    assert!(state.backers().contains(&prefix_of(&b1)));
    assert!(state.backers().contains(&prefix_of(&b2)));
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
        event: TelEvent::deserialize(&sealed)?.into_static(),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let rotation = vrt(&vcp.said, &vcp.said, &[&b1], &[&b1], &[&b2], 1)?;
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &rotation)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };

    let rotated = state.clone().ingest(
        &rotation.signed(vec![issuer.sign(&rotation.bytes, 0)?]),
        &evidence,
    )?;

    assert_eq!(rotated.sn().value(), 1);
    assert_eq!(rotated.latest(), &rotation.said);
    assert!(rotated.backers().contains(&prefix_of(&b2)));
    assert!(!rotated.backers().contains(&prefix_of(&b1)));
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
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
    match state
        .clone()
        .ingest(&two.signed(vec![issuer.sign(&two.bytes, 0)?]), &evidence)
    {
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    // Advance the chain one step so sn 1 is behind the head.
    let one = vrt(&vcp.said, &vcp.said, &[&b1], &[], &[], 1)?;
    let anchor_kel = anchored_rotation(&icp, &vcp.said, &one)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&anchor_kel.parsed),
    };
    let rotated = state.ingest(&one.signed(vec![issuer.sign(&one.bytes, 0)?]), &evidence)?;

    // A DIFFERENT sn-1 rotation — stale, so contested.
    let stale_vrt = vrt(&vcp.said, &vcp.said, &[&b1], &[&b1], &[&b2], 1)?;
    match rotated.ingest(
        &stale_vrt.signed(vec![issuer.sign(&stale_vrt.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
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
        &forked.signed(vec![issuer.sign(&forked.bytes, 0)?]),
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

/// Fold table, row `vrt`, terminal branch: a rotation whose seal no accepted
/// KEL event of the issuer carries — `MissingAnchor`, terminal per the
/// fold table (keripy `MissingAnchorError`), and nothing is applied.
#[test]
fn vrt_unanchored_rejected_without_partial_mutation() -> Fallible<()> {
    let issuer = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let b1 = Key::new()?;
    let vcp = vcp_backers(&icp.prefix, &[&b1], 1)?;
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
    let before = state.clone();

    let rotation = vrt(&vcp.said, &vcp.said, &[&b1], &[], &[], 1)?;
    // Anchor a DIFFERENT interaction — the rotation's seal is nowhere.
    let unrelated = interaction(&icp, 1)?;
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: Some(&unrelated.parsed),
    };
    match state.clone().ingest(
        &rotation.signed(vec![issuer.sign(&rotation.bytes, 0)?]),
        &evidence,
    ) {
        Err(err @ RegistryRejection::MissingAnchor) => {
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let rotation = vrt(&vcp.said, &vcp.said, &[], &[], &[], 0)?;
    let verdict = state.ingest(
        &rotation.signed(vec![issuer.sign(&rotation.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let credential = credential_said(b"credential-one")?;
    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
    let evidence = issuer_evidence(&issuer_state);

    // A replayed iss on an EXISTING chain — the sn is occupied, contested.
    let first = credential_said(b"credential-first")?;
    let first_iss = iss(&first, &vcp.said)?;
    let after_issue = state.ingest(
        &first_iss.signed(vec![issuer.sign(&first_iss.bytes, 0)?]),
        &evidence,
    )?;
    let replay = iss(&first, &vcp.said)?;
    match after_issue.ingest(
        &replay.signed(vec![issuer.sign(&replay.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let elsewhere = credential_said(b"elsewhere-registry")?;
    let credential = credential_said(b"orphan")?;
    let issuance = iss(&credential, &elsewhere)?;
    match state.ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
        &issuer_evidence(&issuer_state),
    ) {
        Err(err @ RegistryRejection::MissingRegistry) => {
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let credential = credential_said(b"impostor-credential")?;
    let issuance = iss(&credential, &vcp.said)?;
    let impostor_icp = genesis(&impostor, &Key::new()?)?;
    let impostor_state = seed(&impostor_icp, &impostor)?;
    let verdict = state.ingest(
        &issuance.signed(vec![impostor.sign(&issuance.bytes, 0)?]),
        &issuer_evidence(&impostor_state),
    );
    match verdict {
        Err(err @ RegistryRejection::MissingIssuer) => {
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
    let evidence = issuer_evidence(&issuer_state);

    let credential = credential_said(b"credential-revoked")?;
    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
        &evidence,
    )?;

    let revocation = rev(&credential, &vcp.said, &issuance.said)?;
    let revoked = after_issue.ingest(
        &revocation.signed(vec![issuer.sign(&revocation.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
    let evidence = issuer_evidence(&issuer_state);

    let credential = credential_said(b"credential-wrong-prior")?;
    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
        &evidence,
    )?;

    let revocation = rev(&credential, &vcp.said, &credential_said(b"not-the-head")?)?;
    match after_issue.ingest(
        &revocation.signed(vec![issuer.sign(&revocation.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
    let evidence = TelEvidence::Backer;

    let credential = credential_said(b"credential-backed")?;
    let endorsement = bis(&credential, &vcp.said, &vcp.said)?;
    let endorsed = state.ingest(
        &endorsement.signed(vec![backer.sign(&endorsement.bytes, 0)?]),
        &evidence,
    )?;
    assert_eq!(endorsed.vcstate(&credential), CredentialStatus::Issued);

    // The backed revocation chains onto the endorsement's chain head and
    // flips the derived status.
    let revocation = brv(&credential, &endorsement.said, &vcp.said, &vcp.said)?;
    let revoked = endorsed.ingest(
        &revocation.signed(vec![backer.sign(&revocation.bytes, 0)?]),
        &evidence,
    )?;
    assert_eq!(revoked.vcstate(&credential), CredentialStatus::Revoked);
    Ok(())
}

/// Fold table, rows `bis`/`brv`, terminal branch: a signature from a key
/// state that is NOT a current backer is rejected — endorsement authority is
/// the backer set, not the issuer (keripy derives verification keys from the
/// recorded backer list, so a non-backer can never verify).
#[test]
fn bis_unrecognized_backer_rejected() -> Fallible<()> {
    let issuer = Key::new()?;
    let recognized = Key::new()?;
    let impostor = Key::new()?;
    let issuer_icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&issuer_icp, &issuer)?;
    let vcp = vcp_backers(&issuer_icp.prefix, &[&recognized], 1)?;
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let credential = credential_said(b"credential-impostor")?;
    let endorsement = bis(&credential, &vcp.said, &vcp.said)?;
    let verdict = state.ingest(
        &endorsement.signed(vec![impostor.sign(&endorsement.bytes, 0)?]),
        &TelEvidence::Backer,
    );
    match verdict {
        Err(err @ RegistryRejection::Signatures(Rejection::MissingSignatures { verified: 0 })) => {
            assert_eq!(err.disposition(), Disposition::Terminal);
        }
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected terminal rejection".into()),
    }
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let credential = credential_said(b"credential-nb")?;
    let endorsement = bis(&credential, &vcp.said, &vcp.said)?;
    let verdict = state.ingest(
        &endorsement.signed(vec![backer.sign(&endorsement.bytes, 0)?]),
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
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;
    let evidence = issuer_evidence(&issuer_state);

    let credential = credential_said(b"status-derivation")?;
    assert_eq!(
        state.vcstate(&credential),
        CredentialStatus::Unknown,
        "no chain: unknown"
    );

    let issuance = iss(&credential, &vcp.said)?;
    let after_issue = state.clone().ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
        &evidence,
    )?;
    assert_eq!(after_issue.vcstate(&credential), CredentialStatus::Issued);

    let revocation = rev(&credential, &vcp.said, &issuance.said)?;
    let revoked = after_issue.ingest(
        &revocation.signed(vec![issuer.sign(&revocation.bytes, 0)?]),
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

/// The signed-message path: the fold verifies the indexed signatures
/// cryptographically over the exact body span — an event signed by a
/// non-issuer key is rejected through the shared
/// [`Rejection::MissingSignatures`] verdict, and a tampered body fails the
/// parse-level SAID verification before the fold ever sees it.
#[test]
fn signed_tel_path_verifies_signatures_and_body() -> Fallible<()> {
    let issuer = Key::new()?;
    let outsider = Key::new()?;
    let icp = genesis(&issuer, &Key::new()?)?;
    let issuer_state = seed(&icp, &issuer)?;
    let vcp = vcp_nb(&icp.prefix)?;
    let state = RegistryState::incept(
        &vcp.signed(vec![issuer.sign(&vcp.bytes, 0)?]),
        &issuer_state,
    )?;

    let credential = credential_said(b"adapter")?;
    let issuance = iss(&credential, &vcp.said)?;

    // A non-issuer signature cannot establish the credential.
    let outsider_signed = issuance.signed(vec![outsider.sign(&issuance.bytes, 0)?]);
    match state
        .clone()
        .ingest(&outsider_signed, &issuer_evidence(&issuer_state))
    {
        Err(RegistryRejection::Signatures(inner)) => assert!(
            matches!(inner, Rejection::MissingSignatures { verified: 0 }),
            "a non-issuer signature must verify zero signatures: {inner}"
        ),
        Err(err) => return Err(format!("wrong rejection: {err}").into()),
        Ok(_) => return Err("expected signature rejection".into()),
    }

    // A tampered body fails the parse-level SAID check before the fold.
    let mut tampered = issuance.bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] = tampered[last].wrapping_add(1);
    assert!(
        TelEvent::deserialize(&tampered).is_err(),
        "a tampered body must not parse"
    );

    // The honest signature verifies and the credential chains.
    let after_issue = state.ingest(
        &issuance.signed(vec![issuer.sign(&issuance.bytes, 0)?]),
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
    let exn = Exn::deserialize(&sealed)?.into_static();

    // Sign with the sender's current keys and frame through the write spine.
    let serialized = exn.serialize()?;
    let siger = sender.sign(serialized.as_bytes(), 0)?;
    let framed = serialized.frame_v1(&ControllerIdxSigs::from_indexed_signatures(&[siger])?)?;
    let (message, rest) = Message::parse(&framed)?;
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
