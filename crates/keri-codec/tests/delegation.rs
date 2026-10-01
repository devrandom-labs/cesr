//! K4 (#90): delegation validation over typed evidence — acceptance and
//! negative rules through the public `incept_delegated`/`ingest_delegated`.
//! Oracle anchors: kswg spec §Cooperative Delegation (+ DND MUST-drop);
//! keripy 9161a705 eventing.py:3009-3416.
mod common;

use cesr::core::primitives::Number;
use common::{
    Fallible, Key, commit, delegated_inception, delegated_rotation_full, genesis, genesis_config,
    interaction, interaction_anchoring, plain_rotation, seed,
};
use keri::{
    AnchoredDelegation, DelegationError, DelegationEvidence, Disposition, EvidenceError,
    EvidenceKind, KeyState, KeyStateSnapshot, Rejection, SameSnVerdict, Signed, StructuralError,
};
use keri_codec::{DelegatedRotationBuilder, EventMessage};
use keri_events::{ConfigTrait, KeriEvent, MessageType, Seal, SigningThreshold};
use proptest::prelude::*;

/// Anchor `target`'s (i, s, d) in an interaction at `sn` on the delegator's
/// KEL, chained onto `prior`.
fn anchor_of(prior: &common::Event, sn: u128, target: &common::Event) -> Fallible<common::Event> {
    interaction_anchoring(
        prior,
        sn,
        vec![Seal::Event {
            i: target.prefix.clone(),
            s: Number::new(target.parsed.sn().value()),
            d: target.said.clone(),
        }],
    )
}

/// dip accepted with anchored evidence; the state carries the delegator.
#[test]
fn dip_accepted_with_anchored_evidence() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let delegator_state = seed(&delegator_icp, &dk0)?;

    let (k0, k1) = (Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let anchor = anchor_of(&delegator_icp, 1, &dip)?;
    let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
        delegator: &delegator_state,
        delegating_event: &anchor.parsed,
    });

    let state = KeyState::incept_delegated(&dip.signed(vec![k0.sign(&dip.bytes, 0)?]), &evidence)?;
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.delegator(), Some(&delegator_icp.prefix));
    assert_eq!(state.prefix(), &dip.prefix);
    Ok(())
}

/// dip → drt accepted; keys roll, the delegator carries over.
#[test]
fn drt_accepted_with_anchored_evidence() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let delegator_state = seed(&delegator_icp, &dk0)?;

    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let dip_anchor = anchor_of(&delegator_icp, 1, &dip)?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &dip_anchor.parsed,
        }),
    )?;

    let drt = delegated_rotation_full(&dip, 1, &k1, &k2)?;
    let drt_anchor = anchor_of(&dip_anchor, 2, &drt)?;
    let next = state.ingest_delegated(
        &drt.signed(vec![k1.sign(&drt.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &drt_anchor.parsed,
        }),
    )?;
    assert_eq!(next.sn().value(), 1);
    assert_eq!(next.delegator(), Some(&delegator_icp.prefix));
    assert_eq!(next.keys()[0].raw(), k1.verfer.raw());
    Ok(())
}

#[test]
fn a11_delegated_rotation_retries_after_anchor_arrives() -> Fallible<()> {
    let (delegator, delegator_next, controller, reveal, next) = (
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
    );
    let delegator_icp = genesis(&delegator, &delegator_next)?;
    let delegator_state = seed(&delegator_icp, &delegator)?;
    let dip = delegated_inception(&controller, &reveal, delegator_icp.prefix.clone())?;
    let mut state = KeyState::incept_delegated(
        &dip.signed(vec![controller.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    let drt = delegated_rotation_full(&dip, 1, &reveal, &next)?;
    let signed = drt.signed(vec![reveal.sign(&drt.bytes, 0)?]);
    let original_said = state.latest_said();
    assert!(matches!(
        state.ingest_mut(&signed),
        Err(Rejection::Delegation(DelegationError::EvidenceRequired))
    ));
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.latest_said(), original_said);

    let unsealed = interaction(&delegator_icp, 1)?;
    assert!(matches!(
        state.ingest_delegated_mut(
            &signed,
            &DelegationEvidence::Anchored(AnchoredDelegation {
                delegator: &delegator_state,
                delegating_event: &unsealed.parsed,
            }),
        ),
        Err(Rejection::Delegation(DelegationError::SealNotFound))
    ));
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.latest_said(), original_said);

    let anchor = anchor_of(&delegator_icp, 1, &drt)?;
    state.ingest_delegated_mut(
        &signed,
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &anchor.parsed,
        }),
    )?;
    assert_eq!(state.sn().value(), 1);
    assert_eq!(state.latest_message_type(), MessageType::Drt);
    Ok(())
}

#[test]
fn signed_wrong_identifier_drt_cannot_advance_delegated_state() -> Fallible<()> {
    let (delegator, delegator_next, controller, reveal, next, other_controller, other_next) = (
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
    );
    let delegator_icp = genesis(&delegator, &delegator_next)?;
    let dip = delegated_inception(&controller, &reveal, delegator_icp.prefix.clone())?;
    let other = delegated_inception(&other_controller, &other_next, delegator_icp.prefix.clone())?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![controller.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    let serialized = DelegatedRotationBuilder::new()
        .prefix(other.prefix.clone())
        .prior_event_said(dip.said.clone())
        .keys(vec![reveal.verfer.clone()])
        .prior_witnesses(vec![])
        .sn(1)
        .next_keys(vec![commit(&next.verfer)?])
        .next_threshold(SigningThreshold::Simple(1))
        .build()?;
    let mut wire = serialized.as_bytes().to_vec();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(reveal.sign(serialized.as_bytes(), 0)?.to_qb64().as_bytes());
    let (message, remainder) = EventMessage::parse(&wire, common::message_limits())?;
    assert!(remainder.is_empty());
    assert_ne!(message.event().prefix(), &dip.prefix);
    assert!(matches!(
        state.ingest_delegated(&Signed::from(&message), &DelegationEvidence::HostAccepted),
        Err(Rejection::Structural(StructuralError::IdentifierMismatch))
    ));
    Ok(())
}

/// A plain rotation cannot bypass delegation on either parsed wire or a
/// recovery candidate after an anchored delegated inception.
#[test]
fn anchored_dip_rejects_plain_rotation_and_recovery() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let delegator_state = seed(&delegator_icp, &dk0)?;
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let anchor = anchor_of(&delegator_icp, 1, &dip)?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &anchor.parsed,
        }),
    )?;

    let rot = plain_rotation(&dip, 1, &k1, &k2)?;
    let signature = k1.sign(&rot.bytes, 0)?;
    let mut wire = rot.bytes.clone();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(signature.to_qb64().as_bytes());
    let (message, rest) = EventMessage::parse(&wire, common::message_limits())?;
    assert!(rest.is_empty());
    let rejected = state.clone().ingest(&Signed::from(&message));
    assert!(matches!(
        rejected,
        Err(Rejection::Delegation(
            DelegationError::PlainRotationOnDelegatedState
        ))
    ));
    assert_eq!(
        Rejection::Delegation(DelegationError::PlainRotationOnDelegatedState).disposition(),
        Disposition::Terminal
    );

    let rewind_state = state.clone();
    let ixn = interaction(&dip, 1)?;
    let head = state.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))?;
    assert!(matches!(
        head.judge_same_sn(&rot.parsed, &ixn.parsed, &[]),
        Err(EvidenceError::IncompatibleEventKind {
            event_kind: MessageType::Rot,
            delegated: true,
        })
    ));
    assert!(matches!(
        rewind_state.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])),
        Err(Rejection::Delegation(
            DelegationError::PlainRotationOnDelegatedState
        ))
    ));
    Ok(())
}

/// A delegated rotation may recover over an interaction when its own anchor
/// and signatures survive the rewind.
#[test]
fn anchored_drt_recovers_over_interaction() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let delegator_state = seed(&delegator_icp, &dk0)?;
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let dip_anchor = anchor_of(&delegator_icp, 1, &dip)?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &dip_anchor.parsed,
        }),
    )?;
    let ixn = interaction(&dip, 1)?;
    let head = state
        .clone()
        .ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))?;
    let drt = delegated_rotation_full(&dip, 1, &k1, &k2)?;
    assert_eq!(
        head.judge_same_sn(&drt.parsed, &ixn.parsed, &[])?,
        SameSnVerdict::Supersedes
    );
    let drt_anchor = anchor_of(&dip_anchor, 2, &drt)?;
    let recovered = state.ingest_delegated(
        &drt.signed(vec![k1.sign(&drt.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &drt_anchor.parsed,
        }),
    )?;
    assert_eq!(recovered.sn().value(), 1);
    assert_eq!(recovered.keys()[0].raw(), k1.verfer.raw());
    Ok(())
}

/// `HostAccepted` skips the seal checks but still verifies signatures.
#[test]
fn host_accepted_still_verifies_signatures() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let (k0, k1, kx) = (Key::new()?, Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;

    // wrong signer: zero verifiable controller signatures — Terminal
    let Err(r) = KeyState::incept_delegated(
        &dip.signed(vec![kx.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    ) else {
        return Err("a forged dip was accepted".into());
    };
    assert!(matches!(r, Rejection::MissingSignatures { verified: 0 }));

    // right signer: accepted without an anchor
    let state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    assert_eq!(state.delegator(), Some(&delegator_icp.prefix));
    Ok(())
}

/// A tampered seal digest is `SealNotFound` — `Awaiting(DelegationEvidence)`.
#[test]
fn tampered_seal_digest_is_seal_not_found() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let delegator_state = seed(&delegator_icp, &dk0)?;
    let (k0, k1) = (Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;

    // anchor the WRONG digest: seal (i, s) match but d is the delegator's said
    let anchor = interaction_anchoring(
        &delegator_icp,
        1,
        vec![Seal::Event {
            i: dip.prefix.clone(),
            s: Number::new(0),
            d: delegator_icp.said.clone(),
        }],
    )?;
    let Err(r) = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &anchor.parsed,
        }),
    ) else {
        return Err("a tampered seal was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Delegation(DelegationError::SealNotFound)
    ));
    assert_eq!(
        r.disposition(),
        Disposition::Awaiting(EvidenceKind::DelegationEvidence)
    );
    Ok(())
}

/// Evidence from the wrong delegator is `DelegatorMismatch`.
#[test]
fn wrong_delegator_is_mismatch() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let (xk0, xk1) = (Key::new()?, Key::new()?);
    let other_icp = genesis(&xk0, &xk1)?;
    let other_state = seed(&other_icp, &xk0)?;
    let (k0, k1) = (Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let anchor = anchor_of(&other_icp, 1, &dip)?;

    let Err(r) = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &other_state,
            delegating_event: &anchor.parsed,
        }),
    ) else {
        return Err("wrong-delegator evidence was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Delegation(DelegationError::DelegatorMismatch)
    ));
    Ok(())
}

/// A delegator with the DND trait denies — Terminal (spec MUST drop).
#[test]
fn dnd_delegator_is_denied_terminal() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis_config(&dk0, &dk1, vec![ConfigTrait::DoNotDelegate])?;
    let delegator_state = seed(&delegator_icp, &dk0)?;
    let (k0, k1) = (Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let anchor = anchor_of(&delegator_icp, 1, &dip)?;

    let Err(r) = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &anchor.parsed,
        }),
    ) else {
        return Err("a DND delegator's delegation was accepted".into());
    };
    assert!(matches!(r, Rejection::Delegation(DelegationError::Denied)));
    assert_eq!(r.disposition(), Disposition::Terminal);
    Ok(())
}

/// A drt on a non-delegated state is `DelegatorUnknown` — Terminal.
#[test]
fn drt_on_plain_state_is_delegator_unknown() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let drt = delegated_rotation_full(&icp, 1, &k1, &k2)?;
    let Err(r) = seed(&icp, &k0)?.ingest_delegated(
        &drt.signed(vec![k1.sign(&drt.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    ) else {
        return Err("a drt on a plain state was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Delegation(DelegationError::DelegatorUnknown)
    ));
    assert_eq!(r.disposition(), Disposition::Terminal);
    let err = seed(&icp, &k0)?.ingest(&drt.signed(vec![k1.sign(&drt.bytes, 0)?]));
    assert!(matches!(
        err,
        Err(Rejection::Delegation(DelegationError::DelegatorUnknown))
    ));
    let ixn = interaction(&icp, 1)?;
    let head = seed(&icp, &k0)?.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))?;
    assert!(matches!(
        head.judge_same_sn(&drt.parsed, &ixn.parsed, &[]),
        Err(EvidenceError::IncompatibleEventKind {
            event_kind: MessageType::Drt,
            delegated: false,
        })
    ));
    Ok(())
}

/// Wrong event types at the delegated entries are structural — Terminal.
#[test]
fn wrong_types_at_delegated_entries_are_structural() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let Err(r) = KeyState::incept_delegated(
        &icp.signed(vec![k0.sign(&icp.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    ) else {
        return Err("a plain icp passed incept_delegated".into());
    };
    assert!(matches!(
        r,
        Rejection::Structural(StructuralError::NotDelegatedInception)
    ));

    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    let ixn = interaction(&dip, 1)?;
    let Err(r_ixn) = state.ingest_delegated(
        &ixn.signed(vec![k1.sign(&ixn.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    ) else {
        return Err("an ixn passed ingest_delegated".into());
    };
    assert!(matches!(
        r_ixn,
        Rejection::Structural(StructuralError::NotDelegatedRotation)
    ));
    Ok(())
}

/// A plain interaction folds onto a delegated state through `ingest` with no
/// evidence (delegation gates establishment only).
#[test]
fn interaction_on_delegated_state_needs_no_evidence() -> Fallible<()> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let (k0, k1) = (Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    let ixn = interaction(&dip, 1)?;
    let next = state.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))?;
    assert_eq!(next.sn().value(), 1);
    assert_eq!(next.delegator(), Some(&delegator_icp.prefix));
    Ok(())
}

/// K6 invariant for accepted delegated histories, with optional interaction
/// steps on either side of a delegated rotation.
fn delegated_history_dual(
    before_rotation: bool,
    after_rotation: bool,
) -> Fallible<(KeyStateSnapshot, KeyStateSnapshot)> {
    let (dk0, dk1) = (Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;
    let delegator_state = seed(&delegator_icp, &dk0)?;

    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let dip_anchor = anchor_of(&delegator_icp, 1, &dip)?;
    let mut state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &dip_anchor.parsed,
        }),
    )?;
    let KeriEvent::DelegatedInception(d) = &dip.parsed else {
        return Err("delegated_inception fixture must parse as a dip".into());
    };
    let mut trusted = KeyStateSnapshot::genesis(d.inception()).advance(&dip.parsed);
    let before = before_rotation.then(|| interaction(&dip, 1)).transpose()?;
    if let Some(ixn) = &before {
        state = state.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))?;
        trusted = trusted.advance(&ixn.parsed);
    }
    let prior = before.as_ref().unwrap_or(&dip);
    let rotation_sn = if before_rotation { 2 } else { 1 };
    let drt = delegated_rotation_full(prior, rotation_sn, &k1, &k2)?;
    let drt_anchor = anchor_of(&dip_anchor, 2, &drt)?;
    state = state.ingest_delegated(
        &drt.signed(vec![k1.sign(&drt.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &delegator_state,
            delegating_event: &drt_anchor.parsed,
        }),
    )?;
    trusted = trusted.advance(&drt.parsed);
    let after = after_rotation
        .then(|| interaction(&drt, rotation_sn + 1))
        .transpose()?;
    if let Some(ixn) = &after {
        state = state.ingest(&ixn.signed(vec![k1.sign(&ixn.bytes, 0)?]))?;
        trusted = trusted.advance(&ixn.parsed);
    }
    Ok((trusted, KeyStateSnapshot::from(&state)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn trusted_fold_matches_validating_fold_on_delegated_kel(
        before_rotation in any::<bool>(),
        after_rotation in any::<bool>(),
    ) {
        let (trusted, validated) = delegated_history_dual(before_rotation, after_rotation)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(trusted, validated);
    }
}

/// The revoke demo: the delegator supersedes its anchoring interaction with a
/// recovery rotation (K3 judge), the host rewinds the delegator's stream, and
/// re-driving the delegate's drt with post-recovery evidence fails
/// `SealNotFound` — the delegation died with the anchor.
#[test]
fn revoked_delegation_is_seal_not_found_after_recovery() -> Fallible<()> {
    // delegator: icp → ixn1 (anchors the delegate's drt)
    let (dk0, dk1, dk2) = (Key::new()?, Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &dk1)?;

    // delegate: dip (HostAccepted for setup brevity) → drt parked awaiting
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
    let delegate_state = KeyState::incept_delegated(
        &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    let drt = delegated_rotation_full(&dip, 1, &k1, &k2)?;
    let ixn1 = anchor_of(&delegator_icp, 1, &drt)?;

    // 1. fold the delegator to head and judge a recovery rot at sn 1
    let delegator_head =
        seed(&delegator_icp, &dk0)?.ingest(&ixn1.signed(vec![dk0.sign(&ixn1.bytes, 0)?]))?;
    let recovery = plain_rotation(&delegator_icp, 1, &dk1, &dk2)?;
    let verdict = delegator_head.judge_same_sn(&recovery.parsed, &ixn1.parsed, &[])?;
    assert_eq!(verdict, SameSnVerdict::Supersedes);

    // 2. host rewinds: the delegator state re-folded from icp + recovery rot
    let recovered = seed(&delegator_icp, &dk0)?
        .ingest(&recovery.signed(vec![dk1.sign(&recovery.bytes, 0)?]))?;

    // 3. re-drive: the recovery rot anchors nothing, so the delegation died
    //    with the anchor — parked until the delegator re-approves
    let Err(r) = delegate_state.ingest_delegated(
        &drt.signed(vec![k1.sign(&drt.bytes, 0)?]),
        &DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: &recovered,
            delegating_event: &recovery.parsed,
        }),
    ) else {
        return Err("a revoked delegation was re-accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::Delegation(DelegationError::SealNotFound)
    ));
    assert_eq!(
        r.disposition(),
        Disposition::Awaiting(EvidenceKind::DelegationEvidence)
    );
    Ok(())
}

mod properties {
    use super::*;

    /// Build a dip and an anchoring interaction whose seal list carries
    /// `decoys` digest seals plus (when `present`) the real event seal of the
    /// dip inserted at `min(pos, decoys)`, then drive `incept_delegated`.
    /// Returns `true` when the fold accepts.
    fn seal_position_verdict(pos: usize, decoys: usize, present: bool) -> Fallible<bool> {
        let (dk0, dk1) = (Key::new()?, Key::new()?);
        let delegator_icp = genesis(&dk0, &dk1)?;
        let delegator_state = seed(&delegator_icp, &dk0)?;
        let (k0, k1) = (Key::new()?, Key::new()?);
        let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;

        let mut seals: Vec<Seal<'static>> = Vec::new();
        for _ in 0..decoys {
            seals.push(Seal::Digest {
                d: dip.said.clone(),
            });
        }
        if present {
            seals.insert(
                pos.min(decoys),
                Seal::Event {
                    i: dip.prefix.clone(),
                    s: Number::new(0),
                    d: dip.said.clone(),
                },
            );
        }
        let anchor = interaction_anchoring(&delegator_icp, 1, seals)?;
        match KeyState::incept_delegated(
            &dip.signed(vec![k0.sign(&dip.bytes, 0)?]),
            &DelegationEvidence::Anchored(AnchoredDelegation {
                delegator: &delegator_state,
                delegating_event: &anchor.parsed,
            }),
        ) {
            Ok(_) => Ok(true),
            Err(Rejection::Delegation(DelegationError::SealNotFound)) => Ok(false),
            Err(r) => Err(format!("unexpected rejection: {r}").into()),
        }
    }

    /// Pair a dip against the right or wrong delegator state and an anchoring
    /// or non-anchoring delegating event; return `authorizes`'s verdict.
    fn authorizes_verdict(
        use_other_delegator: bool,
        anchor_real: bool,
    ) -> Fallible<Result<(), DelegationError>> {
        let (dk0, dk1) = (Key::new()?, Key::new()?);
        let delegator_icp = genesis(&dk0, &dk1)?;
        let (xk0, xk1) = (Key::new()?, Key::new()?);
        let other_icp = genesis(&xk0, &xk1)?;
        let right_state = seed(&delegator_icp, &dk0)?;
        let other_state = seed(&other_icp, &xk0)?;
        let (k0, k1) = (Key::new()?, Key::new()?);
        let dip = delegated_inception(&k0, &k1, delegator_icp.prefix.clone())?;
        let anchor = if anchor_real {
            anchor_of(&delegator_icp, 1, &dip)?
        } else {
            interaction(&delegator_icp, 1)?
        };
        let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
            delegator: if use_other_delegator {
                &other_state
            } else {
                &right_state
            },
            delegating_event: &anchor.parsed,
        });
        let KeriEvent::DelegatedInception(d) = &dip.parsed else {
            return Err("delegated_inception fixture must parse as a dip".into());
        };
        Ok(evidence.authorizes(&dip.parsed, d.delegator()))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// The matching event-seal is found at ANY position among decoy
        /// seals (0, 1, middle, last), and never found when absent — the
        /// keripy filtered-subsequence semantics.
        #[test]
        fn anchor_found_at_any_position(pos in 0usize..4, decoys in 0usize..4) {
            let present = seal_position_verdict(pos, decoys, true)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(present, "seal at min(pos, decoys) among {decoys} decoys must be found");
            let absent = seal_position_verdict(pos, decoys, false)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(!absent, "an absent seal must be SealNotFound, not acceptance");
        }

        /// authorizes is total over arbitrary evidence pairings: any
        /// (delegator state, delegating event) combination returns Ok or a
        /// typed DelegationError — never a panic. Ok iff the delegator is the
        /// declared one AND the event anchors the dip.
        #[test]
        fn authorizes_is_total(use_other_delegator in any::<bool>(), anchor_real in any::<bool>()) {
            let verdict = authorizes_verdict(use_other_delegator, anchor_real)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            match verdict {
                Ok(()) => prop_assert!(!use_other_delegator && anchor_real),
                Err(_) => prop_assert!(use_other_delegator || !anchor_real),
            }
        }
    }
}
