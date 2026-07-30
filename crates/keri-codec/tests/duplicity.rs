//! K3 (#89): same-sn judgment — gate (A) rules through the public
//! `KeyState::judge_same_sn`, with real folded states and forged contests.
//! Oracle anchors: keripy 9161a705, eventing.py:4396-4478 (gate),
//! 2620-2646 (rot recovery enforcement).
mod common;

use cesr::core::primitives::Number;
use common::{
    Event, Fallible, Key, delegated_inception, delegated_rotation, delegated_rotation_anchoring,
    genesis, interaction, interaction_anchoring, plain_rotation, prefix_of, seed,
};
use keri::{DelegationContest, EvidenceError, KeyState, KeyStateSnapshot, SameSnVerdict};
use keri_events::{KeriEvent, Seal};

/// icp → ixn1 → ixn2: a rot at sn 1 or 2 supersedes (lastEst.s = 0 < sn).
#[test]
fn rot_over_interaction_supersedes() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let ixn2 = interaction(&ixn1, 2)?;
    let state = [
        ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]),
        ixn2.signed(vec![k0.sign(&ixn2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    // competing rot at sn 1, prior = icp said — a legitimate recovery fork
    let rot = plain_rotation(&icp, 1, &k1, &k2)?;
    let verdict = state.judge_same_sn(&rot.parsed, &ixn1.parsed, &[])?;
    assert_eq!(verdict, SameSnVerdict::Supersedes);
    Ok(())
}

/// A rot at the last-establishment sn or below never supersedes (A1):
/// different SAID → duplicitous.
#[test]
fn rot_at_last_establishment_sn_is_duplicitous() -> Fallible<()> {
    let (k0, k1, k2, k3) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let rot1 = plain_rotation(&icp, 1, &k1, &k2)?;
    let state = seed(&icp, &k0)?.ingest(&rot1.signed(vec![k1.sign(&rot1.bytes, 0)?]))?;

    // competing rot at sn 1 = lastEst.s — A1 forbids rot-over-rot
    let rot1b = plain_rotation(&icp, 1, &k1, &k3)?;
    let verdict = state.judge_same_sn(&rot1b.parsed, &rot1.parsed, &[])?;
    assert_eq!(
        verdict,
        SameSnVerdict::Duplicitous {
            recorded: rot1.parsed.said()
        }
    );
    Ok(())
}

/// Resending the recorded event itself is an idempotent duplicate.
#[test]
fn same_said_is_duplicate() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let state = seed(&icp, &k0)?.ingest(&ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]))?;

    let verdict = state.judge_same_sn(&ixn1.parsed, &ixn1.parsed, &[])?;
    assert_eq!(verdict, SameSnVerdict::Duplicate);
    Ok(())
}

/// An interaction supersedes nothing (A2): a competing ixn is duplicitous.
#[test]
fn competing_interaction_is_duplicitous() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let state = seed(&icp, &k0)?.ingest(&ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]))?;

    // forge a different ixn at sn 1: a digest anchor changes the SAID
    let ixn1b = interaction_anchoring(
        &icp,
        1,
        vec![Seal::Digest {
            d: icp.said.clone(),
        }],
    )?;
    let verdict = state.judge_same_sn(&ixn1b.parsed, &ixn1.parsed, &[])?;
    assert_ne!(
        verdict,
        SameSnVerdict::Duplicate,
        "fixture bug: forged ixn must differ from recorded"
    );
    assert_eq!(
        verdict,
        SameSnVerdict::Duplicitous {
            recorded: ixn1.parsed.said()
        }
    );
    Ok(())
}

/// A second, different inception is duplicitous; the same one is a duplicate.
#[test]
fn competing_inception_is_duplicitous() -> Fallible<()> {
    let (k0, k1, kx) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let state = seed(&icp, &k0)?;
    let icp2 = genesis(&k0, &kx)?; // same controller key, different next commit
    let verdict = state.judge_same_sn(&icp2.parsed, &icp.parsed, &[])?;
    assert_eq!(
        verdict,
        SameSnVerdict::Duplicitous {
            recorded: icp.parsed.said()
        }
    );
    assert_eq!(
        state.judge_same_sn(&icp.parsed, &icp.parsed, &[])?,
        SameSnVerdict::Duplicate
    );
    Ok(())
}

/// Evidence boundary: a non-stale incoming sn is the host misusing the judge.
#[test]
fn non_stale_incoming_is_an_evidence_error() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let state = seed(&icp, &k0)?;
    let ixn5 = interaction(&icp, 5)?;
    let err = state
        .judge_same_sn(&ixn5.parsed, &icp.parsed, &[])
        .unwrap_err();
    assert_eq!(
        err,
        EvidenceError::IncomingNotStale {
            incoming_sn: 5,
            state_sn: 0
        }
    );
    Ok(())
}

/// Evidence boundary: recorded event at the wrong sn.
#[test]
fn recorded_sn_mismatch_is_an_evidence_error() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let ixn2 = interaction(&ixn1, 2)?;
    let state = [
        ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]),
        ixn2.signed(vec![k0.sign(&ixn2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;
    let ixn1c = interaction(&icp, 1)?;
    let err = state
        .judge_same_sn(&ixn1c.parsed, &ixn2.parsed, &[])
        .unwrap_err();
    assert_eq!(
        err,
        EvidenceError::RecordedSnMismatch {
            incoming_sn: 1,
            recorded_sn: 2
        }
    );
    Ok(())
}

// ── Gate boundary matrix ────────────────────────────────────────────────────
// KEL: icp(0) → ixn1 → rot2 → ixn3 → ixn4, so lastEst.s = 2 and state.sn = 4
// and every contest position in {le-1, le, le+1, state.sn} exists. Per the
// gate table (eventing.py:4409-4411): rot supersedes iff le < sn; drt over a
// recorded ixn supersedes iff le <= sn; anything falling through the recovery
// window SAID-compares (resend → Duplicate, different SAID → Duplicitous).

/// The matrix KEL and its key material.
struct MatrixKel {
    k0: Key,
    k1: Key,
    icp: Event,
    ixn1: Event,
    rot2: Event,
    ixn3: Event,
    ixn4: Event,
}

impl MatrixKel {
    fn new() -> Fallible<Self> {
        let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
        let icp = genesis(&k0, &k1)?;
        let ixn1 = interaction(&icp, 1)?;
        let rot2 = plain_rotation(&ixn1, 2, &k1, &k2)?;
        let ixn3 = interaction(&rot2, 3)?;
        let ixn4 = interaction(&ixn3, 4)?;
        Ok(Self {
            k0,
            k1,
            icp,
            ixn1,
            rot2,
            ixn3,
            ixn4,
        })
    }

    /// Fold the full KEL: head at sn 4, last establishment at sn 2.
    fn fold(&self) -> Fallible<KeyState<'_>> {
        Ok([
            self.ixn1.signed(vec![self.k0.sign(&self.ixn1.bytes, 0)?]),
            self.rot2.signed(vec![self.k1.sign(&self.rot2.bytes, 0)?]),
            self.ixn3.signed(vec![self.k1.sign(&self.ixn3.bytes, 0)?]),
            self.ixn4.signed(vec![self.k1.sign(&self.ixn4.bytes, 0)?]),
        ]
        .into_iter()
        .try_fold(seed(&self.icp, &self.k0)?, |s, ev| s.ingest(&ev))?)
    }

    /// The recorded event at `sn` (1..=4).
    const fn recorded_at(&self, sn: u128) -> &Event {
        match sn {
            1 => &self.ixn1,
            2 => &self.rot2,
            3 => &self.ixn3,
            _ => &self.ixn4,
        }
    }

    /// The event a contest at `sn` chains onto (the recorded sn - 1 event).
    const fn prior_for(&self, sn: u128) -> &Event {
        match sn {
            1 => &self.icp,
            2 => &self.ixn1,
            3 => &self.rot2,
            _ => &self.ixn3,
        }
    }
}

/// rot contest at sn = le-1 = 1: outside the recovery window → SAID-compare.
#[test]
fn gate_rot_below_last_est() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let kx = Key::new()?;
    let contest = plain_rotation(kel.prior_for(1), 1, &kel.k1, &kx)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(1).parsed, &[])?,
        SameSnVerdict::Duplicitous {
            recorded: kel.recorded_at(1).parsed.said()
        }
    );
    // same-SAID cell: resending the recorded event is a duplicate
    assert_eq!(
        state.judge_same_sn(&kel.recorded_at(1).parsed, &kel.recorded_at(1).parsed, &[])?,
        SameSnVerdict::Duplicate
    );
    Ok(())
}

/// rot contest at sn = le = 2: the window bound is strict (`le < sn`), so a
/// rot at the establishment sn itself SAID-compares (A1: no rot-over-rot).
#[test]
fn gate_rot_at_last_est() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let kx = Key::new()?;
    let contest = plain_rotation(kel.prior_for(2), 2, &kel.k1, &kx)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(2).parsed, &[])?,
        SameSnVerdict::Duplicitous {
            recorded: kel.recorded_at(2).parsed.said()
        }
    );
    // same-SAID cell: the recorded rot resent falls through the window
    assert_eq!(
        state.judge_same_sn(&kel.recorded_at(2).parsed, &kel.recorded_at(2).parsed, &[])?,
        SameSnVerdict::Duplicate
    );
    Ok(())
}

/// rot contest at sn = le+1 = 3: inside the recovery window → supersedes.
#[test]
fn gate_rot_above_last_est() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let kx = Key::new()?;
    let contest = plain_rotation(kel.prior_for(3), 3, &kel.k1, &kx)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(3).parsed, &[])?,
        SameSnVerdict::Supersedes
    );
    // same-SAID cell: resending the recorded ixn is a duplicate
    assert_eq!(
        state.judge_same_sn(&kel.recorded_at(3).parsed, &kel.recorded_at(3).parsed, &[])?,
        SameSnVerdict::Duplicate
    );
    Ok(())
}

/// rot contest at sn = state.sn = 4: inside the recovery window → supersedes.
#[test]
fn gate_rot_at_state_head() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let kx = Key::new()?;
    let contest = plain_rotation(kel.prior_for(4), 4, &kel.k1, &kx)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(4).parsed, &[])?,
        SameSnVerdict::Supersedes
    );
    // same-SAID cell: resending the recorded ixn is a duplicate
    assert_eq!(
        state.judge_same_sn(&kel.recorded_at(4).parsed, &kel.recorded_at(4).parsed, &[])?,
        SameSnVerdict::Duplicate
    );
    Ok(())
}

/// drt contest at sn = le-1 = 1: outside the recovery window (`le <= sn`
/// fails) → SAID-compare.
#[test]
fn gate_drt_below_last_est() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let contest = delegated_rotation(kel.prior_for(1), 1, &kel.k1)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(1).parsed, &[])?,
        SameSnVerdict::Duplicitous {
            recorded: kel.recorded_at(1).parsed.said()
        }
    );
    Ok(())
}

/// drt contest at sn = le = 2: inside the window, but the recorded event is
/// the establishment rot — not an ixn, so no supersede; SAID-compare.
#[test]
fn gate_drt_at_last_est() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let contest = delegated_rotation(kel.prior_for(2), 2, &kel.k1)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(2).parsed, &[])?,
        SameSnVerdict::Duplicitous {
            recorded: kel.recorded_at(2).parsed.said()
        }
    );
    Ok(())
}

/// drt contest at sn = le+1 = 3 over a recorded ixn: supersedes.
#[test]
fn gate_drt_above_last_est() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let contest = delegated_rotation(kel.prior_for(3), 3, &kel.k1)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(3).parsed, &[])?,
        SameSnVerdict::Supersedes
    );
    Ok(())
}

/// drt contest at sn = state.sn = 4 over a recorded ixn: supersedes.
#[test]
fn gate_drt_at_state_head() -> Fallible<()> {
    let kel = MatrixKel::new()?;
    let state = kel.fold()?;
    let contest = delegated_rotation(kel.prior_for(4), 4, &kel.k1)?;
    assert_eq!(
        state.judge_same_sn(&contest.parsed, &kel.recorded_at(4).parsed, &[])?,
        SameSnVerdict::Supersedes
    );
    Ok(())
}

// ── Cascade (B/C rules) ─────────────────────────────────────────────────────
// Oracle: `Kever.validateDelegation` (eventing.py:3413-3492). The delegate
// side is a real dip → drt folded through the trusted snapshot fold; the
// delegator-side anchoring events are host-supplied evidence (the judge never
// verifies signatures), so they are built bare.

/// The delegate side of a cascade contest: a delegated KEL (dip sn 0,
/// recorded drt at sn 1) snapshot-folded, plus a challenger drt at sn 1 with
/// different key material (different SAID).
struct DelegateContest {
    drt: Event,
    drt_b: Event,
    snapshot: KeyStateSnapshot,
}

/// dip (sn 0) → drt (sn 1); challenger drt' reveals a different key.
fn delegate_contest() -> Fallible<DelegateContest> {
    let (dk0, dk1, dk2) = (Key::new()?, Key::new()?, Key::new()?);
    let delegator = Key::new()?;
    let dip = delegated_inception(&dk0, &dk1, prefix_of(&delegator).into())?;
    let drt = delegated_rotation(&dip, 1, &dk1)?;
    let drt_b = delegated_rotation(&dip, 1, &dk2)?;
    let KeriEvent::DelegatedInception(d) = &dip.parsed else {
        return Err("delegated_inception fixture must parse as a dip".into());
    };
    let snapshot = KeyStateSnapshot::genesis(d.inception()).advance(&drt.parsed);
    Ok(DelegateContest {
        drt,
        drt_b,
        snapshot,
    })
}

/// The event-seal approving `ev` — `i` is the delegate event's own prefix
/// (self-addressing for a dip-derived identifier, per the #259 widening).
fn event_seal(ev: &Event) -> Seal<'static> {
    Seal::Event {
        i: ev.prefix.clone(),
        s: Number::new(ev.parsed.sn().value()),
        d: ev.said.clone(),
    }
}

/// B1: the challenger's delegating event has a later sn — supersedes.
#[test]
fn cascade_later_delegating_sn_supersedes() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    let incumbent = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt)])?;
    let challenger = interaction_anchoring(&g_icp, 2, vec![event_seal(&contest.drt_b)])?;
    let chain = [DelegationContest {
        incumbent: &incumbent.parsed,
        challenger: &challenger.parsed,
    }];
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)?,
        SameSnVerdict::Supersedes
    );
    Ok(())
}

/// B2 win: same delegating event, challenger's seal at a later position.
#[test]
fn cascade_same_delegating_event_later_seal_supersedes() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    let anchor = interaction_anchoring(
        &g_icp,
        1,
        vec![event_seal(&contest.drt), event_seal(&contest.drt_b)],
    )?;
    let chain = [DelegationContest {
        incumbent: &anchor.parsed,
        challenger: &anchor.parsed,
    }];
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)?,
        SameSnVerdict::Supersedes
    );
    Ok(())
}

/// B2 loss: same delegating event, challenger's seal not later — yields.
#[test]
fn cascade_same_delegating_event_earlier_seal_yields() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    let anchor = interaction_anchoring(
        &g_icp,
        1,
        vec![event_seal(&contest.drt_b), event_seal(&contest.drt)],
    )?;
    let chain = [DelegationContest {
        incumbent: &anchor.parsed,
        challenger: &anchor.parsed,
    }];
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)?,
        SameSnVerdict::Yields
    );
    Ok(())
}

/// B3: challenger delegated by a drt, incumbent by an ixn — supersedes.
#[test]
fn cascade_drt_over_ixn_delegation_supersedes() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    let incumbent = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt)])?;
    let challenger =
        delegated_rotation_anchoring(&g_icp, 1, &gk1, vec![event_seal(&contest.drt_b)])?;
    let chain = [DelegationContest {
        incumbent: &incumbent.parsed,
        challenger: &challenger.parsed,
    }];
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)?,
        SameSnVerdict::Supersedes
    );
    Ok(())
}

/// C: tie at level 0 (same sn, different delegating ixns) climbs; a B1
/// decision at level 1 resolves it.
#[test]
fn cascade_tie_climbs_then_decides() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    // level 0: two different ixns of the same delegator at the same sn — a tie
    let incumbent = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt)])?;
    let challenger = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt_b)])?;
    // level 1: the delegator's own delegator approved the incumbent at sn 1
    // and the challenger at sn 2 — B1 decides for the challenger
    let (hk0, hk1) = (Key::new()?, Key::new()?);
    let h_icp = genesis(&hk0, &hk1)?;
    let h_incumbent = interaction_anchoring(&h_icp, 1, vec![event_seal(&incumbent)])?;
    let h_challenger = interaction_anchoring(&h_incumbent, 2, vec![event_seal(&challenger)])?;
    let chain = [
        DelegationContest {
            incumbent: &incumbent.parsed,
            challenger: &challenger.parsed,
        },
        DelegationContest {
            incumbent: &h_incumbent.parsed,
            challenger: &h_challenger.parsed,
        },
    ];
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)?,
        SameSnVerdict::Supersedes
    );
    Ok(())
}

/// Chain exhausted with the tie unresolved — undecided.
#[test]
fn cascade_exhausted_chain_is_undecided() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    let incumbent = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt)])?;
    let challenger = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt_b)])?;
    let chain = [DelegationContest {
        incumbent: &incumbent.parsed,
        challenger: &challenger.parsed,
    }];
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)?,
        SameSnVerdict::Undecided
    );
    Ok(())
}

/// Empty chain on a drt-vs-drt contest — undecided immediately.
#[test]
fn cascade_empty_chain_is_undecided() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    assert_eq!(
        state.judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &[])?,
        SameSnVerdict::Undecided
    );
    Ok(())
}

/// A pair whose delegating event does not seal the delegated event is a
/// typed evidence error naming the level.
#[test]
fn cascade_unlinked_pair_is_seal_not_found() -> Fallible<()> {
    let contest = delegate_contest()?;
    let state = contest.snapshot.view();
    let (gk0, gk1) = (Key::new()?, Key::new()?);
    let g_icp = genesis(&gk0, &gk1)?;
    let incumbent = interaction_anchoring(&g_icp, 1, vec![event_seal(&contest.drt)])?;
    let challenger = interaction(&g_icp, 2)?; // anchors nothing
    let chain = [DelegationContest {
        incumbent: &incumbent.parsed,
        challenger: &challenger.parsed,
    }];
    let err = state
        .judge_same_sn(&contest.drt_b.parsed, &contest.drt.parsed, &chain)
        .unwrap_err();
    assert_eq!(err, EvidenceError::SealNotFound { level: 0 });
    Ok(())
}

// ── Fold round-trip ─────────────────────────────────────────────────────────

/// After a Supersedes verdict the host rewinds to sn-1 and re-drives the
/// validating fold: the recovery rot chains onto the truncated state and the
/// post-recovery state carries the rot's keys (keripy: Kever.rotate recovery
/// branch checks prior against the recorded sn-1 event — here that IS
/// `check_chains_onto` on the rewound state).
#[test]
fn supersedes_verdict_rewinds_and_refolds() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let ixn2 = interaction(&ixn1, 2)?;
    let head = [
        ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]),
        ixn2.signed(vec![k0.sign(&ixn2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    let rot = plain_rotation(&icp, 1, &k1, &k2)?;
    assert_eq!(
        head.judge_same_sn(&rot.parsed, &ixn1.parsed, &[])?,
        SameSnVerdict::Supersedes
    );

    // host's move: replay the stream truncated to sn-1 = 0, then ingest
    let recovered = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?]))?;
    assert_eq!(recovered.sn().value(), 1);
    assert_eq!(recovered.keys()[0].raw(), k1.verfer.raw());
    assert_eq!(recovered.last_establishment().sn.value(), 1);
    Ok(())
}

// ── Properties ──────────────────────────────────────────────────────────────

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

        /// Totality: any stale sn / recorded pairing / chain depth yields a
        /// verdict or a typed error — never a panic. Drives sns across the
        /// boundary set (small and `u128::MAX >> 1` heads, incoming 0..8) and
        /// chains across 0/1/deep; reaching the assertion at all IS the
        /// property (no panic/overflow anywhere in the judge).
        #[test]
        fn judge_is_total(
            head_sn in prop_oneof![Just(1u128), Just(2), Just(5), Just(u128::MAX >> 1)],
            incoming_sn in 0u128..8,
            chain_len in 0usize..4,
        ) {
            let fail = |e: Box<dyn std::error::Error>| TestCaseError::fail(e.to_string());
            let (k0, k1) = (Key::new().map_err(fail)?, Key::new().map_err(fail)?);
            let icp = genesis(&k0, &k1).map_err(fail)?;

            // Fold a KEL to `head_sn`, capping real events at 5 (the trusted
            // snapshot fold carries the head beyond that — the judge only
            // reads sn / lastEst off it).
            let built = head_sn.min(5);
            let mut chain = vec![icp];
            for sn in 1..=built {
                let prior = chain.last().ok_or_else(|| TestCaseError::fail("chain non-empty"))?;
                chain.push(interaction(prior, sn).map_err(fail)?);
            }
            let KeriEvent::Inception(genesis_event) = &chain[0].parsed else {
                return Err(TestCaseError::fail("genesis fixture parses as icp"));
            };
            let mut snapshot = KeyStateSnapshot::genesis(genesis_event);
            for ev in &chain[1..] {
                snapshot = snapshot.advance(&ev.parsed);
            }
            if head_sn > built {
                // the snapshot is owned 'static — the forged top event only
                // feeds `advance`, no borrow is retained
                let prior = chain.last().ok_or_else(|| TestCaseError::fail("chain non-empty"))?;
                let forged = interaction(prior, head_sn).map_err(fail)?;
                snapshot = snapshot.advance(&forged.parsed);
            }
            let state = snapshot.view();

            // Incoming: a fresh icp at sn 0, a drt at even sn (exercising the
            // cascade against a recorded drt), else a rot.
            let prior_idx = usize::try_from((incoming_sn.saturating_sub(1)).min(built))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let contest_prior = &chain[prior_idx];
            let kx = Key::new().map_err(fail)?;
            let incoming = if incoming_sn == 0 {
                genesis(&kx, &k1).map_err(fail)?
            } else if incoming_sn % 2 == 0 {
                delegated_rotation(contest_prior, incoming_sn, &kx).map_err(fail)?
            } else {
                plain_rotation(contest_prior, incoming_sn, &kx, &k1).map_err(fail)?
            };

            // Recorded at the incoming sn: the real KEL event when one exists,
            // else a forged event of matching ilk (drt pairs exercise the
            // cascade; anything else exercises the gate).
            let recorded = if incoming_sn >= 1 && incoming_sn <= built {
                &chain[usize::try_from(incoming_sn)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?]
            } else {
                &incoming
            };

            // Fully seal-linked chain pairs, each level approving the pair
            // below (ties all the way up — the climb must terminate in
            // Undecided, never hang or overflow).
            let (gk0, gk1) = (Key::new().map_err(fail)?, Key::new().map_err(fail)?);
            let g_icp = genesis(&gk0, &gk1).map_err(fail)?;
            let mut levels: Vec<(Event, Event)> = Vec::new();
            let (mut cur_old, mut cur_new) = (recorded, &incoming);
            for level in 0..chain_len {
                let sn = u128::try_from(level)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?
                    + 1;
                let inc = interaction_anchoring(&g_icp, sn, vec![event_seal(cur_old)])
                    .map_err(fail)?;
                let chal = interaction_anchoring(&g_icp, sn, vec![event_seal(cur_new)])
                    .map_err(fail)?;
                levels.push((inc, chal));
                let (last_inc, last_chal) = &levels[levels.len() - 1];
                cur_old = last_inc;
                cur_new = last_chal;
            }
            let contests: Vec<DelegationContest<'_>> = levels
                .iter()
                .map(|(inc, chal)| DelegationContest {
                    incumbent: &inc.parsed,
                    challenger: &chal.parsed,
                })
                .collect();

            let result = state.judge_same_sn(&incoming.parsed, &recorded.parsed, &contests);
            prop_assert!(
                matches!(result, Ok(_) | Err(_)),
                "judge must return a verdict or a typed error, never panic"
            );
        }

        /// Antisymmetry: two events contesting the same sn cannot both
        /// supersede — judge(a, b) == Supersedes implies judge(b, a) !=
        /// Supersedes. The recorded side is always the real folded-KEL event
        /// (a rot-vs-rot contest above lastEst.s is unreachable in a real
        /// KEL: the recorded establishment would BE lastEst — the gate's A1
        /// bound is what makes the property hold).
        #[test]
        fn supersedes_is_antisymmetric(
            use_rot in any::<bool>(),
            vary_said in any::<bool>(),
            sn in 1u128..4,
        ) {
            let fail = |e: Box<dyn std::error::Error>| TestCaseError::fail(e.to_string());
            let (k0, k1, k2, k3) = (
                Key::new().map_err(fail)?,
                Key::new().map_err(fail)?,
                Key::new().map_err(fail)?,
                Key::new().map_err(fail)?,
            );
            // icp → rot1 → ixn2 → ixn3: lastEst.s = 1, head at sn 3.
            let icp = genesis(&k0, &k1).map_err(fail)?;
            let rot1 = plain_rotation(&icp, 1, &k1, &k2).map_err(fail)?;
            let ixn2 = interaction(&rot1, 2).map_err(fail)?;
            let ixn3 = interaction(&ixn2, 3).map_err(fail)?;
            let chain = [icp, rot1, ixn2, ixn3];
            let KeriEvent::Inception(genesis_event) = &chain[0].parsed else {
                return Err(TestCaseError::fail("genesis fixture parses as icp"));
            };
            let mut snapshot = KeyStateSnapshot::genesis(genesis_event);
            for ev in &chain[1..] {
                snapshot = snapshot.advance(&ev.parsed);
            }
            let state = snapshot.view();

            let prior = &chain[usize::try_from(sn - 1)
                .map_err(|e| TestCaseError::fail(e.to_string()))?];
            let challenger = if use_rot {
                let next = if vary_said { &k2 } else { &k3 };
                plain_rotation(prior, sn, &k1, next).map_err(fail)?
            } else if vary_said {
                interaction_anchoring(prior, sn, vec![Seal::Digest {
                    d: chain[0].said.clone(),
                }])
                .map_err(fail)?
            } else {
                interaction(prior, sn).map_err(fail)?
            };
            let recorded = &chain[usize::try_from(sn)
                .map_err(|e| TestCaseError::fail(e.to_string()))?];

            let forward = state
                .judge_same_sn(&challenger.parsed, &recorded.parsed, &[])
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let backward = state
                .judge_same_sn(&recorded.parsed, &challenger.parsed, &[])
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(
                !(forward == SameSnVerdict::Supersedes && backward == SameSnVerdict::Supersedes),
                "both directions superseded at sn {sn}: forward={forward:?} backward={backward:?}"
            );
        }
    }
}
