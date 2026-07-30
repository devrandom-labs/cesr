# K3 Duplicity + Superseding-Recovery Implementation Plan (#89)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `KeyState::judge_same_sn` — duplicity detection + superseding-recovery as a pure function of state + host-supplied evidence, keripy-conformant (oracle: main `9161a705`).

**Architecture:** New module `crates/keri/src/duplicity.rs` beside `state.rs`; unified accessors added to `keri_events::KeriEvent`; `Disposition::Contested` routes hosts from the K1 fold's stale rejections to the judge. Integration tests live in `crates/keri-codec/tests/` (established pattern — the `keri` crate cannot forge events; fixtures come from `tests/common/mod.rs`). Spec: `docs/superpowers/specs/2026-07-30-89-k3-duplicity-superseding-design.md`.

**Tech Stack:** Rust (`keri-rs`, `keri-events`), proptest, keripy generator scripts (`scripts/keripy_*_gen.py` pattern), `nix flake check` gate.

**PREREQUISITE:** the seal-identifier-widening PR (`docs/superpowers/plans/2026-07-30-seal-identifier-widening.md`) is merged and this branch is rebased on it — the cascade compares `Seal::Event.i` (an `Identifier`) against delegated-event prefixes.

---

### Task 1: Unified accessors on `KeriEvent`

**Files:**
- Modify: `crates/keri-events/src/event/mod.rs`

- [ ] **Step 1: Write the failing tests**

In the existing `mod tests` of `event/mod.rs`:

```rust
#[test]
fn keri_event_unified_accessors() {
    let icp = make_inception();
    let (sn, said, prefix) = (icp.sn(), icp.said().clone(), icp.prefix().clone());
    let event = KeriEvent::Inception(icp);
    assert_eq!(event.sn(), sn);
    assert_eq!(event.said(), &said);
    assert_eq!(event.prefix(), &prefix);
    assert!(event.anchors().is_empty());
}

#[test]
fn keri_event_unified_accessors_delegated() {
    use crate::identifier::Identifier;
    let inner = make_inception();
    let sn = inner.sn();
    let dip = DelegatedInceptionEvent::new(
        inner,
        Identifier::Basic(make_prefixer()),
    );
    let event = KeriEvent::DelegatedInception(dip);
    assert_eq!(event.sn(), sn);
    assert_eq!(event.message_type(), MessageType::Dip);
}
```

- [ ] **Step 2: Run — expect failure**

Run: `nix develop --command cargo nextest run -p keri-events unified_accessors`
Expected: compile FAIL — no method `sn` on `KeriEvent`.

- [ ] **Step 3: Implement the accessors**

In `impl KeriEvent<'_>` — change the impl header to `impl<'a> KeriEvent<'a>` (keep `message_type`/`into_static` inside it):

```rust
    /// Sequence number, uniform across variants.
    #[must_use]
    pub const fn sn(&self) -> Number {
        match self {
            Self::Inception(e) => e.sn(),
            Self::Rotation(e) => e.sn(),
            Self::Interaction(e) => e.sn(),
            Self::DelegatedInception(e) => e.inception().sn(),
            Self::DelegatedRotation(e) => e.rotation().sn(),
        }
    }

    /// SAID, uniform across variants.
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        match self {
            Self::Inception(e) => e.said(),
            Self::Rotation(e) => e.said(),
            Self::Interaction(e) => e.said(),
            Self::DelegatedInception(e) => e.inception().said(),
            Self::DelegatedRotation(e) => e.rotation().said(),
        }
    }

    /// Identifier prefix, uniform across variants.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'a> {
        match self {
            Self::Inception(e) => e.prefix(),
            Self::Rotation(e) => e.prefix(),
            Self::Interaction(e) => e.prefix(),
            Self::DelegatedInception(e) => e.inception().prefix(),
            Self::DelegatedRotation(e) => e.rotation().prefix(),
        }
    }

    /// Anchored seals (the `a` field), uniform across variants.
    #[must_use]
    pub fn anchors(&self) -> &[Seal<'a>] {
        match self {
            Self::Inception(e) => e.anchors(),
            Self::Rotation(e) => e.anchors(),
            Self::Interaction(e) => e.anchors(),
            Self::DelegatedInception(e) => e.inception().anchors(),
            Self::DelegatedRotation(e) => e.rotation().anchors(),
        }
    }
```

Imports at top of file: `use crate::identifier::Identifier; use crate::primitive::Said; use crate::seal::Seal; use cesr::core::primitives::Number;` (adjust to the file's existing paths). If `Number` lacks `const`-compatible copy semantics for a `const fn`, drop `const` — do not fight it.

- [ ] **Step 4: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-events`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/keri-events
git commit -m "feat(keri-events): unified sn/said/prefix/anchors accessors on KeriEvent"
```

### Task 2: `duplicity.rs` — types, gate, cascade

**Files:**
- Create: `crates/keri/src/duplicity.rs`
- Modify: `crates/keri/src/lib.rs` (module + re-exports + crate-doc paragraph)

- [ ] **Step 1: Write the module**

`crates/keri/src/duplicity.rs` — complete content (rule anchors cite keripy `9161a705`):

```rust
//! Duplicity detection and superseding recovery: pure judgment on an event
//! that contests an already-occupied sequence number.
//!
//! The host owns the stream: it already knows what is recorded at `(pre, sn)`
//! and supplies it as evidence; the core judges. On [`SameSnVerdict::Supersedes`]
//! the host rewinds its stream to `sn - 1`, re-folds, and re-ingests the
//! incoming event through the validating fold ([`KeyState::ingest`]) — the
//! prior-digest check against the recorded `sn - 1` event and all
//! signature/commitment/witness validation happen there, never here.
//!
//! keripy conformance (main `9161a705`): the same-sn acceptance gate is
//! `Kevery.processEvent` (eventing.py:4396-4413, icp branch 4362-4392,
//! duplicate-vs-duplicitous 4447-4478); the drt-over-drt cascade is
//! `Kever.validateDelegation` (eventing.py:3413-3492). keripy walks its own
//! database (`fetchDelegatingEvent`) recursively; here the chain arrives as a
//! slice of [`DelegationContest`] pairs, so the climb is a bounded iteration
//! and an adversarial recursion bomb is unrepresentable.
use keri_events::{Identifier, KeriEvent, MessageType, Said, Seal};

use crate::state::KeyState;

/// Judgment on an event contesting an already-occupied sn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSnVerdict<'a> {
    /// Same SAID as the recorded event — idempotent. The host may verify and
    /// log late-arriving signatures (keripy logs them; eventing.py:4449-4472).
    Duplicate,
    /// A recovery rule fired. The host rewinds to `sn - 1`, re-folds, and
    /// re-ingests the incoming event through the validating fold.
    Supersedes,
    /// Different SAID and no recovery rule applies — duplicity evidence.
    /// keripy escrows these for duplicity reporting (`escrowLDEvent`).
    Duplicitous {
        /// SAID of the recorded event, for watcher reporting.
        recorded: &'a Said<'a>,
    },
    /// Cascade loss: same delegating event, and the challenger's seal does
    /// not come after the incumbent's (B2). An inferior recovery claim —
    /// keripy drops it with a bare `ValidationError` (eventing.py:3467-3475),
    /// not duplicity escrow. Drop quietly.
    Yields,
    /// The delegation-chain evidence ran out before a decision (keripy
    /// escrows as missing-delegation, eventing.py:3480-3489). Park and
    /// re-judge when deeper chain evidence arrives.
    Undecided,
}

/// One level of the drt-over-drt climb: the two delegating events whose
/// contest decides (or defers) the level below.
#[derive(Debug, Clone, Copy)]
pub struct DelegationContest<'a> {
    /// Delegating event on the recorded (incumbent) side.
    pub incumbent: &'a KeriEvent<'a>,
    /// Delegating event on the incoming (challenger) side.
    pub challenger: &'a KeriEvent<'a>,
}

/// Host-supplied evidence is inconsistent with the state or with itself.
/// Boundary validation — a typed error, never a verdict.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    /// The incoming event's sn is beyond the state head — not a same-sn
    /// contest at all (the fold's out-of-order path owns it).
    #[error("incoming sn {incoming_sn} is not stale for state at sn {state_sn}")]
    IncomingNotStale {
        /// The incoming event's sequence number.
        incoming_sn: u128,
        /// The state head's sequence number.
        state_sn: u128,
    },
    /// The recorded event is not at the incoming event's sn.
    #[error("recorded event sn {recorded_sn} does not match incoming sn {incoming_sn}")]
    RecordedSnMismatch {
        /// The incoming event's sequence number.
        incoming_sn: u128,
        /// The recorded event's sequence number.
        recorded_sn: u128,
    },
    /// A delegating event at this chain level carries no event-seal matching
    /// the `(i, s, d)` of the delegated event below it — the pair is not a
    /// delegation link. keripy assumes database linkage and would crash here
    /// (`nseals.index`, eventing.py:3459); host-supplied evidence gets a
    /// typed error instead.
    #[error("delegating event at chain level {level} carries no seal of its delegated event")]
    SealNotFound {
        /// Zero-based level in `delegation_chain` (0 = nearest the contest).
        level: usize,
    },
}

impl KeyState<'_> {
    /// Judge an incoming same-sn event against what the host has recorded.
    ///
    /// `recorded` is the accepted event at the incoming event's sn;
    /// `delegation_chain` carries the delegating-event pairs for the
    /// drt-over-drt cascade, ordered from the contest upward (empty for
    /// non-delegated contests).
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] when the supplied evidence is inconsistent:
    /// the incoming event is not stale, the recorded event is at a different
    /// sn, or a chain pair is not seal-linked to the level below.
    pub fn judge_same_sn<'a>(
        &self,
        incoming: &KeriEvent<'_>,
        recorded: &'a KeriEvent<'a>,
        delegation_chain: &[DelegationContest<'_>],
    ) -> Result<SameSnVerdict<'a>, EvidenceError> {
        let incoming_sn = incoming.sn().value();
        let state_sn = self.sn().value();
        if incoming_sn > state_sn {
            return Err(EvidenceError::IncomingNotStale {
                incoming_sn,
                state_sn,
            });
        }
        let recorded_sn = recorded.sn().value();
        if recorded_sn != incoming_sn {
            return Err(EvidenceError::RecordedSnMismatch {
                incoming_sn,
                recorded_sn,
            });
        }
        let last_est_sn = self.last_establishment().sn.value();
        match incoming.message_type() {
            // Inceptions and interactions supersede nothing (gate: only rot
            // and drt have recovery ranges; icp handled at eventing.py:4362).
            MessageType::Icp | MessageType::Dip | MessageType::Ixn => {
                Ok(said_verdict(incoming, recorded))
            }
            // rot recovery: lastEst.s < sn <= expected (eventing.py:4409).
            // The bound IS rule A1 (a rot never supersedes a rot: every sn
            // above lastEst.s holds an interaction) and implies A0.
            MessageType::Rot => {
                if last_est_sn < incoming_sn {
                    Ok(SameSnVerdict::Supersedes)
                } else {
                    Ok(said_verdict(incoming, recorded))
                }
            }
            // drt recovery: lastEst.s <= sn <= expected (eventing.py:4411) —
            // a drt may supersede the establishment event itself, so the
            // recorded event decides the branch.
            MessageType::Drt => {
                if last_est_sn <= incoming_sn {
                    match recorded.message_type() {
                        MessageType::Ixn => Ok(SameSnVerdict::Supersedes),
                        MessageType::Drt => {
                            cascade(incoming, recorded, delegation_chain)
                        }
                        // A drt contesting a recorded icp/dip/rot has no
                        // keripy-sane path (a delegated identifier's
                        // establishment events are dip/drt): SAID-compare.
                        MessageType::Icp | MessageType::Dip | MessageType::Rot => {
                            Ok(said_verdict(incoming, recorded))
                        }
                    }
                } else {
                    Ok(said_verdict(incoming, recorded))
                }
            }
        }
    }
}

/// Same SAID → duplicate; different SAID with no recovery rule → duplicitous
/// (eventing.py:4448-4478).
fn said_verdict<'a>(
    incoming: &KeriEvent<'_>,
    recorded: &'a KeriEvent<'a>,
) -> SameSnVerdict<'a> {
    if incoming.said() == recorded.said() {
        SameSnVerdict::Duplicate
    } else {
        SameSnVerdict::Duplicitous {
            recorded: recorded.said(),
        }
    }
}

/// The drt-over-drt climb (`validateDelegation`, eventing.py:3413-3492),
/// with keripy's recursive database walk replaced by the host-supplied pair
/// slice. Every level is first proven to be a delegation link (seal lookup on
/// both sides — keripy gets this from its `aess` index by construction), then
/// judged: B1 later-delegating-sn wins; B3 delegating drt beats delegating
/// ixn; B2 same delegating event → later seal position wins, else the
/// challenger yields; anything else is a tie — climb. Chain exhausted →
/// undecided.
fn cascade<'a>(
    incoming: &KeriEvent<'_>,
    recorded: &'a KeriEvent<'a>,
    chain: &[DelegationContest<'_>],
) -> Result<SameSnVerdict<'a>, EvidenceError> {
    let mut delegated_old: &KeriEvent<'_> = recorded;
    let mut delegated_new: &KeriEvent<'_> = incoming;
    for (level, contest) in chain.iter().enumerate() {
        let challenger_pos = seal_position(contest.challenger, delegated_new)
            .ok_or(EvidenceError::SealNotFound { level })?;
        let incumbent_pos = seal_position(contest.incumbent, delegated_old)
            .ok_or(EvidenceError::SealNotFound { level })?;
        // B1 (eventing.py:3444): later delegating sn wins.
        if contest.challenger.sn().value() > contest.incumbent.sn().value() {
            return Ok(SameSnVerdict::Supersedes);
        }
        // B3 (eventing.py:3445-3446): delegating drt beats delegating ixn.
        if contest.challenger.message_type() == MessageType::Drt
            && contest.incumbent.message_type() == MessageType::Ixn
        {
            return Ok(SameSnVerdict::Supersedes);
        }
        // B2 (eventing.py:3450-3475): same delegating event — the later seal
        // position wins; otherwise the challenger's claim is inferior.
        if contest.challenger.said() == contest.incumbent.said() {
            return Ok(if challenger_pos > incumbent_pos {
                SameSnVerdict::Supersedes
            } else {
                SameSnVerdict::Yields
            });
        }
        // C (eventing.py:3477-3491): tie — climb one level. keripy climbs
        // without comparing sns further (even challenger.sn < incumbent.sn
        // climbs); mirrored deliberately for parity.
        delegated_old = contest.incumbent;
        delegated_new = contest.challenger;
    }
    Ok(SameSnVerdict::Undecided)
}

/// Position of the event-seal matching `delegated`'s `(i, s, d)` within
/// `delegating`'s event-seals (keripy filters seals to `SealEvent` fields and
/// takes `.index` within the filtered sequence — eventing.py:3455-3463).
fn seal_position(delegating: &KeriEvent<'_>, delegated: &KeriEvent<'_>) -> Option<usize> {
    let target: (&Identifier<'_>, u128, &Said<'_>) =
        (delegated.prefix(), delegated.sn().value(), delegated.said());
    delegating
        .anchors()
        .iter()
        .filter_map(|seal| match seal {
            Seal::Event { i, s, d } => Some((i, s.value(), d)),
            _ => None,
        })
        .position(|(i, s, d)| i == target.0 && s == target.1 && d == target.2)
}
```

- [ ] **Step 2: Wire into `lib.rs`**

In `crates/keri/src/lib.rs`:

```rust
/// Duplicity detection and superseding recovery.
pub mod duplicity;
```

(next to the other module declarations), and extend the re-exports:

```rust
pub use duplicity::{DelegationContest, EvidenceError, SameSnVerdict};
```

Add one crate-doc paragraph after the escrow paragraph:

```rust
//! **Duplicity and superseding recovery are a judgment, not a lookup.** When
//! the fold rejects an event whose sn the KEL already occupies
//! ([`Disposition::Contested`]), the host supplies what it has recorded —
//! the event at that sn, plus delegating-event pairs for delegated contests —
//! and [`KeyState::judge_same_sn`] returns a [`SameSnVerdict`]: duplicate,
//! duplicitous, superseding recovery, an inferior claim, or undecided
//! pending deeper evidence. On `Supersedes` the host rewinds its own stream
//! and re-drives the validating fold; the core never stores or replays.
```

- [ ] **Step 3: Build**

Run: `nix develop --command cargo build -p keri-rs`
Expected: clean (note: `Disposition::Contested` referenced in docs lands in Task 3 — if the doc-link breaks the build, add the paragraph in Task 3 instead).

- [ ] **Step 4: Commit**

```bash
git add crates/keri
git commit -m "feat(keri): #89 duplicity judge — same-sn gate + drt cascade"
```

### Task 3: `Disposition::Contested`

**Files:**
- Modify: `crates/keri/src/error.rs`

- [ ] **Step 1: Update the two failing disposition tests + add the new ones**

In `error.rs` `mod tests`, change:

```rust
    #[test]
    fn out_of_order_stale_is_contested() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 2,
        };
        assert_eq!(r.disposition(), Disposition::Contested);
    }

    #[test]
    fn out_of_order_stale_at_u128_boundary_is_contested() {
        let r = Rejection::OutOfOrder {
            expected: u128::MAX,
            actual: 0,
        };
        assert_eq!(r.disposition(), Disposition::Contested);
    }

    #[test]
    fn duplicate_inception_is_contested() {
        let r = Rejection::from(StructuralError::DuplicateInception);
        assert_eq!(r.disposition(), Disposition::Contested);
    }
```

and repoint the existing `structural_error_is_terminal` test at a variant that
stays terminal:

```rust
    #[test]
    fn structural_error_is_terminal() {
        let r = Rejection::from(StructuralError::InteractionOnEstablishmentOnly);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }
```

(`structural_error_maps_to_structural` can keep using `DuplicateInception` — it tests the `From` wiring, not the disposition.)

- [ ] **Step 2: Run — expect failures**

Run: `nix develop --command cargo nextest run -p keri-rs disposition`
Expected: FAIL — no `Contested` variant / old tests assert `Terminal`.

- [ ] **Step 3: Implement**

Add the variant to `Disposition`:

```rust
    /// The sn is already occupied: fetch the recorded event at that sn (plus
    /// delegating-event pairs for a delegated contest) and consult
    /// [`KeyState::judge_same_sn`](crate::KeyState::judge_same_sn) — the
    /// event may be a duplicate, duplicitous, or a superseding recovery.
    Contested,
```

In `Rejection::disposition`:
- the stale `OutOfOrder` arm (`actual <= expected` branch) returns `Disposition::Contested` (replace the `Terminal` return and its K3-forward-reference comment);
- pull `DuplicateInception` out of the blanket `Structural` arm:

```rust
            Self::Structural(StructuralError::DuplicateInception) => Disposition::Contested,
            Self::Structural(_) => Disposition::Terminal,
```

(keeping the other members of the big `Terminal` `|`-pattern intact; move `Self::Structural(_)` out of that pattern into its own arm so the specific arm precedes it). Update the doc comments on `OutOfOrder` and on `Disposition` (the "Duplicity routing detail is K3" note on `Terminal` is now real — point it at `Contested`).

- [ ] **Step 4: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-rs`
Expected: PASS.

- [ ] **Step 5: Check downstream disposition matches**

Run: `rg -n "Disposition::" crates/keri-codec/tests fuzz fuzz-common fuzz-afl examples 2>/dev/null`
Any exhaustive `match` on `Disposition` gains a `Contested` arm; any test asserting `Terminal` for stale out-of-order or duplicate inception updates to `Contested`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(keri)!: #89 Disposition::Contested routes same-sn contests to the judge"
```

### Task 4: Gate integration tests (A rules)

**Files:**
- Create: `crates/keri-codec/tests/duplicity.rs`
- Modify: `crates/keri-codec/tests/common/mod.rs` (one fixture helper)

- [ ] **Step 1: Add an anchoring-interaction fixture**

`common/mod.rs` already builds interactions via the ixn builder. Add a variant that anchors seals (needed for cascade tests in Task 5, added now so the file is touched once):

```rust
/// Interaction anchoring the given seals (a delegator approving a delegated
/// event does this). Same shape as `interaction`, plus the `a` section.
pub fn interaction_anchoring(
    prior: &Event,
    sn: u128,
    seals: Vec<Seal<'static>>,
) -> Fallible<Event> {
    // copy the body of `interaction` and pass `seals` where it passes the
    // empty anchor list (the ixn builder already takes the anchor Vec —
    // see `builder/ixn.rs`).
}
```

(Write it by copying the real `interaction` body — at execution time — and threading `seals` through; the builder accepts anchors today, `interaction` just passes empty.)

- [ ] **Step 2: Write the gate tests**

`crates/keri-codec/tests/duplicity.rs`:

```rust
//! K3 (#89): same-sn judgment — gate (A) rules through the public
//! `KeyState::judge_same_sn`, with real folded states and forged contests.
//! Oracle anchors: keripy 9161a705, eventing.py:4396-4478 (gate),
//! 2620-2646 (rot recovery enforcement).
mod common;

use common::{
    Fallible, Key, basic_inception, genesis, interaction, plain_rotation, seed,
};
use keri::{EvidenceError, KeyState, SameSnVerdict};
use keri_events::KeriEvent;

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
    let verdict = state.judge_same_sn(&rot.event, &ixn1.event, &[])?;
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
    let state = [rot1.signed(vec![k1.sign(&rot1.bytes, 0)?])]
        .into_iter()
        .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    // competing rot at sn 1 = lastEst.s — A1 forbids rot-over-rot
    let rot1b = plain_rotation(&icp, 1, &k1, &k3)?;
    let verdict = state.judge_same_sn(&rot1b.event, &rot1.event, &[])?;
    assert_eq!(
        verdict,
        SameSnVerdict::Duplicitous {
            recorded: rot1.event.said()
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
    let state = [ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?])]
        .into_iter()
        .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    let verdict = state.judge_same_sn(&ixn1.event, &ixn1.event, &[])?;
    assert_eq!(verdict, SameSnVerdict::Duplicate);
    Ok(())
}

/// An interaction supersedes nothing (A2): a competing ixn is duplicitous.
#[test]
fn competing_interaction_is_duplicitous() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let state = [ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?])]
        .into_iter()
        .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    // forge a different ixn at sn 1 (different prior → different SAID)
    let ixn1b = interaction(&icp, 1)?; // rebuilt — assert it differs, else vary it
    let verdict = state.judge_same_sn(&ixn1b.event, &ixn1.event, &[])?;
    match verdict {
        SameSnVerdict::Duplicate => {
            panic!("fixture bug: forged ixn must differ from recorded")
        }
        v => assert_eq!(
            v,
            SameSnVerdict::Duplicitous {
                recorded: ixn1.event.said()
            }
        ),
    }
    Ok(())
}

/// A second, different inception is duplicitous; the same one is a duplicate.
#[test]
fn competing_inception_is_duplicitous() -> Fallible<()> {
    let (k0, k1, kx) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let state = seed(&icp, &k0)?;
    let icp2 = genesis(&k0, &kx)?; // same controller key, different next commit
    let verdict = state.judge_same_sn(&icp2.event, &icp.event, &[])?;
    assert_eq!(
        verdict,
        SameSnVerdict::Duplicitous {
            recorded: icp.event.said()
        }
    );
    assert_eq!(
        state.judge_same_sn(&icp.event, &icp.event, &[])?,
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
        .judge_same_sn(&ixn5.event, &icp.event, &[])
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
        .judge_same_sn(&ixn1c.event, &ixn2.event, &[])
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
```

Adapt to `common::Event`'s real field names (`.event`, `.bytes` — check `Event` at `common/mod.rs:150`). If `interaction(&icp, 1)?` twice yields identical SAIDs (deterministic builder), vary the second via `interaction_anchoring` with a digest seal so the SAIDs differ — the `competing_interaction` test's `match` guards against a silently-identical fixture either way.

- [ ] **Step 3: Run — expect pass** (implementation landed in Task 2)

Run: `nix develop --command cargo nextest run -p keri-codec duplicity`
Expected: PASS. Any failure here is a real gate bug — fix `duplicity.rs`, not the test.

- [ ] **Step 4: Commit**

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #89 gate (A-rule) coverage for judge_same_sn"
```

### Task 5: Cascade integration tests (B/C rules)

**Files:**
- Modify: `crates/keri-codec/tests/duplicity.rs`
- Modify: `crates/keri-codec/tests/common/mod.rs` (if `delegated_rotation` needs an anchors variant)

- [ ] **Step 1: Write the cascade tests**

Cascade inputs need no valid signatures and no folded delegated state — the judge is pure. Build a minimal delegated contest: state folded from a plain KEL is NOT required; instead use `KeyStateSnapshot` for a delegated stream (the trusted fold accepts drt), then `view()`:

```rust
use keri::KeyStateSnapshot;
use keri::{DelegationContest};
use keri_events::{Identifier, Seal};

/// Build: dip (sn 0) → drt (sn 1) for the delegate; two competing delegator
/// events anchoring the recorded drt and a challenger drt'.
/// Returns (delegate_snapshot, recorded_drt, challenger_drt, chain events…).
///
/// Concretely at execution time: use `common::delegated_inception` /
/// `delegated_rotation` for the delegate side and `interaction_anchoring` /
/// `plain_rotation`-with-anchors for the delegator side, sealing each drt's
/// (i, s, d) with `Seal::Event { i: Identifier::SelfAddressing(said) …}`
/// or `Identifier::Basic` to match the delegate's actual prefix derivation
/// (assert which one `delegated_inception` produces and match it — the seal
/// must compare equal to `event.prefix()`).

/// B1: the challenger's delegating event has a later sn — supersedes.
#[test]
fn cascade_later_delegating_sn_supersedes() -> Fallible<()> { /* … */ }

/// B2 win: same delegating event, challenger's seal at a later position.
#[test]
fn cascade_same_delegating_event_later_seal_supersedes() -> Fallible<()> { /* … */ }

/// B2 loss: same delegating event, challenger's seal not later — yields.
#[test]
fn cascade_same_delegating_event_earlier_seal_yields() -> Fallible<()> { /* … */ }

/// B3: challenger delegated by a drt, incumbent by an ixn — supersedes.
#[test]
fn cascade_drt_over_ixn_delegation_supersedes() -> Fallible<()> { /* … */ }

/// C: tie at level 0 (same sn, different delegating drts) climbs; a B1
/// decision at level 1 resolves it.
#[test]
fn cascade_tie_climbs_then_decides() -> Fallible<()> { /* … */ }

/// Chain exhausted with the tie unresolved — undecided.
#[test]
fn cascade_exhausted_chain_is_undecided() -> Fallible<()> { /* … */ }

/// Empty chain on a drt-vs-drt contest — undecided immediately.
#[test]
fn cascade_empty_chain_is_undecided() -> Fallible<()> { /* … */ }

/// A pair whose delegating event does not seal the delegated event is a
/// typed evidence error naming the level.
#[test]
fn cascade_unlinked_pair_is_seal_not_found() -> Fallible<()> { /* … */ }
```

The test bodies are the mechanical assembly of the helper above plus one
`judge_same_sn` call and one `assert_eq!` each, following exactly the shapes
already shown in Task 4 — write them against the real fixture signatures at
execution time. Each test asserts the exact `SameSnVerdict`/`EvidenceError`
variant; `cascade_unlinked_pair_is_seal_not_found` asserts
`EvidenceError::SealNotFound { level: 0 }`.

- [ ] **Step 2: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-codec duplicity`
Expected: PASS (fix implementation, not tests, on failure).

- [ ] **Step 3: Commit**

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #89 cascade (B/C-rule) coverage for judge_same_sn"
```

### Task 6: Property tests — totality + antisymmetry

**Files:**
- Modify: `crates/keri-codec/tests/duplicity.rs` (a `mod properties` with `proptest!`)

- [ ] **Step 1: Write the properties**

Follow the `proptest` usage pattern in `crates/keri-codec/tests/properties.rs` (strategy imports, config). Two properties:

```rust
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Totality: any stale sn / recorded pairing / chain depth yields a
        /// verdict or a typed error — never a panic. Drive sns across the
        /// boundary set and chains across 0/1/deep.
        #[test]
        fn judge_is_total(
            head_sn in prop_oneof![Just(1u128), Just(2), Just(5), Just(u128::MAX >> 1)],
            incoming_sn in 0u128..8,
            chain_len in 0usize..4,
        ) {
            // build a KEL of head_sn interactions after genesis (cap at 5 for
            // cost; head_sn beyond the built KEL uses the snapshot fold),
            // an incoming rot/ixn at incoming_sn, recorded event at the same
            // sn where possible, and chain_len self-referential contest pairs.
            // Assert: judge_same_sn(...) returns Ok(_) or Err(_) — reaching
            // the assertion at all IS the property (no panic/overflow).
        }

        /// Antisymmetry: two distinct events contesting the same sn cannot
        /// both supersede — judge(a, b) == Supersedes implies
        /// judge(b, a) != Supersedes, over rot/ixn contests on the same state.
        /// (For the gate this is structural: Supersedes depends only on
        /// (ilk, sn) vs lastEst — a rot-vs-rot contest at sn > lastEst.s is
        /// impossible since the recorded establishment would BE lastEst; the
        /// property still probes it via forged recorded events.)
        #[test]
        fn supersedes_is_antisymmetric(
            use_rot_a in any::<bool>(),
            use_rot_b in any::<bool>(),
            sn in 1u128..4,
        ) {
            // build state icp + 3 interactions; incoming/recorded each rot or
            // ixn at `sn` per the flags; assert !(judge(a,b) == Ok(Supersedes)
            // && judge(b,a) == Ok(Supersedes)).
        }
    }
}
```

Fill the bodies with the Task 4 fixture calls (real code, no reimplementation
of judge logic). Keep generation cheap: pre-build the KEL once per case from
the drawn parameters; boundary values `0`, `1`, `MAX` appear via the
`prop_oneof`/range choices shown.

- [ ] **Step 2: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-codec duplicity`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #89 totality + antisymmetry properties for judge_same_sn"
```

### Task 7: Supersedes round-trip with the fold

**Files:**
- Modify: `crates/keri-codec/tests/duplicity.rs`

- [ ] **Step 1: Write the recovery round-trip test**

The whole point of the two-fold seam: after `Supersedes`, rewind + re-ingest works with zero new API.

```rust
/// After a Supersedes verdict the host rewinds to sn-1 and re-drives the
/// validating fold: the recovery rot chains onto the truncated state and the
/// post-recovery state carries the rot's keys (keripy: Kever.rotate recovery
/// branch checks prior against the recorded sn-1 event — here that IS
/// check_chains_onto on the rewound state).
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
        head.judge_same_sn(&rot.event, &ixn1.event, &[])?,
        SameSnVerdict::Supersedes
    );

    // host's move: replay the stream truncated to sn-1 = 0, then ingest
    let recovered = seed(&icp, &k0)?
        .ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?]))?;
    assert_eq!(recovered.sn().value(), 1);
    assert_eq!(recovered.keys()[0].raw(), k1.verfer.raw());
    assert_eq!(recovered.last_establishment().sn.value(), 1);
    Ok(())
}
```

- [ ] **Step 2: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-codec duplicity`

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #89 supersedes verdict round-trips through the validating fold"
```

### Task 8: keripy differential vectors — gate scenarios

**Files:**
- Create: `scripts/keripy_duplicity_gen.py`
- Create: `crates/keri-codec/tests/corpus/duplicity.jsonl` (generated, checked in)
- Create: `crates/keri-codec/tests/keripy_duplicity.rs`

- [ ] **Step 1: Write the generator**

Model on `scripts/keripy_keystate_gen.py` (same argparse/salt/imports skeleton
— copy its header and `main` scaffolding). Scenarios drive a real
`Kevery.processEvent` and record keripy's outcome as the expected verdict.
Core of the script (inside `main`, after the imports/salt from the skeleton):

```python
    from keri.core.eventing import Kevery, incept, interact, rotate
    from keri.kering import LikelyDuplicitousError

    def outcome(kvy, serder, sigers):
        """Feed one event; classify keripy's reaction."""
        pre_state = kvy.kevers[serder.pre].serder.said if serder.pre in kvy.kevers else None
        try:
            kvy.processEvent(serder=serder, sigers=sigers)
        except LikelyDuplicitousError:
            return "duplicitous"
        except Exception as ex:  # noqa: BLE001 — record verbatim for triage
            return f"error:{type(ex).__name__}"
        post = kvy.kevers[serder.pre].serder.said
        if post == serder.said:
            return "supersedes" if pre_state is not None else "accepted"
        return "duplicate"
```

Scenarios (each = fresh `openDB` + `Kevery`, fold the base KEL, then feed the
contest event; emit one JSONL record
`{"name", "events": [b64(raw)…], "sigs": [[qb64…]…], "contest": {"raw": b64, "sigs": […]}, "expected": …}`):

1. `rot_recovers_ixn` — icp, ixn1, ixn2; contest rot at sn 1 (keys from the
   icp's committed next) → expected `supersedes`.
2. `duplicate_resend` — icp, ixn1; contest = ixn1 again → `duplicate`.
3. `duplicitous_ixn` — icp, ixn1; contest ixn1' built with a different anchor
   (`interact(..., data=[{"d": <some digest>}])`) → `duplicitous`.
4. `rot_vs_rot` — icp, rot1; contest rot1' with a different next commitment →
   `duplicitous`.
5. `duplicitous_icp` — icp; contest icp' (same signer, different next
   commitment via a different code or witness list) → `duplicitous`.

Run it:

```bash
DYLD_LIBRARY_PATH=<nix libsodium path> python3 scripts/keripy_duplicity_gen.py \
    --keripy ~/Code/keripy --out crates/keri-codec/tests/corpus/duplicity.jsonl
```

(keripy local env: v2.0.0.dev5 checkout, Python ≥ 3.14.2, nix libsodium via
`DYLD_LIBRARY_PATH` — the setup used by the existing differential corpus.)
Inspect the JSONL: every `expected` must be one of
`supersedes|duplicate|duplicitous` — an `error:*` value means the scenario
construction is wrong; fix the script, don't check it in.

- [ ] **Step 2: Write the differential test**

`crates/keri-codec/tests/keripy_duplicity.rs` — follows `differential.rs`
exactly (same `include_str!` + serde records + `siger_from_qb64` + fold via
`common`), then per vector:

```rust
const CORPUS: &str = include_str!("corpus/duplicity.jsonl");

#[test]
fn keripy_same_sn_verdicts_match() -> Fallible<()> {
    for line in CORPUS.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let v: Vector = serde_json::from_str(line)?;
        // fold v.events through KeyState::incept/ingest (differential.rs pattern),
        // parse v.contest.raw, locate the recorded event at contest.sn among
        // the folded events, then:
        let verdict = state.judge_same_sn(&contest_event, recorded_event, &[])?;
        let got = match verdict {
            SameSnVerdict::Supersedes => "supersedes",
            SameSnVerdict::Duplicate => "duplicate",
            SameSnVerdict::Duplicitous { .. } => "duplicitous",
            SameSnVerdict::Yields | SameSnVerdict::Undecided => "other",
        };
        assert_eq!(got, v.expected, "vector {}", v.name);
    }
    Ok(())
}
```

(File/test names contain `keripy` — the nightly `--all-features keripy` filter
requires it.)

- [ ] **Step 3: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-codec keripy_duplicity`

```bash
git add scripts/keripy_duplicity_gen.py crates/keri-codec/tests
git commit -m "test(keri-codec): #89 keripy differential vectors — same-sn gate verdicts"
```

### Task 9: keripy differential vectors — cascade scenarios

**Files:**
- Modify: `scripts/keripy_duplicity_gen.py`
- Modify: `crates/keri-codec/tests/corpus/duplicity.jsonl`
- Modify: `crates/keri-codec/tests/keripy_duplicity.rs`

- [ ] **Step 1: Extend the generator with delegated scenarios**

Adapt keripy's own `tests/core/test_delegating.py::test_delegation_supersede`
(keripy checkout, line 308) — it already constructs: delegator AID, delegated
AID (`delcept`), anchoring events, and a superseding drt. Port its event
construction into the script (deterministic salt, no Habery if the test shows
a db-level path; follow whatever `test_delegation_supersede` itself uses),
producing at least:

6. `drt_cascade_b1` — challenger drt approved by a LATER delegator event →
   `supersedes`; record the delegating pair in the vector
   (`"chain": [{"incumbent": b64, "challenger": b64}]`).
7. `drt_cascade_b2_loss` — both drts approved by the SAME delegator event,
   challenger's seal at an earlier/equal position → keripy `ValidationError`
   (map to expected `yields`; the `outcome` helper returns
   `error:ValidationError` for it — translate that specific case, for these
   delegated scenarios only, to `yields`).

The delegate-side fold in Rust uses `KeyStateSnapshot::genesis/advance` (the
trusted fold accepts dip/drt; the validating fold rejects them until K4), then
`.view()` for the judge call.

- [ ] **Step 2: Extend the Rust test**

The `Vector` struct gains `#[serde(default)] chain: Vec<ChainPair>`; delegated
vectors fold via the snapshot fold and pass
`&[DelegationContest { incumbent, challenger }]` built from the parsed chain
events. `Yields` maps to `"yields"` in the verdict match (replace the `"other"`
arm with explicit `"yields"` / `"undecided"` strings).

- [ ] **Step 3: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-codec keripy_duplicity`

```bash
git add scripts crates/keri-codec/tests
git commit -m "test(keri-codec): #89 keripy differential vectors — drt cascade winners"
```

If porting `test_delegation_supersede` stalls (keripy delegation setup is the
single riskiest step of this plan), STOP and surface it — do not ship
hand-computed "keripy" vectors; the corpus header must honestly state
provenance.

### Task 10: CHANGELOG, issue notes, PR

**Files:**
- Modify: `crates/keri/CHANGELOG.md`, `crates/keri-events/CHANGELOG.md`

- [ ] **Step 1: CHANGELOG entries**

- `keri-rs` (breaking): `Disposition::Contested` (new variant; stale
  `OutOfOrder` and `DuplicateInception` re-dispositioned), new `duplicity`
  module (`SameSnVerdict`, `DelegationContest`, `EvidenceError`,
  `KeyState::judge_same_sn`).
- `keri-events` (additive): unified `sn`/`said`/`prefix`/`anchors` on
  `KeriEvent`.

- [ ] **Step 2: Push, PR, board**

```bash
git push -u origin 89-k3-duplicity-superseding
gh pr create --title "feat(keri): #89 K3 — duplicity + superseding-recovery judge" \
  --body "<summary; breaking: Disposition::Contested; divergence notes (C1 undecided-vs-discard follows keripy source; keripy seal-index crash typed as EvidenceError::SealNotFound)>"
gh pr merge --auto --squash
```

Pre-push hook runs `nix flake check`. PR body calls out: the breaking
`Disposition` change, both keripy divergence notes from the spec, and that
K4 will extend the evidence types.

---

## Self-review notes

- Spec coverage: types/gate/cascade (Tasks 2, 4, 5), `Contested` (Task 3),
  per-rule + boundary tests (Tasks 4-5), properties (Task 6), fold round-trip
  (Task 7), K9 vectors (Tasks 8-9), CHANGELOG/PR (Task 10). Accessors
  (Task 1) are the one addition beyond the spec — the judge needs uniform
  event access and `state.rs` currently matches variants by hand.
- Tasks 5, 6, 8, 9 contain skeleton test bodies where the real fixture
  signatures must be read at execution time; each names the exact fixtures,
  the exact scenario, and the exact expected variant — the judgment content
  is fully specified, only mechanical assembly is deferred.
- Type consistency: `SameSnVerdict`/`DelegationContest`/`EvidenceError`
  spelled identically in Tasks 2-9; `judge_same_sn` signature fixed in Task 2
  and used unchanged after.
