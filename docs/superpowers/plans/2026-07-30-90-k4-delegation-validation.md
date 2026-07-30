# K4 Delegation Validation Implementation Plan (#90, completes #83)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `dip`/`drt` accepted through both folds with delegation evidence supplied as a typed argument; `Rejection::DelegationUnsupported` retired; delegator widened to `Identifier`.

**Architecture:** New module `crates/keri/src/delegation.rs` (evidence types + `authorizes` method) beside `state.rs`/`duplicity.rs`; dedicated fold entries `incept_delegated`/`ingest_delegated`; the seal lookup becomes `KeriEvent::anchor_position` in keri-events (the keri-rs free-fn budget is 0 — helpers must be methods). Integration tests in `crates/keri-codec/tests/` (the `keri` crate cannot forge events). Spec: `docs/superpowers/specs/2026-07-30-90-k4-delegation-validation-design.md`.

**Tech Stack:** Rust (`keri-rs`, `keri-events`), proptest, keripy generator scripts (`scripts/keripy_*_gen.py` pattern), `nix flake check` gate.

**Conformance oracles:** KERI spec (kswg, main) §Cooperative Delegation + §Configuration Traits (DND MUST-drop); keripy main `9161a705` `Kever.validateDelegation` eventing.py:3009-3416 (acceptance path — the recursive climb beyond 3416 is K3's cascade, landed).

---

### Task 1: `KeriEvent::anchor_position` (keri-events)

**Files:**
- Modify: `crates/keri-events/src/event/mod.rs`

- [ ] **Step 1: Write the failing test**

In the existing `mod tests` of `event/mod.rs` (reuse its fixture helpers; K3's `keri_event_unified_accessors` test shows the idiom):

```rust
#[test]
fn anchor_position_finds_the_matching_event_seal() {
    let delegated = KeriEvent::Inception(make_inception());
    let seal = Seal::Event {
        i: delegated.prefix().clone(),
        s: delegated.sn(),
        d: delegated.said().clone(),
    };
    let decoy = Seal::Digest {
        d: make_saider(),
    };
    let anchoring = KeriEvent::Interaction(make_interaction_with_anchors(vec![decoy, seal]));
    assert_eq!(anchoring.anchor_position(&delegated), Some(1));

    let unrelated = KeriEvent::Interaction(make_interaction_with_anchors(vec![]));
    assert_eq!(unrelated.anchor_position(&delegated), None);
}
```

Adapt constructor names to the fixtures that actually exist in that test module (`make_inception` exists from K3; add a small `make_interaction_with_anchors` helper there if the module lacks one — an `InteractionEvent::new` call with the anchor `Vec`, mirroring how `make_inception` builds its event). `Seal::Digest`'s exact variant shape: check `crates/keri-events/src/seal.rs` and use any non-`Event` variant as the decoy.

- [ ] **Step 2: Run — expect failure**

Run: `nix develop --command cargo nextest run -p keri-events anchor_position`
Expected: compile FAIL — no method `anchor_position`.

- [ ] **Step 3: Implement**

In `impl<'a> KeriEvent<'a>` (same impl block as the K3 accessors), port the body of `seal_position` from `crates/keri/src/duplicity.rs:228-239` verbatim as a method:

```rust
    /// Position of the event-seal matching `delegated`'s `(i, s, d)` within
    /// this event's seals, counted over the event-seal subsequence (keripy
    /// filters seals to `SealEvent` fields and takes `.index` within the
    /// filtered sequence — eventing.py:3455-3463). `None` when this event
    /// does not anchor `delegated`.
    #[must_use]
    pub fn anchor_position(&self, delegated: &KeriEvent<'_>) -> Option<usize> {
        let target: (&Identifier<'_>, u128, &Said<'_>) =
            (delegated.prefix(), delegated.sn().value(), delegated.said());
        self.anchors()
            .iter()
            .filter_map(|seal| match seal {
                Seal::Event { i, s, d } => Some((i, s.value(), d)),
                _ => None,
            })
            .position(|(i, s, d)| i == target.0 && s == target.1 && d == target.2)
    }
```

(`Identifier`, `Said`, `Seal` are already imported at the top of the file for the K3 accessors.)

- [ ] **Step 4: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-events`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/keri-events
git commit -m "feat(keri-events): #90 KeriEvent::anchor_position — event-seal lookup as a method"
```

### Task 2: Error reshape — `DelegationError` in, `DelegationUnsupported` out

**Files:**
- Modify: `crates/keri/src/error.rs`
- Modify: `crates/keri/src/state.rs` (the `ingest` dip/drt arm — keeps the workspace compiling)
- Modify: `crates/keri/src/lib.rs` (doc line referencing the retired variant, re-export)
- Modify: `crates/keri-codec/tests/transitions.rs` (two assertions)

- [ ] **Step 1: Update the failing tests first**

In `error.rs` `mod tests`, replace `delegation_unsupported_awaits_delegation_evidence` with:

```rust
    #[test]
    fn delegation_evidence_required_awaits_delegation_evidence() {
        let r = Rejection::from(DelegationError::EvidenceRequired);
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn delegation_seal_not_found_awaits_delegation_evidence() {
        let r = Rejection::from(DelegationError::SealNotFound);
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn delegation_delegator_mismatch_awaits_delegation_evidence() {
        let r = Rejection::from(DelegationError::DelegatorMismatch);
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn delegation_denied_is_terminal() {
        let r = Rejection::from(DelegationError::Denied);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn delegator_unknown_is_terminal() {
        let r = Rejection::from(DelegationError::DelegatorUnknown);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn delegation_error_maps_to_delegation() {
        let r = Rejection::from(DelegationError::EvidenceRequired);
        assert!(matches!(
            r,
            Rejection::Delegation(DelegationError::EvidenceRequired)
        ));
    }

    #[test]
    fn not_delegated_entry_structural_errors_are_terminal() {
        assert_eq!(
            Rejection::from(StructuralError::NotDelegatedInception).disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            Rejection::from(StructuralError::NotDelegatedRotation).disposition(),
            Disposition::Terminal
        );
    }
```

In `crates/keri-codec/tests/transitions.rs`, retarget the two delegated tests (`delegated_inception_is_unsupported` at :415, `delegated_rotation_is_unsupported` at :428) — rename to `delegated_inception_requires_evidence` / `delegated_rotation_requires_evidence`, assert:

```rust
    assert!(matches!(
        r,
        Rejection::Delegation(DelegationError::EvidenceRequired)
    ));
```

and add `DelegationError` to that file's `use keri::{...}` list.

- [ ] **Step 2: Run — expect failures**

Run: `nix develop --command cargo nextest run -p keri-rs delegation`
Expected: compile FAIL — no `DelegationError`.

- [ ] **Step 3: Implement the error types**

In `error.rs`: delete the `DelegationUnsupported` variant (and its `disposition` arm). Add, after the `Transferability` variant of `Rejection`:

```rust
    /// A delegation rule was violated (K4). See [`DelegationError`] for the
    /// specific rule and its keripy/escrow anchor.
    ///
    /// Disposition: per sub-variant — see [`DelegationError`].
    #[error(transparent)]
    Delegation(#[from] DelegationError),
```

Add the enum (next to `WitnessSetError`):

```rust
/// Delegation-rule violations for delegated establishment events (K4).
///
/// Spec anchors (kswg-keri-specification, §Cooperative Delegation and
/// §Configuration Traits): a validator MUST be given or find the delegating
/// seal in the delegator's KEL, and MUST drop delegated events whose
/// delegator carries the do-not-delegate trait.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DelegationError {
    /// A dip/drt reached a plain fold entry ([`KeyState::incept`]/
    /// [`KeyState::ingest`](crate::KeyState::ingest)) without evidence —
    /// keripy's delegated escrows (`.pdes`/`.udes`). Park and re-drive
    /// through the delegated entry once the host has evidence.
    #[error("delegated event requires delegation evidence")]
    EvidenceRequired,
    /// The supplied delegating event carries no event-seal matching the
    /// delegated event's `(i, s, d)` (keripy nullifies the couple and
    /// escrows — eventing.py:3389-3400; better evidence cures).
    #[error("delegating event carries no seal of the delegated event")]
    SealNotFound,
    /// The supplied delegator state does not match the event's declared
    /// delegator (dip `di` / drt state) or the delegating event's prefix —
    /// evidence for the wrong identifier; correct evidence cures.
    #[error("delegation evidence names a different delegator")]
    DelegatorMismatch,
    /// A delegated rotation on a state that carries no delegator: the
    /// identifier was not incepted as delegated, so no evidence can make a
    /// drt valid.
    #[error("delegated rotation on a non-delegated identifier")]
    DelegatorUnknown,
    /// The delegator carries the do-not-delegate config trait (spec MUST
    /// drop; keripy `doNotDelegate` — eventing.py:3293-3299).
    #[error("delegator does not allow delegation")]
    Denied,
}
```

Add to `StructuralError`:

```rust
    /// `incept_delegated` was called on a non-delegated-inception event.
    #[error("incept_delegated called on a non-delegated-inception event")]
    NotDelegatedInception,
    /// `ingest_delegated` was called on a non-delegated-rotation event.
    #[error("ingest_delegated called on a non-delegated-rotation event")]
    NotDelegatedRotation,
```

In `Rejection::disposition`, replace the `DelegationUnsupported` arm with:

```rust
            Self::Delegation(
                DelegationError::EvidenceRequired
                | DelegationError::SealNotFound
                | DelegationError::DelegatorMismatch,
            ) => Disposition::Awaiting(EvidenceKind::DelegationEvidence),
            Self::Delegation(DelegationError::Denied | DelegationError::DelegatorUnknown) => {
                Disposition::Terminal
            }
```

(No wildcard on `DelegationError` — a new sub-variant must force a decision here.) Update the `EvidenceKind::DelegationEvidence` doc comment: keripy `.pdes`/`.udes` stays, "K4 builds the verification path" becomes "re-drive through [`KeyState::incept_delegated`]/[`KeyState::ingest_delegated`] with the delegator's evidence".

- [ ] **Step 4: Swap the `ingest` arm and the crate-doc line**

In `state.rs`, the `ingest` match arm:

```rust
            KeriEvent::DelegatedInception(_) | KeriEvent::DelegatedRotation(_) => {
                Err(DelegationError::EvidenceRequired.into())
            }
```

(import `DelegationError` in the existing `crate::error` use). Fix the `ingest` doc comment ("Delegated events are rejected (K4 scope)" → "Delegated events require evidence — use the delegated entries; here they park as `Awaiting(DelegationEvidence)`"). In `lib.rs`, update the crate-doc sentence at :40-42 that names `DelegationUnsupported` (full rewrite of that paragraph comes with Task 5; here just make the doc-link compile — point it at `Rejection::Delegation`). Re-export the new type where the other error types are re-exported:

```rust
pub use error::{DelegationError, Disposition, EvidenceKind, Rejection, StructuralError};
```

(match the actual existing re-export list — extend, don't shrink).

- [ ] **Step 5: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-rs -p keri-codec`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/keri crates/keri-codec/tests/transitions.rs
git commit -m "feat(keri)!: #90 DelegationError domain — DelegationUnsupported retired"
```

### Task 3: `delegation.rs` — evidence types + `authorizes`

**Files:**
- Create: `crates/keri/src/delegation.rs`
- Modify: `crates/keri/src/duplicity.rs` (drop private `seal_position`, call the Task 1 method)
- Modify: `crates/keri/src/lib.rs` (module + re-exports)

- [ ] **Step 1: Write the module**

`crates/keri/src/delegation.rs` — complete content:

```rust
//! Delegation validation over typed evidence (K4, #90): the acceptance
//! checks for delegated establishment events, every cross-KEL fact supplied
//! by the host as an argument.
//!
//! The delegator's KEL is the host's stream. The host folds it, locates the
//! anchoring event, and hands both to the fold as [`DelegationEvidence`];
//! the core checks bindings by digest and never walks anything. Spec
//! (kswg-keri-specification, §Cooperative Delegation): *"A Validator MUST
//! be given or find the delegating seal in the delegator's KEL before the
//! event may be accepted as valid"* — this module is the "be given" arm.
//!
//! keripy conformance (main `9161a705`): `Kever.validateDelegation`
//! eventing.py:3009-3416 — the acceptance path. Its recursive climb
//! (3418-3492) is the superseding cascade, which K3 models as the
//! host-supplied [`DelegationContest`](crate::DelegationContest) slice;
//! acceptance itself needs exactly one delegating event.
use keri_events::{ConfigTrait, Identifier, KeriEvent};

use crate::error::DelegationError;
use crate::state::KeyState;

/// Everything the fold needs from the delegator's side. That
/// `delegating_event` is ACCEPTED in the delegator's KEL is host-asserted —
/// the same trust contract as [`Signed::signed_bytes`](crate::Signed).
pub struct AnchoredDelegation<'e> {
    /// The delegator's current key state (the host folds the delegator's
    /// stream; keripy's `dkever`).
    pub delegator: &'e KeyState<'e>,
    /// The accepted event in the delegator's KEL carrying the anchoring
    /// event-seal of the delegated event (a rotation or an interaction).
    pub delegating_event: &'e KeriEvent<'e>,
}

/// Delegation evidence, supplied fat-command style alongside the delegated
/// event to [`KeyState::incept_delegated`] and [`KeyState::ingest_delegated`].
pub enum DelegationEvidence<'e> {
    /// The spec path: the delegating seal is anchored in the delegator's
    /// KEL.
    Anchored(AnchoredDelegation<'e>),
    /// Host policy accepts without an anchor (keripy's
    /// `locallyOwned`/`locallyMembered`/`locallyWitnessed` controller and
    /// witness roles — eventing.py:3281-3284; not in the spec, which is
    /// validator-role). Signatures, thresholds, and witnessing are still
    /// enforced; only the seal/delegator checks are skipped. The host
    /// decides WHEN to assert this — the fold never does.
    HostAccepted,
}

impl DelegationEvidence<'_> {
    /// Check that this evidence authorizes `delegated` under
    /// `expected_delegator` — the K4 acceptance rules, in keripy's order:
    /// delegator identity, do-not-delegate, seal binding. All checks are
    /// digest comparisons; [`HostAccepted`](Self::HostAccepted) skips them
    /// by construction.
    ///
    /// # Errors
    ///
    /// Returns the first [`DelegationError`] rule violated.
    pub fn authorizes(
        &self,
        delegated: &KeriEvent<'_>,
        expected_delegator: &Identifier<'_>,
    ) -> Result<(), DelegationError> {
        let Self::Anchored(anchor) = self else {
            return Ok(());
        };
        if anchor.delegator.prefix() != expected_delegator
            || anchor.delegating_event.prefix() != anchor.delegator.prefix()
        {
            return Err(DelegationError::DelegatorMismatch);
        }
        if anchor
            .delegator
            .config()
            .iter()
            .any(|c| matches!(c, ConfigTrait::DoNotDelegate))
        {
            return Err(DelegationError::Denied);
        }
        if anchor.delegating_event.anchor_position(delegated).is_none() {
            return Err(DelegationError::SealNotFound);
        }
        Ok(())
    }
}
```

- [ ] **Step 2: Switch `duplicity.rs` to the method**

Delete the private `seal_position` function (duplicity.rs:226-239) and its two call sites in `cascade` become:

```rust
        let challenger_pos = contest
            .challenger
            .anchor_position(delegated_new)
            .ok_or(EvidenceError::SealNotFound { level })?;
        let incumbent_pos = contest
            .incumbent
            .anchor_position(delegated_old)
            .ok_or(EvidenceError::SealNotFound { level })?;
```

Drop now-unused imports (`Identifier`, `Said`, `Seal` — keep what the file still uses; the compiler will say).

- [ ] **Step 3: Wire into `lib.rs`**

```rust
/// Delegation validation over typed evidence.
pub mod delegation;
```

next to the other module declarations, and:

```rust
pub use delegation::{AnchoredDelegation, DelegationEvidence};
```

- [ ] **Step 4: Build**

Run: `nix develop --command cargo build -p keri-rs`
Expected: clean (doc-links to `incept_delegated`/`ingest_delegated` land in Task 5 — if rustdoc intra-doc links break the build here, write them as plain code spans and link them in Task 5).

- [ ] **Step 5: Commit**

```bash
git add crates/keri
git commit -m "feat(keri): #90 DelegationEvidence — anchored/host-accepted evidence with authorizes"
```

### Task 4: Delegator widening — `Option<&Identifier>` through state + snapshot

**Files:**
- Modify: `crates/keri/src/state.rs`
- Modify: `crates/keri-codec/tests/snapshot.rs` (if any test names `delegator`)

- [ ] **Step 1: Widen the fields**

In `state.rs` (the K6 comment at :497-499 predicts exactly this change):

- `KeyState.delegator: Option<&'e Identifier<'e>>` (was `Option<&'e BasicPrefix<'e>>`)
- accessor: `pub const fn delegator(&self) -> Option<&'e Identifier<'e>>`
- `KeyStateSnapshot.delegator: Option<Identifier<'static>>`
- `view()`: `delegator: self.delegator.as_ref(),` (unchanged text, new type)
- `From<&KeyState>` arm: `delegator: state.delegator.map(|d| d.clone().into_static()),` (unchanged text, new type)

Update the accessor doc: "Delegator identifier, if this identifier is delegated. Widened from `BasicPrefix` in K4 — the spec's `di` may be self-addressing." Remove `BasicPrefix` from the state.rs import list only if now unused (witnesses still use it — it stays).

- [ ] **Step 2: Carry the delegator through the trusted fold**

In `KeyStateSnapshot::advance`, the dip arm (replace the K4 TODO comment block at :494-504):

```rust
            // A dip seeds the delegated genesis: the wrapped inception's
            // establishment data plus the delegator binding (spec: drt has
            // no `di` — the delegator is fixed at inception).
            KeriEvent::DelegatedInception(dip) => {
                let mut next = Self::genesis(dip.inception());
                next.latest_message_type = MessageType::Dip;
                next.delegator = Some(dip.delegator().clone().into_static());
                next
            }
```

(drt already carries the delegator over via `..self` in `rolled`.)

- [ ] **Step 3: Blast-radius grep**

Run: `rg -n "delegator" crates/keri-codec/tests fuzz fuzz-common fuzz-afl examples benches 2>/dev/null`
Fix any caller assuming `BasicPrefix` (expected: none — the accessor has returned `None` everywhere until now).

- [ ] **Step 4: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-rs -p keri-codec`
Expected: PASS.

```bash
git add -A
git commit -m "feat(keri)!: #90 widen delegator to Identifier; trusted fold carries dip delegator"
```

### Task 5: Fold entries — `incept_delegated` / `ingest_delegated`

**Files:**
- Modify: `crates/keri/src/state.rs`
- Modify: `crates/keri/src/lib.rs` (crate-doc delegation paragraph)

- [ ] **Step 1: Extract the shared inception validation**

In `state.rs`, `impl<'e> KeyState<'e>`: pull the body of `incept` between the `match` and the final `Ok(Self::seed(...))` into a private method, and re-express `incept` with it:

```rust
    pub fn incept(signed: &Signed<'e>) -> Result<Self, Rejection> {
        let KeriEvent::Inception(icp) = signed.event else {
            return Err(StructuralError::NotInception.into());
        };
        let transferability = Self::validate_inception(icp, signed)?;
        Ok(Self::seed(icp, transferability))
    }

    /// The inception rules shared by plain and delegated genesis: zero sn,
    /// self-certifying authority, transferability/next-key agreement,
    /// witness threshold, and TOAD receipting.
    fn validate_inception(
        icp: &'e InceptionEvent<'e>,
        signed: &Signed<'e>,
    ) -> Result<Transferability, Rejection> {
        let sn = icp.sn().value();
        if sn != 0 {
            return Err(StructuralError::NonZeroGenesisSn { sn }.into());
        }
        icp.authority().well_formed()?;
        icp.authority().verify(signed.signed_bytes, &signed.sigs)?;
        let transferability = decide_transferability(icp)?;
        check_witness_threshold(icp.witnesses().len(), icp.witness_threshold().value())?;
        Witnessing::new(icp.witnesses(), icp.witness_threshold())
            .receipted_by(signed.signed_bytes, &signed.wigs)?;
        Ok(transferability)
    }
```

Wait — `authority()`/`commitment()` are methods on `KeyState`, but `icp.authority()` in the current `incept` body is a method on the event; keep the existing calls exactly as `incept` has them today (this is a pure extraction — the doc comments on `incept` keep their current text).

- [ ] **Step 2: Add the delegated entries**

```rust
    /// Seed the fold from a delegated genesis (`dip`), with the delegator's
    /// evidence supplied fat-command style.
    ///
    /// Runs the full inception rules ([`incept`](Self::incept)) on the
    /// wrapped inception, then the delegation acceptance checks
    /// ([`DelegationEvidence::authorizes`]) against the event's declared
    /// delegator (`di`), and seeds a state carrying that delegator.
    ///
    /// # Errors
    ///
    /// Returns a [`Rejection`]: everything [`incept`](Self::incept) rejects,
    /// plus [`DelegationError`] for a missing seal, mismatched delegator, or
    /// a delegator that forbids delegation.
    pub fn incept_delegated(
        signed: &Signed<'e>,
        evidence: &DelegationEvidence<'e>,
    ) -> Result<Self, Rejection> {
        let KeriEvent::DelegatedInception(dip) = signed.event else {
            return Err(StructuralError::NotDelegatedInception.into());
        };
        let transferability = Self::validate_inception(dip.inception(), signed)?;
        evidence.authorizes(signed.event, dip.delegator())?;
        Ok(Self {
            latest_message_type: MessageType::Dip,
            delegator: Some(dip.delegator()),
            ..Self::seed(dip.inception(), transferability)
        })
    }

    /// Fold one delegated rotation (`drt`) onto this state, with the
    /// delegator's evidence supplied fat-command style.
    ///
    /// Runs the full rotation rules (chains-onto, revealed authority,
    /// prior-next commitment exposure, witnessing), then the delegation
    /// acceptance checks against the delegator established at inception
    /// (spec: a drt carries no `di`).
    ///
    /// # Errors
    ///
    /// Returns a [`Rejection`]: everything a plain rotation rejects, plus
    /// [`DelegationError`] — [`DelegatorUnknown`](DelegationError::DelegatorUnknown)
    /// when this state carries no delegator, and the seal/delegator/DND
    /// rules for the supplied evidence.
    pub fn ingest_delegated(
        self,
        signed: &Signed<'e>,
        evidence: &DelegationEvidence<'e>,
    ) -> Result<Self, Rejection> {
        if !self.is_transferable() {
            return Err(Rejection::NonTransferableState);
        }
        let KeriEvent::DelegatedRotation(drt) = signed.event else {
            return Err(StructuralError::NotDelegatedRotation.into());
        };
        let Some(delegator) = self.delegator else {
            return Err(DelegationError::DelegatorUnknown.into());
        };
        let next = self.rotate(drt.rotation(), signed)?;
        evidence.authorizes(signed.event, delegator)?;
        Ok(Self {
            latest_message_type: MessageType::Drt,
            ..next
        })
    }
```

Imports: add `DelegationEvidence` (from `crate::delegation`) and extend the `crate::error` import with `DelegationError` (Task 2 may already have it). Ordering note (keripy parity): signatures/thresholds/witnessing verify BEFORE the delegation checks (`valSigsWigsDel` runs sigs first) — the code above preserves that for both entries.

- [ ] **Step 3: Rewrite the crate-doc delegation paragraph**

In `lib.rs`, replace the paragraph at :40-42 ("verifying the delegator's authorizing seal requires the delegator's KEL, which this crate does not have…"):

```rust
//! **Delegation is validated over typed evidence, never a walk.** The
//! delegator's KEL is the host's stream: the host folds it and supplies the
//! anchoring event plus the delegator's state as [`DelegationEvidence`];
//! [`KeyState::incept_delegated`] and [`KeyState::ingest_delegated`] check
//! the seal binding, delegator identity, and do-not-delegate rule by digest
//! comparison alone. A dip/drt reaching the plain entries parks as
//! [`Awaiting(DelegationEvidence)`](Disposition::Awaiting) until the host
//! re-drives it with evidence.
```

- [ ] **Step 4: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-rs -p keri-codec`
Expected: PASS (new entries have no test coverage yet — Task 6 supplies it; existing suites must stay green).

- [ ] **Step 5: Commit**

```bash
git add crates/keri
git commit -m "feat(keri): #90 incept_delegated + ingest_delegated — evidence-checked fold entries"
```

### Task 6: Integration tests — acceptance + negative suite

**Files:**
- Modify: `crates/keri-codec/tests/common/mod.rs`
- Create: `crates/keri-codec/tests/delegation.rs`

- [ ] **Step 1: Fixture updates**

In `common/mod.rs`:

1. Widen `delegated_inception` (at :637): parameter `delegator: &BasicPrefix<'static>` becomes `delegator: Identifier<'static>`; the builder call becomes `DelegatedInceptionBuilder::new(delegator)` (the builder already takes `impl Into<Identifier<'static>>` — `crates/keri-codec/src/builder/icp.rs:140`). Update existing callers (`transitions.rs`, `duplicity.rs` cascade fixtures): `&prefix_of(&kd)` becomes `prefix_of(&kd).into()`.
2. Add a fold-worthy drt fixture (the existing `delegated_rotation` commits no next keys — fine for the judge, an abandonment for the fold):

```rust
/// A delegated rotation (`drt`) at `sn` revealing `reveal` and committing to
/// `next` — foldable through `ingest_delegated` (the anchors-free shape).
pub fn delegated_rotation_full(
    prior: &Event,
    sn: u128,
    reveal: &Key,
    next: &Key,
) -> Fallible<Event> {
    let ser = DelegatedRotationBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .keys(vec![reveal.verfer.clone()])
        .prior_witnesses(vec![])
        .sn(sn)
        .next_keys(vec![commit(&next.verfer)?])
        .build()?;
    Event::build(
        ser.as_bytes().to_vec(),
        ser.said().clone().into_static(),
        prior.prefix.clone(),
    )
}
```

(Mirror `delegated_rotation`'s exact builder-call shape for anything it also sets — copy that function and add the `next_keys` line; if the builder wants an explicit `threshold`/`next_threshold`, thread `SigningThreshold::Simple(1)` like `plain_rotation` does.)

- [ ] **Step 2: Write the acceptance + negative tests**

`crates/keri-codec/tests/delegation.rs`:

```rust
//! K4 (#90): delegation validation over typed evidence — acceptance and
//! negative rules through the public `incept_delegated`/`ingest_delegated`.
//! Oracle anchors: kswg spec §Cooperative Delegation (+ DND MUST-drop);
//! keripy 9161a705 eventing.py:3009-3416.
mod common;

use cesr::core::primitives::Number;
use common::{
    Fallible, Key, delegated_inception, delegated_rotation_full, genesis, genesis_config,
    interaction_anchoring, seed,
};
use keri::{
    AnchoredDelegation, DelegationError, DelegationEvidence, Disposition, EvidenceKind, KeyState,
    Rejection, StructuralError,
};
use keri_events::{ConfigTrait, KeriEvent, Seal};

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

    let state =
        KeyState::incept_delegated(&dip.signed(vec![k0.sign(&dip.bytes, 0)?]), &evidence)?;
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
    assert_eq!(next.keys()[0], k1.verfer);
    Ok(())
}

/// HostAccepted skips the seal checks but still verifies signatures.
#[test]
fn host_accepted_still_verifies_signatures() -> Fallible<()> {
    let (dk0, _) = (Key::new()?, Key::new()?);
    let (k0, k1, kx) = (Key::new()?, Key::new()?, Key::new()?);
    let delegator_icp = genesis(&dk0, &Key::new()?)?;
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

/// A tampered seal digest is SealNotFound — Awaiting(DelegationEvidence).
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

/// Evidence from the wrong delegator is DelegatorMismatch.
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

/// A drt on a non-delegated state is DelegatorUnknown — Terminal.
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
    let ixn = common::interaction(&dip, 1)?;
    let Err(r) = state.ingest_delegated(
        &ixn.signed(vec![k1.sign(&ixn.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    ) else {
        return Err("an ixn passed ingest_delegated".into());
    };
    assert!(matches!(
        r,
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
    let ixn = common::interaction(&dip, 1)?;
    let next = state.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]))?;
    assert_eq!(next.sn().value(), 1);
    assert_eq!(next.delegator(), Some(&delegator_icp.prefix));
    Ok(())
}
```

Adapt mechanical details at execution time (e.g. `Number::new` vs a `Number` accessor on `Event`; `keys()[0]` comparison — compare raw bytes if `VerifyingKey` lacks `PartialEq` with the fixture's verfer, following how `transitions.rs` asserts rolled keys). Do not weaken any asserted variant.

- [ ] **Step 3: Run — expect pass**

Run: `nix develop --command cargo nextest run -p keri-codec delegation`
Expected: PASS. A failure is a real fold bug — fix `state.rs`/`delegation.rs`, not the test.

- [ ] **Step 4: Commit**

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #90 delegation acceptance + negative suite"
```

### Task 7: Differential invariant + revoked-then-used recovery

**Files:**
- Modify: `crates/keri-codec/tests/delegation.rs`

- [ ] **Step 1: Trusted-fold ≡ validating-fold invariant over a delegated KEL**

```rust
use keri::KeyStateSnapshot;

/// K6 invariant extended to delegated KELs: folding ACCEPTED events through
/// the trusted fold equals snapshotting the validating fold.
#[test]
fn trusted_fold_matches_validating_fold_on_delegated_kel() -> Fallible<()> {
    // build the same dip → drt → ixn chain as drt_accepted_with_anchored_evidence
    // (delegator icp + two anchors), fold it through incept_delegated /
    // ingest_delegated / ingest, then:
    let validated_snapshot = KeyStateSnapshot::from(&validating_head);

    let trusted_head = [&drt.parsed, &ixn.parsed]
        .into_iter()
        .fold(KeyStateSnapshot::genesis_of(&dip.parsed), KeyStateSnapshot::advance);
    assert_eq!(validated_snapshot, trusted_head);
    Ok(())
}
```

`genesis_of` above is shorthand — at execution time use the real trusted seeding path for a dip: `KeyStateSnapshot::advance` on a dip does the delegated genesis internally, so seed however `snapshot.rs` seeds mixed streams (check its existing delegated test around the `advance` dip arm) and keep the final `assert_eq!` on the two `KeyStateSnapshot`s — including `delegator()` equality via the views:
`assert_eq!(validated_snapshot.view().delegator(), trusted_head.view().delegator());`

- [ ] **Step 2: The W8 demo path — revoked delegation, recovery, re-drive**

```rust
use keri::SameSnVerdict;

/// The revoke demo: the delegator supersedes its anchoring interaction with a
/// recovery rotation (K3 judge), the host rewinds the delegator's stream, and
/// re-driving the delegate's drt with post-recovery evidence fails SealNotFound
/// — the delegation died with the anchor.
#[test]
fn revoked_delegation_is_seal_not_found_after_recovery() -> Fallible<()> {
    // delegator: icp → ixn1 (anchors delegate drt)
    // delegate:  dip (HostAccepted for setup brevity) → drt parked awaiting
    // 1. fold delegator to head, judge a recovery rot at sn 1:
    //    verdict == SameSnVerdict::Supersedes   (K3, A0)
    // 2. host rewinds: delegator state re-folded from icp + recovery rot
    // 3. re-drive: ingest_delegated(drt, Anchored { delegator: recovered,
    //    delegating_event: recovery_rot }) — the rot anchors nothing:
    //    Rejection::Delegation(DelegationError::SealNotFound), disposition
    //    Awaiting(DelegationEvidence) — parked until a delegator re-approves.
    Ok(())
}
```

Assemble from existing fixtures: `plain_rotation` for the recovery rot (empty anchors), `anchor_of` for ixn1, the Task 6 helpers for the delegate side; every step's exact expected variant is stated above — assert all three (verdict, rejection variant, disposition).

- [ ] **Step 3: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-codec delegation`

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #90 trusted-fold invariant + revoked-delegation recovery path"
```

### Task 8: Property tests — seal position + evidence totality

**Files:**
- Modify: `crates/keri-codec/tests/delegation.rs` (a `mod properties`)

- [ ] **Step 1: Write the properties**

Follow the proptest pattern of `crates/keri-codec/tests/properties.rs` (imports, config):

```rust
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The matching event-seal is found at ANY position among decoy
        /// seals (0, 1, middle, last), and never found when absent — the
        /// keripy filtered-subsequence semantics.
        #[test]
        fn anchor_found_at_any_position(pos in 0usize..4, decoys in 0usize..4) {
            // build a dip and an anchoring interaction whose seal list has
            // `decoys` digest-seals with the real Seal::Event inserted at
            // min(pos, decoys); incept_delegated with that anchor must
            // accept iff the real seal is present; removing it must yield
            // Rejection::Delegation(DelegationError::SealNotFound).
        }

        /// authorizes is total over arbitrary evidence pairings: any
        /// (delegator state, delegating event) combination returns Ok or a
        /// typed DelegationError — never a panic.
        #[test]
        fn authorizes_is_total(use_other_delegator in any::<bool>(), anchor_real in any::<bool>()) {
            // pair a dip against {right, wrong} delegator state and
            // {anchoring, non-anchoring} delegating event; call
            // evidence.authorizes(...) directly; reaching the end without
            // panic IS the property, plus: Ok iff (right && anchoring).
        }
    }
}
```

Fill bodies with the Task 6 fixtures (no logic reimplementation). Boundary values: seal-position 0, last, and absent are all exercised by the ranges shown.

- [ ] **Step 2: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-codec delegation`

```bash
git add crates/keri-codec/tests
git commit -m "test(keri-codec): #90 seal-position + authorizes totality properties"
```

### Task 9: keripy differential vectors — delegation corpus

**Files:**
- Create: `scripts/keripy_delegation_gen.py`
- Create: `crates/keri-codec/tests/corpus/delegation.jsonl` (generated, checked in)
- Create: `crates/keri-codec/tests/keripy_delegation.rs`

- [ ] **Step 1: Write the generator**

Model on `scripts/keripy_duplicity_gen.py` (same argparse/salt/env skeleton; run with `~/.local/bin/python3.14`, `PYTHONPATH` to the keripy venv site-packages, `DYLD_LIBRARY_PATH` to the nix libsodium — the documented local-env recipe). Scenarios drive `Kevery.processEvent` on a VALIDATOR-role Kevery (not locally owned) so `validateDelegation` runs the full seal path; keripy's own `tests/core/test_delegating.py` shows the `delcept` + anchoring-`interact` construction. Emit one JSONL record per scenario:

```json
{"name": "...", "delegator_events": ["b64", "..."], "delegator_sigs": [["qb64"], ["..."]],
 "delegate_events": ["b64"], "delegate_sigs": [["qb64"]],
 "anchor_index": 1, "expected": "accepted"}
```

Scenarios:

1. `dip_anchored_ixn` — delegator icp; delegate `delcept`; delegator `interact` anchoring the dip's `(i, s, d)`; feed dip → expected `accepted`.
2. `drt_anchored_ixn` — extend 1 with a delegate `deltate` (drt) anchored by a second interact → `accepted`.
3. `dip_missing_anchor` — feed the dip with no anchoring event in the delegator KEL → keripy `MissingDelegationError` → expected `awaiting`.
4. `dip_dnd_delegator` — delegator icp with `cnfg=["DND"]` → keripy `ValidationError` → expected `denied`.
5. `dip_tampered_seal` — anchoring interact seals a WRONG digest (the delegator icp's said) → `MissingDelegationError` (seal search fails) → expected `awaiting`.

The `outcome` helper classifies: accepted (kevers updated with the delegate said), `MissingDelegationError` → `awaiting`, `ValidationError` → `denied`, anything else `error:<name>` (fix the scenario, never check an `error:` in).

- [ ] **Step 2: Write the differential test**

`crates/keri-codec/tests/keripy_delegation.rs` (name must contain `keripy` for the nightly filter) — follow `keripy_duplicity.rs`'s parse/fold scaffolding:

```rust
const CORPUS: &str = include_str!("corpus/delegation.jsonl");

#[test]
fn keripy_delegation_verdicts_match() -> Fallible<()> {
    for line in CORPUS.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let v: Vector = serde_json::from_str(line)?;
        // fold delegator_events through KeyState::incept/ingest to a head
        // state; parse delegate_events; build evidence from
        // delegator_events[anchor_index] (when present); fold the delegate
        // through incept_delegated/ingest_delegated; classify:
        let got = match result {
            Ok(_) => "accepted",
            Err(r) => match r.disposition() {
                Disposition::Awaiting(EvidenceKind::DelegationEvidence) => "awaiting",
                Disposition::Terminal
                    if matches!(r, Rejection::Delegation(DelegationError::Denied)) =>
                {
                    "denied"
                }
                _ => "other",
            },
        };
        assert_eq!(got, v.expected, "vector {}", v.name);
    }
    Ok(())
}
```

For `dip_missing_anchor` the Rust side drives the PLAIN `ingest`/`incept` path (no evidence exists) and expects `Awaiting(DelegationEvidence)` — mirroring the host that has nothing to enrich with.

- [ ] **Step 3: Run — expect pass; Commit**

Run: `nix develop --command cargo nextest run -p keri-codec keripy_delegation`

```bash
git add scripts/keripy_delegation_gen.py crates/keri-codec/tests
git commit -m "test(keri-codec): #90 keripy differential vectors — delegation acceptance"
```

If the keripy validator-role setup stalls (Kevery must NOT be locally-owned or the seal path short-circuits — construct the Kevery over a database whose habs do not include either AID), STOP and surface it — never ship hand-computed "keripy" vectors.

### Task 10: #83 boundary docs, CHANGELOG, PR

**Files:**
- Modify: `crates/keri-events/src/event/delegation.rs` (rustdoc)
- Modify: `crates/keri/CHANGELOG.md`, `crates/keri-events/CHANGELOG.md`

- [ ] **Step 1: #83 boundary rustdoc**

On `DelegatedInceptionEvent` and `DelegatedRotationEvent` (keri-events), add the layer statement:

```rust
/// # Validation boundary
///
/// This type is pure vocabulary. Structural acceptance — seal binding in the
/// delegator's KEL, delegator identity, do-not-delegate — is the `keri`
/// crate's fold over caller-supplied evidence
/// (`KeyState::incept_delegated`). Evidence *acquisition* (walking a
/// delegator's KEL, OOBI resolution, escrow storage, the approval ceremony)
/// belongs to the hosting layer above.
```

Also fix `DelegatedRotationEvent`'s stale doc line ("can be looked up from the KEL" → "is established at inception and carried in the key state").

- [ ] **Step 2: CHANGELOG entries**

- `keri-rs` (breaking): `DelegationUnsupported` removed → `Rejection::Delegation(DelegationError)`; `KeyState::delegator()`/`KeyStateSnapshot` delegator widened `BasicPrefix` → `Identifier`; new `delegation` module (`DelegationEvidence`, `AnchoredDelegation`), new entries `incept_delegated`/`ingest_delegated`; new `StructuralError::NotDelegatedInception`/`NotDelegatedRotation`; trusted fold carries the dip delegator.
- `keri-events` (additive): `KeriEvent::anchor_position`.

- [ ] **Step 3: Push, PR, board**

```bash
git push -u origin 90-k4-delegation-validation
gh pr create --title "feat(keri)!: #90 K4 — delegation validation over typed evidence" \
  --body "<summary; closes #90, closes #83; breaking: DelegationUnsupported retired, delegator widened to Identifier; spec anchors (Validator MUST find seal; DND MUST drop); HostAccepted = keripy local-role parity, host-decided>"
gh pr merge --auto --squash
```

Pre-push hook runs `nix flake check`. PR body calls out both breaking changes, the spec MUST anchors, and that `HostAccepted` models keripy's local-role acceptance as an explicit host assertion.

---

## Self-review notes

- Spec coverage: evidence types + checks (Task 3), fold entries (Task 5),
  error reshape + dispositions (Task 2), widening + trusted fold (Task 4),
  acceptance/negative suite incl. HostAccepted and W8 recovery (Tasks 6-7),
  properties (Task 8), K9 vectors (Task 9), #83 docs + CHANGELOG (Task 10).
  `anchor_position` (Task 1) replaces the plan's earlier free-fn helper —
  the keri-rs free-fn budget is 0, so shared lookups are methods.
- Tasks 7-9 carry skeleton bodies where fixture signatures must be read at
  execution time; each names exact fixtures, scenario, and expected variant.
- Type consistency: `DelegationEvidence`/`AnchoredDelegation`/
  `DelegationError` spelled identically Tasks 2-9; `authorizes(delegated,
  expected_delegator)` fixed in Task 3, used in Task 5; `anchor_position`
  fixed in Task 1, used in Tasks 3 and 8.
- keripy order preserved: sigs/thresholds/witnessing before delegation
  checks in both entries (valSigsWigsDel parity).
