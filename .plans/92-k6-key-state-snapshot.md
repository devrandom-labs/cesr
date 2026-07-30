# K6 — KeyStateSnapshot Duality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> Per Joel's workflow, implementation is dispatched via the kimi-delegate skill; this plan is the work order.

**Goal:** Add the owned `KeyStateSnapshot` carrier and the total, crypto-free trusted fold (`genesis`/`advance`) to `keri-rs`, dual to the K1 validating fold.

**Architecture:** Two folds over one domain (spec: `docs/superpowers/specs/2026-07-29-k6-key-state-snapshot-design.md`). The validating fold (`KeyState<'e>::incept/ingest`, exists) runs at decide time with full crypto. The new trusted fold (`KeyStateSnapshot::genesis/advance`) runs at apply/replay time: total, infallible, no signatures. `PathBuf`/`Path` duality: `snapshot.view()` lends the borrowed working state; `From<&KeyState>` owns one back. No `KelProvider`, no `MemKel`, no mnesis dependency — host compatibility is by shape only.

**Tech Stack:** Rust edition 2024, `no_std` + `alloc` (`crates/keri`), existing `into_static()` owners on all cesr/keri-events primitives, tests in `crates/keri-codec/tests/` (where the K1 fold fixtures live), proptest, `nix flake check` gate.

**Branch:** `feat/92-k6-key-state-snapshot` (already created off latest main; spec committed).

---

## EXECUTION NOTES FOR K3 (override the per-step run/commit instructions)

- **ALL TASKS SEQUENTIAL** — every task touches `crates/keri/src/state.rs` and/or `crates/keri-codec/tests/snapshot.rs`; no parallel fan-out, no worktrees.
- **NEVER run tests** (`cargo test`/`cargo nextest`) — they hang in this sandbox. Wherever a step says "Run: … cargo nextest …", instead verify with:
  `cargo check -p keri-rs -p keri-codec --tests` and `cargo clippy -p keri-rs -p keri-codec --tests`
  Both must be CLEAN (clippy is deny-everything; fix code, never add `#[allow]` without a `reason` on a specific item, never relax lints). Tests are executed by the controller after your run — write them exactly as specified so they pass there.
- **NEVER run git commands** — no commit, no push, no branch ops. Skip every "Step N: Commit" and all of Task 6 Steps 2–3 (controller drives commits, gate, PR, issue rewrite). Your job: Tasks 1–5 code+tests plus Task 6 Step 1 (crate docs).
- The "TDD failing-test first" step ordering collapses under check-only verification: for each task, write the test(s) AND the implementation, then run the two check commands. Keep the test content byte-faithful to the plan (adjusting only where a plan NOTE explicitly authorizes fixture-reality adjustments).
- Import rules are enforced by hooks: all `use` at file top, no fully-qualified construction paths in `src/`; test files are exempt but follow the existing style of `crates/keri-codec/tests/*.rs`.

---

## Verified facts the implementer must not re-derive

- `KeyState<'e>` private fields (`crates/keri/src/state.rs:83-98`): `prefix: &'e Identifier<'e>`, `sn: Number`, `latest_said: &'e Said<'e>`, `latest_message_type: MessageType`, `keys: &'e [VerifyingKey<'e>]`, `threshold: &'e SigningThreshold`, `next_keys: &'e [Digest<'e>]`, `next_threshold: &'e SigningThreshold`, `witnesses: Cow<'e, [BasicPrefix<'e>]>`, `witness_threshold: Toad`, `config: &'e [ConfigTrait]`, `delegator: Option<&'e BasicPrefix<'e>>`, `transferability: Transferability`, `last_est: EstablishmentRef<'e>`. The snapshot lives in the SAME module → direct private-field access; **no public change to `KeyState`**.
- `into_static()` exists on: role newtypes (`VerifyingKey`, `Digest`, `Said`, `BasicPrefix` — macro at `crates/keri-events/src/primitive.rs:60`), `Identifier` (`identifier.rs:57`), all event types, `Matter` (`crates/cesr/src/core/matter/matter.rs:152`).
- `Number`, `Toad`, `MessageType`, `ConfigTrait` are `Copy`; `SigningThreshold` is `Clone + PartialEq + Eq`; `Transferability` is `Copy + PartialEq + Eq`. Role newtypes have `PartialEq` (K1 compares `w == r`).
- Accessors: `InceptionEvent`: `prefix() sn() said() keys() threshold() next_keys() next_threshold() witnesses() witness_threshold() config()`. `RotationEvent`: same minus prefix/witnesses/config, plus `prior_event_said() witness_removals() witness_additions()`. `InteractionEvent`: `sn() said() prior_event_said()`. `DelegatedInceptionEvent`: `inception()`, `delegator() -> &Identifier` (NOTE: `Identifier`, not `BasicPrefix` — see Task 3 dip note). `DelegatedRotationEvent`: `rotation()`.
- Test fixtures: `crates/keri-codec/tests/common/mod.rs` — `Key`, `genesis(k0, next)`, `interaction(prior, sn)`, `plain_rotation(prior, sn, reveal, next)`, `rotation_witnessed(...)`, `Event { parsed: KeriEvent<'static>, bytes, said, prefix }`, `Event::signed(sigs)`, `Event::receipted(sigs, wigs)`, `seed(icp, k0) -> KeyState`, `Key::sign(&bytes, index)`. keri-rs is already a dev-dependency of keri-codec.
- Test-run shortcut during iteration: `nix develop --command cargo nextest run -p keri-codec --test snapshot` (plus `-p keri-rs` for unit probes). NEVER pipe gate commands. Final verification happens at push (pre-push hook runs `nix flake check` on committed state).
- `cesr-fn-ratchet` counts **free `pub fn`s** per module — this plan adds only methods and private free fns, so budgets are untouched.

---

### Task 1: `KeyStateSnapshot` type, `From<&KeyState>`, `view()`

**Files:**
- Modify: `crates/keri/src/state.rs` (append after `KeyState` impl, before the free validation fns)
- Modify: `crates/keri/src/lib.rs:49` (re-export)
- Test: `crates/keri-codec/tests/snapshot.rs` (create)

- [ ] **Step 1: Write the failing round-trip test**

Create `crates/keri-codec/tests/snapshot.rs`:

```rust
//! K6 snapshot-duality tests: the owned [`KeyStateSnapshot`] carrier and the
//! total trusted fold, pinned against the K1 validating fold.
//!
//! The heart of this suite is the differential invariant: for any ACCEPTED
//! event sequence, folding with `genesis`/`advance` (trusted, crypto-free)
//! must produce exactly `KeyStateSnapshot::from(&validating_fold_result)`.
mod common;

use common::{Fallible, Key, genesis, interaction, plain_rotation, seed};
use keri::{KeyState, KeyStateSnapshot};

/// Assert a lent view equals the state it was snapshotted from, field by field.
/// (`KeyState` has no `PartialEq`; accessors are the public comparison surface.)
fn assert_view_matches(view: &KeyState<'_>, original: &KeyState<'_>) {
    assert_eq!(view.prefix(), original.prefix());
    assert_eq!(view.sn().value(), original.sn().value());
    assert_eq!(view.latest_said(), original.latest_said());
    assert_eq!(view.latest_message_type(), original.latest_message_type());
    assert_eq!(view.keys(), original.keys());
    assert_eq!(view.threshold(), original.threshold());
    assert_eq!(view.next_keys(), original.next_keys());
    assert_eq!(view.next_threshold(), original.next_threshold());
    assert_eq!(view.witnesses(), original.witnesses());
    assert_eq!(view.witness_threshold(), original.witness_threshold());
    assert_eq!(view.config(), original.config());
    assert_eq!(view.delegator(), original.delegator());
    assert_eq!(view.transferability(), original.transferability());
    assert_eq!(
        view.last_establishment().sn.value(),
        original.last_establishment().sn.value()
    );
    assert_eq!(view.last_establishment().said, original.last_establishment().said);
}

#[test]
fn snapshot_round_trips_through_view() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn = interaction(&icp, 1)?;
    let rot = plain_rotation(&ixn, 2, &k1, &k2)?;

    let state = [
        ixn.signed(vec![k0.sign(&ixn.bytes, 0)?]),
        rot.signed(vec![k1.sign(&rot.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    let snapshot = KeyStateSnapshot::from(&state);
    assert_view_matches(&snapshot.view(), &state);

    // Round-trip: snapshotting the view again is identity on the snapshot.
    let again = KeyStateSnapshot::from(&snapshot.view());
    assert_eq!(again, snapshot);
    Ok(())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: COMPILE FAIL — `no KeyStateSnapshot in the root` (unresolved import `keri::KeyStateSnapshot`).

- [ ] **Step 3: Implement the type**

Append to `crates/keri/src/state.rs` (after the `impl<'e> KeyState<'e>` block, before the `// ── Validation rules` section). Imports to add at the top of the file: `use keri_events::{DelegatedInceptionEvent, ...}` is NOT needed yet (Task 3 adds event imports it needs); this task needs nothing new — every named type is already imported.

```rust
/// Owned snapshot of a [`KeyState`]: the storage-facing carrier.
///
/// The `PathBuf` to [`KeyState`]'s `&Path`: [`view`](Self::view) lends the
/// zero-copy working state back, and [`From<&KeyState>`] owns one out of a
/// fold result. `Send + Sync + 'static`, so an event-sourced host can hold it
/// as aggregate state. The trusted fold ([`genesis`](Self::genesis),
/// [`advance`](Self::advance)) rebuilds it from ACCEPTED events without
/// re-verifying — validation happened at decide time, in the K1 fold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStateSnapshot {
    prefix: Identifier<'static>,
    sn: Number,
    latest_said: Said<'static>,
    latest_message_type: MessageType,
    keys: Vec<VerifyingKey<'static>>,
    threshold: SigningThreshold,
    next_keys: Vec<Digest<'static>>,
    next_threshold: SigningThreshold,
    witnesses: Vec<BasicPrefix<'static>>,
    witness_threshold: Toad,
    config: Vec<ConfigTrait>,
    delegator: Option<BasicPrefix<'static>>,
    transferability: Transferability,
    last_est_sn: Number,
    last_est_said: Said<'static>,
}

impl KeyStateSnapshot {
    /// Lend the zero-copy working view: every borrow in the returned
    /// [`KeyState`] points into this snapshot's owned fields.
    #[must_use]
    pub fn view(&self) -> KeyState<'_> {
        KeyState {
            prefix: &self.prefix,
            sn: self.sn,
            latest_said: &self.latest_said,
            latest_message_type: self.latest_message_type,
            keys: &self.keys,
            threshold: &self.threshold,
            next_keys: &self.next_keys,
            next_threshold: &self.next_threshold,
            witnesses: Cow::Borrowed(self.witnesses.as_slice()),
            witness_threshold: self.witness_threshold,
            config: &self.config,
            delegator: self.delegator.as_ref(),
            transferability: self.transferability,
            last_est: EstablishmentRef {
                sn: self.last_est_sn,
                said: &self.last_est_said,
            },
        }
    }
}

impl From<&KeyState<'_>> for KeyStateSnapshot {
    fn from(state: &KeyState<'_>) -> Self {
        Self {
            prefix: state.prefix.clone().into_static(),
            sn: state.sn,
            latest_said: state.latest_said.clone().into_static(),
            latest_message_type: state.latest_message_type,
            keys: state.keys.iter().map(|k| k.clone().into_static()).collect(),
            threshold: state.threshold.clone(),
            next_keys: state
                .next_keys
                .iter()
                .map(|d| d.clone().into_static())
                .collect(),
            next_threshold: state.next_threshold.clone(),
            witnesses: state
                .witnesses
                .iter()
                .map(|w| w.clone().into_static())
                .collect(),
            witness_threshold: state.witness_threshold,
            config: state.config.to_vec(),
            delegator: state.delegator.map(|d| d.clone().into_static()),
            transferability: state.transferability,
            last_est_sn: state.last_est.sn,
            last_est_said: state.last_est.said.clone().into_static(),
        }
    }
}
```

If `Eq` fails to derive because a contained primitive lacks `Eq`, drop `Eq` and keep `PartialEq` (then Task 1 Step 1's `assert_eq!(again, snapshot)` still compiles); note which type blocked it in the commit body.

In `crates/keri/src/lib.rs` change the state re-export line to:

```rust
pub use state::{EstablishmentRef, KeyState, KeyStateSnapshot, Signed, Transferability};
```

Add a unit probe inside a new `#[cfg(test)] mod tests` at the bottom of `state.rs` (the file has none today):

```rust
#[cfg(test)]
mod tests {
    use super::KeyStateSnapshot;

    /// The snapshot satisfies the owned-aggregate-state shape an event-sourced
    /// host requires (spec §5 constraint 1). Fails to compile if a borrowed
    /// field sneaks in.
    #[test]
    fn snapshot_is_send_sync_static() {
        fn probe<T: Send + Sync + core::fmt::Debug + Clone + 'static>() {}
        probe::<KeyStateSnapshot>();
    }
}
```

(`core::fmt::Debug` path inline is fine here — test modules are exempt from the import rules.)

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot` and `nix develop --command cargo nextest run -p keri-rs`
Expected: PASS (2 new tests: `snapshot_round_trips_through_view`, `snapshot_is_send_sync_static`).

- [ ] **Step 5: Commit**

```bash
git add crates/keri/src/state.rs crates/keri/src/lib.rs crates/keri-codec/tests/snapshot.rs
git commit -m "feat(keri): #92 KeyStateSnapshot — owned carrier + view()/From duality"
```

---

### Task 2: Trusted seed — `KeyStateSnapshot::genesis`

**Files:**
- Modify: `crates/keri/src/state.rs`
- Test: `crates/keri-codec/tests/snapshot.rs`

- [ ] **Step 1: Write the failing differential-genesis test**

Append to `crates/keri-codec/tests/snapshot.rs` (and extend the `use` lines accordingly — `keri_events::KeriEvent` joins the imports):

```rust
use keri_events::KeriEvent;

/// Extract the inception out of a fixture event (`Fallible`, not `panic!` —
/// the workspace denies `clippy::panic` in test targets too).
fn as_inception(ev: &common::Event) -> Fallible<&keri_events::InceptionEvent<'static>> {
    let KeriEvent::Inception(icp) = &ev.parsed else {
        return Err("fixture is not an inception".into());
    };
    Ok(icp)
}

#[test]
fn trusted_genesis_matches_validating_incept() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;

    let validated = seed(&icp, &k0)?; // full crypto path
    let trusted = KeyStateSnapshot::genesis(as_inception(&icp)?); // no crypto

    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: COMPILE FAIL — `no function or associated item named genesis`.

- [ ] **Step 3: Implement `genesis`**

Add to the `impl KeyStateSnapshot` block in `state.rs`:

```rust
    /// Trusted seed: fold an ACCEPTED inception event. Total and crypto-free —
    /// the K1 validating fold ([`KeyState::incept`]) already authenticated it
    /// at decide time. Transferability is derived from the prefix alone; the
    /// transferability/next-key agreement rules were enforced at acceptance.
    #[must_use]
    pub fn genesis(icp: &InceptionEvent<'_>) -> Self {
        let transferability = if icp.prefix().is_transferable() {
            Transferability::Transferable
        } else {
            Transferability::NonTransferable
        };
        Self {
            prefix: icp.prefix().clone().into_static(),
            sn: icp.sn(),
            latest_said: icp.said().clone().into_static(),
            latest_message_type: MessageType::Icp,
            keys: icp.keys().iter().map(|k| k.clone().into_static()).collect(),
            threshold: icp.threshold().clone(),
            next_keys: icp
                .next_keys()
                .iter()
                .map(|d| d.clone().into_static())
                .collect(),
            next_threshold: icp.next_threshold().clone(),
            witnesses: icp
                .witnesses()
                .iter()
                .map(|w| w.clone().into_static())
                .collect(),
            witness_threshold: icp.witness_threshold(),
            config: icp.config().to_vec(),
            delegator: None,
            transferability,
            last_est_sn: icp.sn(),
            last_est_said: icp.said().clone().into_static(),
        }
    }
```

(`InceptionEvent` is already imported at the top of `state.rs`.)

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/keri/src/state.rs crates/keri-codec/tests/snapshot.rs
git commit -m "feat(keri): #92 trusted seed — KeyStateSnapshot::genesis"
```

---

### Task 3: Trusted step — `KeyStateSnapshot::advance`

**Files:**
- Modify: `crates/keri/src/state.rs`
- Test: `crates/keri-codec/tests/snapshot.rs`

- [ ] **Step 1: Write the failing differential tests**

Append to `snapshot.rs` (extend imports: `rotation_witnessed`, `WitnessChange`, `prefix_of` from `common` — check `common/mod.rs:173,386` for the exact `WitnessChange`/`rotation_witnessed` signatures before writing calls):

```rust
/// The K6 heart: trusted fold ≡ snapshot of the validating fold, over a KEL
/// exercising all three accepted event kinds.
#[test]
fn trusted_fold_matches_validating_fold() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn1 = interaction(&icp, 1)?;
    let rot = plain_rotation(&ixn1, 2, &k1, &k2)?;
    let ixn2 = interaction(&rot, 3)?;

    let validated = [
        ixn1.signed(vec![k0.sign(&ixn1.bytes, 0)?]),
        rot.signed(vec![k1.sign(&rot.bytes, 0)?]),
        ixn2.signed(vec![k1.sign(&ixn2.bytes, 0)?]),
    ]
    .into_iter()
    .try_fold(seed(&icp, &k0)?, |s, ev| s.ingest(&ev))?;

    let trusted = [&ixn1, &rot, &ixn2].into_iter().fold(
        KeyStateSnapshot::genesis(as_inception(&icp)?),
        |s, ev| s.advance(&ev.parsed),
    );

    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}

/// Same invariant across a witnessed rotation (mirrors the arrangement of
/// `rotation_swaps_a_witness` in `transitions.rs:100`): the trusted cut/add
/// algebra must land on exactly the validating fold's resolved witness set.
#[test]
fn trusted_fold_matches_validating_fold_with_witness_deltas() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, w1) = (Key::witness()?, Key::witness()?);

    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![prefix_of(&w0)],
            removals: vec![prefix_of(&w0)],
            additions: vec![prefix_of(&w1)],
            toad: 1,
        },
    )?;

    let s0 =
        KeyState::incept(&icp.receipted(vec![k0.sign(&icp.bytes, 0)?], icp.receipts(&[&w0])?))?;
    let validated =
        s0.ingest(&rot.receipted(vec![k1.sign(&rot.bytes, 0)?], rot.receipts(&[&w1])?))?;

    let trusted = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&rot.parsed);

    assert_eq!(trusted, KeyStateSnapshot::from(&validated));
    Ok(())
}
```

Extend the test-file imports for this task: `use keri_events::SigningThreshold;` and add `inception_full, rotation_witnessed, WitnessChange, prefix_of` to the `common` import list.

- [ ] **Step 2: Run to verify failure**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: COMPILE FAIL — `no method named advance`.

- [ ] **Step 3: Implement `advance` + private helpers**

Add `KeriEvent`, `RotationEvent`, `InteractionEvent` usage (all already imported in `state.rs`). Add to the `impl KeyStateSnapshot` block:

```rust
    /// Trusted step: fold one ACCEPTED event. Total and crypto-free — the
    /// validating fold authenticated it at decide time; this fold only
    /// computes. On input no validating fold would ever accept, it stays
    /// deterministic (idempotent witness algebra, no checks) instead of
    /// panicking: garbage in, deterministic garbage out — store integrity is
    /// the hosting layer's invariant, not this fold's.
    #[must_use]
    pub fn advance(self, event: &KeriEvent<'_>) -> Self {
        match event {
            KeriEvent::Inception(icp) => Self::genesis(icp),
            // Delegation validation is K4 scope. A dip/drt in an accepted
            // stream cannot exist before K4 extends BOTH folds (the
            // validating fold rejects them); folding the underlying
            // establishment data keeps `advance` total and deterministic
            // meanwhile. K4 also carries the delegator (an `Identifier`,
            // which today's `KeyState.delegator: Option<&BasicPrefix>`
            // cannot hold — widening it is a K4 change).
            KeriEvent::DelegatedInception(dip) => {
                let mut next = Self::genesis(dip.inception());
                next.latest_message_type = MessageType::Dip;
                next
            }
            KeriEvent::Rotation(rot) => self.rolled(rot, MessageType::Rot),
            KeriEvent::DelegatedRotation(drt) => self.rolled(drt.rotation(), MessageType::Drt),
            KeriEvent::Interaction(ixn) => self.stepped(ixn),
        }
    }

    /// Roll establishment state onto a rotation, trusted: keys, thresholds,
    /// commitment, and the cut/add-resolved witness set advance; prefix,
    /// config, transferability, and delegator carry over.
    fn rolled(self, rot: &RotationEvent<'_>, message_type: MessageType) -> Self {
        Self {
            sn: rot.sn(),
            latest_said: rot.said().clone().into_static(),
            latest_message_type: message_type,
            keys: rot.keys().iter().map(|k| k.clone().into_static()).collect(),
            threshold: rot.threshold().clone(),
            next_keys: rot
                .next_keys()
                .iter()
                .map(|d| d.clone().into_static())
                .collect(),
            next_threshold: rot.next_threshold().clone(),
            witnesses: trusted_witnesses(
                &self.witnesses,
                rot.witness_removals(),
                rot.witness_additions(),
            ),
            witness_threshold: rot.witness_threshold(),
            last_est_sn: rot.sn(),
            last_est_said: rot.said().clone().into_static(),
            ..self
        }
    }

    /// Advance the pointer onto an interaction, trusted: sn, latest SAID, and
    /// message type move; everything else carries over.
    fn stepped(self, ixn: &InteractionEvent<'_>) -> Self {
        Self {
            sn: ixn.sn(),
            latest_said: ixn.said().clone().into_static(),
            latest_message_type: MessageType::Ixn,
            ..self
        }
    }
```

And a private free fn next to `resolve_witnesses` (mirror its doc style):

```rust
/// Trusted counterpart of [`resolve_witnesses`]: the same cut/add algebra as
/// idempotent set operations — cutting an absent prefix is a no-op, adding a
/// present prefix is a skip. On accepted rotations (where the validating fold
/// already rejected overlaps and unknown cuts) it computes the identical set;
/// on anything else it stays total and deterministic.
fn trusted_witnesses(
    current: &[BasicPrefix<'static>],
    removals: &[BasicPrefix<'_>],
    additions: &[BasicPrefix<'_>],
) -> Vec<BasicPrefix<'static>> {
    let mut resolved: Vec<BasicPrefix<'static>> = current
        .iter()
        .filter(|w| !removals.iter().any(|r| r == *w))
        .cloned()
        .collect();
    for a in additions {
        if !resolved.iter().any(|w| *w == *a) {
            resolved.push(a.clone().into_static());
        }
    }
    resolved
}
```

(Lifetime note: `BasicPrefix` is covariant — a `&BasicPrefix<'static>` shortens to unify with `&BasicPrefix<'e>` in the `==`; the covariance probe tests in keri-events guarantee this keeps compiling.)

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/keri/src/state.rs crates/keri-codec/tests/snapshot.rs
git commit -m "feat(keri): #92 trusted step — KeyStateSnapshot::advance, total by construction"
```

---

### Task 4: Determinism on adversarial input (defensive boundary)

**Files:**
- Test: `crates/keri-codec/tests/snapshot.rs`

- [ ] **Step 1: Write the tests** (these should pass immediately — they pin behavior Task 3 built; if any fails, Task 3 is wrong, fix it there)

```rust
// ── Defensive boundary: advance is total and deterministic on input the
// validating fold would reject. No panics, exact deterministic outcomes. ──

#[test]
fn advance_on_second_inception_reseeds() -> Fallible<()> {
    let (k0, k1, k2, k3) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp_a = genesis(&k0, &k1)?;
    let icp_b = genesis(&k2, &k3)?;

    let reseeded = KeyStateSnapshot::genesis(as_inception(&icp_a)?).advance(&icp_b.parsed);
    assert_eq!(reseeded, KeyStateSnapshot::genesis(as_inception(&icp_b)?));
    Ok(())
}

#[test]
fn trusted_witness_cut_of_absent_prefix_is_noop_and_duplicate_add_is_skip() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let (w0, wx) = (Key::witness()?, Key::witness()?);

    // Actual current set: [w0]. The delta CLAIMS prior [wx], cuts wx (absent
    // from the true set), and adds w0 (already present). The builder accepts
    // it (cut/add relations hold against the CLAIMED prior — see the
    // WitnessChange doc, common/mod.rs:173); the validating fold rejects it
    // (WitnessSetError::RemovalNotCurrent). The trusted fold must compute
    // deterministically: cut-absent no-op, add-present skip → still [w0].
    let icp = inception_full(&[&k0], &[&k1], SigningThreshold::Simple(1), &[&w0], 1)?;
    let rot = rotation_witnessed(
        &icp,
        1,
        &k1,
        &k2,
        WitnessChange {
            prior: vec![prefix_of(&wx)],
            removals: vec![prefix_of(&wx)],
            additions: vec![prefix_of(&w0)],
            toad: 1,
        },
    )?;

    let stepped = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&rot.parsed);
    let view = stepped.view();
    assert_eq!(view.witnesses().len(), 1);
    assert_eq!(view.witnesses()[0].raw(), w0.verfer.raw());
    Ok(())
}

#[test]
fn advance_on_out_of_order_sn_takes_event_values_verbatim() -> Fallible<()> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let ixn_gap = interaction(&icp, 7)?; // validating fold would reject: expected 1

    let stepped = KeyStateSnapshot::genesis(as_inception(&icp)?).advance(&ixn_gap.parsed);
    assert_eq!(stepped.view().sn().value(), 7);
    assert_eq!(stepped.view().latest_said(), &ixn_gap.said);
    Ok(())
}
```

NOTE to implementer: `interaction(prior, 7)` builds a syntactically valid event with a gapped sn (the fixture takes sn verbatim — `common/mod.rs:338`). If the `rotation_witnessed` builder unexpectedly rejects the false-prior claim in the second test, fall back to `overlap_rotation` (`common/mod.rs:412`, a wire-forged cut/add overlap) and assert the overlap outcome instead: cut wins then add re-inserts — witnesses end as `[wit]`, still deterministic.

- [ ] **Step 2: Run**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: PASS (8 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/keri-codec/tests/snapshot.rs
git commit -m "test(keri): #92 advance determinism on adversarial input"
```

---

### Task 5: Property test — differential over generated KEL shapes

**Files:**
- Test: `crates/keri-codec/tests/snapshot.rs`

- [ ] **Step 1: Write the property test** (mirrors the bounded-generator idiom of `properties.rs` — real keys, real signatures, capped cases)

```rust
use proptest::prelude::*;

/// Fold the same generated KEL both ways and return the pair of snapshots.
/// Shape: genesis, then for each element of `plan` an interaction (false) or
/// a plain rotation (true), sns strictly sequential — every event accepted.
fn both_folds(plan: &[bool]) -> Fallible<(KeyStateSnapshot, KeyStateSnapshot)> {
    let mut keys = vec![Key::new()?, Key::new()?];
    let icp = genesis(&keys[0], &keys[1])?;

    let mut events = Vec::new();
    let mut current = 0usize; // index of the current signing key
    for (i, &rotate) in plan.iter().enumerate() {
        let sn = u128::try_from(i)?.checked_add(1).ok_or("sn overflow")?;
        let prior = events.last().unwrap_or(&icp);
        if rotate {
            keys.push(Key::new()?);
            let reveal_idx = current + 1;
            let next_idx = keys.len() - 1;
            let ev = plain_rotation(prior, sn, &keys[reveal_idx], &keys[next_idx])?;
            events.push(ev);
            current = reveal_idx;
        } else {
            events.push(interaction(prior, sn)?);
        }
    }

    // Validating fold: sign each event with the key controlling at that point.
    let mut signer = 0usize;
    let mut state = seed(&icp, &keys[0])?;
    for (i, ev) in events.iter().enumerate() {
        if plan[i] {
            signer += 1;
        }
        let sig = keys[signer].sign(&ev.bytes, 0)?;
        state = state.ingest(&ev.signed(vec![sig]))?;
    }

    // Trusted fold: parsed events only.
    let trusted = events.iter().fold(
        KeyStateSnapshot::genesis(as_inception(&icp)?),
        |s, ev| s.advance(&ev.parsed),
    );

    Ok((trusted, KeyStateSnapshot::from(&state)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))] // real Ed25519 per case
    /// Spec §6.2: trusted fold ≡ snapshot of validating fold on any accepted
    /// sequence. Boundaries: empty plan (genesis only), all-rotations,
    /// all-interactions, and mixed, up to length 6.
    #[test]
    fn trusted_fold_is_differential_dual(plan in proptest::collection::vec(any::<bool>(), 0..=6)) {
        let (trusted, validated) = both_folds(&plan).expect("accepted KEL must fold");
        prop_assert_eq!(trusted, validated);
    }
}
```

NOTE to implementer: the signer-index bookkeeping above assumes `plain_rotation(prior, sn, reveal, next)` reveals the key committed by the PRIOR establishment event — verify against `common/mod.rs:372` and the existing `rotation_chains_across_two_rotations` test in `transitions.rs`; adjust the index arithmetic to match reality, keeping the invariant that every generated event is ACCEPTED by the validating fold (an `Err` from `ingest` fails the property, which is correct).

- [ ] **Step 2: Run**

Run: `nix develop --command cargo nextest run -p keri-codec --test snapshot`
Expected: PASS (9 tests, property runs 16 cases).

- [ ] **Step 3: Commit**

```bash
git add crates/keri-codec/tests/snapshot.rs
git commit -m "test(keri): #92 proptest — trusted fold is the validating fold's differential dual"
```

---

### Task 6: Docs, gate, PR, issue rewrite

**Files:**
- Modify: `crates/keri/src/lib.rs:1-31` (crate docs)
- Modify: issue #92 body (gh)

- [ ] **Step 1: Extend the crate docs**

In `crates/keri/src/lib.rs`, after the paragraph ending "…drives the transition over its own iterator or stream with `try_fold`." add:

```rust
//!
//! **Two folds, one domain.** The validating fold above runs at decide time —
//! an event is *proposed*, so it carries proof obligations (signatures,
//! commitment openings, receipts). [`KeyStateSnapshot`] is the owned,
//! `'static` dual for storage-facing hosts: [`KeyStateSnapshot::view`] lends
//! the zero-copy working state back, and the trusted fold
//! ([`KeyStateSnapshot::genesis`], [`KeyStateSnapshot::advance`]) replays
//! ACCEPTED events totally and crypto-free — validation never runs twice.
//! An event-sourced host keeps the snapshot as aggregate state, validates
//! proposals through [`KeyState::ingest`], and rehydrates with the trusted
//! fold. `keri` itself stores nothing and looks nothing up: evidence a rule
//! needs arrives as arguments (delegation and receipt evidence are K4/K5).
```

- [ ] **Step 2: Push (the gate runs in the pre-push hook — do NOT foreground-poll `nix flake check`)**

```bash
git add crates/keri/src/lib.rs
git commit -m "docs(keri): #92 two-folds-one-domain crate docs"
git push -u origin feat/92-k6-key-state-snapshot
```

Expected: pre-push hook runs `nix flake check` on the committed state and the push lands. If the hook rejects, fix, commit, push again.

- [ ] **Step 3: Rewrite issue #92 body and open the PR**

Rewrite #92 (title: `K6 · KeyStateSnapshot duality — owned carrier + trusted fold (KelProvider dissolved)`) with: link to the spec file, the §1 reframe summary (KelProvider/MemKel/Acceptance dead, why), and the shipped surface. Then:

```bash
gh issue edit 92 --repo devrandom-labs/cesr --title "K6 · KeyStateSnapshot duality — owned carrier + trusted fold (KelProvider dissolved)" --body-file <rewritten-body.md>
gh pr create --title "feat(keri): #92 K6 — KeyStateSnapshot duality (owned carrier + trusted fold)" --body-file <pr-body.md>
gh pr merge --auto --squash
```

PR body must call out: additive public API (`KeyStateSnapshot`, re-export; `KeyState` untouched), the differential invariant as the review anchor, spec path, and `Closes #92`. End with the standard generated-with footer. Use the `joeldsouzax` gh account.

---

## Self-review notes (already applied)

- Spec §3 `genesis` used `Number::new(0)` for sn; plan takes `icp.sn()` — identical on accepted input (validating fold guarantees sn 0), more honest on the "fields come from the event" trusted rule. Spec stands.
- All test bodies are written against verified fixture signatures (`inception_full`, `rotation_witnessed`, `WitnessChange` claimed-prior semantics per `common/mod.rs:173`, `Event::receipted`/`receipts`); the only adjust-if-reality-differs notes are the Task 4 builder-rejection fallback and the Task 5 signer-index check.
- Ratchet/tripwires: no new free `pub fn`s (methods + one private free fn), no version-grammar tokens — both spine gates unaffected.
- `dip` advance sets `latest_message_type = MessageType::Dip` via a `mut` local; if clippy's pedantic set objects, restructure `genesis` into a private `seeded(icp, message_type)` helper shared by `Icp`/`Dip` arms — behavior identical.
