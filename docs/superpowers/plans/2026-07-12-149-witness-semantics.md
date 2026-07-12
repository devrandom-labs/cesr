# Witness Semantics Parity (#149) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make all four establishment-event builders enforce keripy's witness-configuration semantics (duplicate-free sets, rotation cut/add relations against a required prior witness set, `ample` TOAD default, TOAD bounds), closing issue #149.

**Architecture:** A new `pub(crate)` domain module `cesr/src/serder/builder/witness.rs` holds the shared validation (exact port of keripy `incept()`/`rotate()` preconditions, `eventing.py` @ `de59bc7d`). `RotationBuilder`/`DelegatedRotationBuilder` gain a required `NeedsPriorWitnesses` typestate (**breaking change**). The parity harness's `TRACKED`/`INEXPRESSIBLE` burn-down tables empty out and the `#[ignore]` bug-probe is deleted.

**Tech Stack:** Rust 1.95 (edition 2024), thiserror-style `SerderError::Validation`, cargo-nextest for the red/green loop, `nix flake check` as the final gate (needs committed state — commit each task, gate at the end).

**Spec:** `docs/superpowers/specs/2026-07-12-149-witness-semantics-design.md`
**Branch:** `fix/149-witness-semantics` (already created off `origin/main`)

**Conventions that bind every task** (from CLAUDE.md): no inline `use`; imports at top of file; checked arithmetic for counts; tests match `SerderError::Validation` via `let ... else`, never stringify-only; comments only for the why.

---

### Task 1: `witness.rs` — shared validation helpers (TDD)

**Files:**
- Create: `cesr/src/serder/builder/witness.rs`
- Modify: `cesr/src/serder/builder.rs` (register module)

- [ ] **Step 1: Register the module**

In `cesr/src/serder/builder.rs`, after line 16 (`pub mod rot;`) add:

```rust
/// Witness-set validation shared by the establishment-event builders.
mod witness;
```

- [ ] **Step 2: Create `witness.rs` with failing tests**

Create `cesr/src/serder/builder/witness.rs` with the module doc, `use` block, function *signatures returning `todo!()`-free stubs are not allowed* — write the tests first with empty impls that compile by returning `Ok(...)`/`Ok(0)`, so the tests FAIL (not error). Full file:

```rust
//! Witness-set validation shared by the establishment-event builders.
//!
//! Port of keripy's witness preconditions in `incept()` (`eventing.py:624-640`)
//! and `rotate()` (`eventing.py:788-831`), keripy `de59bc7d`: duplicate-free
//! witness lists, rotation cut/add set relations against the prior witness
//! set, and TOAD bounds.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};

use crate::core::primitives::Prefixer;
use crate::serder::error::SerderError;

/// Rejects duplicate prefixes, mirroring keripy's
/// `len(oset(x)) != len(x)` checks. `label` names the offending field.
pub(crate) fn validate_distinct(
    prefixes: &[Prefixer<'static>],
    label: &str,
) -> Result<(), SerderError> {
    prefixes
        .iter()
        .enumerate()
        .all(|(i, prefix)| !contains(&prefixes[..i], prefix))
        .then_some(())
        .ok_or_else(|| SerderError::Validation(format!("{label} must not contain duplicates")))
}

fn contains(set: &[Prefixer<'static>], prefix: &Prefixer<'static>) -> bool {
    set.iter().any(|member| member == prefix)
}

/// Validates a rotation's witness configuration against the prior witness
/// set — keripy's check order: duplicate-free prior/cuts, `cuts ⊆ prior`,
/// duplicate-free adds, `adds ∩ prior = ∅`, `cuts ∩ adds = ∅` — and returns
/// the post-rotation witness count `|(prior − cuts) ∪ adds|`.
///
/// keripy's final size check (`len(newitset) != len(wits) - len(cuts) +
/// len(adds)`, marked `# redundant?` in its own source) is provably implied
/// by these relations and is not ported: distinct cuts drawn from `prior`
/// remove exactly `len(cuts)` members and distinct adds disjoint from both
/// contribute exactly `len(adds)`.
pub(crate) fn validate_rotation_witnesses(
    prior: &[Prefixer<'static>],
    cuts: &[Prefixer<'static>],
    adds: &[Prefixer<'static>],
) -> Result<usize, SerderError> {
    validate_distinct(prior, "prior witnesses")?;
    validate_distinct(cuts, "witness removals")?;
    if !cuts.iter().all(|cut| contains(prior, cut)) {
        return Err(SerderError::Validation(
            "witness removals must all be prior witnesses".to_owned(),
        ));
    }
    validate_distinct(adds, "witness additions")?;
    if adds.iter().any(|add| contains(prior, add)) {
        return Err(SerderError::Validation(
            "witness additions must not already be prior witnesses".to_owned(),
        ));
    }
    if cuts.iter().any(|cut| contains(adds, cut)) {
        return Err(SerderError::Validation(
            "witness removals and additions must be disjoint".to_owned(),
        ));
    }
    let kept = prior.iter().filter(|wit| !contains(cuts, wit)).count();
    kept.checked_add(adds.len()).ok_or_else(|| {
        SerderError::Validation("post-rotation witness count overflows usize".to_owned())
    })
}

/// Bounds-checks a witness threshold (TOAD) against its governing witness
/// count: `1 <= toad <= count` when witnesses exist, exactly `0` when none
/// do (keripy `eventing.py:634-640` incept / `:825-831` rotate).
pub(crate) fn validate_toad(toad: u32, witness_count: usize) -> Result<(), SerderError> {
    let out_of_bounds = || {
        SerderError::Validation(format!(
            "witness threshold {toad} out of bounds for {witness_count} witnesses"
        ))
    };
    if witness_count == 0 {
        return (toad == 0).then_some(()).ok_or_else(out_of_bounds);
    }
    usize::try_from(toad)
        .ok()
        .filter(|toad| (1..=witness_count).contains(toad))
        .map(|_| ())
        .ok_or_else(out_of_bounds)
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::VerKeyCode;

    use super::*;

    fn prefixer(tag: u8) -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![tag; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn distinct_accepts_empty_single_and_distinct() {
        assert!(validate_distinct(&[], "wits").is_ok());
        assert!(validate_distinct(&[prefixer(1)], "wits").is_ok());
        assert!(validate_distinct(&[prefixer(1), prefixer(2)], "wits").is_ok());
    }

    #[test]
    fn distinct_rejects_duplicates_with_label() {
        let result = validate_distinct(&[prefixer(1), prefixer(2), prefixer(1)], "prior witnesses");
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate prefixes must be rejected");
        };
        assert_eq!(msg, "prior witnesses must not contain duplicates");
    }

    #[test]
    fn rotation_count_is_prior_minus_cuts_plus_adds() {
        let prior = [prefixer(1), prefixer(2), prefixer(3), prefixer(4)];
        let cuts = [prefixer(1)];
        let adds = [prefixer(5), prefixer(6)];
        assert_eq!(validate_rotation_witnesses(&prior, &cuts, &adds).unwrap(), 5);
        assert_eq!(validate_rotation_witnesses(&[], &[], &[]).unwrap(), 0);
        assert_eq!(
            validate_rotation_witnesses(&prior, &prior.clone(), &[]).unwrap(),
            0
        );
    }

    #[test]
    fn rotation_rejects_cut_not_in_prior() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[prefixer(9)], &[]);
        let Err(SerderError::Validation(msg)) = result else {
            panic!("cut outside the prior set must be rejected");
        };
        assert_eq!(msg, "witness removals must all be prior witnesses");
    }

    #[test]
    fn rotation_rejects_add_already_prior() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[], &[prefixer(1)]);
        let Err(SerderError::Validation(msg)) = result else {
            panic!("re-adding a prior witness must be rejected");
        };
        assert_eq!(msg, "witness additions must not already be prior witnesses");
    }

    #[test]
    fn rotation_rejects_cut_add_overlap() {
        let result =
            validate_rotation_witnesses(&[prefixer(1)], &[prefixer(1)], &[prefixer(1)]);
        // add ∩ prior fires first (keripy order); make the overlap-only case:
        let Err(SerderError::Validation(_)) = result else {
            panic!("overlapping cut/add must be rejected");
        };
        let overlap_only =
            validate_rotation_witnesses(&[prefixer(1), prefixer(2)], &[prefixer(1)], &[prefixer(1)]);
        let Err(SerderError::Validation(msg)) = overlap_only else {
            panic!("overlapping cut/add must be rejected");
        };
        assert_eq!(msg, "witness additions must not already be prior witnesses");
    }

    #[test]
    fn toad_boundaries_match_keripy() {
        assert!(validate_toad(0, 0).is_ok());
        assert!(validate_toad(1, 0).is_err());
        assert!(validate_toad(0, 1).is_err());
        assert!(validate_toad(1, 1).is_ok());
        assert!(validate_toad(1, 3).is_ok());
        assert!(validate_toad(3, 3).is_ok());
        assert!(validate_toad(4, 3).is_err());
        assert!(validate_toad(u32::MAX, 3).is_err());
    }
}
```

NOTE for the `rotation_rejects_cut_add_overlap` test: a cut/add pair that overlaps while the add is NOT a prior witness cannot exist when `cuts ⊆ prior` (any overlapping add IS a prior witness, so the `adds ∩ prior` check fires first, exactly as in keripy). The test documents this ordering; the disjointness branch itself is unreachable through `validate_rotation_witnesses` once the earlier checks pass — keep the check anyway because it ports keripy's line and guards against future reordering. If clippy flags the unreachable branch, do NOT remove the check; there is no lint that sees this, it is data-dependent.

- [ ] **Step 3: Run the module tests**

```bash
nix develop --command cargo nextest run -p cesr-rs 'serder::builder::witness'
```

Expected: all 7 tests PASS (the implementation above is complete; if you wrote stubs first, they fail then pass after filling in).

- [ ] **Step 4: Commit**

```bash
git add cesr/src/serder/builder.rs cesr/src/serder/builder/witness.rs
git commit -m "feat(serder): witness-set validation helpers ported from keripy incept/rotate

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Inception builders — duplicate wits + TOAD bounds

**Files:**
- Modify: `cesr/src/serder/builder/icp.rs` (build() at ~192-234, tests)
- Modify: `cesr/src/serder/builder/dip.rs` (build() at ~183-231, tests)

- [ ] **Step 1: Write failing tests in `icp.rs`**

Append to the `tests` module in `cesr/src/serder/builder/icp.rs`. The existing `make_prefixer()` always produces the same prefix (raw `[3u8; 32]`) — add a tagged variant next to it:

```rust
    fn make_prefixer_tag(tag: u8) -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![tag; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn duplicate_witnesses_rejected() {
        // keripy incept(): "Invalid wits = ..., has duplicates" (validation.jsonl incept/dup_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witnesses(vec![make_prefixer(), make_prefixer()])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate witnesses must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_exceeding_witness_count_rejected() {
        // keripy incept(): "Invalid toad ... for wits" (incept/toad_gt_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witnesses(vec![make_prefixer()])
            .witness_threshold(2)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("toad above the witness count must be rejected");
        };
        assert!(msg.contains("out of bounds"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_zero_with_witnesses_rejected() {
        // keripy incept(): toad < 1 with wits (incept/toad_zero_with_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witnesses(vec![make_prefixer()])
            .witness_threshold(0)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("zero toad alongside witnesses must be rejected");
        };
        assert!(msg.contains("out of bounds"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_nonzero_without_witnesses_rejected() {
        // keripy incept(): toad != 0 with no wits (incept/toad_nonzero_no_wits)
        let result = InceptionBuilder::new()
            .keys(vec![make_verfer()])
            .witness_threshold(1)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("nonzero toad with no witnesses must be rejected");
        };
        assert!(msg.contains("out of bounds"), "unexpected message: {msg}");
    }
```

`SerderError` is already imported at the top of `icp.rs` (line 22); `make_prefixer_tag` is used by the weighted test in Task 7 — if clippy flags it unused after this task, add it in Task 7 instead.

- [ ] **Step 2: Run to verify the new tests fail**

```bash
nix develop --command cargo nextest run -p cesr-rs 'serder::builder::icp'
```

Expected: the 4 new tests FAIL (builder currently accepts); all pre-existing tests PASS.

- [ ] **Step 3: Implement in `icp.rs` build()**

Add to the import block (after line 21 `use crate::serder::ample::ample;`):

```rust
use super::witness::{validate_distinct, validate_toad};
```

In `build()` replace the witness_threshold block (lines 214-217):

```rust
        validate_distinct(&self.witnesses, "witnesses")?;

        let witness_threshold = match self.witness_threshold {
            Some(explicit) => explicit,
            None => ample(self.witnesses.len())?,
        };
        validate_toad(witness_threshold, self.witnesses.len())?;
```

Extend the `# Errors` doc list on `build()` (after "- Next threshold exceeds the number of next keys (when non-empty)"):

```rust
    /// - `witnesses` contains duplicates
    /// - Witness threshold is out of bounds (`1..=len(witnesses)`, or nonzero
    ///   with no witnesses)
```

- [ ] **Step 4: Same for `dip.rs`**

Tests: append the same 4 tests to `dip.rs`'s tests module, with the dip builder chain (`DelegatedInceptionBuilder::new().keys(vec![make_verfer()]).delegator(make_prefixer_tag(9))` — check the existing dip tests for the exact `delegator(...)` call shape and reuse their `make_prefixer()` for the delegator where it doesn't collide with a witness; when a test needs both a witness and a delegator, use `make_prefixer_tag(7)` for the delegator so it differs from the witness). Add the same `make_prefixer_tag` helper to dip's tests module.

Implementation: add the same `use super::witness::{validate_distinct, validate_toad};` import (after line 17 `use crate::serder::ample::ample;`) and the same three-line change replacing the witness_threshold match at lines 205-208, plus the same `# Errors` doc additions.

- [ ] **Step 5: Run both builders' tests**

```bash
nix develop --command cargo nextest run -p cesr-rs 'serder::builder::icp' 'serder::builder::dip'
```

Expected: ALL PASS (8 new + all pre-existing, including `witness_threshold_default_ample`).

- [ ] **Step 6: Commit**

```bash
git add cesr/src/serder/builder/icp.rs cesr/src/serder/builder/dip.rs
git commit -m "fix(serder): #149 duplicate-witness and TOAD bounds validation on icp/dip builders

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `RotationBuilder` — required prior witnesses + full validation (BREAKING)

**Files:**
- Modify: `cesr/src/serder/builder/rot.rs` (whole file: typestate, build(), tests)

- [ ] **Step 1: Add the typestate and field**

In `cesr/src/serder/builder/rot.rs`:

After line 26 (`pub struct NeedsKeys;`) add:

```rust
/// Type state: prior witness set not yet provided.
pub struct NeedsPriorWitnesses;
```

Add the field to the struct (after line 55 `witness_additions: ...`):

```rust
    prior_witnesses: Vec<Prefixer<'static>>,
```

Add `prior_witnesses: Vec::new(),` to the `new()` literal (after line 75 `witness_additions: Vec::new(),`) and `prior_witnesses: self.prior_witnesses,` to the three state-transition struct literals in `prefix()` (line ~94), `prior_event_said()` (line ~122), and `keys()` (line ~144).

Change `keys()` (line 135) to return the new state:

```rust
impl RotationBuilder<NeedsKeys> {
    /// Set the new signing keys (required).
    pub fn keys(self, keys: Vec<Verfer<'static>>) -> RotationBuilder<NeedsPriorWitnesses> {
```

(body unchanged apart from the added `prior_witnesses` field move).

Insert a new impl block between `impl RotationBuilder<NeedsKeys>` and `impl RotationBuilder<Ready>`:

```rust
impl RotationBuilder<NeedsPriorWitnesses> {
    /// Set the prior witness set the removals/additions rotate (required —
    /// pass an empty `Vec` for an identifier with no current witnesses).
    ///
    /// Validation-only input mirroring keripy `rotate(wits=...)`: the prior
    /// set never appears in the serialized event, but the cut/add set
    /// relations and the default witness threshold are functions of it.
    pub fn prior_witnesses(
        self,
        prior_witnesses: Vec<Prefixer<'static>>,
    ) -> RotationBuilder<Ready> {
        RotationBuilder {
            prefix: self.prefix,
            prior_event_said: self.prior_event_said,
            keys: self.keys,
            sn: self.sn,
            threshold: self.threshold,
            next_keys: self.next_keys,
            next_threshold: self.next_threshold,
            witness_removals: self.witness_removals,
            witness_additions: self.witness_additions,
            prior_witnesses,
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors,
            said_code: self.said_code,
            _state: PhantomData,
        }
    }
}
```

Update the builder's doc comment (lines 31-44): required fields are now `prefix`, `prior_event_said`, `keys`, `prior_witnesses`, and the `# Examples` block gains `.prior_witnesses(vec![])` after `.keys(vec![verfer])`. Update the `witness_threshold` setter doc (line 192) from "(default: 0)" to "(default: `ample` of the post-rotation witness set)".

- [ ] **Step 2: Wire validation into `build()`**

Add to the import block (after line 15 `use super::icp::{...};`):

```rust
use super::witness::{validate_rotation_witnesses, validate_toad};
use crate::serder::ample::ample;
```

Replace line 255 (`let witness_threshold = self.witness_threshold.unwrap_or(0);`) with:

```rust
        let witness_count = validate_rotation_witnesses(
            &self.prior_witnesses,
            &self.witness_removals,
            &self.witness_additions,
        )?;
        let witness_threshold = match self.witness_threshold {
            Some(explicit) => explicit,
            None => ample(witness_count)?,
        };
        validate_toad(witness_threshold, witness_count)?;
```

Extend the `# Errors` doc on `build()`:

```rust
    /// - `prior_witnesses`, `witness_removals`, or `witness_additions` contain duplicates
    /// - A removal is not a prior witness, or an addition already is one
    /// - Witness threshold is out of bounds for the post-rotation witness set
```

- [ ] **Step 3: Fix existing tests and add the keripy-case tests**

In rot.rs's tests module:

a. Add the tagged helper next to `make_prefixer()`:

```rust
    fn make_prefixer_tag(tag: u8) -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![tag; 32]))
            .unwrap()
            .build()
            .unwrap()
    }
```

b. Every existing test appends `.prior_witnesses(vec![])` directly after its `.keys(...)` call — tests: `build_minimal_rotation`, `said_code_selects_digest`, `threshold_default_majority`, `roundtrip`, `sn_zero_rejected`, `empty_keys_rejected`, `build_rotation_with_self_addressing_prefix`, `default_impl`.

c. `build_with_all_options` currently cuts and adds the SAME prefix (both `make_prefixer()`) — now invalid. Rewrite its witness lines to:

```rust
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(6)])
            .witness_removals(vec![make_prefixer_tag(5)])
            .witness_threshold(1)
```

(keep `.prior_witnesses(...)` immediately after `.keys(...)` — it is the typestate transition; the later setters stay where they are).

d. Append the new tests:

```rust
    #[test]
    fn duplicate_prior_witnesses_rejected() {
        // keripy rotate(): "Invalid wits = ..., has duplicates" (validation.jsonl rotate/dup_wits_prior)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5), make_prefixer_tag(5)])
            .witness_threshold(2)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate prior witnesses must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn duplicate_witness_removals_rejected() {
        // keripy rotate(): "Invalid cuts = ..., has duplicates" (rotate/dup_cuts)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(5), make_prefixer_tag(5)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate removals must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn duplicate_witness_additions_rejected() {
        // keripy rotate(): "Invalid adds = ..., has duplicates" (rotate/dup_adds)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .witness_additions(vec![make_prefixer_tag(6), make_prefixer_tag(6)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate additions must be rejected");
        };
        assert!(msg.contains("duplicates"), "unexpected message: {msg}");
    }

    #[test]
    fn removal_not_prior_witness_rejected() {
        // keripy rotate(): "Invalid cuts = ..., not all members in wits" (rotate/cut_not_in_wits)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(9)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("removing a non-witness must be rejected");
        };
        assert!(msg.contains("prior witnesses"), "unexpected message: {msg}");
    }

    #[test]
    fn addition_already_prior_witness_rejected() {
        // keripy rotate(): "Intersecting wits and adds" (rotate/add_already_in_wits)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(5)])
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("re-adding a prior witness must be rejected");
        };
        assert!(msg.contains("already"), "unexpected message: {msg}");
    }

    #[test]
    fn overlapping_removal_and_addition_rejected() {
        // keripy rotate(): "Intersecting cuts and adds" (rotate/cut_add_intersect).
        // The overlapping member must be a prior witness (else cuts ⊆ wits fires
        // first), so the adds ∩ wits check rejects it — same terminal Err as keripy.
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(5)])
            .build();
        let Err(SerderError::Validation(_)) = result else {
            panic!("cutting and adding the same witness must be rejected");
        };
    }

    #[test]
    fn toad_exceeding_new_witness_set_rejected() {
        // keripy rotate(): "Invalid toad ... for wits" against the post-rotation set (rotate/toad_gt_new_wits)
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_removals(vec![make_prefixer_tag(5)])
            .witness_additions(vec![make_prefixer_tag(6)])
            .witness_threshold(2)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("toad above the post-rotation witness count must be rejected");
        };
        assert!(msg.contains("out of bounds"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_zero_with_witnesses_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(5)])
            .witness_threshold(0)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("zero toad alongside a non-empty witness set must be rejected");
        };
        assert!(msg.contains("out of bounds"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_nonzero_without_witnesses_rejected() {
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![])
            .witness_threshold(1)
            .build();
        let Err(SerderError::Validation(msg)) = result else {
            panic!("nonzero toad with no witnesses must be rejected");
        };
        assert!(msg.contains("out of bounds"), "unexpected message: {msg}");
    }

    #[test]
    fn toad_defaults_to_ample_of_post_rotation_set() {
        // 4 prior − 1 cut + 2 adds = 5 witnesses → ample(5) = 4 (keripy test_ample table).
        let result = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![
                make_prefixer_tag(1),
                make_prefixer_tag(2),
                make_prefixer_tag(3),
                make_prefixer_tag(4),
            ])
            .witness_removals(vec![make_prefixer_tag(1)])
            .witness_additions(vec![make_prefixer_tag(5), make_prefixer_tag(6)])
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
        assert_eq!(parsed["bt"].as_str().unwrap(), "4");
        let br = parsed["br"].as_array().unwrap();
        assert_eq!(br.len(), 1);
        let ba = parsed["ba"].as_array().unwrap();
        assert_eq!(ba.len(), 2);
    }

    #[test]
    fn witness_change_roundtrip() {
        let serialized = RotationBuilder::new()
            .prefix(make_prefixer())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .prior_witnesses(vec![make_prefixer_tag(1), make_prefixer_tag(2)])
            .witness_removals(vec![make_prefixer_tag(1)])
            .witness_additions(vec![make_prefixer_tag(3)])
            .build()
            .unwrap();

        let recovered =
            crate::serder::deserialize::deserialize_rotation(serialized.as_bytes()).unwrap();
        assert_eq!(recovered.witness_removals().len(), 1);
        assert_eq!(recovered.witness_additions().len(), 1);
        assert_eq!(recovered.witness_threshold(), 2);
    }
```

Before relying on `recovered.witness_removals()` / `.witness_additions()` / `.witness_threshold()` check the accessor names on `RotationEvent` (`cesr/src/keri/event/rotation.rs` — `witness_additions` at line 120; confirm the removals/threshold accessors nearby and adjust the assertions to the actual names).

- [ ] **Step 4: Run rot tests**

```bash
nix develop --command cargo nextest run -p cesr-rs 'serder::builder::rot'
```

Expected: ALL PASS. (Compile errors listing other call sites — `drt.rs` is untouched so far and compiles; `validation.rs`, `tests/kel_chain.rs`, `examples/kel_chain.rs` WILL fail to compile — that is Tasks 5-6; nextest may refuse to run until they compile. If so, proceed to Task 4/5/6 and run the full suite after Task 6.)

- [ ] **Step 5: Commit** (if the crate compiles; otherwise fold into the Task 5 commit)

```bash
git add cesr/src/serder/builder/rot.rs
git commit -m "fix(serder)!: #149 RotationBuilder requires prior witnesses; keripy witness validation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: `DelegatedRotationBuilder` — same change

**Files:**
- Modify: `cesr/src/serder/builder/drt.rs` (whole file)

- [ ] **Step 1: Mirror Task 3 exactly in `drt.rs`**

The drt builder is structurally identical to rot (states at lines 20-30, struct at 48-63, transitions at 65-159, build() at 233-291, `let witness_threshold = self.witness_threshold.unwrap_or(0);` at line 262):

- Add `pub struct NeedsPriorWitnesses;` after `NeedsKeys` (line 27).
- Add field `prior_witnesses: Vec<Prefixer<'static>>` + `prior_witnesses: Vec::new(),` in `new()` + `prior_witnesses: self.prior_witnesses,` in `prefix()`, `prior_event_said()`, `keys()` literals.
- `keys()` returns `DelegatedRotationBuilder<NeedsPriorWitnesses>`.
- New `impl DelegatedRotationBuilder<NeedsPriorWitnesses>` block with the same `prior_witnesses(...) -> DelegatedRotationBuilder<Ready>` method and doc as Task 3 Step 1 (type name changed).
- Imports: `use super::witness::{validate_rotation_witnesses, validate_toad};` and `use crate::serder::ample::ample;` after line 16.
- Replace line 262 with the same `validate_rotation_witnesses` / `ample` / `validate_toad` block as Task 3 Step 2.
- Same doc updates (struct docs, example, `witness_threshold` setter, `# Errors`).

- [ ] **Step 2: Mirror the test changes**

- Add `make_prefixer_tag` helper.
- Append `.prior_witnesses(vec![])` after `.keys(...)` in: `build_minimal_delegated_rotation`, `said_code_selects_digest`, `build_delegated_rotation_with_self_addressing_prefix`, `threshold_default_majority`, `roundtrip`, `sn_zero_rejected`, `empty_keys_rejected`, `default_impl`.
- `build_with_all_options`: same fix as rot (prior `[tag 5]`, removals `[tag 5]`, additions `[tag 6]`, toad 1).
- Append the same 11 new tests from Task 3 Step 3d with `RotationBuilder` → `DelegatedRotationBuilder` and the roundtrip/deserialize calls switched to `deserialize_delegated_rotation(...)` with `.rotation()` accessor prefixes (see the existing drt `roundtrip` test for the pattern: `recovered.rotation().keys()` etc.). In `witness_change_roundtrip` assert via `recovered.rotation().witness_removals()` etc.

- [ ] **Step 3: Run drt tests**

```bash
nix develop --command cargo nextest run -p cesr-rs 'serder::builder::drt'
```

Expected: ALL PASS (same compile caveat as Task 3 — full-crate compile lands after Task 6).

- [ ] **Step 4: Commit**

```bash
git add cesr/src/serder/builder/drt.rs
git commit -m "fix(serder)!: #149 DelegatedRotationBuilder requires prior witnesses; keripy witness validation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: cesr call sites — kel_chain example and integration test

**Files:**
- Modify: `cesr/examples/kel_chain.rs` (~line 50)
- Modify: `cesr/tests/kel_chain.rs` (~line 76)

- [ ] **Step 1: Update both rotation constructions**

Both build a plain rotation with no witnesses. In each, after `.keys(vec![rot_key])` insert:

```rust
        .prior_witnesses(vec![])
```

- [ ] **Step 2: Verify they compile and the test passes**

```bash
nix develop --command cargo build -p cesr-rs --examples
nix develop --command cargo nextest run -p cesr-rs --test kel_chain
```

Expected: build OK, test PASS.

- [ ] **Step 3: Commit**

```bash
git add cesr/examples/kel_chain.rs cesr/tests/kel_chain.rs
git commit -m "fix(serder): #149 kel_chain call sites state empty prior witness set

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Parity harness — burn down TRACKED and INEXPRESSIBLE

**Files:**
- Modify: `cesr/src/keripy_parity/validation.rs`

- [ ] **Step 1: Pass prior wits in the replays**

In `replay_rotate` (line ~163) and `replay_deltate` (line ~214), the `.keys(verfers(p))` call now returns the `NeedsPriorWitnesses` state — chain the transition immediately:

```rust
    let mut b = RotationBuilder::new()
        .prefix(dummy_prefixer()?)
        .prior_event_said(dummy_saider(DigestCode::Blake3_256)?)
        .keys(verfers(p))
        .prior_witnesses(prefixers(p, "wits"));
```

(and identically for `DelegatedRotationBuilder` in `replay_deltate`).

- [ ] **Step 2: Empty the burn-down tables and update docs**

Replace the `TRACKED` and `INEXPRESSIBLE` consts (lines 34-76) with:

```rust
/// Rejection rows cesr's builders accept today — the parity burn-down.
/// Emptied by #149; new corpus rows that cesr does not yet enforce go here
/// (the main sweep skips them; the stale-entry guard forces pruning).
const TRACKED: &[(&str, &str, &str)] = &[];

/// Rejection rows whose keripy parameters cannot be expressed through cesr's
/// builder API. Emptied by #149 (rotation builders now take the prior witness
/// set). Per the porting doctrine, a type-level fix moves a row to a
/// type-enforced skip — see the module doc — never to a forced runtime `Err`.
const INEXPRESSIBLE: &[(&str, &str, &str)] = &[];
```

Update the module doc (lines 1-12): replace the two sentences describing the open #149 gap ("Rows keripy rejects but cesr still accepts are the #149 burn-down (`TRACKED`); rows whose parameters cannot be expressed ... pending #149's design decision.") with:

```rust
//! builder. `TRACKED` holds rows keripy rejects but cesr still accepts (a
//! burn-down list, emptied by #149); `INEXPRESSIBLE` holds rows whose
//! parameters cannot be stated through the builder API (also emptied by #149
//! — rotation builders now require the prior witness set). Per the porting
```

(keep the trailing porting-doctrine sentence).

- [ ] **Step 3: Delete the spent bug-probe**

Delete the whole `tracked_validation_rows_reject_149` test including its doc comment (lines ~318-343). Its contract was to FAIL while any TRACKED row was unenforced; with the table empty it can only pass vacuously, and the main sweep now asserts every row for real.

- [ ] **Step 4: Run the parity sweeps**

```bash
nix develop --command cargo nextest run -p cesr-rs 'keripy_parity'
```

Expected: ALL PASS — `builder_validation_matches_keripy` output line shows `0 tracked`, and every former TRACKED/INEXPRESSIBLE row is now asserted (12 more rows asserted than before). `tracked_tables_match_corpus` passes trivially on empty tables.

If `lookup` or another helper is now dead code (clippy `deny`), keep `lookup` — it is still called by the sweep with both (empty) tables; only delete code the compiler actually flags, and prefer keeping the burn-down machinery intact for future corpus regens.

- [ ] **Step 5: Full cesr suite now compiles — run it**

```bash
nix develop --command cargo nextest run -p cesr-rs
```

Expected: ALL PASS (1600+ tests). Fix any straggler call sites the compiler surfaces (doc-tests are checked in the final gate).

- [ ] **Step 6: Commit**

```bash
git add cesr/src/keripy_parity/validation.rs
git commit -m "test(parity): #149 burn down witness-validation TRACKED/INEXPRESSIBLE tables

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Weighted-threshold end-to-end builder test (acceptance half-gap)

**Files:**
- Modify: `cesr/src/serder/builder/icp.rs` (tests module)

- [ ] **Step 1: Add the end-to-end test**

Today only rejection shapes of weighted thresholds are builder-tested (`empty_weighted_clause_list_rejected`, `empty_weighted_clause_rejected`). Append:

```rust
    #[test]
    fn weighted_threshold_builds_end_to_end() {
        // #149 acceptance: a valid weighted threshold ("1/2, 1/2, 1/2" over
        // 3 keys) must build, serialize as the fraction list, and round-trip.
        let serialized = InceptionBuilder::new()
            .keys(vec![make_verfer(), make_verfer(), make_verfer()])
            .threshold(Tholder::Weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]))
            .build()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(serialized.as_bytes()).unwrap();
        assert_eq!(parsed["kt"], serde_json::json!(["1/2", "1/2", "1/2"]));

        let recovered =
            crate::serder::deserialize::deserialize_inception(serialized.as_bytes()).unwrap();
        assert_eq!(
            *recovered.threshold(),
            Tholder::Weighted(vec![vec![(1, 2), (1, 2), (1, 2)]])
        );
    }
```

Two facts to verify while writing it (adjust the assertion, not the goal): (a) the exact JSON shape of a single-clause weighted `kt` — keripy serializes one clause as a flat list `["1/2","1/2","1/2"]`, nested lists only for multi-clause; check `cesr/src/serder/serialize/` for the Tholder writer and mirror what it emits; (b) `Tholder` derives `PartialEq` for the `assert_eq!` — if not, match with `let Tholder::Weighted(clauses) = recovered.threshold() else { panic!(...) }` and assert on `clauses`.

- [ ] **Step 2: Run**

```bash
nix develop --command cargo nextest run -p cesr-rs weighted_threshold_builds_end_to_end
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cesr/src/serder/builder/icp.rs
git commit -m "test(serder): #149 weighted-threshold inception builds end-to-end

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: keri crate test fixtures — claimed prior sets and the forged overlap event

**Files:**
- Modify: `keri/tests/common/mod.rs` (WitnessChange at ~128, `rotation()` at ~240, `delegated_rotation()` at ~318)
- Modify: `keri/tests/transitions.rs` (six WitnessChange literals + the overlap test)

The keri fold-rejection tests intentionally build witness-invalid events. The builder validates the **caller's claimed** prior set; the fold validates against the **true** key state. Most tests stay constructable by claiming a prior set that satisfies the builder while the fold still rejects. The cut∩add overlap event is intrinsically invalid (no claim makes the builder emit it — keripy's factory can't either) and is forged by byte-patching; it remains fold-relevant because wire input from other implementations can carry it.

- [ ] **Step 1: Extend `WitnessChange`**

In `keri/tests/common/mod.rs` add a field (first, before `removals`):

```rust
/// A rotation's witness delta: the claimed prior set, prefixes to cut,
/// prefixes to add, and the new TOAD.
pub struct WitnessChange {
    /// The prior witness set the delta claims to rotate. The builder
    /// validates cut/add relations against this claim; the fold checks the
    /// true key state, so a false claim yields a builder-valid event the
    /// fold rejects — exactly the shape the rejection tests need.
    pub prior: Vec<Prefixer<'static>>,
    /// Current witnesses to remove.
    pub removals: Vec<Prefixer<'static>>,
    /// New witnesses to add.
    pub additions: Vec<Prefixer<'static>>,
    /// The post-rotation witness threshold (TOAD).
    pub toad: u32,
}

impl WitnessChange {
    /// No witness change and a zero TOAD.
    pub const fn none() -> Self {
        Self {
            prior: Vec::new(),
            removals: Vec::new(),
            additions: Vec::new(),
            toad: 0,
        }
    }
}
```

- [ ] **Step 2: Thread it through the rotation fixtures**

In `rotation()` (~line 247), after `.keys(verfers(keys.reveal))` insert:

```rust
        .prior_witnesses(witnesses.prior)
```

In `delegated_rotation()` (~line 318), after `.keys(vec![reveal.verfer.clone()])` insert:

```rust
        .prior_witnesses(vec![])
```

- [ ] **Step 3: Update the `WitnessChange` literals in `transitions.rs`**

- `rotation_swaps_a_witness` (~line 108): add `prior: vec![w0.verfer.clone()],` (true prior — icp has w0).
- `rotation_adds_a_witness` (~line 133): add `prior: vec![],` (true prior — genesis has none).
- The literals at ~lines 424 and 449 (additions of `w0` onto witness-less inceptions): add `prior: vec![],`.
- `rotation_removing_a_non_witness_is_rejected` (~line 374): add `prior: vec![ghost.verfer.clone()],` with a comment `// falsely claimed prior — the builder accepts, the fold knows better`.
- `rotation_with_toad_above_resolved_witness_count_is_rejected` (~line 439): introduce a decoy key and claim it, so the builder sees a 2-member post-rotation set while the fold resolves 1:

```rust
    let (k0, k1, k2, w0, decoy) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    ...
        WitnessChange {
            // falsely claimed prior — builder sees {decoy, w0} (toad 2 in
            // bounds), the fold resolves {w0} and rejects.
            prior: vec![decoy.verfer.clone()],
            removals: vec![],
            additions: vec![w0.verfer.clone()],
            toad: 2,
        },
```

(keep the existing assertion `Rejection::WitnessThresholdExceeded { .. }`).

- [ ] **Step 4: Forge the overlap event**

`rotation_with_overlapping_cut_and_add_is_rejected` (~line 393) can no longer use the builder (cut∩add is an event-level contradiction every honest factory refuses). Replace the `rotation_witnessed(...)` call with a byte-patched construction. Add a fixture to `keri/tests/common/mod.rs` (next to `rotation_witnessed`):

```rust
/// A rotation whose `br` and `ba` both contain `wit` — an event-level
/// contradiction no factory (ours or keripy's) will emit, but which can
/// arrive over the wire. Forged by building a valid swap (`cut wit, add
/// decoy`) and rewriting the decoy's qb64 to `wit`'s (same code, same
/// length, so offsets survive). The stale SAID is irrelevant: the fold
/// rejects on the witness delta and never verifies the digest.
pub fn overlap_rotation(
    prior: &Event,
    sn: u128,
    reveal: &Key,
    next: &Key,
    wit: &Key,
    decoy: &Key,
) -> Fallible<Event> {
    let ser = RotationBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .keys(vec![reveal.verfer.clone()])
        .prior_witnesses(vec![wit.verfer.clone()])
        .sn(sn)
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(&next.verfer)?])
        .next_threshold(Tholder::Simple(1))
        .witness_removals(vec![wit.verfer.clone()])
        .witness_additions(vec![decoy.verfer.clone()])
        .witness_threshold(1)
        .build()?;
    let forged = String::from_utf8(ser.as_bytes().to_vec())?
        .replace(&decoy.verfer.to_qb64(), &wit.verfer.to_qb64());
    Event::build(
        forged.into_bytes(),
        ser.said().clone().into_static(),
        prior.prefix.clone(),
    )
}
```

(match the surrounding fixtures for the exact `commit`/`Tholder` imports already in scope; `String` needs no import in the tests crate — it is std. If `Fallible`'s error type does not absorb `FromUtf8Error` via `?`, map it: `.map_err(|e| e.to_string())?` following how the file handles other conversions.)

Then the test becomes:

```rust
#[test]
fn rotation_with_overlapping_cut_and_add_is_rejected() -> Fallible<()> {
    let (k0, k1, k2, w0, decoy) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_full(&[&k0], &[&k1], Tholder::Simple(1), &[&w0], 1)?;
    let rot = overlap_rotation(&icp, 1, &k1, &k2, &w0, &decoy)?;
    let Err(r) = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation cutting and adding the same witness was accepted".into());
    };
    assert!(matches!(
        r,
        Rejection::WitnessSet(WitnessSetError::CutAddOverlap)
    ));
    Ok(())
}
```

(update the test's import list to pull `overlap_rotation` from common and drop `rotation_witnessed` if now unused there — check the other tests first.)

- [ ] **Step 5: Run the keri test suite**

```bash
nix develop --command cargo nextest run -p keri-rs
```

Expected: ALL PASS. Pay attention to the five touched rejection tests — each must still reject with its original `Rejection` variant (the assertion, not just an Err).

- [ ] **Step 6: Commit**

```bash
git add keri/tests/common/mod.rs keri/tests/transitions.rs
git commit -m "test(keri): #149 fixtures claim prior witness sets; forge the cut/add-overlap event

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: CHANGELOG + spec acceptance

**Files:**
- Modify: `cesr/CHANGELOG.md` (under `## [Unreleased]`)
- Modify: `docs/superpowers/specs/2026-07-12-149-witness-semantics-design.md` (tick acceptance boxes)

- [ ] **Step 1: CHANGELOG entry**

Under `## [Unreleased]` in `cesr/CHANGELOG.md` add (matching the style of the 0.7.0 entries):

```markdown
### Fixed

- *(serder)* [**breaking**] #149 witness semantics parity in establishment builders — `RotationBuilder`/`DelegatedRotationBuilder` require the prior witness set via a new `NeedsPriorWitnesses` typestate (`.prior_witnesses(vec![...])` after `.keys(...)`; pass `vec![]` for no witnesses); all four establishment builders now reject duplicate witnesses, non-prior removals, already-present additions, overlapping cut/add sets, and out-of-bounds TOADs; rot/drt TOAD defaults to `ample(post-rotation set)` instead of `0`
```

- [ ] **Step 2: Tick the three acceptance checkboxes in the spec** (they are the issue's acceptance criteria; the differential/parity evidence is Task 10's gate output).

- [ ] **Step 3: Commit**

```bash
git add cesr/CHANGELOG.md docs/superpowers/specs/2026-07-12-149-witness-semantics-design.md
git commit -m "docs(changelog): #149 breaking witness-semantics entry

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: Final gate and PR

- [ ] **Step 1: The single gate** (all work is committed — the flake only sees committed state):

```bash
nix flake check
```

Expected: PASS (clippy god-level, fmt, taplo, audit, deny, nextest across feature combos, doctests, wasm, no_std). Fix any failure with a follow-up commit and re-run until green. Likely stragglers: rustfmt on the new module (`nix develop --command cargo fmt` then commit), clippy pedantic on test helpers.

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin fix/149-witness-semantics
gh pr create --title "fix(serder)!: #149 witness semantics parity in establishment builders" --body "$(cat <<'EOF'
## Summary
- **BREAKING**: `RotationBuilder`/`DelegatedRotationBuilder` gain a required `NeedsPriorWitnesses` typestate — `.prior_witnesses(vec![...])` after `.keys(...)` (pass `vec![]` for no witnesses). The prior set is validation-only input mirroring keripy `rotate(wits=...)`; it never appears on the wire.
- All four establishment builders now enforce keripy's witness preconditions (`eventing.py` @ `de59bc7d`): duplicate-free wits/cuts/adds, `cuts ⊆ wits`, `adds ∩ wits = ∅`, `cuts ∩ adds = ∅`, TOAD bounds (`1..=len`, or 0 iff empty), and rot/drt TOAD defaulting to `ample(post-rotation set)` instead of `0`.
- Parity burn-down: `TRACKED` (8 rows) and `INEXPRESSIBLE` (4 rows) tables emptied — every witness-validation corpus row now asserts live; the spent `#[ignore]` bug-probe is deleted.
- keripy's redundant post-rotation size check is documented as provably implied, not ported.
- Acceptance extras: weighted-threshold inception now builder-tested end-to-end; keri fold-rejection fixtures updated (claimed-prior pattern + byte-forged cut/add-overlap event).

Closes #149

## Test plan
- `nix flake check` (full gate: clippy/fmt/taplo/audit/deny/nextest/doctests/wasm/no_std)
- New builder tests: one typed `SerderError::Validation` case per keripy `ValueError` (rot/drt ×9, icp/dip ×4), `ample` TOAD defaults, witness round-trips
- Parity sweep `builder_validation_matches_keripy` asserts 12 previously-tracked rows

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Attach the PR/issue to the CESR project board** (org Project #5) if not auto-attached, using the `joeldsouzax` account (`gh auth switch --user joeldsouzax` on a collaborator/scope error).

---

## Self-review notes

- **Spec coverage:** typestate decision → Tasks 3-4; validation semantics → Tasks 1-4; parity harness → Task 6; call sites → Tasks 5, 8; per-ValueError tests → Tasks 2-4; weighted end-to-end → Task 7; CHANGELOG/breaking callout → Tasks 9-10; keystate differential + gate → Task 10.
- **Known judgment points for the executor:** (a) exact `kt` JSON shape for a single weighted clause (Task 7 — read the serializer, don't guess); (b) `RotationEvent` accessor names in the round-trip tests (Task 3/4); (c) whether nextest can run rot/drt tests before Tasks 5-6 land (workspace compile) — if not, run the full suite at Task 6 Step 5.
