# K1 · KeyState + pure key-state fold — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the sans-io KERI core's foundation — a `KeyState<'a>` value type and a pure `validate`/`apply` fold — in the `keri-rs` crate, consuming only `cesr`'s public API.

**Architecture:** Nexus decide/apply split. `validate(state, event, sigs, wigs) -> Result<Accepted, Rejection>` is fallible and pure (KERI rules + threshold arithmetic; **no signature verification** — that stays upstream; the one hash it computes is the next-key commitment). `apply(state, &Accepted) -> KeyState` is an infallible fold. A `fold(state, impl IntoIterator)` convenience sits on top; the caller owns any real stream (sans-io).

**Tech Stack:** Rust 2024, `no_std` + `alloc`, `keri-rs` crate depending on `cesr` features `["core","keri","crypto","alloc"]`. Tests use `cesr`'s public `serder` builders (dev-dependency) to construct event fixtures, and `proptest` for properties. Verified only via `nix flake check`.

**Spec:** `docs/superpowers/specs/2026-07-05-87-keystate-fold-design.md`

---

## Ground rules for the executor

- **Verification is `nix flake check` only.** Never run bare `cargo`. Per-task "run test" steps use `nix develop --command cargo nextest run -p keri-rs <filter>` for the fast inner loop, but a task is not "done" until the relevant slice passes; the final gate is `nix flake check`.
- **New files must be `git add`ed before `nix flake check`** (the flake builds from the git tree). Commit frequently.
- **Import style is enforced by commit hooks:** all `use` at the top of the file, no inline `use`, no fully-qualified construction paths, `#[allow(...)]` needs `reason = "..."`. Test modules (`#[cfg(test)]`) are exempt from the no-inline-`use` rule but still may not need it.
- **No `unwrap`/`expect`/`panic` in non-test code.** `clippy.toml` sets `allow-unwrap-in-tests = true` and `allow-expect-in-tests = true`, so tests may use them.
- **Arithmetic safety:** production size/count math uses `checked_*` and returns `Err` on overflow — never `saturating_*`, never `unwrap_or(sentinel)`.
- **All modules `#![no_std]`-clean:** gate `alloc` imports with `#[cfg(feature = "alloc")]` following the existing `cesr` pattern.

Reference APIs (all `cesr` public):
- Primitives: `Verfer<'a>=Matter<'a,VerKeyCode>`, `Diger<'a>`/`Saider<'a>=Matter<'a,DigestCode>`, `Prefixer<'a>=Matter<'a,VerKeyCode>`, `Seqner` (`.value()->u128`, `Seqner::new(u128)`), `Tholder` (`Simple(u64)`/`Weighted(Vec<Vec<(u64,u64)>>)`), `Siger<'a>` (`.index()->u32`, `.ondex()->Option<u32>`, `.verfer()->Option<&Verfer>`, `.raw()->&[u8]`).
- `Matter`: `.raw()->&[u8]`, `.to_qb64b()->Vec<u8>`, `.to_qb64()->String`, `.code()`.
- `VerKeyCode::is_transferable()->bool`.
- Events (`cesr::keri`): `KeriEvent` enum (`.ilk()->Ilk`) with `Inception/Rotation/Interaction/DelegatedInception/DelegatedRotation`. Getters per event as listed in each task.
- `Ilk` (`Icp/Rot/Ixn/Dip/Drt`), `ConfigTrait` (`EstOnly/DoNotDelegate`), `Identifier<'a>` (`Basic(Prefixer)`/`SelfAddressing(Saider)`, `.as_prefixer()`, `.as_saider()`).
- Digest: `cesr::crypto::digest(code: DigestCode, data: &[u8]) -> Result<Diger<'static>, DigestError>`.

---

## File structure

```
keri/
  Cargo.toml                     # add cesr features core/keri/crypto/alloc; dev-deps serder+proptest
  src/
    lib.rs                       # module wiring + no_std scaffold (exists)
    error.rs                     # Rejection, RejectionReason
    threshold.rs                 # satisfied_by(&Tholder, &[u32]) -> bool  (simple + weighted)
    state.rs                     # KeyState<'a> + EstablishmentRef<'a> + getters
    fold/
      mod.rs                     # validate/apply/fold public fns + Accepted + shared helpers
      inception.rs               # inception validate + genesis apply
      rotation.rs                # rotation validate (incl next-key commitment) + apply
      interaction.rs             # interaction validate + apply
  tests/
    corpus/keystate.jsonl        # minimal happy-path KEL differential vector (K9 expands)
    differential.rs              # fold the vector, compare final state to keripy fields
cesr/
  src/keri/state.rs              # DELETE
  src/keri/mod.rs                # remove `pub mod state;` + `pub use state::KeyState;`
  src/lib.rs                     # remove KeyState from the keri re-export
CHANGELOG.md                     # note the breaking removal (or cesr/CHANGELOG.md if per-crate)
```

---

## Phase 0 — cesr cleanup + keri-rs wiring

### Task 0.1: Remove the vestigial owned `cesr::keri::KeyState`

**Files:**
- Delete: `cesr/src/keri/state.rs`
- Modify: `cesr/src/keri/mod.rs` (drop `pub mod state;` and `pub use state::KeyState;`)
- Modify: `cesr/src/lib.rs` (drop `KeyState` from the `pub use keri::{...}` re-export)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Delete the file and its re-exports**

```bash
git rm cesr/src/keri/state.rs
```

In `cesr/src/keri/mod.rs` remove these two lines:
```rust
/// Computed key state for an identifier.
pub mod state;
```
```rust
pub use state::KeyState;
```

In `cesr/src/lib.rs` change the keri re-export from:
```rust
pub use keri::{Identifier, Ilk, KeriError, KeriEvent, KeyState, Role, Seal};
```
to:
```rust
pub use keri::{Identifier, Ilk, KeriError, KeriEvent, Role, Seal};
```

- [ ] **Step 2: Add the CHANGELOG entry**

Under the cesr-rs unreleased/next section in `CHANGELOG.md`, add:
```markdown
### Changed (breaking)
- **Removed** the logic-free `cesr::keri::KeyState` (and its `cesr::KeyState` re-export).
  Computed key state now lives in the `keri-rs` crate as a folded `KeyState<'a>` (#87).
```

- [ ] **Step 3: Verify cesr still builds and nothing else referenced it**

Run: `nix develop --command cargo build -p cesr-rs --features keri,serder,crypto,stream`
Expected: builds clean. If a reference remains, the compiler names the file:line — fix it (there should be none outside the deleted file).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(#87)!: remove vestigial owned cesr::keri::KeyState

BREAKING: computed key state moves to the keri-rs crate (folded KeyState<'a>)."
```

### Task 0.2: Wire keri-rs features, dev-deps, and module skeleton

**Files:**
- Modify: `keri/Cargo.toml`
- Modify: `keri/src/lib.rs`

- [ ] **Step 1: Update `keri/Cargo.toml`**

Set the `cesr` dependency features and add dev-dependencies. Replace the `[dependencies]` cesr block and add `[dev-dependencies]`:

```toml
[dependencies]
# PUBLIC API ONLY. Must NOT enable cesr's `internals` or `test-utils` features
# (enforced by the flake `cesr-keri-boundary` check, which greps this manifest).
cesr = { package = "cesr-rs", path = "../cesr", version = "0.4", default-features = false, features = [
    "core",
    "keri",
    "crypto",
    "alloc",
] }

[dev-dependencies]
# serder is cesr PUBLIC API — used only to build event fixtures in tests. It pulls
# `internals` transitively, but as a dev-dependency that never reaches downstream
# consumers, and the literal "internals" string is absent here so the boundary check
# stays green.
cesr = { package = "cesr-rs", path = "../cesr", default-features = false, features = [
    "std",
    "core",
    "keri",
    "crypto",
    "stream",
    "serder",
] }
proptest = "1"
```

Add `alloc` to the feature table (env feature) if not present:
```toml
[features]
default = ["std"]
std = ["cesr/std"]
alloc = ["cesr/alloc"]
```

- [ ] **Step 2: Wire modules in `keri/src/lib.rs`**

Keep the existing header + `#![no_std]` + `#[cfg(feature = "std")] extern crate std;`. Add `extern crate alloc;` and the module declarations + re-exports. Replace the file body (keeping the doc header) with:

```rust
#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Validation verdict types.
pub mod error;
/// The pure key-state fold: `validate`, `apply`, `fold`.
pub mod fold;
/// Computed key state for a KERI identifier.
pub mod state;
/// Signing-threshold satisfaction over a signer index-set.
pub mod threshold;

pub use error::{Rejection, RejectionReason};
pub use fold::{apply, fold, validate, Accepted};
pub use state::KeyState;
```

- [ ] **Step 3: Add placeholder modules so it compiles**

Create each module file with a minimal `//!` doc and nothing else yet (later tasks fill them). This keeps the crate compiling between tasks. Create `keri/src/error.rs`, `keri/src/state.rs`, `keri/src/threshold.rs`, `keri/src/fold/mod.rs`, and the three fold submodules with a doc line each. For `fold/mod.rs`:
```rust
//! The pure key-state fold.
mod inception;
mod interaction;
mod rotation;
```

> Note: the `pub use` in lib.rs references items not yet defined — to keep intermediate compiles green, add the `pub use` lines in the task that first defines each item, not in Step 2. Adjust: in Step 2 include only the `pub mod` lines; append each `pub use` in its defining task.

- [ ] **Step 4: Verify it compiles**

Run: `nix develop --command cargo build -p keri-rs`
Expected: builds clean (empty modules).

- [ ] **Step 5: Commit**

```bash
git add keri/Cargo.toml keri/src
git commit -m "chore(#87): wire keri-rs features, dev-deps, and module skeleton"
```

---

## Phase 1 — Threshold satisfaction

This is the trickiest arithmetic; build it first, in isolation, fully property-tested.

### Task 1.1: `satisfied_by` for simple thresholds

**Files:**
- Modify: `keri/src/threshold.rs`
- Test: inline `#[cfg(test)]` in `keri/src/threshold.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! Signing-threshold satisfaction over a signer index-set.
use cesr::core::primitives::Tholder;

/// Returns `true` if the signers at `indices` satisfy `tholder`.
///
/// `indices` are the key-list positions whose signatures a caller has already
/// cryptographically verified. Duplicates are tolerated (deduplicated internally).
#[must_use]
pub fn satisfied_by(tholder: &Tholder, indices: &[u32]) -> bool {
    // implemented in Step 3
    let _ = (tholder, indices);
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::core::primitives::Tholder;

    #[test]
    fn simple_threshold_counts_distinct_indices() {
        let th = Tholder::Simple(2);
        assert!(!satisfied_by(&th, &[]));
        assert!(!satisfied_by(&th, &[0]));
        assert!(satisfied_by(&th, &[0, 1]));
        assert!(satisfied_by(&th, &[0, 1, 2]));
        // duplicates must not inflate the count
        assert!(!satisfied_by(&th, &[0, 0]));
    }

    #[test]
    fn simple_threshold_zero_is_always_met() {
        assert!(satisfied_by(&Tholder::Simple(0), &[]));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo nextest run -p keri-rs threshold::tests::simple`
Expected: FAIL (`satisfied_by` returns `false`).

- [ ] **Step 3: Implement simple satisfaction**

Replace the body of `satisfied_by`. Deduplicate indices without allocating a set by using a bitmask when small, else fall back to sort. Simplest correct approach using `alloc`:

```rust
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[must_use]
pub fn satisfied_by(tholder: &Tholder, indices: &[u32]) -> bool {
    let mut distinct: Vec<u32> = indices.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    match tholder {
        Tholder::Simple(threshold) => {
            let count = u64::try_from(distinct.len()).unwrap_or(u64::MAX);
            count >= *threshold
        }
        Tholder::Weighted(_clauses) => false, // Task 1.2
    }
}
```

> `u64::try_from(len)` can only fail on a 128-bit-`usize` platform holding >`u64::MAX` signatures — impossible in practice; `unwrap_or(u64::MAX)` here still satisfies any real threshold and never under-counts. (This is the one place a saturating fallback is defensible because it can only make satisfaction *easier* against an impossibly-large set; document it in a comment.)

Actually, to honor the "no `unwrap_or(sentinel)`" rule, prefer the explicit form — replace the count line with:
```rust
            let Ok(count) = u64::try_from(distinct.len()) else {
                return true; // more distinct signers than u64::MAX — any threshold is met
            };
            count >= *threshold
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo nextest run -p keri-rs threshold::tests::simple`
Expected: PASS (both simple tests).

- [ ] **Step 5: Commit**

```bash
git add keri/src/threshold.rs keri/src/lib.rs
git commit -m "feat(#87): threshold satisfied_by for simple thresholds"
```

Also append to `keri/src/lib.rs`:
```rust
pub use threshold::satisfied_by;
```

### Task 1.2: `satisfied_by` for weighted thresholds (exact rational)

**Files:**
- Modify: `keri/src/threshold.rs`

Weighted model (keripy `Tholder`): `Weighted(Vec<Vec<(num,den)>>)`. Each inner `Vec` is a **clause**; positions are assigned to clauses **in order** (clause 0 owns the first `clause0.len()` key positions, clause 1 the next `clause1.len()`, …). A clause is satisfied when the fractions at its **signed** positions sum to `>= 1`. The whole threshold is satisfied when **every** clause is satisfied.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod weighted_tests {
    use super::*;
    use cesr::core::primitives::Tholder;

    // one clause of three halves: any two of three positions reach 1.
    fn half_x3() -> Tholder {
        Tholder::Weighted(alloc::vec![alloc::vec![(1, 2), (1, 2), (1, 2)]])
    }

    #[test]
    fn weighted_single_clause() {
        let th = half_x3();
        assert!(!satisfied_by(&th, &[0]));       // 1/2 < 1
        assert!(satisfied_by(&th, &[0, 1]));     // 1/2 + 1/2 = 1
        assert!(satisfied_by(&th, &[1, 2]));     // any two
        assert!(satisfied_by(&th, &[0, 1, 2]));  // 3/2 >= 1
    }

    #[test]
    fn weighted_multi_clause_is_and_of_clauses() {
        // clause 0 owns positions {0,1}; clause 1 owns positions {2,3}.
        let th = Tholder::Weighted(alloc::vec![
            alloc::vec![(1, 2), (1, 2)],
            alloc::vec![(1, 1), (1, 1)],
        ]);
        assert!(!satisfied_by(&th, &[0, 1]));        // clause 1 unmet
        assert!(!satisfied_by(&th, &[2]));           // clause 0 unmet (clause1 met by pos2=1/1)
        assert!(satisfied_by(&th, &[0, 1, 2]));      // c0: 1/2+1/2=1 ; c1: pos2=1 >=1
    }

    #[test]
    fn weighted_index_outside_any_clause_is_ignored() {
        // total positions = 2; index 5 has no weight and contributes nothing.
        let th = Tholder::Weighted(alloc::vec![alloc::vec![(1, 2), (1, 2)]]);
        assert!(!satisfied_by(&th, &[0, 5]));
        assert!(satisfied_by(&th, &[0, 1, 5]));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop --command cargo nextest run -p keri-rs threshold::weighted_tests`
Expected: FAIL (weighted arm returns `false`).

- [ ] **Step 3: Implement weighted satisfaction with exact rational arithmetic**

Replace the `Tholder::Weighted` arm. Sum fractions per clause exactly by accumulating over a common denominator with checked arithmetic; a clause is met when `numerator_sum * 1 >= denominator_common` i.e. `sum >= 1`. Add a helper:

```rust
/// Exact test that the summed fractions at `signed` positions within one clause reach `>= 1`.
/// Positions in `signed` are clause-local. Returns `None` on arithmetic overflow.
fn clause_reaches_one(clause: &[(u64, u64)], signed: &[bool]) -> Option<bool> {
    // Accumulate sum = Σ num_i/den_i as a single fraction (acc_num / acc_den).
    let mut acc_num: u64 = 0;
    let mut acc_den: u64 = 1;
    for (i, &(num, den)) in clause.iter().enumerate() {
        if den == 0 {
            return None; // malformed weight; treat as unsatisfiable-by-error upstream
        }
        if signed.get(i).copied().unwrap_or(false) {
            // acc = acc_num/acc_den + num/den = (acc_num*den + num*acc_den) / (acc_den*den)
            let lhs = acc_num.checked_mul(den)?;
            let rhs = num.checked_mul(acc_den)?;
            acc_num = lhs.checked_add(rhs)?;
            acc_den = acc_den.checked_mul(den)?;
        }
    }
    // sum >= 1  <=>  acc_num >= acc_den
    Some(acc_num >= acc_den)
}
```

And the weighted arm of `satisfied_by`:
```rust
        Tholder::Weighted(clauses) => {
            let mut distinct = indices.to_vec();
            distinct.sort_unstable();
            distinct.dedup();
            let mut base: usize = 0; // first global position owned by the current clause
            for clause in clauses {
                let width = clause.len();
                // clause-local signed flags for positions [base, base+width)
                let mut signed = alloc::vec![false; width];
                for &idx in &distinct {
                    let Ok(idx_usize) = usize::try_from(idx) else { continue };
                    if idx_usize >= base && idx_usize < base + width {
                        signed[idx_usize - base] = true;
                    }
                }
                match clause_reaches_one(clause, &signed) {
                    Some(true) => {}
                    Some(false) | None => return false,
                }
                let Some(next_base) = base.checked_add(width) else { return false };
                base = next_base;
            }
            true
        }
```

- [ ] **Step 4: Run to verify pass**

Run: `nix develop --command cargo nextest run -p keri-rs threshold`
Expected: PASS (all simple + weighted tests).

- [ ] **Step 5: Commit**

```bash
git add keri/src/threshold.rs
git commit -m "feat(#87): weighted threshold satisfaction (exact rational, checked)"
```

### Task 1.3: Property tests for threshold satisfaction

**Files:**
- Modify: `keri/src/threshold.rs` (add a `proptest` module)

- [ ] **Step 1: Write the property tests**

```rust
#[cfg(test)]
mod prop_tests {
    use super::*;
    use cesr::core::primitives::Tholder;
    use proptest::prelude::*;

    proptest! {
        // Simple: satisfied iff distinct-count >= threshold.
        #[test]
        fn simple_matches_count(threshold in 0u64..8, idxs in proptest::collection::vec(0u32..8, 0..12)) {
            let th = Tholder::Simple(threshold);
            let mut d = idxs.clone();
            d.sort_unstable(); d.dedup();
            let expected = (d.len() as u64) >= threshold;
            prop_assert_eq!(satisfied_by(&th, &idxs), expected);
        }

        // Monotonicity: adding a signer never revokes satisfaction.
        #[test]
        fn adding_signer_is_monotone(threshold in 0u64..6, mut idxs in proptest::collection::vec(0u32..6, 0..8), extra in 0u32..6) {
            let th = Tholder::Simple(threshold);
            let before = satisfied_by(&th, &idxs);
            idxs.push(extra);
            let after = satisfied_by(&th, &idxs);
            prop_assert!(!before || after);
        }

        // Weighted single clause of N halves: satisfied iff >= ceil(N/2)... expressed as sum.
        #[test]
        fn weighted_halves_boundary(n in 1usize..6, idxs in proptest::collection::vec(0u32..6, 0..8)) {
            let clause: alloc::vec::Vec<(u64,u64)> = core::iter::repeat((1u64,2u64)).take(n).collect();
            let th = Tholder::Weighted(alloc::vec![clause]);
            let mut d: alloc::vec::Vec<u32> = idxs.iter().copied().filter(|&i| (i as usize) < n).collect();
            d.sort_unstable(); d.dedup();
            // sum of halves = d.len()/2 >= 1  <=>  d.len() >= 2
            let expected = d.len() >= 2;
            prop_assert_eq!(satisfied_by(&th, &idxs), expected);
        }
    }
}
```

> `as` casts appear here inside `#[cfg(test)]`; the `as_conversions` lint is workspace-wide but tests commonly need them — if clippy flags it, add `#[allow(clippy::as_conversions, reason = "test-only index/width arithmetic")]` on the `prop_tests` module.

- [ ] **Step 2: Run**

Run: `nix develop --command cargo nextest run -p keri-rs threshold::prop_tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add keri/src/threshold.rs
git commit -m "test(#87): property tests for threshold satisfaction"
```

---

## Phase 2 — `Rejection` / `RejectionReason`

### Task 2.1: The validation verdict error type

**Files:**
- Modify: `keri/src/error.rs`
- Modify: `keri/src/lib.rs` (add `pub use error::{Rejection, RejectionReason};`)

- [ ] **Step 1: Write the type + a matching test**

```rust
//! Validation verdict types for the key-state fold.
use core::fmt;

/// Why an event was not accepted. **Placeholder taxonomy — K2 expands this**
/// into the full escrow routing. `#[non_exhaustive]` keeps additions non-breaking
/// for external matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// Sequence number is ahead of the expected next sn (a gap). K2 → out-of-order escrow.
    OutOfOrder,
    /// Prior-event digest does not match the current state's latest SAID. K3 → duplicity.
    PriorDigestMismatch,
    /// Signing threshold not satisfied by the provided signatures. K2 → partially-signed escrow.
    MissingSignatures,
    /// A structural KERI rule was violated (arity, transferability, ilk placement, ranges).
    InvalidEvent,
    /// Rotation's revealed keys do not match the prior next-key commitment.
    NextKeyCommitmentMismatch,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OutOfOrder => "event sequence number is out of order",
            Self::PriorDigestMismatch => "prior-event digest does not match current state",
            Self::MissingSignatures => "signing threshold not satisfied",
            Self::InvalidEvent => "event violates a structural KERI rule",
            Self::NextKeyCommitmentMismatch => "revealed keys do not match prior next-key commitment",
        };
        f.write_str(s)
    }
}

/// A validation rejection: the reason plus optional diagnostic context.
#[derive(Debug, Clone, thiserror::Error)]
#[error("event rejected: {reason}")]
pub struct Rejection {
    /// The failure domain.
    pub reason: RejectionReason,
    /// Expected sequence number, when the failure is sequence-related.
    pub expected_sn: Option<u128>,
    /// Actual sequence number carried by the event, when relevant.
    pub actual_sn: Option<u128>,
}

impl Rejection {
    /// A rejection carrying only a reason (no sn context).
    #[must_use]
    pub const fn new(reason: RejectionReason) -> Self {
        Self { reason, expected_sn: None, actual_sn: None }
    }

    /// A sequence-related rejection carrying expected/actual sn.
    #[must_use]
    pub const fn sn(reason: RejectionReason, expected: u128, actual: u128) -> Self {
        Self { reason, expected_sn: Some(expected), actual_sn: Some(actual) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_carries_reason_and_context() {
        let r = Rejection::sn(RejectionReason::OutOfOrder, 1, 4);
        assert_eq!(r.reason, RejectionReason::OutOfOrder);
        assert_eq!(r.expected_sn, Some(1));
        assert_eq!(r.actual_sn, Some(4));
    }
}
```

- [ ] **Step 2: Add `thiserror` to keri-rs deps**

In `keri/Cargo.toml` under `[dependencies]` add:
```toml
thiserror = { workspace = true }
```

- [ ] **Step 3: Run**

Run: `nix develop --command cargo nextest run -p keri-rs error::tests`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add keri/Cargo.toml keri/src/error.rs keri/src/lib.rs
git commit -m "feat(#87): Rejection + placeholder RejectionReason taxonomy"
```

---

## Phase 3 — `KeyState<'a>`

### Task 3.1: The `KeyState<'a>` value type and getters

**Files:**
- Modify: `keri/src/state.rs`
- Modify: `keri/src/lib.rs` (add `pub use state::KeyState;`)

`KeyState` fields are `pub(crate)` so the `fold` module (same crate) constructs it directly; the public surface is the getters (typed primitives / borrowed slices — never `String`).

- [ ] **Step 1: Write the type + a smoke test**

```rust
//! Computed key state for a KERI identifier at a point in its KEL.
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

use cesr::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use cesr::keri::{ConfigTrait, Ilk};

/// `(sn, said)` of the last establishment event (keripy `lastEst`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentRef<'a> {
    /// Sequence number of the last establishment event.
    pub sn: Seqner,
    /// SAID of the last establishment event.
    pub said: Saider<'a>,
}

/// Computed key state. Borrow-capable (`Cow`), but produced owned by `apply`
/// because state must outlive any single input event.
#[derive(Debug, Clone)]
pub struct KeyState<'a> {
    pub(crate) prefix: Prefixer<'a>,
    pub(crate) sn: Seqner,
    pub(crate) latest_said: Saider<'a>,
    pub(crate) latest_ilk: Ilk,
    pub(crate) keys: Cow<'a, [Verfer<'a>]>,
    pub(crate) threshold: Tholder,
    pub(crate) next_keys: Cow<'a, [Diger<'a>]>,
    pub(crate) next_threshold: Tholder,
    pub(crate) witnesses: Cow<'a, [Prefixer<'a>]>,
    pub(crate) witness_threshold: u32,
    pub(crate) config: Cow<'a, [ConfigTrait]>,
    pub(crate) delegator: Option<Prefixer<'a>>,
    pub(crate) transferable: bool,
    pub(crate) last_est: EstablishmentRef<'a>,
}

impl<'a> KeyState<'a> {
    /// Autonomic identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> &Prefixer<'a> { &self.prefix }
    /// Sequence number of the latest applied event.
    #[must_use]
    pub const fn sn(&self) -> &Seqner { &self.sn }
    /// SAID of the latest applied event.
    #[must_use]
    pub const fn latest_said(&self) -> &Saider<'a> { &self.latest_said }
    /// Ilk of the latest applied event.
    #[must_use]
    pub const fn latest_ilk(&self) -> Ilk { self.latest_ilk }
    /// Current signing keys.
    #[must_use]
    pub fn keys(&self) -> &[Verfer<'a>] { &self.keys }
    /// Current signing threshold.
    #[must_use]
    pub const fn threshold(&self) -> &Tholder { &self.threshold }
    /// Committed next-key digests.
    #[must_use]
    pub fn next_keys(&self) -> &[Diger<'a>] { &self.next_keys }
    /// Threshold for the next key set.
    #[must_use]
    pub const fn next_threshold(&self) -> &Tholder { &self.next_threshold }
    /// Current witness prefixes.
    #[must_use]
    pub fn witnesses(&self) -> &[Prefixer<'a>] { &self.witnesses }
    /// Witness threshold (TOAD).
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 { self.witness_threshold }
    /// Configuration traits in effect.
    #[must_use]
    pub fn config(&self) -> &[ConfigTrait] { &self.config }
    /// Delegator prefix, if this identifier is delegated.
    #[must_use]
    pub const fn delegator(&self) -> Option<&Prefixer<'a>> { self.delegator.as_ref() }
    /// Whether the identifier is transferable (rotatable).
    #[must_use]
    pub const fn transferable(&self) -> bool { self.transferable }
    /// `(sn, said)` of the last establishment event.
    #[must_use]
    pub const fn last_establishment(&self) -> &EstablishmentRef<'a> { &self.last_est }

    /// `true` if this state has the `EstOnly` config trait.
    #[must_use]
    pub fn is_establishment_only(&self) -> bool {
        self.config.iter().any(|c| matches!(c, ConfigTrait::EstOnly))
    }
}

#[cfg(test)]
mod tests {
    // KeyState is constructed only by `apply`; its behavior is covered by the
    // fold round-trip tests (Phase 4+). This module asserts the getter surface
    // compiles and is reachable via a state produced there — see fold tests.
}
```

- [ ] **Step 2: Verify it compiles**

Run: `nix develop --command cargo build -p keri-rs`
Expected: builds clean.

- [ ] **Step 3: Commit**

```bash
git add keri/src/state.rs keri/src/lib.rs
git commit -m "feat(#87): KeyState<'a> value type + typed getters"
```

---

## Phase 4 — Shared fold scaffolding + inception

### Task 4.1: `Accepted`, shared helpers, and public fn signatures

**Files:**
- Modify: `keri/src/fold/mod.rs`
- Modify: `keri/src/lib.rs` (add `pub use fold::{apply, fold, validate, Accepted};`)

- [ ] **Step 1: Write the scaffolding (no per-ilk logic yet)**

```rust
//! The pure key-state fold: `validate` (fallible) → `Accepted` → `apply` (infallible).
#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, vec::Vec};

use cesr::core::primitives::{Prefixer, Siger, Verfer};
use cesr::keri::KeriEvent;

use crate::error::{Rejection, RejectionReason};
use crate::state::KeyState;

mod inception;
mod interaction;
mod rotation;

/// A validation certificate: proof that `event` passed `validate`, carrying the
/// pre-resolved witness set so `apply` is a pure, infallible move.
#[derive(Debug)]
pub struct Accepted<'a> {
    pub(crate) event: &'a KeriEvent,
    /// Witness set *after* applying any rotation cuts/adds (for icp/ixn this is the
    /// event's own / the carried-over witness list).
    pub(crate) resolved_witnesses: Cow<'a, [Prefixer<'a>]>,
}

/// Collect the distinct key-list indices carried by already-verified signatures.
pub(crate) fn signed_indices(sigs: &[Siger<'_>]) -> Vec<u32> {
    sigs.iter().map(Siger::index).collect()
}

/// Validate a candidate `event` against `state` (its current key state, or `None`
/// for an inception). `sigs` are controller signatures **already cryptographically
/// verified upstream**; `wigs` are witness signatures/receipts. This performs KERI
/// structural rules + threshold arithmetic and, for rotation, the next-key commitment
/// hash — it does **not** verify signatures.
///
/// # Errors
/// Returns [`Rejection`] describing the first failing rule; never panics on any input.
pub fn validate<'a>(
    state: Option<&KeyState<'_>>,
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
    wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    match (state, event) {
        (None, KeriEvent::Inception(_) | KeriEvent::DelegatedInception(_)) => {
            inception::validate(event, sigs, wigs)
        }
        (None, _) => Err(Rejection::new(RejectionReason::OutOfOrder)),
        (Some(st), KeriEvent::Rotation(_) | KeriEvent::DelegatedRotation(_)) => {
            rotation::validate(st, event, sigs, wigs)
        }
        (Some(st), KeriEvent::Interaction(_)) => interaction::validate(st, event, sigs),
        (Some(_), KeriEvent::Inception(_) | KeriEvent::DelegatedInception(_)) => {
            Err(Rejection::new(RejectionReason::InvalidEvent)) // duplicate inception
        }
    }
}

/// Fold an already-accepted event into new key state. Infallible: `Accepted` is proof
/// every fallible check already passed.
#[must_use]
pub fn apply<'a>(state: Option<KeyState<'a>>, accepted: &Accepted<'a>) -> KeyState<'a> {
    match accepted.event {
        KeriEvent::Inception(_) | KeriEvent::DelegatedInception(_) => {
            inception::apply(accepted)
        }
        KeriEvent::Rotation(_) | KeriEvent::DelegatedRotation(_) => {
            rotation::apply(state, accepted)
        }
        KeriEvent::Interaction(_) => interaction::apply(state, accepted),
    }
}
```

> `apply` takes `Option<KeyState>` for a uniform signature; inception ignores it. This matches the spec's `fn apply(state: Option<KeyState>, ...)`.

- [ ] **Step 2: Add a `fold` convenience over an iterator (caller owns the stream)**

Append to `fold/mod.rs`:
```rust
/// A signed event ready to fold: the event plus its already-verified signatures.
pub struct SignedEvent<'a> {
    /// The candidate event.
    pub event: &'a KeriEvent,
    /// Controller signatures, already cryptographically verified upstream.
    pub sigs: Vec<Siger<'a>>,
    /// Witness signatures / receipts.
    pub wigs: Vec<Siger<'a>>,
}

/// Fold a sequence of signed events into key state, validating each in turn. Stops at
/// the first rejection. The caller owns the iteration source (sync iterator, async
/// stream drained to a `Vec`, DB cursor, …) — this fn does not own a stream.
///
/// # Errors
/// Returns the first [`Rejection`] encountered.
pub fn fold<'a, I>(mut state: Option<KeyState<'a>>, events: I) -> Result<KeyState<'a>, Rejection>
where
    I: IntoIterator<Item = SignedEvent<'a>>,
{
    let mut last: Option<KeyState<'a>> = None;
    for se in events {
        let accepted = validate(state.as_ref(), se.event, &se.sigs, &se.wigs)?;
        let next = apply(state.take(), &accepted);
        state = Some(next.clone());
        last = Some(next);
    }
    last.ok_or_else(|| Rejection::new(RejectionReason::InvalidEvent))
}
```

> The `Accepted` borrows `event` from `se`; because `SignedEvent` borrows `event: &'a KeriEvent` with the same `'a` as the returned state, the borrow checker is satisfied. If lifetime friction arises, restructure `fold` to take `&'a [SignedEvent<'a>]` and index — keep the caller-owns-loop shape either way.

- [ ] **Step 3: Provide empty per-ilk stubs so it compiles**

Create `inception::validate/apply`, `rotation::validate/apply`, `interaction::validate/apply` as `todo!()`-free stubs returning `Err(Rejection::new(RejectionReason::InvalidEvent))` / a trivial state, to be filled in the next tasks. Since `todo!`/`unimplemented!` are denied, use explicit placeholder returns and mark with `// FILLED IN Task N`.

- [ ] **Step 4: Compile**

Run: `nix develop --command cargo build -p keri-rs`
Expected: builds clean.

- [ ] **Step 5: Commit**

```bash
git add keri/src/fold keri/src/lib.rs
git commit -m "feat(#87): fold scaffolding — validate/apply dispatch, Accepted, fold()"
```

### Task 4.2: Test fixture helpers (build events via serder)

**Files:**
- Create: `keri/tests/common/mod.rs` (shared test helpers)

These helpers build real CESR events and signatures using cesr's **public** `serder` builders + `MatterBuilder` + `IndexerBuilder`, then `deserialize_event` to obtain a `KeriEvent`. They live under `tests/` (integration) so they can use the `serder` dev-dependency.

- [ ] **Step 1: Write the fixture helpers**

```rust
//! Shared test fixtures — build real KERI events via cesr's public serder API.
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::{Diger, Prefixer, Tholder, Verfer};
use cesr::crypto::digest;
use cesr::keri::KeriEvent;
use cesr::serder::{deserialize_event, InceptionBuilder, KeriSerialize};
use std::borrow::Cow;

/// A deterministic Ed25519 verfer from a 32-byte seed byte.
pub fn verfer(fill: u8) -> Verfer<'static> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(vec![fill; 32]))
        .unwrap()
        .build()
        .unwrap()
}

/// Blake3-256 digest of a verfer's qb64b — the next-key commitment for `v`.
pub fn commit(v: &Verfer<'static>) -> Diger<'static> {
    digest(DigestCode::Blake3_256, &v.to_qb64b()).unwrap()
}

/// Build a single-sig inception: current key `k0`, committing to next key `k1`.
/// Returns the parsed `KeriEvent`.
pub fn inception(k0: &Verfer<'static>, k1: &Verfer<'static>) -> KeriEvent {
    let event = InceptionBuilder::new()
        .keys(vec![k0.clone()])
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(k1)])
        .next_threshold(Tholder::Simple(1))
        .build()
        .unwrap();
    let raw = event.serialize().unwrap();
    deserialize_event(raw.as_bytes()).unwrap()
}
```

> Exact builder method names/paths (`InceptionBuilder::new().keys(...).build()`, `SerializedEvent::as_bytes()`) must be confirmed against `cesr/src/serder/builder/icp.rs` and `serialize.rs` while implementing — adjust the calls to the real API. The **shape** (build → serialize → deserialize_event) is the contract.

- [ ] **Step 2: Wire the module into a smoke test**

Create `keri/tests/smoke.rs`:
```rust
mod common;
use common::{inception, verfer};

#[test]
fn fixtures_build_a_real_inception() {
    let k0 = verfer(1);
    let k1 = verfer(2);
    let icp = inception(&k0, &k1);
    assert!(matches!(icp, cesr::keri::KeriEvent::Inception(_)));
}
```

- [ ] **Step 3: Run**

Run: `nix develop --command cargo nextest run -p keri-rs --test smoke`
Expected: PASS (proves the fixture path works end-to-end).

- [ ] **Step 4: Commit**

```bash
git add keri/tests
git commit -m "test(#87): serder-based event fixtures for the fold tests"
```

### Task 4.3: Inception validation

**Files:**
- Modify: `keri/src/fold/inception.rs`

Rules (keripy `eventing.py` L2228–2316), for `icp`/`dip`:
- `sn == 0`.
- Transferability consistency: the prefix code determines transferable; a `Basic` non-transferable prefix (`VerKeyCode::is_non_transferable`) must have exactly one key equal to the prefix and an empty next-key commitment; transferable prefixes require a next-key commitment.
- `keys` non-empty; `threshold` satisfiable by `keys.len()` (`Simple(t)` needs `t <= keys.len()`, `t >= 1`).
- `next_keys` arity consistent with `next_threshold`.
- Witnesses: `witness_threshold (toad) <= witnesses.len()`; duplicates rejected.
- Controller signatures satisfy `threshold` over their indices (bounds-checked: every `sig.index() < keys.len()`).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    // Integration-style: these live in keri/tests/fold_inception.rs (see below) so they
    // can use serder fixtures. This inline module stays empty.
}
```

Create `keri/tests/fold_inception.rs`:
```rust
mod common;
use common::{inception, verfer, sig_for};
use keri::{validate, RejectionReason};

#[test]
fn valid_inception_is_accepted() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let sigs = vec![sig_for(&icp, 0, &k0)];
    let accepted = validate(None, &icp, &sigs, &[]).expect("valid inception");
    assert!(matches!(accepted.event, cesr::keri::KeriEvent::Inception(_)));
}

#[test]
fn inception_without_enough_signatures_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let err = validate(None, &icp, &[], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::MissingSignatures);
}
```

Add a `sig_for` helper to `common/mod.rs` that builds an indexed `Siger` for a key index over the event (signature bytes are placeholder — validate does NOT verify them, only reads the index):
```rust
use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::core::primitives::Siger;

/// An indexed signature at `index`. The raw bytes are a fixed placeholder — the fold
/// never verifies them (verification is upstream); it only reads `.index()`.
pub fn sig_for(_event: &KeriEvent, index: u32, signer: &Verfer<'static>) -> Siger<'static> {
    let indexer = IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519)
        .with_index(index)
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 64]))
        .unwrap()
        .build()
        .unwrap();
    Siger::new(indexer).with_verfer(signer.clone())
}
```
> Confirm `IndexerBuilder` / `IndexedSigCode` paths and method names against `cesr/src/core/indexer/`. Adjust to the real API; the shape (index + 64-byte raw) is the contract.

- [ ] **Step 2: Run to verify failure**

Run: `nix develop --command cargo nextest run -p keri-rs --test fold_inception`
Expected: FAIL (stub rejects everything / wrong reason).

- [ ] **Step 3: Implement `inception::validate`**

```rust
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

use cesr::core::primitives::{Siger, Tholder};
use cesr::keri::{Identifier, KeriEvent};

use crate::error::{Rejection, RejectionReason};
use crate::fold::{signed_indices, Accepted};
use crate::threshold::satisfied_by;

pub(crate) fn validate<'a>(
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
    _wigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    // Extract the inner InceptionEvent (delegated shares the same body).
    let icp = match event {
        KeriEvent::Inception(e) => e,
        KeriEvent::DelegatedInception(e) => e.inception(),
        _ => return Err(Rejection::new(RejectionReason::InvalidEvent)),
    };

    // sn == 0
    if icp.sn().value() != 0 {
        return Err(Rejection::sn(RejectionReason::InvalidEvent, 0, icp.sn().value()));
    }

    // keys non-empty
    let keys = icp.keys();
    if keys.is_empty() {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }

    // threshold well-formed vs key count
    if let Tholder::Simple(t) = icp.threshold() {
        if *t == 0 || *t as u128 > keys.len() as u128 {
            return Err(Rejection::new(RejectionReason::InvalidEvent));
        }
    }

    // transferability consistency
    let transferable = match icp.prefix() {
        Identifier::Basic(p) => p.code().is_transferable(),
        Identifier::SelfAddressing(_) => true,
    };
    if !transferable && !icp.next_keys().is_empty() {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    if transferable && matches!(icp.prefix(), Identifier::SelfAddressing(_)) && icp.next_keys().is_empty() {
        // a transferable identifier commits to next keys (rotation possible)
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }

    // witness toad within range, no duplicates
    let wits = icp.witnesses();
    if icp.witness_threshold() as u128 > wits.len() as u128 {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }

    // every signature index is in range
    if sigs.iter().any(|s| s.index() as usize >= keys.len()) {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }

    // threshold satisfied by the (already-verified) signer indices
    if !satisfied_by(icp.threshold(), &signed_indices(sigs)) {
        return Err(Rejection::new(RejectionReason::MissingSignatures));
    }

    Ok(Accepted {
        event,
        resolved_witnesses: Cow::Owned(icp.witnesses().to_vec()),
    })
}
```
> `as` casts here are in production code — replace `*t as u128 > keys.len() as u128` with `u128::from(*t) > keys.len() as u128`; and `keys.len() as u128` → use `u128::try_from(keys.len()).unwrap_or(u128::MAX)` is banned — instead compare via `usize`: `usize::try_from(*t).map_or(true, |t| t > keys.len())`. Rework each `as` to a `try_from`/`From` per the arithmetic-safety rule while implementing; the **logic** (t in `1..=keys.len()`) is the contract. Similarly `s.index() as usize` → `usize::try_from(s.index())`.

- [ ] **Step 4: Run to verify pass**

Run: `nix develop --command cargo nextest run -p keri-rs --test fold_inception`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add keri/src/fold/inception.rs keri/tests
git commit -m "feat(#87): inception validation rules"
```

### Task 4.4: Inception apply (genesis state)

**Files:**
- Modify: `keri/src/fold/inception.rs`

- [ ] **Step 1: Write the failing round-trip test**

Append to `keri/tests/fold_inception.rs`:
```rust
use keri::{apply, KeyState};

#[test]
fn apply_inception_produces_genesis_state() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let sigs = vec![sig_for(&icp, 0, &k0)];
    let accepted = validate(None, &icp, &sigs, &[]).unwrap();
    let state: KeyState = apply(None, &accepted);
    assert_eq!(state.sn().value(), 0);
    assert_eq!(state.latest_ilk(), cesr::keri::Ilk::Icp);
    assert_eq!(state.keys().len(), 1);
    assert_eq!(state.keys()[0].raw(), k0.raw());
    assert_eq!(state.next_keys().len(), 1);
    assert!(state.transferable());
    assert_eq!(state.last_establishment().sn.value(), 0);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop --command cargo nextest run -p keri-rs --test fold_inception apply_inception`
Expected: FAIL.

- [ ] **Step 3: Implement `inception::apply`**

```rust
use cesr::core::primitives::Seqner;
use cesr::keri::Identifier;
use crate::state::{EstablishmentRef, KeyState};

pub(crate) fn apply<'a>(accepted: &Accepted<'a>) -> KeyState<'a> {
    let icp = match accepted.event {
        KeriEvent::Inception(e) => e,
        KeriEvent::DelegatedInception(e) => e.inception(),
        // apply is only reached for inception variants by dispatch; unreachable others
        // collapse to a minimal but valid state is impossible — dispatch guarantees icp.
        _ => unreachable_inception(),
    };
    let prefix = match icp.prefix() {
        Identifier::Basic(p) => p.clone().into_static(),
        Identifier::SelfAddressing(_s) => prefixer_from_saddr(icp), // see note
    };
    let transferable = match icp.prefix() {
        Identifier::Basic(p) => p.code().is_transferable(),
        Identifier::SelfAddressing(_) => true,
    };
    let said = icp.said().clone().into_static();
    KeyState {
        prefix,
        sn: Seqner::new(0),
        latest_said: said.clone(),
        latest_ilk: cesr::keri::Ilk::Icp,
        keys: Cow::Owned(icp.keys().to_vec()),
        threshold: icp.threshold().clone(),
        next_keys: Cow::Owned(icp.next_keys().to_vec()),
        next_threshold: icp.next_threshold().clone(),
        witnesses: match &accepted.resolved_witnesses {
            Cow::Owned(v) => Cow::Owned(v.clone()),
            Cow::Borrowed(s) => Cow::Owned(s.to_vec()),
        },
        witness_threshold: icp.witness_threshold(),
        config: Cow::Owned(icp.config().to_vec()),
        delegator: delegator_of(accepted.event),
        transferable,
        last_est: EstablishmentRef { sn: Seqner::new(0), said },
    }
}
```

Resolve the two notes while implementing:
- **`prefix` for a self-addressing identifier**: `KeyState.prefix` is a `Prefixer` (a `Matter<VerKeyCode>`), but a self-addressing prefix is a `Saider` (`Matter<DigestCode>`). This type mismatch means `KeyState.prefix` must be able to hold *either*. **Change `KeyState.prefix` to `Identifier<'a>`** (which already models Basic|SelfAddressing) rather than `Prefixer<'a>`. Update Task 3.1's field + getter to `Identifier<'a>` / `-> &Identifier<'a>`. (This is a spec refinement — record it in the plan's self-review and the design doc.)
- **`delegator_of` / delegated variants**: for `DelegatedInception`, `delegator` = `Some(e.delegator())` narrowed to its prefixer (`Identifier::as_prefixer`); for plain inception, `None`. Implement `fn delegator_of(event: &KeriEvent) -> Option<Prefixer<'_>>` accordingly.
- Replace `unreachable_inception()` with an explicit construction path that cannot be reached under dispatch — but since `panic`/`unreachable!` are denied, restructure `apply` so the inner match is done once in `fold::apply` and the ilk body receives the already-narrowed `&InceptionEvent`. **Refactor:** change `inception::apply(accepted)` to `inception::apply(icp: &'a InceptionEvent, accepted: &Accepted<'a>)`, moving the narrowing to `fold::apply` where the variant is already known. Do the same for rotation/interaction. This removes every unreachable arm.

- [ ] **Step 4: Run to verify pass**

Run: `nix develop --command cargo nextest run -p keri-rs --test fold_inception`
Expected: PASS (validation + apply).

- [ ] **Step 5: Commit**

```bash
git add keri/src
git commit -m "feat(#87): inception apply — genesis KeyState"
```

---

## Phase 5 — Interaction

### Task 5.1: Interaction validate + apply

**Files:**
- Modify: `keri/src/fold/interaction.rs`
- Test: `keri/tests/fold_interaction.rs`

Rules: `sn == state.sn + 1`; `prior_event_said == state.latest_said`; **no key/threshold/witness change** (interaction carries only anchors — enforced structurally by the type); rejected if `state.is_establishment_only()`; controller `sigs` satisfy `state.threshold`. `apply` advances only `sn` + `latest_said` (+ `latest_ilk = Ixn`); keys/next/witnesses/last_est carry over unchanged.

- [ ] **Step 1: Failing tests** — build an inception, fold to genesis, then an interaction with `prior = icp.said`, `sn = 1`:

```rust
mod common;
use common::{inception, interaction_after, verfer, sig_for};
use keri::{apply, validate, RejectionReason};

#[test]
fn valid_interaction_advances_sn_only() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let g_sigs = vec![sig_for(&icp, 0, &k0)];
    let g = apply(None, &validate(None, &icp, &g_sigs, &[]).unwrap());

    let ixn = interaction_after(&g, 1);
    let sigs = vec![sig_for(&ixn, 0, &k0)];
    let accepted = validate(Some(&g), &ixn, &sigs, &[]).unwrap();
    let s1 = apply(Some(g.clone()), &accepted);
    assert_eq!(s1.sn().value(), 1);
    assert_eq!(s1.latest_ilk(), cesr::keri::Ilk::Ixn);
    // keys unchanged
    assert_eq!(s1.keys()[0].raw(), g.keys()[0].raw());
    // last establishment still points at inception
    assert_eq!(s1.last_establishment().sn.value(), 0);
}

#[test]
fn out_of_order_interaction_is_rejected() {
    let (k0, k1) = (verfer(1), verfer(2));
    let icp = inception(&k0, &k1);
    let g = apply(None, &validate(None, &icp, &vec![sig_for(&icp, 0, &k0)], &[]).unwrap());
    let ixn = interaction_after(&g, 3); // gap
    let err = validate(Some(&g), &ixn, &vec![sig_for(&ixn, 0, &k0)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::OutOfOrder);
}
```

Add an `interaction_after(state, sn)` fixture to `common/mod.rs` using `InteractionBuilder` with `prior = state.latest_said().to_qb64()` and the given `sn`.

- [ ] **Step 2: Run to verify failure.** Expected FAIL.

- [ ] **Step 3: Implement `interaction::validate` and `apply`.** validate:

```rust
pub(crate) fn validate<'a>(
    state: &KeyState<'_>,
    event: &'a KeriEvent,
    sigs: &[Siger<'_>],
) -> Result<Accepted<'a>, Rejection> {
    let ixn = match event {
        KeriEvent::Interaction(e) => e,
        _ => return Err(Rejection::new(RejectionReason::InvalidEvent)),
    };
    if state.is_establishment_only() {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    let expected = state.sn().value().checked_add(1).ok_or_else(|| Rejection::new(RejectionReason::InvalidEvent))?;
    if ixn.sn().value() != expected {
        return Err(Rejection::sn(RejectionReason::OutOfOrder, expected, ixn.sn().value()));
    }
    if ixn.prior_event_said().raw() != state.latest_said().raw() {
        return Err(Rejection::new(RejectionReason::PriorDigestMismatch));
    }
    if sigs.iter().any(|s| usize::try_from(s.index()).map_or(true, |i| i >= state.keys().len())) {
        return Err(Rejection::new(RejectionReason::InvalidEvent));
    }
    if !satisfied_by(state.threshold(), &signed_indices(sigs)) {
        return Err(Rejection::new(RejectionReason::MissingSignatures));
    }
    Ok(Accepted { event, resolved_witnesses: Cow::Owned(state.witnesses().to_vec()) })
}
```
apply carries everything from prior state, bumping `sn`, `latest_said`, `latest_ilk`:
```rust
pub(crate) fn apply<'a>(state: Option<KeyState<'a>>, accepted: &Accepted<'a>) -> KeyState<'a> {
    // dispatch guarantees Some(state) and Interaction; narrow in fold::apply per Task 4.4 refactor
    let prior = state.expect("interaction requires prior state"); // in non-test this path is guarded; see refactor note
    let ixn = /* narrowed &InteractionEvent passed in */;
    let mut next = prior.clone();
    next.sn = Seqner::new(ixn.sn().value());
    next.latest_said = ixn.said().clone().into_static();
    next.latest_ilk = cesr::keri::Ilk::Ixn;
    next
}
```
> The `.expect` is illegal in production. Apply the Task 4.4 refactor: `fold::apply` matches the variant and passes `interaction::apply(prior: KeyState<'a>, ixn: &InteractionEvent)`, so `apply` receives a non-optional `prior` and the narrowed event — no `expect`, no `unreachable`.

- [ ] **Step 4: Run.** Expected PASS.

- [ ] **Step 5: Commit** `feat(#87): interaction validate + apply`.

---

## Phase 6 — Rotation (incl. next-key commitment)

### Task 6.1: Rotation validate

**Files:**
- Modify: `keri/src/fold/rotation.rs`
- Test: `keri/tests/fold_rotation.rs`

Rules (keripy L2483–2531): `sn == state.sn + 1` (in-order path; superseding is K3); `prior_event_said == state.latest_said`; **next-key commitment** — the rotation's `keys` (revealed) must match `state.next_keys` (committed digests) under `state.next_threshold`, checked by hashing (`digest(committed.code(), revealed.to_qb64b()).raw() == committed.raw()`), positionally; new `keys`/`threshold` well-formed; witness cut ⊆ current witnesses, add disjoint from post-cut set, new toad in range; controller `sigs` satisfy the **new** `threshold` AND the prior commitment is satisfied (the revealed keys as a set satisfy `state.next_threshold`).

- [ ] **Step 1: Failing tests** — inception commits to `k1`; rotation reveals `k1`, commits to `k2`:

```rust
mod common;
use common::{inception, rotation_after, verfer, sig_for, commit};
use keri::{apply, validate, RejectionReason};

#[test]
fn valid_rotation_replaces_keys() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));
    let icp = inception(&k0, &k1);
    let g = apply(None, &validate(None, &icp, &vec![sig_for(&icp, 0, &k0)], &[]).unwrap());

    let rot = rotation_after(&g, 1, &k1, &k2); // reveal k1, commit k2
    let sigs = vec![sig_for(&rot, 0, &k1)];
    let accepted = validate(Some(&g), &rot, &sigs, &[]).unwrap();
    let s1 = apply(Some(g.clone()), &accepted);
    assert_eq!(s1.sn().value(), 1);
    assert_eq!(s1.latest_ilk(), cesr::keri::Ilk::Rot);
    assert_eq!(s1.keys()[0].raw(), k1.raw());          // rotated to k1
    assert_eq!(s1.last_establishment().sn.value(), 1); // rotation is establishment
}

#[test]
fn rotation_with_wrong_revealed_key_fails_commitment() {
    let (k0, k1, k2, kx) = (verfer(1), verfer(2), verfer(3), verfer(9));
    let icp = inception(&k0, &k1);
    let g = apply(None, &validate(None, &icp, &vec![sig_for(&icp, 0, &k0)], &[]).unwrap());
    // reveal kx (not the committed k1) → commitment mismatch
    let rot = rotation_after(&g, 1, &kx, &k2);
    let err = validate(Some(&g), &rot, &vec![sig_for(&rot, 0, &kx)], &[]).unwrap_err();
    assert_eq!(err.reason, RejectionReason::NextKeyCommitmentMismatch);
}
```

Add `rotation_after(state, sn, reveal, next)` to `common/mod.rs` via `RotationBuilder` with `prior = state.latest_said`, `keys=[reveal]`, `next_keys=[commit(next)]`, appropriate thresholds.

- [ ] **Step 2: Run to verify failure.** Expected FAIL.

- [ ] **Step 3: Implement `rotation::validate`** including the commitment check:

```rust
use cesr::crypto::digest;

/// Every revealed key must equal one committed digest, positionally.
fn commitment_holds(revealed: &[Verfer<'_>], committed: &[Diger<'_>]) -> Result<bool, Rejection> {
    if revealed.len() != committed.len() {
        return Ok(false);
    }
    for (v, d) in revealed.iter().zip(committed.iter()) {
        let got = digest(*d.code(), &v.to_qb64b())
            .map_err(|_| Rejection::new(RejectionReason::NextKeyCommitmentMismatch))?;
        if got.raw() != d.raw() {
            return Ok(false);
        }
    }
    Ok(true)
}
```
Then the sequence/prior/commitment/threshold/witness checks, returning the resolved witness set (`current − removals + additions`) in `Accepted`.

> Confirm `Diger::code()` returns `&DigestCode` (deref/copy as needed for `digest(*code, …)`).

- [ ] **Step 4: Run.** Expected PASS.

- [ ] **Step 5: Commit** `feat(#87): rotation validation incl next-key commitment + witness cut/add`.

### Task 6.2: Rotation apply

**Files:**
- Modify: `keri/src/fold/rotation.rs`
- Test: extend `keri/tests/fold_rotation.rs`

- [ ] **Step 1: Failing test** — assert `apply` replaces keys/next/threshold, updates witnesses to the resolved set, and sets `last_est` to `(sn, said)` (already asserted partially in 6.1; add witness cut/add assertion with a witnessed inception fixture).

- [ ] **Step 2–4:** Implement `rotation::apply`: clone prior, replace `keys`, `threshold`, `next_keys`, `next_threshold`, `witnesses` (= `accepted.resolved_witnesses`), `witness_threshold`, bump `sn`/`latest_said`/`latest_ilk=Rot`, set `last_est = (sn, said)`. Run → PASS.

- [ ] **Step 5: Commit** `feat(#87): rotation apply — key/witness rollover + lastEst`.

---

## Phase 7 — Sequence / round-trip + fold() convenience

### Task 7.1: Multi-event chain test through `fold()`

**Files:**
- Test: `keri/tests/fold_chain.rs`

- [ ] **Step 1: Write the chain test** — `icp → ixn → rot → ixn` via the public `fold()`:

```rust
mod common;
use common::*;
use keri::{fold, SignedEvent};

#[test]
fn folds_a_four_event_kel() {
    let (k0, k1, k2) = (verfer(1), verfer(2), verfer(3));
    // build icp (commits k1), then ixn@1, rot@2 (reveal k1 commit k2), ixn@3.
    // NOTE: each fixture must be built against the running state's latest_said, so
    // construct sequentially, folding as you go to learn each prior said. The cleanest
    // form: build+validate+apply step-by-step (as in earlier tests) and separately
    // assert fold() over the pre-built SignedEvent list yields the same final state.
    // ... (assemble the Vec<SignedEvent>, call fold(None, events), assert final sn == 3,
    //     final keys == k1, final latest_ilk == Ixn, last_est.sn == 2)
}
```
> Because each event's `prior` digest depends on the previous event's SAID, the fixtures must be built in order. Provide a `common::build_kel()` helper that returns a `Vec<(KeriEvent, Vec<Siger>)>` for the canonical 4-event chain, computing each prior from the previous event's `.said()`. Fill in the concrete assembly here.

- [ ] **Step 2: Run.** Expected PASS (this exercises `fold()` + all three ilks + establishment tracking end to end).

- [ ] **Step 3: Commit** `test(#87): four-event KEL round-trip through fold()`.

### Task 7.2: Defensive boundary sweep

**Files:**
- Test: `keri/tests/fold_boundary.rs`

- [ ] **Step 1: One test per `Rejection` path**, each asserting the exact `RejectionReason`: duplicate inception (`Some(state)` + icp → `InvalidEvent`); rotation `sn` gap → `OutOfOrder`; rotation wrong prior digest → `PriorDigestMismatch`; under-threshold sigs → `MissingSignatures`; sig index out of range → `InvalidEvent`; `ixn` under `estOnly` inception → `InvalidEvent`; toad > witness count → `InvalidEvent`; commitment mismatch → `NextKeyCommitmentMismatch`. Each must **fail if the bug is present** (no both-branches-pass tests).

- [ ] **Step 2: Run.** Expected PASS.

- [ ] **Step 3: Commit** `test(#87): defensive boundary sweep — every Rejection path`.

---

## Phase 8 — Differential vs keripy (happy-path)

### Task 8.1: Minimal keripy KEL vector + comparison harness

**Files:**
- Create: `keri/tests/corpus/keystate.jsonl`
- Create: `keri/tests/differential.rs`

The full corpus is K9 (#95). K1 ships **one** happy-path chain generated from keripy and asserts the folded final state matches keripy's reported `Kever` fields.

- [ ] **Step 1: Generate the vector from the local keripy env**

Using the local keripy environment (Python ≥3.14.2, nix libsodium via `DYLD_LIBRARY_PATH` — see the project's keripy-diff notes), write a short script that incepts a transferable AID, rotates once, interacts once, and emits one JSON line with: each event's raw bytes (base64), the controller signatures (qb64), and the **final** `Kever` state fields (prefix qb64, sn, keys qb64[], threshold, next_keys qb64[], next_threshold, witnesses qb64[], toad). Save to `keri/tests/corpus/keystate.jsonl`.

> If the keripy env is unavailable to the executor, hand-author the vector from keripy's documented output for this exact chain and record in the file header comment that it is keripy-derived, plus the keripy version. Do **not** synthesize expected values from this crate's own fold (that would make the test circular).

- [ ] **Step 2: Write the harness**

`differential.rs` parses each JSONL line, `deserialize_event`s each raw event, builds `Siger`s from the qb64 signatures, folds via `keri::fold`, and asserts the final `KeyState` fields equal the recorded keripy fields (compare via `to_qb64`/`.value()` — exact equality, per test-quality rules).

- [ ] **Step 3: Run.**

Run: `nix develop --command cargo nextest run -p keri-rs --test differential`
Expected: PASS (folded state == keripy state).

- [ ] **Step 4: Commit** `test(#87): keripy differential vector for happy-path KEL fold`.

---

## Phase 9 — no_std / wasm / final gate

### Task 9.1: Confirm no_std + wasm builds and extend the flake matrix

**Files:**
- Modify: `flake.nix` (extend `cesr-nostd` / `cesr-wasm` to also build `keri-rs` with its real features), if not already covered.

- [ ] **Step 1: Check the flake already builds keri-rs for wasm/nostd**

The flake lines around 132–145 already reference `keri-rs` for wasm and no_std. Confirm they use `keri-rs`'s features (which now pull `cesr` `crypto`). If the no_std build (`cargo build -p keri-rs --no-default-features`) fails because a module needs `alloc`, ensure every `alloc` use is `#[cfg(feature = "alloc")]`-gated and that `keri-rs`'s `alloc` feature (Task 0.2) chains `cesr/alloc` + `cesr/crypto`'s alloc needs.

- [ ] **Step 2: Local wasm/nostd sanity**

Run:
```bash
nix develop --command cargo build -p keri-rs --target wasm32-unknown-unknown --no-default-features --features alloc
nix develop --command cargo build -p keri-rs --no-default-features --features alloc
```
Expected: both build clean.

- [ ] **Step 3: Commit** any flake/feature adjustments `ci(#87): keri-rs in the wasm + no_std flake matrix`.

### Task 9.2: Full gate

- [ ] **Step 1: Stage everything and run the one gate**

```bash
git add -A
nix flake check
```
Expected: all checks green — clippy (god-level), fmt, taplo, audit, deny, nextest (incl. the new keri-rs tests), doctest, wasm, no_std, boundary (`cesr-keri-boundary` still passes — `keri/Cargo.toml` contains no `"internals"`/`"test-utils"` literal).

- [ ] **Step 2: Fix any clippy findings** — most likely: `as_conversions` in production (convert to `try_from`/`From`), `missing_docs` on new public items, `cognitive-complexity` in `validate` (extract helpers if a fn exceeds threshold 9 / 80 lines).

- [ ] **Step 3: Final commit**

```bash
git commit -m "feat(#87): K1 KeyState + pure key-state fold — full gate green"
```

---

## Self-review

**1. Spec coverage:**
- `KeyState` value type, Cow-backed, typed getters, no `String` API → Phase 3 (Task 3.1). ✔ (Refinement: `prefix` field is `Identifier<'a>`, not `Prefixer<'a>`, to hold self-addressing prefixes — recorded in Task 4.4; **update the design doc's `KeyState` sketch to match**.)
- `validate`/`apply` pure fns → Phase 4–6. ✔
- `fold` convenience, caller owns stream → Task 4.1 Step 2. ✔
- Threshold satisfaction, simple + weighted, exact rational → Phase 1. ✔
- Next-key commitment via `crypto::digest` → Task 6.1. ✔
- `Rejection` + placeholder `RejectionReason` (`#[non_exhaustive]`) → Phase 2. ✔
- Remove old `cesr::keri::KeyState` (breaking, CHANGELOG) → Task 0.1. ✔
- Property tests → Task 1.3 (threshold); sequence/round-trip → Phase 7; boundary → Task 7.2; differential → Phase 8; no_std/wasm → Phase 9. ✔
- Trust boundary documented on `validate` → Task 4.1 doc comment. ✔

**2. Placeholder scan:** The per-ilk stubs in Task 4.1 Step 3 are explicit interim returns (not `todo!`), replaced in Tasks 4.3–6.2. The `expect`/`unreachable` sketches in Tasks 4.4/5.1 are explicitly flagged for the "narrow-in-`fold::apply`" refactor that removes them. The keripy vector (Task 8.1) has a concrete generation path + hand-author fallback. No `TBD`.

**3. Type consistency:** `satisfied_by(&Tholder, &[u32]) -> bool` used identically in inception/interaction/rotation. `Accepted { event, resolved_witnesses }` consistent across all three apply paths. `signed_indices(&[Siger]) -> Vec<u32>` shared. `RejectionReason` variants referenced in tests all exist in Phase 2. The Task 4.4 refactor (narrow the `KeriEvent` variant once in `fold::{validate,apply}`, pass the inner event to each ilk fn) is applied uniformly to inception/interaction/rotation — implement it there before Phase 5/6 to keep signatures consistent.

**Two spec refinements to fold back into the design doc during Task 0.1's commit or a follow-up docs edit:**
1. `KeyState.prefix` is `Identifier<'a>` (not `Prefixer<'a>`).
2. `apply` narrows the event variant in `fold::apply` and passes the inner event to each ilk's `apply`, so no ilk `apply` contains an unreachable arm.
