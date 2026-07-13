# serder Domain Redesign Rungs 1–3 Implementation Plan (#171)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the first three rungs of the #171 serder domain redesign — `Toad` + typed errors (rung 1), `SequenceNumber` (rung 2), `ThresholdForm` closing #168 (rung 3) — as three independently-green PRs, without changing a single wire byte except where #168's tracked reds flip green.

**Architecture:** Domain types move into `cesr::keri` with owned invariants and their own `thiserror` enums; `cesr::serder` bridges them via `#[from]` variants and consumes them in the parser conversion layer, both writer backends, and the builders. The #145 byte-identity corpora gate every rung. Spec: `docs/superpowers/specs/2026-07-13-serder-domain-redesign-design.md`.

**Tech Stack:** Rust 2024 (workspace crates `cesr-rs` + `keri-rs`), `thiserror`, `proptest`, `nix flake check` as the single gate, keripy corpus generators in Python 3.14 (local venv `~/Code/keripy/.venv`, keripy checkout at pin `de59bc7d`).

---

## Context for an engineer with zero repo history

- **The gate:** `nix flake check` only (clippy `all`+`pedantic`+`nursery` at deny + restriction suite, rustfmt, taplo, audit, deny, nextest across feature combos, doctests, wasm, no_std). Fast dev loops may use `nix develop --command cargo nextest run -p <crate> --all-features` and `cargo clippy -p <crate> --all-features --all-targets`, but the gate before each PR is `nix flake check` on COMMITTED state (it snapshots the git tree; dirty-tree runs are vacuous).
- **Byte-identity is law:** `cesr/src/keripy_parity/` replays keripy-generated corpora (`cesr/tests/corpus/keripy/parity/*.jsonl`); `keri/tests/differential.rs` replays `keri/tests/corpus/{keystate,kels}.jsonl`. Rungs 1–2 must not change any output byte. Rung 3 changes bytes ONLY for the two intive vectors (which currently don't round-trip at all).
- **Import rules (enforced by commit hooks):** all `use` at top of file; no inline `use`; no fully-qualified construction (`crate::x::Y::new()`) in bodies; `as` aliases on collision. Every `#[allow]` carries a `reason` on a specific item.
- **Error rules:** `thiserror` everywhere; one variant = one failure domain; never `|_|` — preserve sources with `#[source]`/`#[from]`; a keri-domain type returns its own keri-domain error, and `SerderError` bridges with `#[from]`.
- **Breaking changes are fine** (pre-1.0 active development) but never accidental: each rung's PR body lists them, and each crate's `CHANGELOG.md` gets an entry (check whether the repo's CHANGELOGs are release-plz-generated — `cesr/CHANGELOG.md` header says generated; if so, the PR body + conventional-commit subject carries the breaking-change callout instead of hand-editing the CHANGELOG. Verify by reading the file header before editing; do NOT hand-edit a generated changelog).
- **Feature gates:** the `keri` module is gated by feature `keri`; new files there compile under `no_std`+`alloc` — use `alloc::` imports (`use alloc::vec::Vec;`) exactly as sibling files (`cesr/src/keri/config.rs`) do, never `std::` in `cesr/src/keri/`.
- **PR flow per rung:** branch off latest `origin/main`, land, merge (squash), next rung branches off the new main. Rung 1 reuses the existing `171-serder-domain-redesign` branch (it already carries the spec + this plan).

### Current-state map (verified 2026-07-13)

| Surface | Location |
|---|---|
| `ample()` free fn + tests | `cesr/src/serder/ample.rs` (whole file moves into `Toad`) |
| `validate_toad` | `cesr/src/serder/builder/witness.rs:80+` (absorbed by `Toad::exact`) |
| `validate_distinct`, `validate_rotation_witnesses` | `cesr/src/serder/builder/witness.rs` (stringly errors → typed) |
| `majority()`, `validate_threshold`, `dummy_saider`, `dummy_prefixer` | `cesr/src/serder/builder.rs` |
| Builder `build()` bodies | `cesr/src/serder/builder/{icp,rot,ixn,dip,drt}.rs` |
| `SerderError` (incl. `Validation(String)`) | `cesr/src/serder/error.rs:120` |
| Event structs (`witness_threshold: u32`, `sn: Seqner`) | `cesr/src/keri/event/{inception,rotation,interaction,delegation}.rs` |
| Seals (`s: Seqner` in `Source`/`Event`) | `cesr/src/keri/seal.rs:27,36` |
| Parser conversion layer (`tholder_from_parsed`, `witness_threshold_from_parsed`, seal/sn conversion) | `cesr/src/serder/deserialize.rs:245-296+` |
| Wire-form capture (`ParsedTholder::{Hex,Number,Weighted}`, `ParsedCount::{Hex,Number}`) | `cesr/src/serder/deserialize/canonical.rs:40-58` |
| Writer backends | `cesr/src/serder/serialize/{icp,rot,ixn,dip,drt}.rs` (SerdeJson path) + `cesr/src/serder/serialize/direct.rs` (DirectJson) |
| `sn_to_hex` | `cesr/src/serder/primitives.rs:42` |
| keri-rs fold (compile-through only this plan) | `keri/src/state.rs` (`witness_threshold: u32`, `sn: Seqner`, `EstablishmentRef.sn`) |
| intive tracked reds | `cesr/src/keripy_parity/events.rs` (`TRACKED`, `#[ignore]`d probe, not-stale guard) + corpus rows `reserialize:"blocked"` + generator `blocked=True` (`scripts/keripy_events_gen.py`) |
| #145 intive fixtures (exact keripy bytes) | corpus rows `icp_intive` / `rot_intive` in `cesr/tests/corpus/keripy/parity/events.jsonl` |

---

# RUNG 1 — `Toad` + typed errors

Branch: continue on `171-serder-domain-redesign` (already contains spec + plan).

### Task 1: `keri::Toad` with `ToadError`

**Files:**
- Create: `cesr/src/keri/toad.rs`
- Modify: `cesr/src/keri/mod.rs` (add `mod toad;` + `pub use`)

- [ ] **Step 1: Write the new type with its tests** (TDD note: the file lands with tests in the same commit; run them before wiring any consumer)

Create `cesr/src/keri/toad.rs`. Content — port the arithmetic verbatim from `cesr/src/serder/ample.rs:19-44` (read it first; the checked-arithmetic shape is proven) and the invariant from `witness.rs::validate_toad`:

```rust
//! Witness threshold (TOAD) — the KERI witness-agreement domain type.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;

/// Witness agreement threshold (keripy: TOAD, "threshold of accountable
/// duplicity").
///
/// Owns the invariants keripy enforces in `incept()`/`rotate()` at pin
/// `de59bc7d` (`eventing.py`): `0` iff the witness set is empty, otherwise
/// `1..=witness_count`. Constructed via [`Toad::ample`] (BFT default),
/// [`Toad::exact`] (validated), or [`Toad::from_wire`] (unvalidated — for
/// rotation parsing, where the governing witness set is unknowable from the
/// event body alone and the fold validates instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Toad(u32);

/// Violations of the TOAD domain rules.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ToadError {
    /// Threshold outside `1..=witness_count` (or nonzero with no witnesses).
    #[error("witness threshold {toad} out of range for {witnesses} witnesses")]
    OutOfRange {
        /// The rejected threshold value.
        toad: u32,
        /// The governing witness-set size.
        witnesses: usize,
    },
    /// The computed or supplied threshold exceeds the KERI `bt` field's u32
    /// range.
    #[error("witness threshold for {witnesses} witnesses exceeds the u32 range")]
    Overflow {
        /// The governing witness-set size.
        witnesses: usize,
    },
}

impl Toad {
    /// BFT sufficient-majority default for `witness_count` witnesses.
    ///
    /// Port of keripy `ample(n, f=None, weak=True)`: for the maximum fault
    /// count `f` satisfying `n >= 3f + 1`, minimize `m` subject to
    /// `(n + f + 1) / 2 <= m <= n - f`; both floor and ceiling candidates
    /// for `f` are tried and the smaller `m` wins. Zero witnesses → 0.
    ///
    /// # Errors
    ///
    /// [`ToadError::Overflow`] when the threshold exceeds `u32::MAX`.
    pub fn ample(witness_count: usize) -> Result<Self, ToadError> {
        let Some(faultable) = witness_count.checked_sub(1) else {
            return Ok(Self(0));
        };
        let f_floor = (faultable / 3).max(1);
        let f_ceil = faultable.div_ceil(3).max(1);
        let m_floor = least_strong_majority(witness_count, f_floor)?;
        let m_ceil = least_strong_majority(witness_count, f_ceil)?;
        let threshold = witness_count.min(m_floor).min(m_ceil);
        u32::try_from(threshold)
            .map(Self)
            .map_err(|_| ToadError::Overflow {
                witnesses: witness_count,
            })
    }

    /// A caller-chosen threshold, validated against its governing witness set:
    /// `0` iff `witness_count == 0`, else `1..=witness_count`.
    ///
    /// # Errors
    ///
    /// [`ToadError::OutOfRange`] when the rule is violated.
    pub fn exact(toad: u32, witness_count: usize) -> Result<Self, ToadError> {
        let valid = if witness_count == 0 {
            toad == 0
        } else {
            toad >= 1 && (toad as usize) <= witness_count
        };
        if valid {
            Ok(Self(toad))
        } else {
            Err(ToadError::OutOfRange {
                toad,
                witnesses: witness_count,
            })
        }
    }

    /// A threshold read off the wire without set-size validation.
    ///
    /// Rotation events carry only witness deltas (`br`/`ba`), so the
    /// governing set size is unknowable at parse time; the key-state fold
    /// validates against the resolved set instead. Performs NO validation.
    #[must_use]
    pub const fn from_wire(toad: u32) -> Self {
        Self(toad)
    }

    /// The threshold value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Least `m` satisfying the strong-majority lower bound
/// `m >= (n + f + 1) / 2` for `f` faulty witnesses out of `n`.
fn least_strong_majority(n: usize, f: usize) -> Result<usize, ToadError> {
    n.checked_add(f)
        .and_then(|sum| sum.checked_add(1))
        .map(|sum| sum.div_ceil(2))
        .ok_or(ToadError::Overflow { witnesses: n })
}
```

Note `toad as usize`: this is a widening u32→usize cast on 32/64-bit targets, but clippy's restriction suite may deny `as` — use `usize::try_from(toad).is_ok_and(|t| t <= witness_count)` combined with `toad >= 1` if `cast_lossless`/`as_conversions` fires. Adjust to whatever the lint demands; the invariant is the spec, not the exact expression.

Then move the ENTIRE test module from `cesr/src/serder/ample.rs:46-161` into `toad.rs`'s `#[cfg(test)] mod tests`, adapting `ample(n).unwrap()` → `Toad::ample(n).unwrap().value()` and the two overflow tests to `ToadError::Overflow` (`assert!(matches!(err, ToadError::Overflow { .. }))`). Keep the keripy-oracle proptest and the exhaustive 0..=256 sweep verbatim. ADD boundary tests for `exact`:

```rust
    #[test]
    fn exact_zero_witnesses_accepts_only_zero() {
        assert_eq!(Toad::exact(0, 0).unwrap().value(), 0);
        assert_eq!(
            Toad::exact(1, 0).unwrap_err(),
            ToadError::OutOfRange { toad: 1, witnesses: 0 }
        );
    }

    #[test]
    fn exact_bounds_are_one_to_count_inclusive() {
        assert_eq!(
            Toad::exact(0, 3).unwrap_err(),
            ToadError::OutOfRange { toad: 0, witnesses: 3 }
        );
        assert_eq!(Toad::exact(1, 3).unwrap().value(), 1);
        assert_eq!(Toad::exact(3, 3).unwrap().value(), 3);
        assert_eq!(
            Toad::exact(4, 3).unwrap_err(),
            ToadError::OutOfRange { toad: 4, witnesses: 3 }
        );
    }
```

- [ ] **Step 2: Wire the module and run the new tests**

In `cesr/src/keri/mod.rs`: add `mod toad;` alongside the existing module list and `pub use toad::{Toad, ToadError};` following the file's existing re-export style (read the file; mirror how `config`/`seal` are exposed).

Run: `nix develop --command cargo nextest run -p cesr-rs --all-features toad`
Expected: all new tests PASS. (`serder::ample` still exists and passes — deleted in Task 2.)

- [ ] **Step 3: Commit**

```bash
git add cesr/src/keri/toad.rs cesr/src/keri/mod.rs
git commit -m "feat(keri): Toad witness-threshold domain type with owned invariants (#171)"
```

### Task 2: adopt `Toad` across events, builders, parser, writers; delete `ample.rs` + `validate_toad`

**Files:**
- Modify: `cesr/src/keri/event/inception.rs` (field, `new()`, accessor)
- Modify: `cesr/src/keri/event/rotation.rs` (same)
- Modify: `cesr/src/serder/error.rs` (add `#[from] ToadError` variant)
- Modify: `cesr/src/serder/builder.rs`, `cesr/src/serder/builder/{icp,rot,dip,drt}.rs`, `cesr/src/serder/builder/witness.rs`
- Modify: `cesr/src/serder/deserialize.rs`
- Modify: `cesr/src/serder/serialize/{icp,rot,dip,drt}.rs`, `cesr/src/serder/serialize/direct.rs`
- Modify: `keri/src/state.rs` (mechanical compile-through)
- Delete: `cesr/src/serder/ample.rs` (and its `mod ample;` in `cesr/src/serder/mod.rs`)

- [ ] **Step 1: Event structs carry `Toad`**

In `inception.rs` and `rotation.rs`: change field `witness_threshold: u32` → `witness_threshold: Toad`, the `new()` parameter likewise, and the accessor to

```rust
    /// Witness agreement threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> Toad {
        self.witness_threshold
    }
```

Add `use crate::keri::toad::Toad;` (or the crate-relative path matching sibling imports) at top. Update the in-file `#[cfg(test)]` constructions (`inception.rs:185` passes `1,` — becomes `Toad::exact(1, 1).unwrap(),`; check rotation.rs tests likewise).

- [ ] **Step 2: Bridge `ToadError` into `SerderError`**

In `cesr/src/serder/error.rs`, replace nothing yet — ADD:

```rust
    /// Witness-threshold domain rule violated.
    #[error(transparent)]
    Toad(#[from] ToadError),
```

with `use crate::keri::toad::ToadError;` at top. (The `Validation(String)` variant dies in Task 3.)

- [ ] **Step 3: Builders construct `Toad`**

In each establishment builder's `build()` (`icp.rs:220-226` pattern, mirrored in `dip.rs:211-216`, `rot.rs:291-295`, `drt.rs:298-302`): the setter keeps its `u32` parameter (callers don't know the resolved set size — validation belongs at `build()`), and the resolution becomes:

```rust
        let witness_threshold = match self.witness_threshold {
            Some(explicit) => Toad::exact(explicit, self.witnesses.len())?,
            None => Toad::ample(self.witnesses.len())?,
        };
```

(for rot/drt the count is the `validate_rotation_witnesses(...)?` post-set count already in scope as `witness_count`). Delete the now-redundant `validate_toad(...)` calls and the `validate_toad` fn in `witness.rs`; delete `use` of `ample` and add `use crate::keri::toad::Toad;`. The `?` works via the Task 2 Step 2 `#[from]`.

- [ ] **Step 4: Parser constructs `Toad`**

In `cesr/src/serder/deserialize.rs`: `witness_threshold_from_parsed` keeps returning the raw `u32` (rename it `witness_threshold_wire`); at the icp/dip event-construction sites pass `Toad::exact(bt, witnesses.len())?` (the parsed `b` array length), and at rot/drt sites `Toad::from_wire(bt)`. Find every `InceptionEvent::new(`/`RotationEvent::new(` call in this file and thread the right constructor. keripy never emits an out-of-range icp toad, so the corpora stay green; hand-crafted invalid input now gets a typed rejection.

- [ ] **Step 5: Writers render through `.value()`**

Both backends currently render bt via `sn_to_hex(u128::from(event.witness_threshold()))` (`direct.rs:127,170`; `serialize/icp.rs:51`, `serialize/rot.rs:48`, dip/drt equivalents). Change to `sn_to_hex(u128::from(event.witness_threshold().value()))`. Output bytes identical.

- [ ] **Step 6: keri-rs compiles through**

`keri/src/state.rs`: `KeyState.witness_threshold` stays `u32`; at the two seed/rotate sites reading events (`state.rs:225` `icp.witness_threshold()` and the rot equivalent) append `.value()`. `check_witness_threshold(...)` keeps its `u32` signature. (Full `Toad` adoption in the fold is the spec's follow-on card, not this plan.)

- [ ] **Step 7: Delete `ample.rs`, run the full test sweep**

Remove `cesr/src/serder/ample.rs`, its `mod`/`pub use` in `cesr/src/serder/mod.rs` (rg for `ample` to catch doc references — builder doc comments at `icp.rs:159`, `dip.rs:149` say "default: `ample(witnesses.len())`"; update to "default: `Toad::ample(witnesses.len())`").

Run:
```bash
nix develop --command cargo nextest run --workspace --all-features 2>&1 | tail -5
nix develop --command cargo clippy --workspace --all-features --all-targets 2>&1 | tail -3
```
Expected: everything passes (byte-identity suites untouched: `keripy_parity`, `differential`). Zero clippy warnings.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(serder)!: events and builders adopt keri::Toad; ample() absorbed (#171)

BREAKING: InceptionEvent/RotationEvent::new take Toad; witness_threshold()
returns Toad; serder::ample removed (use keri::Toad::ample)."
```

### Task 3: delete `SerderError::Validation(String)` — typed variants

**Files:**
- Modify: `cesr/src/serder/error.rs`
- Modify: `cesr/src/serder/builder.rs`, `cesr/src/serder/builder/{icp,rot,ixn,dip,drt,witness}.rs` (all `Validation(` sites + their tests)

- [ ] **Step 1: Survey every remaining `Validation(` site**

Run: `rg -n "Validation\(" cesr/src/ --type rust`
Expected sites (verified at plan time; the survey is the source of truth if drift occurred): `witness.rs` (duplicates, cut/add relations, count overflow), builder `build()`s ("keys must not be empty", "prefix is required", "prior_event_said is required", "delegator is required"), `builder.rs` (`majority` overflow, `validate_threshold` bounds, `dummy_saider`/`dummy_prefixer` `map_err(|e| ... e.to_string())`), plus the tests matching `Validation(msg)`.

- [ ] **Step 2: Replace the variant with typed ones**

In `error.rs`, DELETE `Validation(String)` and ADD:

```rust
    /// A builder terminal-state field that must be set before `build()`.
    #[error("builder field `{0}` is required")]
    MissingBuilderField(&'static str),

    /// A key list that must be non-empty.
    #[error("`{0}` must not be empty")]
    EmptyKeys(&'static str),

    /// A prefix list carrying duplicate entries.
    #[error("`{0}` must not contain duplicates")]
    DuplicatePrefixes(&'static str),

    /// A rotation witness removal that is not a prior witness.
    #[error("witness removals must all be prior witnesses")]
    RemovalNotPriorWitness,

    /// A rotation witness addition that is already a prior witness.
    #[error("witness additions must not already be prior witnesses")]
    AdditionAlreadyWitness,

    /// Overlapping rotation witness removals and additions.
    #[error("witness removals and additions must be disjoint")]
    RemovalAdditionOverlap,

    /// Post-rotation witness count exceeds addressable size.
    #[error("post-rotation witness count overflows usize")]
    WitnessCountOverflow,

    /// A signing threshold outside `1..=key_count` (or the weighted-clause
    /// arity mismatch), for the named threshold field.
    #[error("{field} threshold out of range for {keys} keys")]
    SigningThresholdOutOfRange {
        /// Which threshold: "signing" or "next signing".
        field: &'static str,
        /// The governing key-set size.
        keys: usize,
    },

    /// Majority computation exceeded the threshold value range.
    #[error("majority for {keys} keys exceeds the threshold range")]
    MajorityOverflow {
        /// The governing key-set size.
        keys: usize,
    },

    /// A dummy/placeholder primitive failed to construct — an internal
    /// invariant, never input-dependent.
    #[error("placeholder primitive construction failed: {source}")]
    PlaceholderPrimitive {
        /// The underlying matter-construction error.
        #[source]
        source: ValidationError,
    },
```

IMPORTANT: before finalizing variant shapes, read `builder.rs::validate_threshold` and `majority` to capture exactly what each rejects — if `validate_threshold` distinguishes more cases (e.g. weighted clause length vs numeric bound), keep ONE variant per distinct failure with the data that names it; the list above is the target taxonomy, refine field payloads to match reality. `dummy_saider`'s `map_err` currently stringifies a `MatterBuildError`-family error — check its actual error type (`rg -n "fn dummy_saider" -A 8 cesr/src/serder/builder.rs`) and give `PlaceholderPrimitive.source` that exact type instead of `ValidationError` if it differs.

- [ ] **Step 3: Update every construction site and every test**

Mechanical sweep per the Step 1 survey. Tests currently doing `let Err(SerderError::Validation(msg)) = ... ; assert!(msg.contains("duplicates"))` become direct variant matches: `assert!(matches!(err, SerderError::DuplicatePrefixes("witnesses")))` — this is the repo's stated test style (match the enum, never stringify). Every test keeps asserting the SAME rejection it did before, just typed.

- [ ] **Step 4: Verify no stringly residue and run the sweep**

```bash
rg -n "Validation\(" cesr/src/ --type rust        # expect: no hits
nix develop --command cargo nextest run -p cesr-rs --all-features 2>&1 | tail -4
nix develop --command cargo clippy -p cesr-rs --all-features --all-targets 2>&1 | tail -3
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(serder)!: replace Validation(String) with typed error variants (#171)

BREAKING: SerderError::Validation removed; one typed variant per builder
failure domain, sources preserved."
```

### Task 4: rung-1 gate + PR

- [ ] **Step 1: Gate on committed state**

```bash
git status --porcelain          # must be empty
nix flake check 2>/tmp/gate-r1.log; echo "GATE_EXIT=$?"
```
Expected `GATE_EXIT=0`. Never pipe the gate through head/tail; read the log file on failure.

- [ ] **Step 2: Push + PR**

```bash
git push -u origin 171-serder-domain-redesign
gh pr create --repo devrandom-labs/cesr --base main \
  --title "refactor(serder)!: rung 1 — keri::Toad + typed builder errors (#171)" \
  --body "Rung 1 of #171 (spec: docs/superpowers/specs/2026-07-13-serder-domain-redesign-design.md, committed here).

- New \`cesr::keri::Toad\` owns the TOAD invariants (ample formula + the
  0-iff-no-witnesses / 1..=n rule keripy enforces): \`serder::ample()\` and
  \`validate_toad\` are absorbed and deleted.
- Events/builders/parser/writers speak \`Toad\`; rot/drt parse via
  \`Toad::from_wire\` (governing set unknowable from deltas; fold validates).
- \`SerderError::Validation(String)\` deleted — one typed variant per failure
  domain, sources preserved.

## Breaking
- \`InceptionEvent::new\`/\`RotationEvent::new\` signatures (internals feature)
- \`witness_threshold()\` returns \`Toad\`
- \`serder::ample\` removed; \`SerderError::Validation\` removed (typed variants added)

Wire bytes unchanged: full #145 byte-identity + fold corpora green.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --repo devrandom-labs/cesr --watch
```
Merge (squash) once green, then `git checkout main && git pull`.

---

# RUNG 2 — `SequenceNumber`

Branch: `git fetch origin main && git checkout -b 171-sequence-number origin/main`

### Task 5: `keri::SequenceNumber`

**Files:**
- Create: `cesr/src/keri/sequence.rs`
- Modify: `cesr/src/keri/mod.rs`

- [ ] **Step 1: Write the type + tests**

```rust
//! Event sequence number — hex-rendered ordinal, not a CESR primitive.

use core::fmt;

/// A KERI event sequence number.
///
/// In the event body (`s`) and in seal fields (`Seal::Source.s`,
/// `Seal::Event.s`) this renders as minimal lowercase hex — keripy's
/// `Number(num=n).numh` — never as a qb64 primitive. The CESR `Seqner`
/// Matter remains in `cesr::core` for genuinely qb64 contexts (streams,
/// receipts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNumber(u128);

impl SequenceNumber {
    /// Wrap an ordinal.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The ordinal value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for SequenceNumber {
    /// Minimal lowercase hex; zero renders as `"0"`, never empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn displays_minimal_lowercase_hex() {
        assert_eq!(SequenceNumber::new(0).to_string(), "0");
        assert_eq!(SequenceNumber::new(1).to_string(), "1");
        assert_eq!(SequenceNumber::new(10).to_string(), "a");
        assert_eq!(SequenceNumber::new(255).to_string(), "ff");
        assert_eq!(
            SequenceNumber::new(u128::MAX).to_string(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(SequenceNumber::new(2) < SequenceNumber::new(10));
    }
}
```

Wire `mod sequence;` + `pub use sequence::SequenceNumber;` in `cesr/src/keri/mod.rs`.

Run: `nix develop --command cargo nextest run -p cesr-rs --all-features sequence` → PASS.

- [ ] **Step 2: Commit**

```bash
git add cesr/src/keri/sequence.rs cesr/src/keri/mod.rs
git commit -m "feat(keri): SequenceNumber domain type — hex-rendered event ordinal (#171)"
```

### Task 6: adopt `SequenceNumber` in events, seals, parser, writers; shrink `sn_to_hex`

**Files:**
- Modify: `cesr/src/keri/event/{inception,rotation,interaction}.rs` (`sn: Seqner` → `sn: SequenceNumber`; accessor returns `SequenceNumber` by value)
- Modify: `cesr/src/keri/seal.rs` (`Source.s`, `Event.s`: `Seqner` → `SequenceNumber`)
- Modify: `cesr/src/serder/deserialize.rs` (+ possibly `deserialize/reference.rs`) — construct `SequenceNumber::new(parsed)` where `Seqner::new` was used for events/seals
- Modify: `cesr/src/serder/serialize/{icp,rot,ixn,dip,drt}.rs`, `direct.rs` — render `event.sn().to_string()` / write via `Display`; seal `s` fields likewise
- Modify: `cesr/src/serder/builder/*.rs` — `Seqner::new(0)` → `SequenceNumber::new(0)` etc.; `.sn(u128)` setters construct `SequenceNumber`
- Modify: `cesr/src/serder/primitives.rs` — `sn_to_hex` doc updated: it now serves ONLY the `bt` field (deleted at rung 3)
- Modify: `keri/src/state.rs` — `sn: Seqner` → `sn: SequenceNumber` (both `KeyState` and pub `EstablishmentRef.sn`), `Seqner::new(0)` sites, import swap; `.value()` call sites unchanged in shape
- Modify: `keri/tests/*.rs` + `cesr` tests constructing events with `Seqner::new`

- [ ] **Step 1: Sweep the type through**

Do the mechanical swap per the file list. Discovery commands (run BEFORE editing so nothing is missed, and re-run after — both must go to zero for event/seal contexts):

```bash
rg -n "Seqner" cesr/src/keri/ cesr/src/serder/ keri/src/ keri/tests/
```
`Seqner` legitimately remains ONLY in `cesr/src/core/` and any stream/receipt code — event/seal/serder/fold contexts all move to `SequenceNumber`. The seal JSON rendering sites are `direct.rs:309,318` (`sn_to_hex(s.value())` → `write_str(buf, &s.to_string())`) and the SerdeJson seal path in `serialize.rs::seal_to_json` (same substitution). Event `s` fields: `sn_to_hex(e.sn().value())` → `e.sn().to_string()` at `direct.rs:117,158,196` and the five SerdeJson renderers.

- [ ] **Step 2: Full sweep + byte-identity check**

```bash
nix develop --command cargo nextest run --workspace --all-features 2>&1 | tail -5
nix develop --command cargo clippy --workspace --all-features --all-targets 2>&1 | tail -3
```
Expected: all green — in particular `keripy_parity::events` (26-vector byte identity), `said_codes`, `seal_events`, and both keri-rs differential fold tests. These prove sn/seal rendering emitted identical bytes.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "refactor(keri,serder)!: events and seals carry SequenceNumber, not Seqner (#171)

BREAKING: event sn()/Seal::{Source,Event}.s are SequenceNumber; keri-rs
EstablishmentRef.sn likewise. Wire bytes unchanged."
```

### Task 7: rung-2 gate + PR

- [ ] **Step 1: Gate** — `git status --porcelain` empty, then `nix flake check 2>/tmp/gate-r2.log; echo "GATE_EXIT=$?"` → 0.

- [ ] **Step 2: Push + PR + merge**

```bash
git push -u origin 171-sequence-number
gh pr create --repo devrandom-labs/cesr --base main \
  --title "refactor(keri,serder)!: rung 2 — SequenceNumber domain type (#171)" \
  --body "Rung 2 of #171: events and seals carry \`keri::SequenceNumber\` (hex-rendered ordinal) instead of the CESR \`Seqner\` Matter — the event body never rendered sn as qb64, so the Matter there was a layering mismatch. \`Seqner\` remains in core for qb64 contexts. \`sn_to_hex\` now serves only \`bt\` (dies at rung 3).

## Breaking
- Event \`sn()\` and \`Seal::{Source,Event}.s\` types; \`new()\` signatures (internals)
- keri-rs: \`KeyState\`/\`EstablishmentRef\` sn types

Wire bytes unchanged: #145 byte-identity + fold corpora green.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --repo devrandom-labs/cesr --watch
```
Merge (squash), `git checkout main && git pull`.

---

# RUNG 3 — `ThresholdForm` (closes #168)

Branch: `git fetch origin main && git checkout -b 171-threshold-form origin/main`

### Task 8: `keri::ThresholdForm` + event field

**Files:**
- Create: `cesr/src/keri/threshold_form.rs`
- Modify: `cesr/src/keri/mod.rs`
- Modify: `cesr/src/keri/event/{inception,rotation}.rs`

- [ ] **Step 1: The enum**

```rust
//! Wire encoding of numeric threshold fields (keripy's `intive` flag).

/// How an establishment event's numeric threshold fields (`kt`/`nt`/`bt`)
/// are rendered on the wire.
///
/// keripy's `incept()`/`rotate()` take a single `intive` flag per event:
/// `False` (default) renders numeric thresholds as hex strings
/// (`"kt":"2"`, `"bt":"0"`); `True` renders them as JSON integers
/// (`"kt":2`, `"bt":1`) when the value fits `MaxIntThold = 2^32 - 1`.
/// Weighted thresholds are always arrays regardless of form. Mixed forms
/// are not in keripy's output language; the strict parser rejects them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ThresholdForm {
    /// Hex-string rendering (`"kt":"2"`) — keripy `intive=False`, the default.
    #[default]
    HexString,
    /// JSON-integer rendering (`"kt":2`) — keripy `intive=True`.
    Integer,
}
```

(Unit tests for a two-variant fieldless enum would be assertion-free ceremony; the behavior is tested end-to-end in Task 9/10 through parse/render/round-trip.)

Wire into `cesr/src/keri/mod.rs` (`mod threshold_form;` + `pub use`).

- [ ] **Step 2: Events carry it**

`InceptionEvent`/`RotationEvent`: add field `threshold_form: ThresholdForm`, a `new()` parameter (keep parameter order: append after `anchors`/last current param — pick one order and use it consistently in BOTH structs and ALL call sites), and accessor:

```rust
    /// Wire encoding of the numeric threshold fields (keripy `intive`).
    #[must_use]
    pub const fn threshold_form(&self) -> ThresholdForm {
        self.threshold_form
    }
```

Delegated events inherit through `.inception()`/`.rotation()` — no change in `delegation.rs`. `InteractionEvent` has no thresholds — untouched. Update in-file tests (`ThresholdForm::HexString` at existing constructions).

- [ ] **Step 3: Compile-fix all `new()` call sites, run sweep, commit**

`rg -n "InceptionEvent::new|RotationEvent::new" cesr/ keri/` — thread `ThresholdForm::HexString` everywhere for now (parser/builder wire-up is Task 9; bytes unchanged).

```bash
nix develop --command cargo nextest run --workspace --all-features 2>&1 | tail -4
git add -A
git commit -m "feat(keri): ThresholdForm on establishment events (keripy intive) (#171)"
```

### Task 9: parser inference + builder knob + writer rendering

**Files:**
- Modify: `cesr/src/serder/deserialize.rs`
- Modify: `cesr/src/serder/error.rs` (one new variant)
- Modify: `cesr/src/serder/builder/{icp,rot,dip,drt}.rs`
- Modify: `cesr/src/serder/serialize.rs` (SerdeJson threshold/bt rendering), `cesr/src/serder/serialize/{icp,rot,dip,drt}.rs`, `cesr/src/serder/serialize/direct.rs`
- Modify: `cesr/src/serder/primitives.rs` (delete `sn_to_hex`)

- [ ] **Step 1: Failing test first — the #145 intive fixture round-trips**

In `cesr/src/serder/deserialize.rs`'s test module (or the module where existing round-trip tests live — match the file's structure), add a test that feeds the EXACT keripy intive icp bytes. Pull them from the corpus so they're provably keripy's (the corpus row `icp_intive` in `cesr/tests/corpus/keripy/parity/events.jsonl` carries them in its `raw` field — copy the JSON string verbatim into the test as a raw string literal, with a comment citing the corpus row):

```rust
    #[test]
    fn intive_event_round_trips_byte_identically() {
        // keripy incept(..., intive=True) — corpus row `icp_intive`,
        // cesr/tests/corpus/keripy/parity/events.jsonl (pin de59bc7d).
        let raw: &str = /* paste the icp_intive `raw` value verbatim */;
        let event = deserialize_event(raw.as_bytes()).expect("intive icp reads");
        let re = serialize(&event).expect("intive icp writes");
        assert_eq!(re.as_bytes(), raw.as_bytes());
    }
```

Run: `nix develop --command cargo nextest run -p cesr-rs --all-features intive_event_round_trips` → FAIL (`"kt":"2"` vs `"kt":2`) — the #168 bug, reproduced at unit level.

- [ ] **Step 2: Parser inference**

In `deserialize.rs`'s conversion layer, derive the form from `bt` (the reliable signal — always present, always numeric-capable on icp/rot):

```rust
fn threshold_form_of(bt: &ParsedCount<'_>) -> ThresholdForm {
    match bt {
        ParsedCount::Hex(_) => ThresholdForm::HexString,
        ParsedCount::Number(_) => ThresholdForm::Integer,
    }
}

/// A simple-numeric kt/nt must agree with bt's form; weighted is exempt.
fn check_form_consistency(
    field: &'static str,
    t: &ParsedTholder<'_>,
    form: ThresholdForm,
) -> Result<(), SerderError> {
    let consistent = match (t, form) {
        (ParsedTholder::Weighted(_), _) => true,
        (ParsedTholder::Hex(_), ThresholdForm::HexString)
        | (ParsedTholder::Number(_), ThresholdForm::Integer) => true,
        _ => false,
    };
    if consistent {
        Ok(())
    } else {
        Err(SerderError::MixedThresholdForms { field })
    }
}
```

Add the variant to `error.rs`:

```rust
    /// Numeric threshold fields mixing integer and hex-string wire forms —
    /// not in keripy's output language (one `intive` flag per event).
    #[error("threshold field `{field}` wire form disagrees with `bt`")]
    MixedThresholdForms {
        /// The disagreeing field: "kt" or "nt".
        field: &'static str,
    },
```

At each icp/rot (and dip/drt inner) conversion site: compute the form from the parsed `bt` BEFORE converting, run `check_form_consistency("kt", ...)` and `("nt", ...)`, and pass the form into the event constructor. ALSO enforce keripy's `MaxIntThold`: an integer-form `kt`/`nt` parsing above `u32::MAX as u64` is not keripy-emittable (keripy falls back to hex above `2^32-1`, which would be mixed-form) — reject via `MixedThresholdForms` on that field (it IS a form disagreement: value demands hex, wire says integer).

- [ ] **Step 3: Writer rendering (BOTH backends — cross-backend proptest still gates until rung 5)**

SerdeJson path (`serialize.rs`): `tholder_to_json(tholder)` gains a form parameter — `tholder_to_json(tholder: &Tholder, form: ThresholdForm) -> Value`: `Simple(n)` renders `Value::String(format!("{n:x}"))` under `HexString` and `Value::Number(n.into())` under `Integer` (n ≤ u32::MAX is guaranteed by parse/build validation; debug-assert only, no silent cap); weighted unchanged. The five renderers pass `event.threshold_form()` (ixn has none). `bt`: replace the `sn_to_hex` call with a small `fn toad_json(toad: Toad, form: ThresholdForm) -> Value` — hex string or integer.

Direct path (`direct.rs`): `write_tholder(buf, tholder)` gains the form parameter — integer form writes the ASCII decimal WITHOUT quotes; hex form writes the quoted hex exactly as today. `bt` likewise (`write_str(...)` today at `:127,170` — becomes quoted-hex vs bare-decimal branch).

Delete `sn_to_hex` from `primitives.rs` (last consumer was `bt`).

- [ ] **Step 4: Builder knob**

Each establishment builder (icp/rot/dip/drt): field `threshold_form: ThresholdForm` (Default), chainable setter

```rust
    /// Render numeric `kt`/`nt`/`bt` as JSON integers (keripy `intive=True`)
    /// instead of hex strings.
    #[must_use]
    pub const fn threshold_form(mut self, form: ThresholdForm) -> Self {
        self.threshold_form = form;
        self
    }
```

and `build()` threads it into the event. Build-time validation: `Integer` form with `Tholder::Simple(n)` where `n > u64::from(u32::MAX)` → new error variant:

```rust
    /// A signing threshold too large for integer wire form
    /// (keripy `MaxIntThold = 2^32 - 1` falls back to hex, which cesr
    /// models as an explicit constraint instead of a silent form change).
    #[error("threshold {value} exceeds integer wire form range (2^32-1)")]
    IntegerFormOverflow {
        /// The oversized threshold value.
        value: u64,
    },
```

(`bt` is `Toad` = u32, always fits.)

- [ ] **Step 5: Unit tests green + builder emits intive**

Step 1's round-trip test now PASSES. Add the builder-side test in the icp builder test module — build a 2-of-3 witnessed event with `.threshold_form(ThresholdForm::Integer)` and assert the rendered bytes contain `"kt":2` and `"bt":1` unquoted (assert on exact substrings of `String::from_utf8_lossy(built.as_bytes())`), plus a `rot_intive`-fixture round-trip test mirroring Step 1. Add mixed-form rejection tests: take the intive fixture, flip only `"bt":1` to `"bt":"1"` (adjusting nothing else → kt stays integer → mixed), assert `MixedThresholdForms { field: "kt" }`.

Run: `nix develop --command cargo nextest run -p cesr-rs --all-features 2>&1 | tail -4` — note `keripy_parity::events::tracked_entries_are_not_stale` now FAILS (the tracked gap round-trips!) — that failure is the designed signal, resolved in Task 10. Everything else green.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(serder)!: ThresholdForm end-to-end — intive events round-trip (#168, #171)

Parser infers form from bt and rejects mixed forms; both writer backends
render kt/nt/bt by form; builders gain .threshold_form(). BREAKING:
event new() signatures (internals), tholder_to_json/write_tholder shapes."
```

### Task 10: flip the tracked reds — corpus, parity family, ledger

**Files:**
- Modify: `scripts/keripy_events_gen.py` (drop `blocked=True` + `blocked_by`)
- Modify: `cesr/tests/corpus/keripy/parity/events.jsonl` (regenerated)
- Modify: `cesr/src/keripy_parity/events.rs` (delete TRACKED machinery)
- Modify: `cesr/src/keripy_parity/mod.rs` (drop `blocked_by` field or keep with default — see step)
- Modify: `docs/keripy-parity/ledger.md` (intive subsection → resolved)

- [ ] **Step 1: Generator no longer marks intive blocked**

In `scripts/keripy_events_gen.py`: remove `blocked=True` from the `icp_intive` and `rot_intive` `add(...)` calls, remove the `blocked` parameter/`blocked_by` emission machinery entirely (no rows use it anymore — keep the schema field OUT rather than always-empty), and update the module docstring sentence about `reserialize="blocked"` to state all rows must round-trip. Regenerate:

```bash
DYLD_LIBRARY_PATH="$(nix build --no-link --print-out-paths nixpkgs#libsodium)/lib" \
  ~/Code/keripy/.venv/bin/python scripts/keripy_events_gen.py \
  --keripy ~/Code/keripy --out cesr/tests/corpus/keripy/parity \
  --kels-out keri/tests/corpus/kels.jsonl
git diff --stat cesr/tests/corpus/keripy/parity/events.jsonl   # only the 2 intive rows change
```

- [ ] **Step 2: Parity family drops the tracked-red machinery**

In `cesr/src/keripy_parity/events.rs`: delete `TRACKED`, `tracked_issue`, the blocked-branch in the byte-identity sweep (every row now round-trips; `asserted` becomes 26 — update `assert_eq!(asserted, 26, ...)` and drop the `skipped` counter), delete `tracked_entries_are_not_stale`, and PROMOTE the `#[ignore]`d probe into the main sweep by deleting it (its rows are now covered by the sweep). Update the module doc: intive is no longer a gap; cite #168 as closed by this change. In `mod.rs`: the `EventVector.blocked_by` field and `reserialize` field — corpus rows now all say `"reserialize":"identical"`; keep `reserialize` and assert homogeneity in the sweep (`assert_eq!(v.reserialize, "identical")` per row — an anti-rot guard against a future generator re-introducing blocked rows without a Rust-side counterpart), and delete `blocked_by` (no longer emitted).

- [ ] **Step 3: Ledger tells the truth**

`docs/keripy-parity/ledger.md`, section "intive integer thresholds (tracked, #168)": rewrite to a short resolution note — `ThresholdForm` on establishment events closed #168 (rung 3 of #171); intive vectors assert byte-identity in the main sweep; mixed wire forms are rejected as non-canonical (this last clause is a live divergence-of-strictness statement and stays in the ledger).

- [ ] **Step 4: Full sweep**

```bash
nix develop --command cargo nextest run --workspace --all-features 2>&1 | tail -4
nix develop --command cargo clippy --workspace --all-features --all-targets 2>&1 | tail -3
```
Expected: ALL green, zero ignored tests in `keripy_parity::events`, sweep stderr `events: 26 asserted, 0 tracked`... (adjust the summary eprintln when deleting the skip machinery — no stale "#168" strings; `rg -n "168" cesr/src/keripy_parity/` should return only the module-doc historical citation, or nothing).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(diff): intive vectors join the byte-identity sweep — #168 closed (#171)"
```

### Task 11: rung-3 gate + PR

- [ ] **Step 1: Gate** — `git status --porcelain` empty; `nix flake check 2>/tmp/gate-r3.log; echo "GATE_EXIT=$?"` → 0.

- [ ] **Step 2: Push + PR**

```bash
git push -u origin 171-threshold-form
gh pr create --repo devrandom-labs/cesr --base main \
  --title "feat(serder)!: rung 3 — ThresholdForm closes the intive write gap (#168, #171)" \
  --body "Closes #168. Rung 3 of #171.

Establishment events carry \`ThresholdForm\` (keripy's per-event \`intive\`
flag): the strict parser infers it from \`bt\`'s wire form and rejects mixed
forms; both writer backends render \`kt\`/\`nt\`/\`bt\` from it; builders gain
\`.threshold_form()\`. The two intive corpus vectors now assert byte-identity
in the main sweep — TRACKED table, \`#[ignore]\`d probe, and not-stale guard
deleted; ledger updated.

## Breaking
- Event \`new()\` signatures (internals feature) gain ThresholdForm
- \`SerderError\` gains \`MixedThresholdForms\`/\`IntegerFormOverflow\`
- \`sn_to_hex\` removed

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --repo devrandom-labs/cesr --watch
```
Merge (squash). Post-merge: comment on #171 that rungs 1–3 are landed and rungs 4–6 (SigningThreshold #130, writer promotion, zero-copy #129) follow in a subsequent plan.

---

## Self-Review

**Spec coverage (rungs 1–3 sections of the spec):** Toad constructors/invariants → Task 1; ample absorption + event/builder/parser/writer adoption → Task 2; typed error split → Task 3; SequenceNumber incl. seals + `Seqner` stays in core → Tasks 5–6; ThresholdForm event field, bt-inference, mixed-form rejection, MaxIntThold, builder knob, both-backend rendering, #168 red-flip incl. generator/corpus/parity-family/ledger → Tasks 8–10; per-rung `nix flake check` + PR + breaking-change callouts → Tasks 4/7/11. keri-rs full vocabulary adoption is explicitly the spec's follow-on card, and this plan does only mechanical compile-through (Tasks 2.6, 6.1) — consistent.

**Placeholder scan:** the one deliberate gap is Task 9 Step 1's fixture paste (`/* paste the icp_intive raw value verbatim */`) — the exact bytes live in the corpus file the executor reads; copying them into the plan would risk drift with a regenerated corpus, so the plan points at the authoritative source instead. Task 3 Step 2 explicitly instructs refining variant payloads against `builder.rs` reality rather than trusting the plan's taxonomy — that is a survey instruction, not a placeholder.

**Type consistency:** `Toad::{ample,exact,from_wire,value}` used consistently in Tasks 1/2/9; `SequenceNumber::{new,value}` + `Display` in Tasks 5/6; `ThresholdForm::{HexString,Integer}` + `threshold_form()` accessor in Tasks 8/9/10; error variants named identically at definition (Tasks 3/9) and use sites.

**Known risks for the executor:**
- Clippy god-level will push back on cast idioms and `const fn` eligibility — fix the code to the lint, never relax lints.
- If any byte-identity test fails on rungs 1–2, the refactor changed rendering — STOP and diff the bytes; do not touch corpora or tests to make it pass.
- The `internals`-gated `new()` signatures change in every rung — each is a called-out breaking change, and `keri/tests/common/mod.rs` (fixture builders) likely constructs events via builders or `new()`; sweep it on every rung.
