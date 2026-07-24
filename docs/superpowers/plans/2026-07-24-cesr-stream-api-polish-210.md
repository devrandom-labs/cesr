# cesr-stream API polish (#210) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the four medium-severity `cesr-stream` API-surface findings from #210: collapse the duplicated group iterator, rename a keripy-contraction method, honest copy-once docs, rename the qb2 conversion pair.

**Architecture:** Four independent, mostly-mechanical changes on branch `devx/210-cesr-stream-api-polish` (already cut from `origin/main`, spec committed). Each finding is one task = one commit. The existing round-trip / boundary tests are the safety net; renames keep them green after call-site updates, and the iterator collapse adds a parity test proving `Groups::<V1>`/`Groups::<V2>` reproduce the old two-struct behavior.

**Tech Stack:** Rust 2024, `bytes::Bytes`, sealed `Version`/`V1`/`V2` phantom-type markers (crates/cesr-stream/src/version.rs), `thiserror`. no_std/WASM-capable.

**Design spec:** `docs/superpowers/specs/2026-07-24-cesr-stream-api-polish-210-design.md`

## Verification policy

- **Dev loop (fast, NOT verification of record):** a subagent may run
  `nix develop --command cargo nextest run -p cesr-stream` (and `-p keri-codec`
  where touched) for quick feedback while iterating.
- **Verification of record:** the FINAL gate task runs `nix flake check` — the
  single source of truth (clippy, fmt, taplo, audit, deny, nextest across
  feature combos, doctest, wasm, no_std, version-owner + fn-ratchet tripwires).
  No task may claim "done/verified" from a bare `cargo` run.
- All import rules from CLAUDE.md apply: imports at top of file, no inline
  `use`, no fully-qualified construction paths.

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `crates/cesr-stream/src/qb2.rs` | qb64↔qb2 conversion | rename `qb2_to_qb64`→`to_text`, `qb64_to_qb2`→`from_text` (Task 1) |
| `crates/cesr-stream/src/keripy_diff/stream.rs` | keripy differential harness | call-site update for qb2 rename (Task 1) |
| `crates/cesr-stream/src/group/kinds.rs` | group-kind builders + tests | rename `from_sigers`→`from_indexed_signatures` (Task 2) |
| `crates/keri-codec/src/serialize.rs` | codec tests | call-site update for `from_sigers` rename (Task 2) |
| `crates/cesr-stream/src/group/mod.rs` | group types + `Groups` iterator + docs | collapse `Groups`/`GroupsV2` (Task 3); copy-once doc sweep (Task 4) |
| `crates/cesr-stream/src/lib.rs` | public re-exports | update `Groups`/`GroupsV2` + qb2 re-exports (Tasks 1, 3) |
| `crates/cesr-stream/CHANGELOG.md` | changelog | record three breaking changes (Task 5) |

---

### Task 1: F5 — rename qb2 conversion pair

**Files:**
- Modify: `crates/cesr-stream/src/qb2.rs` (fn defs at 24, 56; test names)
- Modify: `crates/cesr-stream/src/lib.rs:73` (re-export)
- Modify: `crates/cesr-stream/src/keripy_diff/stream.rs:9,35` (callers)

- [ ] **Step 1: Rename the two functions**

In `qb2.rs`:
- `pub fn qb64_to_qb2(qb64: &[u8]) -> Result<Vec<u8>, ParseError>` → `pub fn from_text(qb64: &[u8]) -> Result<Vec<u8>, ParseError>`
- `pub fn qb2_to_qb64(qb2: &[u8]) -> Result<Vec<u8>, ParseError>` → `pub fn to_text(qb2: &[u8]) -> Result<Vec<u8>, ParseError>`

Update the doc comments to name the new functions where they cross-reference. Keep the "Every 4 qb64 characters encode 3 qb2 bytes" body prose.

- [ ] **Step 2: Update the re-export**

`lib.rs:73`: `pub use qb2::{qb2_to_qb64, qb64_to_qb2};` → `pub use qb2::{from_text, to_text};`

Check whether the surrounding block re-exports under a `qb2` path or flat. If flat at crate root, the public path becomes `cesr_stream::to_text` — verify that is intended (spec says `qb2::to_text`). If the intent is `cesr_stream::qb2::to_text`, instead make the `qb2` module `pub` and drop the flat re-export. Inspect `lib.rs` around line 73 and match the crate's existing module-exposure pattern; prefer `qb2::to_text` (module-qualified) per the spec's naming.

- [ ] **Step 3: Update callers in keripy_diff/stream.rs**

Line 9 `use crate::{qb2_to_qb64, qb64_to_qb2};` → import the new names/path.
Line 35 `qb2_to_qb64(&expected_qb2)` → `to_text(&expected_qb2)` (or `qb2::to_text(...)` matching the chosen path). Update the `.unwrap_or_else(|e| panic!("qb2_to_qb64: {e:?}"))` message string to the new name.

- [ ] **Step 4: Rename the tests**

In `qb2.rs` test module, rename tests referencing the old names (`qb2_to_qb64_roundtrip`, `qb2_to_qb64_counter_roundtrip`, `qb2_to_qb64_rejects_misaligned_length`, and any body calls) to the new function names. Assertions/values stay identical — this is a rename, not a behavior change.

- [ ] **Step 5: Dev-loop check**

Run: `nix develop --command cargo nextest run -p cesr-stream`
Expected: PASS (same test count, renamed tests green).

- [ ] **Step 6: Commit**

```bash
git add crates/cesr-stream/src/qb2.rs crates/cesr-stream/src/lib.rs crates/cesr-stream/src/keripy_diff/stream.rs
git commit -m "refactor(cesr-stream)!: rename qb2_to_qb64/qb64_to_qb2 to qb2::to_text/from_text (#210)"
```

---

### Task 2: F2 — rename `from_sigers` → `from_indexed_signatures`

**Files:**
- Modify: `crates/cesr-stream/src/group/kinds.rs` (defs 639, 657; doc xref 650; test module `mod from_sigers`)
- Modify: `crates/cesr-stream/src/group/mod.rs:150` (doc xref)
- Modify: `crates/keri-codec/src/serialize.rs` (callers 528, 537, 553, 554, 572, 589, 607)

- [ ] **Step 1: Rename both method definitions**

`kinds.rs:639` (`impl ControllerIdxSigs`) and `kinds.rs:657` (`impl WitnessIdxSigs`):
`pub fn from_sigers(sigers: &[Siger<'_>]) -> Result<Self, ParseError>` → `pub fn from_indexed_signatures(sigers: &[Siger<'_>]) -> Result<Self, ParseError>`

Body unchanged (`encode_sigers(sigers)` etc.). The `sigers` *parameter* name may stay — it names the local, not the public API — but rename it to `signatures` for consistency with the method name (still no keripy contraction in the mint).

- [ ] **Step 2: Update doc cross-references**

- `kinds.rs:650` doc: `[ControllerIdxSigs::from_sigers]` → `[ControllerIdxSigs::from_indexed_signatures]`.
- `mod.rs:150` doc: `[ControllerIdxSigs::from_sigers]` → `[ControllerIdxSigs::from_indexed_signatures]`.

- [ ] **Step 3: Update keri-codec test callers**

In `crates/keri-codec/src/serialize.rs`, replace all `::from_sigers(` with `::from_indexed_signatures(` at 528, 537, 553, 554, 572, 589, 607 (`ControllerIdxSigs` and `WitnessIdxSigs` receivers).

- [ ] **Step 4: Rename the test module + test fns**

In `kinds.rs`, `mod from_sigers` → `mod from_indexed_signatures`; rename the contained test fns (`controller_from_sigers_roundtrips_through_parse`, `witness_from_sigers_roundtrips_through_parse`, `from_sigers_empty_slice_yields_count_zero_group`, `from_sigers_single_siger_boundary`, `from_sigers_count_and_raw_stay_consistent_at_counter_capacity_boundary`) to use `from_indexed_signatures` in place of `from_sigers`, and update the calls inside them. Assertions/values unchanged.

- [ ] **Step 5: Dev-loop check**

Run: `nix develop --command cargo nextest run -p cesr-stream -p keri-codec`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cesr-stream/src/group/kinds.rs crates/cesr-stream/src/group/mod.rs crates/keri-codec/src/serialize.rs
git commit -m "refactor(cesr-stream)!: rename from_sigers to from_indexed_signatures (#210)"
```

---

### Task 3: F1+F4 — collapse `Groups`/`GroupsV2` into `Groups<'a, V: Version = V1>`

**Files:**
- Modify: `crates/cesr-stream/src/group/mod.rs` (`Groups` struct ~767, `GroupsV2` struct ~952 delete; Debug test ~2267; `GroupsV2::over` test sites)
- Modify: `crates/cesr-stream/src/lib.rs:71` (re-export)

- [ ] **Step 1: Write the parity test (failing)**

Add to the group/mod.rs test module. It must call the collapsed API and assert V2 parity — it will not compile until Step 3 (that is the "fail"). Reuse an existing V2 multi-group fixture (see the existing `GroupsV2::over` test near line 1755/1804 for how a V2 stream is built) and assert element equality against `Groups::<V2>::over`:

```rust
#[test]
fn groups_generic_v2_matches_collected_parse_v2() {
    let input = /* same fixture the old GroupsV2 test used */;
    let out: Vec<CesrGroup> = Groups::<V2>::over(&input)
        .collect::<Result<_, _>>()
        .unwrap();
    // assert the exact expected variants/counts the old test asserted
    assert_eq!(out.len(), /* expected */);
    // ...same per-element assertions as the pre-collapse GroupsV2 test...
}

#[test]
fn groups_default_type_param_is_v1() {
    // Groups::over(x) with no turbofish must select V1.
    let input = /* a V1 stream fixture reused from an existing Groups test */;
    let out: Vec<CesrGroup> = Groups::over(&input)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(out.len(), /* expected */);
}
```

(Copy the concrete fixtures + expected values verbatim from the existing pre-collapse `Groups` and `GroupsV2` tests so the assertions are exact, not `contains`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-stream groups_generic`
Expected: FAIL to compile — `Groups::<V2>` / type param not yet defined.

- [ ] **Step 3: Make `Groups` generic; delete `GroupsV2`**

Ensure top-of-file imports include `core::marker::PhantomData`, `cesr::core::version::CesrVersion`, and the `Version`/`V1`/`V2` markers (check existing `use` block; add via alias if a name collides — no inline `use`).

Replace the `Groups<'a>` struct + its `over`, `Debug`, and `Iterator` impls with:

```rust
/// An iterator that yields successive [`CesrGroup`]s from a byte stream,
/// parsed with version `V`'s counter table (default [`V1`]).
///
/// The attachment region is copied into a shared [`Bytes`] once, lazily, on
/// the first [`Iterator::next`]; every subsequent group is an O(1) slice of
/// that buffer — copy-once, not zero-copy.
pub struct Groups<'a, V: Version = V1> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
    version: PhantomData<V>,
}

impl<'a, V: Version> Groups<'a, V> {
    /// The iterator over the successive CESR groups laid over `input`.
    #[must_use]
    pub const fn over(input: &'a [u8]) -> Self {
        Self { input, buf: None, cursor: 0, version: PhantomData }
    }
}

impl<V: Version> fmt::Debug for Groups<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Groups")
            .field("len", &self.input.len())
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl<V: Version> Iterator for Groups<'_, V> {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self
            .buf
            .get_or_insert_with(|| Bytes::copy_from_slice(self.input));
        let buf_len = buf.len();
        if self.cursor >= buf_len {
            return None;
        }
        let parsed = match V::VERSION {
            CesrVersion::V1 => CesrGroup::parse_bytes_at(buf, self.cursor),
            CesrVersion::V2 => CesrGroup::parse_bytes_v2_at(buf, self.cursor),
        };
        match parsed {
            Ok((group, rest)) => {
                self.cursor = buf_len - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.cursor = buf_len;
                Some(Err(e))
            }
        }
    }
}
```

Delete the entire `GroupsV2` struct + its `over`/`Debug`/`Iterator` impls (~952–1003).

- [ ] **Step 4: Update the re-export**

`lib.rs:71`: `pub use group::{Groups, GroupsV2};` → `pub use group::Groups;`

- [ ] **Step 5: Retarget existing GroupsV2 tests + Debug assertion**

- Every `GroupsV2::over(x)` in the group/mod.rs test module → `Groups::<V2>::over(x)` (sites near 1755, 1771, 1781, 1804, 2267).
- Debug test at ~2267–2269: expected `"GroupsV2 { len: 92, cursor: 0, .. }"` → `"Groups { len: 92, cursor: 0, .. }"`.
- Import `V2` (and `V1` if used) into the test module (`use super::*;` likely already covers it — verify the markers are in scope).

- [ ] **Step 6: Run tests to verify pass**

Run: `nix develop --command cargo nextest run -p cesr-stream`
Expected: PASS, including the two new `groups_generic*` / `groups_default_type_param_is_v1` tests and all retargeted V2 iterator tests.

- [ ] **Step 7: Commit**

```bash
git add crates/cesr-stream/src/group/mod.rs crates/cesr-stream/src/lib.rs
git commit -m "refactor(cesr-stream)!: collapse Groups/GroupsV2 into Groups<'a, V: Version = V1> (#210)"
```

---

### Task 4: F3 — copy-once doc sweep

**Files:**
- Modify: `crates/cesr-stream/src/group/mod.rs` (docstrings only)

- [ ] **Step 1: Find every overpromising claim**

Run: `nix develop --command rg -n -i 'zero.?copy' crates/cesr-stream/src/group/mod.rs`
Note each hit (known: `parse_bytes` doc ~618 "Zero-copy parsing core"; `CesrGroup::parse` doc ~588–589 wording; iterator docs). The collapsed `Groups` doc from Task 3 already uses the honest wording — leave it.

- [ ] **Step 2: Reword each to the copy-once model**

For each hit, replace the "zero-copy" framing with the honest statement: the input is copied once into a shared `Bytes` (at construction or first `next()`), and every subsequent operation is an O(1) refcounted slice of that buffer. Keep `parse_bytes`'s doc accurate: it slices an already-shared `Bytes` (no copy at that layer) — describe it as "shared-buffer slicing," not "zero-copy," since the copy happened upstream in `parse`/`Groups`. Do not touch any code or signatures.

- [ ] **Step 3: Verify no claim remains**

Run: `nix develop --command rg -n -i 'zero.?copy' crates/cesr-stream/src/group/mod.rs`
Expected: no overpromising hits (or only ones that are literally accurate and reworded to say so).

- [ ] **Step 4: Doctest sanity**

Run: `nix develop --command cargo test -p cesr-stream --doc`
Expected: PASS (doc examples unaffected).

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/group/mod.rs
git commit -m "docs(cesr-stream): describe the group read path as copy-once, not zero-copy (#210)"
```

---

### Task 5: CHANGELOG + full gate (verification of record)

**Files:**
- Modify: `crates/cesr-stream/CHANGELOG.md`

- [ ] **Step 1: Record the breaking changes**

In the cesr-stream `CHANGELOG.md` unreleased/next section, add under a breaking-changes heading (match the file's existing format):

- `GroupsV2` removed; `Groups` is now `Groups<'a, V: Version = V1>` — use `Groups::<V2>::over(..)` for V2 streams.
- `ControllerIdxSigs::from_sigers` / `WitnessIdxSigs::from_sigers` renamed to `from_indexed_signatures`.
- `qb2_to_qb64` / `qb64_to_qb2` renamed to `qb2::to_text` / `qb2::from_text`.

(keri-codec has no public change — only test-internal call-site updates — so no keri-codec CHANGELOG entry.)

- [ ] **Step 2: Commit the changelog**

```bash
git add crates/cesr-stream/CHANGELOG.md
git commit -m "docs(cesr-stream): changelog for #210 API polish"
```

- [ ] **Step 3: Run the full gate (single source of truth)**

Run and capture exit code without piping (per the never-pipe-gate rule):
```bash
nix flake check > /tmp/gate-210.log 2>&1; echo "EXIT: $?"
```
Expected: `EXIT: 0`. If non-zero, read `/tmp/gate-210.log`, fix, re-run — do not proceed until the gate is green.

- [ ] **Step 4: Push + open PR**

```bash
git push -u origin devx/210-cesr-stream-api-polish
```
Open a PR titled `refactor(cesr-stream)!: API polish (#210)`; body lists the four findings addressed + the three breaking changes; link issue #210; note F3-borrowing-path and F5-buffer-variants deferred. Attach to CESR project board (Project #5).

---

## Self-Review

**Spec coverage:**
- F1 collapse → Task 3. F4 read/write symmetry → Task 3 (same generic; parse/parse_v2 left value-level as specced). F2 rename → Task 2. F3 docs → Task 4. F5 rename → Task 1; buffer variants explicitly deferred (spec Scope boundary). CHANGELOG → Task 5. All covered.

**Placeholder scan:** Fixtures in Task 3 Step 1 say "copy verbatim from existing test" rather than inlining a 90-byte hex blob — this is a deliberate pointer to concrete existing values, not a TODO; the engineer copies exact bytes + exact expected assertions from the named pre-collapse tests.

**Type consistency:** `from_indexed_signatures` used consistently (Task 2). `Groups<'a, V: Version = V1>`, `Groups::<V2>::over`, `V::VERSION`, `CesrGroup::parse_bytes_at`/`parse_bytes_v2_at` consistent across Task 3. `qb2::to_text`/`from_text` consistent across Task 1. Commit scope-bang `!` on all three breaking renames/collapse.
