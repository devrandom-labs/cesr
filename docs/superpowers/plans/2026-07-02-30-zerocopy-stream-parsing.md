# Zero-copy Stream Parsing (#30) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the per-group `Bytes::copy_from_slice` allocations in `src/stream/` by threading a shared `bytes::Bytes` through the group parsers and slicing (O(1) refcount) instead of copying, so the codec path becomes truly zero-copy and the sync path drops from ~N allocations/message to 1.

**Architecture:** A `Bytes`-based parsing core (`parse_group_bytes`) slices its input for every group and element (0 copies). The public `parse_group(&[u8])` stays a non-breaking wrapper that copies its borrowed input into a `Bytes` exactly once. The async codec already owns a `Bytes` and calls the core directly (0 copies). The `Groups` iterator copies the attachment region once and slices each group from it.

**Tech Stack:** Rust (edition 2024, stable 1.95.0, no_std+alloc, wasm32), `bytes = 1.10.1`, hand-rolled cursor parser (no parser-combinator library — see spec), `nix flake check` as the sole gate.

**Spec:** `docs/superpowers/specs/2026-07-02-30-zerocopy-stream-parsing-design.md`

---

## Background the engineer must know

- **`Bytes::slice(range)` is O(1)** — it bumps an `Arc` refcount and adjusts pointers; it does NOT copy. `Bytes::copy_from_slice(&s)` allocates a fresh buffer and copies. The whole point of this issue is replacing the latter with the former.
- **`Bytes` derefs to `[u8]`** (`impl Deref<Target=[u8]>`), so existing code like `&input[offset..]` and `skip_matter(&input[offset..])` compiles unchanged when `input` becomes a `Bytes` instead of `&[u8]`.
- **The base64 hard wall:** `Matter`/`Indexer` `raw` fields come from base64 decode and are genuinely owned (`Cow::Owned`). This plan does NOT touch that — only the qb64-text copies in `stream/`.
- **The single gate is `nix flake check`.** Do NOT use raw `cargo`. Run inside the nix shell: `nix develop --command bash -c "<cmd>"`. For a fast unit-test loop while iterating, `nix develop --command cargo nextest run <filter>` is acceptable, but every task's final verification is `nix flake check` (or at minimum the nextest + clippy checks it runs). New files must be `git add`-ed before `nix flake check` (staged-files gate).
- **Mandatory Rule 2 (arithmetic safety):** size/offset math uses `checked_*` and returns `Err` on overflow. `saturating_*` and `unwrap_or(sentinel)` are BANNED in these paths.
- **Clippy is deny-level** (`all`+`pedantic`+`nursery`+restrictions). Every `#[allow]` needs `reason = "..."`. No `unwrap`/`expect`/`panic`/`as` in production; tests are exempt via the existing per-module `#[allow(...)]` in `#[cfg(test)]` blocks.

## Signature convention: parsers take `&Bytes`, not `Bytes`

All `Bytes`-based parsers in this plan take their input by **reference** (`&Bytes`) and
return `(T, Bytes)` where the "rest" is a fresh O(1) `.slice()`. Rationale: `Bytes::slice`
and `Bytes::len` only need `&self`, and the parser never *consumes* the buffer — so a
by-value `Bytes` parameter trips `clippy::needless_pass_by_value` (denied via pedantic) and
would force a policy-violating `#[allow]` on every parser. `&Bytes` derefs to `[u8]`
(deref coercion covers `parse_counter(buf)` and `&buf[offset..]`), so the skip-loop bodies
are unchanged. Callers keep ownership of their buffer.

## The mechanical group-parser transformation (referenced by later tasks)

Every element-group parser in `src/stream/group/*.rs` (except the nested and quadlet ones, handled separately) has this exact shape:

```rust
pub(super) fn parse(input: &[u8], count: u32) -> Result<(T, &[u8]), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_X(&input[offset..])?;   // one or more skip_* calls — UNCHANGED
        // ...
    }
    let raw = Bytes::copy_from_slice(&input[..offset]);
    Ok((T::new(raw, count), &input[offset..]))
}
```

The transformation (identical for all of them) is:

```rust
pub(super) fn parse(input: &Bytes, count: u32) -> Result<(T, Bytes), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_X(&input[offset..])?;   // UNCHANGED — Bytes derefs to [u8]
        // ...
    }
    let raw = input.slice(..offset);
    let rest = input.slice(offset..);
    Ok((T::new(raw, count), rest))
}
```

Only two things change: the **signature** (`&[u8] -> &Bytes` for the param, `&[u8] -> Bytes`
for the "rest" return), and the **final two lines** (`copy_from_slice` → two `slice` calls).
The `skip_*` loop body is byte-for-byte identical. `T::new` already takes `Bytes` today, so it
is unchanged.

Test modules in these files call `parse(&input, n)` / `parse(b"", 0)` and assert on
`rest: &[u8]`. Those calls must become `parse(&Bytes::copy_from_slice(&input), n)` /
`parse(&Bytes::new(), 0)` (bind the `Bytes` to a `let` first if the borrow needs to outlive
the call), and `rest` assertions must compare against `Bytes` (e.g.
`assert_eq!(rest, Bytes::from_static(b"EXTRA"))`, `assert!(rest.is_empty())`).

---

## Task 1: Fix banned arithmetic in `quadlet_group` (independent, do first)

`parse_quadlets`/`parse_quadlets_v2` currently use `saturating_mul(4)` and `unwrap_or(0)` — both banned by Mandatory Rule 2. Fix them before the refactor so the fix is a clean, isolated commit.

**Files:**
- Modify: `src/stream/group/quadlet_group.rs:74-88` and `:90-104`
- Test: same file, `#[cfg(test)]` module (add one)

- [ ] **Step 1: Write the failing test**

Add to a `#[cfg(test)]` module in `src/stream/group/quadlet_group.rs` (create the module with the standard test `#[allow]` header if absent):

```rust
#[test]
fn parse_quadlets_rejects_count_overflow() {
    // count * 4 overflows usize on 64-bit only at absurd values; use u32::MAX
    // which multiplies to 17_179_869_180 — fits usize on 64-bit, so instead
    // assert the NeedBytes path: a huge count with tiny input must error, not panic.
    let input = b"AAAA";
    let err = parse_quadlets(input, u32::MAX).unwrap_err();
    assert!(matches!(err, ParseError::NeedBytes(_)));
}
```

- [ ] **Step 2: Run test to verify it passes today but for the wrong reason / establish baseline**

Run: `nix develop --command cargo nextest run -p cesr quadlet_group::tests::parse_quadlets_rejects_count_overflow`
Expected: PASS (documents current behavior; the real fix is removing `saturating`/`unwrap_or`).

- [ ] **Step 3: Replace the banned arithmetic**

In both `parse_quadlets` and `parse_quadlets_v2`, replace:

```rust
    let total_bytes = usize::try_from(count).unwrap_or(0).saturating_mul(4);
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
```

with:

```rust
    let total_bytes = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(4))
        .ok_or(ParseError::Malformed("quadlet count overflow".into()))?;
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
```

- [ ] **Step 4: Run the test + clippy**

Run: `nix develop --command cargo nextest run -p cesr quadlet_group`
Expected: PASS. Then confirm no clippy regressions locally with `nix develop --command cargo clippy --all-features` (expected: clean).

- [ ] **Step 5: Commit**

```bash
git add src/stream/group/quadlet_group.rs
git commit -m "fix(#30): replace banned saturating/unwrap_or arithmetic in quadlet_group with checked_mul

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add the `Bytes`-based parsing core (`parse_group_bytes`) alongside the existing `&[u8]` path

Introduce the zero-copy core and a slicing dispatch **without** yet converting the leaf group parsers. To keep this task self-contained and green, the new dispatch temporarily bridges to the still-`&[u8]` leaf parsers by copying (this bridge is removed in Task 4). This lets us land and test the core wiring first.

**Files:**
- Modify: `src/stream/group/mod.rs` (add `parse_group_bytes`, keep `parse_group_inner`)
- Test: `src/stream/group/mod.rs` `#[cfg(test)]`

- [ ] **Step 1: Write the failing test**

Add to `mod.rs` tests (create the `#[cfg(test)]` block with the standard `#[allow]` header if none exists):

```rust
#[test]
fn parse_group_bytes_matches_slice_path() {
    use bytes::Bytes;
    // Build one ControllerIdxSigs group: counter "-AAB" + one Siger.
    let mut input = crate::b64::encode_int(1, core::num::NonZeroUsize::new(2).unwrap());
    let mut buf = format!("-A{input}").into_bytes();
    buf.extend_from_slice(&{
        use crate::core::indexer::IndexerBuilder;
        use crate::core::indexer::code::IndexedSigCode;
        IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap()
            .to_qb64()
            .into_bytes()
    });
    let _ = &mut input;

    let bytes = Bytes::copy_from_slice(&buf);
    let (group, rest) = parse_group_bytes(bytes).unwrap();
    assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
    assert!(rest.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr group::tests::parse_group_bytes_matches_slice_path`
Expected: FAIL — `parse_group_bytes` not found.

- [ ] **Step 3: Add `parse_group_bytes` and a `Bytes` dispatch bridge**

In `src/stream/group/mod.rs`, add (keep the existing `parse_group`, `parse_group_inner`, `dispatch_v1` untouched for now):

```rust
use bytes::Bytes;

/// Zero-copy parsing core: slices `buf` for the counter and hands the element
/// region to the dispatch. Returns the remaining bytes as an O(1) `Bytes` slice.
pub(crate) fn parse_group_bytes(buf: Bytes) -> Result<(CesrGroup, Bytes), ParseError> {
    let (code, count, after_counter) = parse_counter(&buf)?;
    let consumed = buf.len() - after_counter.len();
    let elements = buf.slice(consumed..);
    dispatch_v1_bytes(code, count, elements)
}

pub(crate) fn parse_group_bytes_v2(buf: Bytes) -> Result<(CesrGroup, Bytes), ParseError> {
    let (code, count, after_counter) = parse_counter_v2(&buf)?;
    let consumed = buf.len() - after_counter.len();
    let elements = buf.slice(consumed..);
    dispatch_v2_bytes(code, count, elements)
}
```

Add temporary bridge dispatchers that call the existing `&[u8]` leaf parsers and re-wrap the remainder as `Bytes` (removed in Task 4):

```rust
fn dispatch_v1_bytes(
    code: CounterCodeV1,
    count: u32,
    elements: Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let (group, rest) = dispatch_v1(code, count, &elements)?;
    let consumed = elements.len() - rest.len();
    Ok((group, elements.slice(consumed..)))
}

fn dispatch_v2_bytes(
    code: CounterCodeV2,
    count: u32,
    elements: Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let (group, rest) = dispatch_v2(code, count, &elements)?;
    let consumed = elements.len() - rest.len();
    Ok((group, elements.slice(consumed..)))
}
```

> Note: this bridge still copies inside the leaf parsers — that is intentional for this task. Task 4 replaces the leaf parsers and deletes these bridges.

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo nextest run -p cesr group::tests::parse_group_bytes_matches_slice_path`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stream/group/mod.rs
git commit -m "feat(#30): add Bytes-based parse_group_bytes core (bridged to leaf parsers)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Convert `ControllerIdxSigs` leaf parser to `Bytes` + slice (reference conversion)

This is the reference for the mechanical conversions in Task 4. It includes the **aliasing test** that proves slicing (not copying) — the true bug-probe for this whole issue.

**Files:**
- Modify: `src/stream/group/controller_idx_sigs.rs`
- Modify: `src/stream/group/mod.rs` (point the `dispatch_v1`/`dispatch_v2` arms for ControllerIdxSigs at the new `Bytes` parser — see below)

- [ ] **Step 1: Write the failing aliasing test**

Add to `controller_idx_sigs.rs` tests:

```rust
#[test]
fn parse_slices_without_copying() {
    use bytes::Bytes;
    let input = build_siger_qb64(0);
    let parent = Bytes::copy_from_slice(&input);
    let parent_start = parent.as_ptr() as usize;
    let parent_end = parent_start + parent.len();

    let (group, _rest) = parse(parent, 1).unwrap();
    let raw_ptr = group.raw_bytes().as_ptr() as usize;

    // A slice points INTO the parent buffer; a copy would point elsewhere.
    assert!(
        raw_ptr >= parent_start && raw_ptr < parent_end,
        "group raw must be a slice of the parent buffer, not a copy"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr controller_idx_sigs`
Expected: FAIL — `parse` still takes `&[u8]` (type error), or (once signature changes) the pointer assertion fails while it still copies.

- [ ] **Step 3: Apply the mechanical transformation**

In `controller_idx_sigs.rs`, change `parse` per the template in "The mechanical group-parser transformation":

```rust
pub(super) fn parse(input: Bytes, count: u32) -> Result<(ControllerIdxSigs, Bytes), ParseError> {
    let mut offset = 0;
    for _ in 0..count {
        offset += skip_indexer(&input[offset..])?;
    }
    let raw = input.slice(..offset);
    let rest = input.slice(offset..);
    Ok((ControllerIdxSigs::new(raw, count), rest))
}
```

Update the existing tests in this file to pass `Bytes` and compare `Bytes` rests:
- `parse(b"", 0)` → `parse(Bytes::new(), 0)`
- `parse(&input, n)` → `parse(Bytes::copy_from_slice(&input), n)`
- `assert_eq!(rest, b"TRAILING")` → `assert_eq!(rest, Bytes::from_static(b"TRAILING"))`
- Add `use bytes::Bytes;` to the test module if not already imported via `use super::*;` (it is, since the file has `use bytes::Bytes;` at top).

- [ ] **Step 4: Point the dispatch arms at the new parser**

In `mod.rs`, the `dispatch_v1_bytes`/`dispatch_v2_bytes` bridges from Task 2 currently call the old `&[u8]` `dispatch_v1`. That won't compile now that `controller_idx_sigs::parse` takes `Bytes`. For this task only, special-case ControllerIdxSigs directly in the `_bytes` dispatchers before falling back to the bridge:

```rust
fn dispatch_v1_bytes(
    code: CounterCodeV1,
    count: u32,
    elements: Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    match code {
        CounterCodeV1::ControllerIdxSigs => {
            let (g, r) = controller_idx_sigs::parse(elements, count)?;
            Ok((CesrGroup::ControllerIdxSigs(g), r))
        }
        _ => {
            let (group, rest) = dispatch_v1(code, count, &elements)?;
            let consumed = elements.len() - rest.len();
            Ok((group, elements.slice(consumed..)))
        }
    }
}
```

But the old `dispatch_v1` still references `controller_idx_sigs::parse(rest, count)` with `rest: &[u8]` — that now fails to compile. Temporarily change the `ControllerIdxSigs` arm in the OLD `dispatch_v1`/`dispatch_v2` to copy-adapt:

```rust
        CounterCodeV1::ControllerIdxSigs => {
            let (g, r) = controller_idx_sigs::parse(Bytes::copy_from_slice(rest), count)?;
            let consumed = rest.len() - r.len();
            Ok((CesrGroup::ControllerIdxSigs(g), &rest[consumed..]))
        }
```

Apply the same one-arm adaptation in `dispatch_v2` (both `ControllerIdxSigs` and `BigControllerIdxSigs` map to `controller_idx_sigs::parse`). These adapters vanish in Task 4 when `dispatch_v1`/`v2` are deleted.

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop --command cargo nextest run -p cesr controller_idx_sigs`
Expected: PASS, including `parse_slices_without_copying`.

- [ ] **Step 6: Commit**

```bash
git add src/stream/group/controller_idx_sigs.rs src/stream/group/mod.rs
git commit -m "refactor(#30): ControllerIdxSigs parses Bytes and slices instead of copying

Includes the aliasing bug-probe test proving the group raw is a slice of the
parent buffer, not a fresh allocation.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Convert the remaining simple leaf parsers + collapse the dispatchers

Apply the identical mechanical transformation to every remaining single-`raw: Bytes` element-group parser, then delete the old `&[u8]` `dispatch_v1`/`dispatch_v2` and the Task-2 bridges so the `_bytes` dispatchers call leaf parsers directly.

**Files to modify (each gets the mechanical transformation from the reference section; the `copy_from_slice` line number is given for orientation):**

| File | copy line | skip pattern per element |
|---|---|---|
| `witness_idx_sigs.rs` | 19 | `skip_indexer` ×1 |
| `non_trans_receipt_couples.rs` | 23 | `skip_matter` ×2 |
| `first_seen_replay_couples.rs` | 23 | `skip_matter` ×2 |
| `seal_source_couples.rs` | 20 | `skip_matter` ×2 |
| `seal_source_triples.rs` | 21 | `skip_matter` ×3 |
| `seal_source_last_singles.rs` | 22 | `skip_matter` ×1 |
| `digest_seal_singles.rs` | 19 | `skip_matter` ×1 |
| `merkle_root_seal_singles.rs` | 22 | `skip_matter` ×1 |
| `backer_registrar_seal_couples.rs` | 23 | `skip_matter` ×2 |
| `typed_digest_seal_couples.rs` | 23 | `skip_matter` ×2 |
| `blinded_state_quadruples.rs` | 25 | `skip_matter` ×4 |
| `bound_state_sextuples.rs` | 24 | `skip_matter` ×6 |
| `typed_media_quadruples.rs` | 22 | `skip_matter` ×4 |
| `trans_receipt_quadruples.rs` | 26 | `skip_matter` ×3 + `skip_indexer`/seal (preserve existing loop exactly) |

For EACH file above:

- [ ] **Step 1: Transform `parse` (and `parse_v2` if the file has one)** using the reference template: signature `&[u8] -> Bytes`, and replace the trailing `let raw = Bytes::copy_from_slice(&input[..offset]); Ok((T::new(raw, count), &input[offset..]))` with `let raw = input.slice(..offset); let rest = input.slice(offset..); Ok((T::new(raw, count), rest))`. **Do not alter the skip-loop body.**

- [ ] **Step 2: Update that file's tests** — `parse(b"", 0)` → `parse(Bytes::new(), 0)`; `parse(&input, n)` → `parse(Bytes::copy_from_slice(&input), n)`; `rest` assertions → compare to `Bytes` (`assert!(rest.is_empty())` stays; `assert_eq!(rest, b"X")` → `assert_eq!(rest, Bytes::from_static(b"X"))`).

- [ ] **Step 3: Collapse the dispatchers.** In `mod.rs`:
  - Delete the temporary `dispatch_v1_bytes`/`dispatch_v2_bytes` bridge bodies and the old `dispatch_v1`/`dispatch_v2` (and `dispatch_v2_quadlets` — fold into the bytes dispatch). Re-create `dispatch_v1`/`dispatch_v2` to take `elements: Bytes` and return `(CesrGroup, Bytes)`, with each arm calling the now-`Bytes` leaf parser directly:

    ```rust
    fn dispatch_v1(code: CounterCodeV1, count: u32, rest: Bytes)
        -> Result<(CesrGroup, Bytes), ParseError>
    {
        match code {
            CounterCodeV1::ControllerIdxSigs => {
                let (g, r) = controller_idx_sigs::parse(rest, count)?;
                Ok((CesrGroup::ControllerIdxSigs(g), r))
            }
            // ...one arm per group, each moving `rest` into the single matched parser...
        }
    }
    ```
  - Point `parse_group_bytes`/`parse_group_bytes_v2` at these directly (drop the `_bytes` suffix indirection).

- [ ] **Step 4: Run the full stream test suite**

Run: `nix develop --command cargo nextest run -p cesr stream`
Expected: PASS (all group + dispatch tests).

- [ ] **Step 5: Commit** (one commit for the batch is fine; or commit per-file if preferred)

```bash
git add src/stream/group/
git commit -m "refactor(#30): remaining leaf group parsers slice Bytes; collapse dispatch to Bytes core

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Convert the nested parsers (`trans_idx_sig_groups`, `trans_last_idx_sig_groups`) and `quadlet_group`

These have two copy sites each and drive inner group parsing.

**Files:**
- Modify: `src/stream/group/trans_idx_sig_groups.rs:38,62`
- Modify: `src/stream/group/trans_last_idx_sig_groups.rs:39,67`
- Modify: `src/stream/group/quadlet_group.rs`

- [ ] **Step 1: Transform `trans_idx_sig_groups::parse` and `parse_v2`** per the reference template (signature `&[u8]->Bytes`, final `copy_from_slice`→`slice` pair). The inner `skip_matter`/`skip_counter`/`skip_indexer` loop and the `CounterCodeV1::ControllerIdxSigs` guard stay **exactly** as-is. Do the same for `trans_last_idx_sig_groups.rs`. Update both files' tests to pass/compare `Bytes` (see Task 4 Step 2).

- [ ] **Step 2: Convert `QuadletGroup` to a `Bytes` parser type.** In `quadlet_group.rs`:
  - Change the parser fn type: `type GroupParser = fn(Bytes) -> Result<(CesrGroup, Bytes), ParseError>;`
  - Change `parse_quadlets`/`parse_quadlets_v2` signatures to `(input: Bytes, count: u32) -> Result<(QuadletGroup, Bytes), ParseError>`, replace `Bytes::copy_from_slice(&input[..total_bytes])` with `input.slice(..total_bytes)` and `&input[total_bytes..]` with `input.slice(total_bytes..)`.
  - Pass `super::parse_group_bytes` / `super::parse_group_bytes_v2` as the parser (instead of `parse_group_inner`).
  - Update `QuadletGroup::Iterator::next` to slice: `let remaining = self.input.slice(self.cursor..);` then `match (self.parser)(remaining) { Ok((group, rest)) => { self.cursor = self.input.len() - rest.len(); ... } }`.

- [ ] **Step 3: Write the nested aliasing test** in `quadlet_group.rs`:

```rust
#[test]
fn inner_groups_share_parent_allocation() {
    use bytes::Bytes;
    // Build an attachment quadlet group wrapping one ControllerIdxSigs.
    // (Reuse an existing test vector builder from this module's tests.)
    // Assert the inner group's raw_bytes pointer falls within the parent Bytes range.
    // See controller_idx_sigs::tests::parse_slices_without_copying for the pointer-range assertion pattern.
}
```

Fill in the builder using the module's existing test helpers (the file already has quadlet test vectors). The load-bearing assertion is the pointer-range check from Task 3 Step 1.

- [ ] **Step 4: Run tests**

Run: `nix develop --command cargo nextest run -p cesr 'trans_idx_sig_groups|trans_last_idx_sig_groups|quadlet_group'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stream/group/
git commit -m "refactor(#30): nested + quadlet group parsers slice Bytes and drive parse_group_bytes

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Non-breaking `&[u8]` wrappers + wire the codec to the zero-copy core

Keep the public `&[u8]` API and make the codec path truly zero-copy.

**Files:**
- Modify: `src/stream/group/mod.rs` (`parse_group`, `parse_group_v2`, `parse_group_inner*`)
- Modify: `src/stream/codec.rs` (call `parse_group_bytes` with the already-frozen `Bytes`)
- Also fix any callers of `parse_group_inner` in `types.rs:430,585` (the two remaining `copy_from_slice` sites) and `unwrap.rs` (Task 7 handles unwrap fully; here just make it compile).

- [ ] **Step 1: Make `parse_group`/`parse_group_v2` copy-once wrappers**

```rust
pub fn parse_group(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    let (group, rest) = parse_group_bytes(Bytes::copy_from_slice(input))?;
    let consumed = input.len() - rest.len();
    Ok((group, &input[consumed..]))
}
```

Same shape for `parse_group_v2` calling `parse_group_bytes_v2`. Keep `parse_group_inner`/`parse_group_inner_v2` as thin `&[u8]` shims delegating to the same wrapper body **only if** other modules still call them; otherwise delete and update callers to `parse_group`/`parse_group_bytes`.

- [ ] **Step 2: Wire the codec**

In `src/stream/codec.rs`, the decode path already produces `let payload = frozen.slice(counter_size..);` as a `Bytes`. Replace the group-construction call so it hands `payload` (or the appropriate `Bytes`) straight to `parse_group_bytes`/`parse_group_bytes_v2` instead of going through a `&[u8]` path. Verify no `copy_from_slice` remains on the decode hot path in this file.

- [ ] **Step 3: Add a codec zero-copy assertion test**

In `codec.rs` tests, decode a frame from a `BytesMut` and assert the resulting group's `raw_bytes().as_ptr()` lies within the original frozen buffer's address range (same pointer-range pattern as Task 3). This proves the codec path performs **zero** copies.

- [ ] **Step 4: Run tests**

Run: `nix develop --command cargo nextest run -p cesr --features async stream::codec`
Expected: PASS, including the zero-copy assertion.

- [ ] **Step 5: Commit**

```bash
git add src/stream/
git commit -m "feat(#30): copy-once &[u8] wrappers; codec path is now truly zero-copy

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Thread `Bytes` through `unwrap_generic_group` (eliminate nested double-copy)

`unwrap.rs:45,77` copy nested groups during recursive genus/version unwrapping. Slice the parent `Bytes` through the recursion instead.

**Files:**
- Modify: `src/stream/unwrap.rs`

- [ ] **Step 1: Write the failing aliasing test** in `unwrap.rs` tests: unwrap a nested generic group and assert the unwrapped inner bytes pointer falls within the original parent `Bytes` range (pointer-range pattern from Task 3).

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr unwrap`
Expected: FAIL — current code copies via `copy_from_slice`, so the inner pointer is outside the parent range.

- [ ] **Step 3: Replace the copies with slices.** At `unwrap.rs:45` and `:77`, replace `Bytes::copy_from_slice(group.raw_bytes())` / `Bytes::copy_from_slice(&inner_raw[genus_size..])` with `.slice(...)` of the parent `Bytes` the function already holds (thread the parent `Bytes` in if the current signature only has `&[u8]`; adjust the internal signature — this is `pub(crate)`/internal plumbing, keep the public `unwrap_generic_group` signature if it is public, adding a `Bytes`-based inner helper if needed).

- [ ] **Step 4: Run tests**

Run: `nix develop --command cargo nextest run -p cesr unwrap`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stream/unwrap.rs
git commit -m "refactor(#30): unwrap_generic_group slices parent Bytes through recursion (no nested copy)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Copy-once in the `Groups` iterator (flat sync path: G allocations → 1)

Make `Groups` copy the attachment region once, then slice each group from the shared `Bytes`. Public type and `groups()`/`parse_message` signatures stay unchanged.

**Files:**
- Modify: `src/stream/group/mod.rs` (`Groups`, `groups`)
- Test: `src/stream/group/mod.rs` tests

- [ ] **Step 1: Write the failing test** — parse a two-group stream via `groups()` and assert **both** returned groups' `raw_bytes()` pointers fall within a single shared buffer range (i.e. the second group is NOT a fresh allocation independent of the first). Pattern: capture the first group's parent range, assert the second's pointer is within a range derived from the same copy.

```rust
#[test]
fn groups_iterator_copies_once_and_slices() {
    // Build two adjacent ControllerIdxSigs groups.
    // Collect via groups(&stream). Assert group[1].raw_bytes().as_ptr() and
    // group[0].raw_bytes().as_ptr() are within the same contiguous region
    // (end of g0 <= start of g1 < g0_start + total_len).
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr group::tests::groups_iterator_copies_once`
Expected: FAIL — today each `parse_group_inner`/`parse_group` copies independently, so the two groups live in different allocations.

- [ ] **Step 3: Add lazy copy-once state to `Groups`**

```rust
pub struct Groups<'a> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
}

#[must_use]
pub const fn groups(input: &[u8]) -> Groups<'_> {
    Groups { input, buf: None, cursor: 0 }
}
```

In `Iterator::next`, copy once on first use, then slice from `buf`:

```rust
fn next(&mut self) -> Option<Self::Item> {
    if self.buf.is_none() {
        self.buf = Some(Bytes::copy_from_slice(self.input));
    }
    let buf = self.buf.as_ref()?;
    if self.cursor >= buf.len() {
        return None;
    }
    let slice = buf.slice(self.cursor..);
    match parse_group_bytes(slice) {
        Ok((group, rest)) => {
            self.cursor = buf.len() - rest.len();
            Some(Ok(group))
        }
        Err(e) => {
            self.cursor = buf.len();
            Some(Err(e))
        }
    }
}
```

(Keep the `'a` lifetime param so `Groups<'a>` / `CesrMessage<'a>` public signatures are unchanged. The `input` field remains for the initial copy source.)

- [ ] **Step 4: Run tests (full stream suite — this touches message.rs consumers)**

Run: `nix develop --command cargo nextest run -p cesr stream`
Expected: PASS (message + groups tests).

- [ ] **Step 5: Commit**

```bash
git add src/stream/group/mod.rs
git commit -m "perf(#30): Groups iterator copies the attachment region once, slices each group

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Benchmark the allocation/throughput improvement (acceptance criterion)

Prove the "reduced allocations / higher throughput" acceptance criterion on the P0.1 harness.

**Files:**
- Modify/Create: the P0.1 benchmark under `benches/` (locate the existing stream-parse benchmark; if none targets group parsing, add one)

- [ ] **Step 1: Locate the P0.1 benchmark harness**

Run: `nix develop --command bash -c "ls benches/ && grep -rl 'parse_group\|parse_message\|stream' benches/"`
Expected: identifies the existing bench file(s) to extend.

- [ ] **Step 2: Add/extend a benchmark** that parses a realistic multi-group CESR stream (reuse keripy conformance vectors already in the test suite) via `parse_message`/`groups` and via the codec path. If the harness supports allocation counting (e.g. a counting allocator), assert/report allocation count; otherwise report throughput (bytes/sec).

- [ ] **Step 3: Capture before/after**

Run the benchmark on `origin/main` and on this branch; record the numbers in the PR description. Expected: allocation count per message drops (≈G → 1 on the sync path; 0 added on the codec path), throughput non-regressed or improved.

- [ ] **Step 4: Commit**

```bash
git add benches/
git commit -m "bench(#30): stream group-parse allocation/throughput benchmark

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Full gate + docs + CHANGELOG

- [ ] **Step 1: Run the full gate**

Run: `nix flake check`
Expected: all checks green — clippy (deny), rustfmt, taplo, audit, deny, nextest (all feature combos), doctest, wasm build, no_std build.

- [ ] **Step 2: Fix any gate failures** (most likely: a `#[cfg(test)]` file missing `use bytes::Bytes;`, a `rest` comparison type mismatch, or a leftover `#[allow(dead_code)]` on a now-used `skip_*`). If a `skip_*` in `parse.rs` is now used, remove its `#[allow(dead_code, reason = "...")]`; if any remains unused, keep the allow with an accurate reason.

- [ ] **Step 3: Update CHANGELOG**

Add an entry under the unreleased section noting: zero-copy stream group parsing — codec path is now allocation-free; sync `parse_group`/`parse_message` copy the input once instead of per-group. Public signatures unchanged (non-breaking). If any group **type**'s public surface changed, note it as an intentional MINOR (0.x) breaking change.

- [ ] **Step 4: Verify the copy sites are gone**

Run: `nix develop --command bash -c "grep -rn 'copy_from_slice' src/stream --include='*.rs' | grep -v 'mod tests'"`
Expected: only the intentional copy-once sites remain (`parse_group`/`parse_group_v2` wrappers and `Groups::next`), i.e. ~3 sites down from 29. Document the remaining ones as the deliberate outermost-boundary copies.

- [ ] **Step 5: Commit + open PR**

```bash
git add CHANGELOG.md
git commit -m "docs(#30): CHANGELOG for zero-copy stream parsing

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push -u origin perf/30-zerocopy-stream-parsing
gh pr create --fill --base main
```

---

## Self-review notes (coverage against spec)

- **Kill the 29 `copy_from_slice`** → Tasks 3–8 + verified in Task 10 Step 4.
- **Hand-rolled parser kept, no winnow/nom** → no dependency added anywhere in the plan.
- **`bytes::Bytes` + `.slice()` ownership** → Tasks 2–8.
- **Copy-once at outermost boundary; non-breaking public API** → Task 6 (wrappers) + Task 8 (Groups); public signatures unchanged.
- **Codec truly zero-copy** → Task 6 + zero-copy assertion test.
- **`raw` stays owned; no `Matter<'a>`** → out of scope, untouched.
- **Arithmetic safety** → Task 1 (quadlet `checked_mul`); skip-loop `offset +=` left as-is (provably bounded by input length, pre-existing).
- **No panic on untrusted input** → `skip_*` already return `Result`; new code returns `ParseError`, no `unwrap`/`expect`/`panic`/`as`.
- **Testing categories** → aliasing bug-probe tests (Tasks 3,5,6,7,8), existing round-trip/boundary tests preserved, `nix flake check` cross-feature matrix (Task 10), benchmark (Task 9).
- **CHANGELOG note** → Task 10 Step 3.
