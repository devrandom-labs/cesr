# #57 Utils Consolidation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Kill the two remaining "utils" dumping grounds (`stream/util.rs`, `core/utils.rs`), collapse the triplicated Base64 primitives into `b64`, de-collide the error-enum names, and document the naming + error rules — all behaviour-preserving.

**Architecture:** `b64` stays a pure, dependency-free primitive leaf owning the alphabet lookup + integer/binary codecs. Code-aware qb64↔qb2 stays in `stream` (renamed `qb2.rs`). CESR code-size lookups move next to their only caller in `core/matter/code`. Every task is a pure move/rename/delegation with no logic change, so the full suite (incl. `keripy_diff`, `cesr-nostd`, `cesr-wasm`) stays green throughout.

**Tech Stack:** Rust 2024, no_std/alloc. Gate: `nix flake check`. Intermediate checks via `nix develop --command cargo ...`. New/moved files MUST be `git add`-ed before `nix flake check` (nix builds from the git tree).

**Spec:** `docs/superpowers/specs/2026-07-02-57-utils-consolidation-design.md`

---

## File Structure

- **Modify** `src/b64/alphabet.rs` — replace `b64_char_to_index(char)` with `b64_byte_to_index(u8)`; convert its unit tests.
- **Modify** `src/b64/int.rs` — `decode_to_int` → `decode_int`, input `AsRef<[u8]>`, iterate bytes.
- **Modify** `src/b64/mod.rs` — re-export `decode_int` (was `decode_to_int`).
- **Modify** ~15 `decode_to_int` call sites → `decode_int` (matter builder, indexer builder, stream parse/unwrap).
- **Delete** `src/stream/util.rs`; **modify** `src/stream/mod.rs`, `src/stream/encode.rs`, `src/stream/message.rs`.
- **Rename** `src/stream/binary.rs` → `src/stream/qb2.rs`; **modify** `src/stream/mod.rs`.
- **Delete** `src/core/utils.rs`; **create** `src/core/matter/code/hard.rs`; **modify** `src/core/mod.rs`, `src/core/matter/code/mod.rs`, `src/core/matter/code/matter_code.rs`.
- **Modify** `src/core/indexer/indexer.rs` — local `int_to_b64` delegates to `b64::encode_int`.
- **Rename** `indexer::error::{ParseError, ValidationError}` → `{IndexerParseError, IndexerValidationError}`; **modify** `src/core/indexer/**` + `src/stream/error.rs`.
- **Modify** `CLAUDE.md`, `CHANGELOG.md`.

---

## Task 1: `b64` byte-lookup primitive + `decode_int`

**Files:**
- Modify: `src/b64/alphabet.rs`
- Modify: `src/b64/int.rs`
- Modify: `src/b64/mod.rs`
- Modify (rename call sites): `src/core/matter/builder.rs`, `src/core/indexer/builder.rs`, `src/stream/parse.rs`, `src/stream/unwrap.rs`

- [ ] **Step 1: Replace `b64_char_to_index` with `b64_byte_to_index` in `alphabet.rs`**

Replace the existing `b64_char_to_index` fn (lines ~35-48) with:

```rust
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — module is private but the lookup is used across sibling modules (stream, core)"
)]
pub(crate) fn b64_byte_to_index(b: u8) -> Result<u8, Error> {
    let idx = B64_REVERSE[usize::from(b)];
    if idx == 255 {
        return Err(Error::InvalidBase64Char(char::from(b)));
    }
    Ok(idx)
}
```

(Delete the old `#[allow(...)]` block that sat above `b64_char_to_index` and the fn itself. `b64_index_to_char` below it is unchanged.)

- [ ] **Step 2: Convert the `char_to_index_*` unit tests to bytes**

In `alphabet.rs` `mod tests`, replace each `char_to_index_*` test that calls `b64_char_to_index('X')` with the byte form. Replace the whole `// --- b64_char_to_index ---` test block with:

```rust
    // --- b64_byte_to_index ---

    #[test]
    fn byte_to_index_a_is_0() {
        assert_eq!(b64_byte_to_index(b'A').unwrap(), 0);
    }

    #[test]
    fn byte_to_index_z_upper_is_25() {
        assert_eq!(b64_byte_to_index(b'Z').unwrap(), 25);
    }

    #[test]
    fn byte_to_index_a_lower_is_26() {
        assert_eq!(b64_byte_to_index(b'a').unwrap(), 26);
    }

    #[test]
    fn byte_to_index_9_is_61() {
        assert_eq!(b64_byte_to_index(b'9').unwrap(), 61);
    }

    #[test]
    fn byte_to_index_hyphen_is_62() {
        assert_eq!(b64_byte_to_index(b'-').unwrap(), 62);
    }

    #[test]
    fn byte_to_index_underscore_is_63() {
        assert_eq!(b64_byte_to_index(b'_').unwrap(), 63);
    }

    #[test]
    fn byte_to_index_rejects_plus() {
        assert_eq!(b64_byte_to_index(b'+').unwrap_err(), Error::InvalidBase64Char('+'));
    }

    #[test]
    fn byte_to_index_rejects_slash() {
        assert_eq!(b64_byte_to_index(b'/').unwrap_err(), Error::InvalidBase64Char('/'));
    }

    #[test]
    fn byte_to_index_rejects_space() {
        assert_eq!(b64_byte_to_index(b' ').unwrap_err(), Error::InvalidBase64Char(' '));
    }
```

(The `index_to_char_*`, roundtrip, and table-correctness tests below are unchanged. Note the roundtrip test `index_char_roundtrip_all_64_values` calls `b64_char_to_index(c)` — update its inner call to `b64_byte_to_index(u8::try_from(c as u32).unwrap())`; simpler: replace that test body with a byte roundtrip:)

```rust
    #[test]
    fn index_byte_roundtrip_all_64_values() {
        for i in 0u8..64 {
            let c = b64_index_to_char(i).unwrap();
            let j = b64_byte_to_index(c as u8).unwrap();
            assert_eq!(i, j, "roundtrip failed for index {i}, char {c}");
        }
    }
```

(If the test module lacks `clippy::as_conversions` allow for `c as u8`, it already has `#![allow(clippy::as_conversions, ...)]` at the `mod tests` head — verify and keep.)

- [ ] **Step 3: Switch `decode_to_int` → `decode_int` (bytes) in `int.rs`**

In `src/b64/int.rs`, change the import on line 1 from `alphabet::b64_char_to_index` to `alphabet::b64_byte_to_index`:

```rust
use super::{alphabet::B64_ALPHABET, alphabet::b64_byte_to_index, error::Error};
```

Replace the `decode_to_int` fn with:

```rust
/// Decodes a Base64 URL-safe byte string into an unsigned integer of type `N`.
///
/// # Errors
///
/// Returns [`Error::InvalidBase64Char`] if any byte is not a valid URL-safe
/// Base64 character, or [`Error::IntegerOverflow`] if the decoded value exceeds
/// the capacity of `N`.
pub fn decode_int<T, N>(stream: T) -> Result<N, Error>
where
    T: AsRef<[u8]>,
    N: PrimInt + Unsigned + CheckedShl + 'static,
{
    let mut out: N = N::zero();
    for &b in stream.as_ref() {
        let b64_val = b64_byte_to_index(b)?;
        let wide_val = N::from(b64_val).ok_or(Error::IntegerOverflow)?;
        if out.leading_zeros() < 6 {
            return Err(Error::IntegerOverflow);
        }
        out = out
            .checked_shl(6)
            .and_then(|shifted| shifted.checked_add(&wide_val))
            .ok_or(Error::IntegerOverflow)?;
    }
    Ok(out)
}
```

Update any `decode_to_int` references inside `int.rs`'s own `mod test` to `decode_int` (the test calls pass string literals like `"C"` which satisfy `AsRef<[u8]>`).

- [ ] **Step 4: Re-export the renamed fn in `b64/mod.rs`**

Change line 28 of `src/b64/mod.rs`:

```rust
pub use int::{decode_int, encode_int};
```

- [ ] **Step 5: Rename the ~13 external `decode_to_int` call sites**

Replace `decode_to_int` with `decode_int` at each (imports + calls):
- `src/core/matter/builder.rs`: line 8 import, lines 130, 250.
- `src/core/indexer/builder.rs`: line 17 import, lines 121, 129, 143, 248.
- `src/stream/parse.rs`: line 1 import, lines 71, 167, 214, 264, 281.
- `src/stream/unwrap.rs`: line 132 (`crate::b64::decode_int`).

(These all pass `&str`/`String`, which satisfy `AsRef<[u8]>`.)

- [ ] **Step 6: Verify**

Run: `nix develop --command cargo nextest run --all-features b64:: keripy_diff`
Expected: PASS (alphabet byte tests + int codec + all differential vectors).

- [ ] **Step 7: Commit**

```bash
git add src/b64/ src/core/matter/builder.rs src/core/indexer/builder.rs src/stream/parse.rs src/stream/unwrap.rs
git commit -m "refactor(#57): b64 byte lookup + decode_int (was decode_to_int)

b64_char_to_index -> b64_byte_to_index (the single byte lookup primitive);
decode_to_int -> decode_int with AsRef<[u8]> input. Behaviour-preserving."
```

---

## Task 2: Delete `stream/util.rs`, reroute to `b64`

**Files:**
- Delete: `src/stream/util.rs`
- Modify: `src/stream/mod.rs`, `src/stream/encode.rs`, `src/stream/message.rs`

- [ ] **Step 1: Reroute `int_to_b64` in `stream/encode.rs`**

Remove the import `use crate::stream::util::int_to_b64;` (line 51). Add `use crate::b64::encode_int;` at the top (alongside the other `crate::b64` imports). Replace the five `int_to_b64(x, w)` calls in `encode_version_string_v2` (lines ~682-687) with `encode_int(x, w).into_bytes()` — but `encode_int` needs `NonZeroUsize` widths. Since all five widths are the literals `1`, `2`, `1`, `2`, `4`, wrap each: define a tiny local helper at the top of `encode.rs`:

```rust
fn encode_int_bytes(value: u64, width: usize) -> Vec<u8> {
    match NonZeroUsize::new(width) {
        Some(w) => encode_int(value, w).into_bytes(),
        None => Vec::new(),
    }
}
```

and replace the five `int_to_b64(...)` calls with `encode_int_bytes(...)` (identical signature to the old `int_to_b64`). `NonZeroUsize` is already imported in `encode.rs` (line 7).

- [ ] **Step 2: Reroute `b64_to_int` in `stream/message.rs`**

Remove `use crate::stream::util::b64_to_int;` (line 8). Add `use crate::b64::decode_int;`. Replace the three helpers' `b64_to_int(input)?` calls with `decode_int::<_, u64>(input).map_err(|e| ParseError::Malformed(format!("invalid B64: {e}")))?`. Concretely, `b64_to_u8` becomes:

```rust
fn b64_to_u8(input: &[u8], field: &str) -> Result<u8, ParseError> {
    let raw: u64 = decode_int(input).map_err(|e| ParseError::Malformed(format!("invalid B64: {e}")))?;
    u8::try_from(raw).map_err(|_| ParseError::Malformed(format!("{field} out of range")))
}
```

Apply the same change to `b64_to_u16` (→`u16::try_from`) and `b64_to_u32` (→`u32::try_from`). Ensure `format` is imported (it is, line 1).

- [ ] **Step 2b: Widen `decode_int` overflow error into `ParseError`**

The old `b64_to_int` returned `ParseError::Malformed("B64 integer overflow")` on overflow. `decode_int` returns `Error::IntegerOverflow`, which the `map_err` above turns into `ParseError::Malformed("invalid B64: Integer Overflow: ...")` — a preserved-source message. This is acceptable (still `ParseError::Malformed`, source text preserved).

- [ ] **Step 3: Remove the module declaration**

In `src/stream/mod.rs`, delete lines 31-32:

```rust
#[doc(hidden)]
pub mod util;
```

- [ ] **Step 4: Delete the file**

```bash
git rm src/stream/util.rs
```

(This drops `stream::util`'s own test module — the `int_to_b64` keripy vectors. Those exact width/value cases are already covered by `b64::int`'s `encode_int` tests; no coverage is lost. If any case is unique, port it into `src/b64/int.rs`'s test module first.)

- [ ] **Step 5: Verify**

Run: `nix develop --command cargo nextest run --all-features stream:: keripy_diff`
Expected: PASS (version-string encode/parse round-trips + differential vectors).

- [ ] **Step 6: Commit**

```bash
git add src/stream/
git commit -m "refactor(#57): delete stream/util.rs, route int/b64 codecs through b64

int_to_b64 -> b64::encode_int; b64_to_int -> b64::decode_int. Kills the
second 'utils' dumping ground."
```

---

## Task 3: Rename `stream/binary.rs` → `stream/qb2.rs`, drop the third `b64_val`

**Files:**
- Rename: `src/stream/binary.rs` → `src/stream/qb2.rs`
- Modify: `src/stream/mod.rs`

- [ ] **Step 1: Rename the file**

```bash
git mv src/stream/binary.rs src/stream/qb2.rs
```

- [ ] **Step 2: Replace the private `b64_val` with the shared lookup**

In `src/stream/qb2.rs`, delete the private `fn b64_val(byte: u8) -> Result<u8, ParseError>` (lines ~91-...). Add at the top: `use crate::b64::alphabet::b64_byte_to_index;`. Replace every `b64_val(x)?` call with `b64_byte_to_index(x).map_err(|_e| ParseError::Malformed("invalid qb64 character".into()))?` — matching the old error domain (`b64_val` returned `ParseError::Malformed`). If `b64_val` was called at multiple sites, apply to each. Keep `truncate_u32_to_u8` / `usize_from_u32` (framing-local helpers, not Base64 primitives).

- [ ] **Step 3: Update the module declaration + re-export**

In `src/stream/mod.rs`: change line 14 `pub mod binary;` → `pub mod qb2;` (keep the doc comment, reword to `/// qb64 <-> qb2 (text <-> binary) conversion.`). Change line 43 `pub use binary::{qb2_to_qb64, qb64_to_qb2};` → `pub use qb2::{qb2_to_qb64, qb64_to_qb2};`.

(The public path `stream::qb64_to_qb2` / `stream::qb2_to_qb64` is unchanged — those come from the root re-export. Only the internal module name changes. `keripy_diff` imports via the root re-export and is unaffected.)

- [ ] **Step 4: Verify**

Run: `nix develop --command cargo nextest run --all-features qb2 keripy_diff`
Expected: PASS (qb64↔qb2 round-trips + differential vectors).

- [ ] **Step 5: Commit**

```bash
git add src/stream/
git commit -m "refactor(#57): rename stream/binary.rs -> stream/qb2.rs, drop 3rd b64_val

qb2.rs owns qb64<->qb2; its private b64_val is deleted in favour of
b64::alphabet::b64_byte_to_index. Public stream::qb64_to_qb2 path unchanged."
```

---

## Task 4: Delete `core/utils.rs`, move code-size lookups into `core/matter/code`

**Files:**
- Delete: `src/core/utils.rs`
- Create: `src/core/matter/code/hard.rs`
- Modify: `src/core/mod.rs`, `src/core/matter/code/mod.rs`, `src/core/matter/code/matter_code.rs`

- [ ] **Step 1: Create `core/matter/code/hard.rs`**

Create `src/core/matter/code/hard.rs` with the two fns moved verbatim from `core/utils.rs` (including their `#[allow(clippy::redundant_pub_crate, reason = ...)]`):

```rust
//! Hard (code) size lookups: leading Base64 char / binary sextet -> code size.

/// Returns the hard (code) size in characters for a leading Base64 byte.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — module is private but function is used across sibling modules"
)]
pub(crate) const fn get_hard_size_from_byte(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' | b'a'..=b'z' => Some(1),
        b'0' | b'4' | b'5' | b'6' => Some(2),
        b'1' | b'2' | b'3' | b'7' | b'8' | b'9' => Some(4),
        _ => None,
    }
}

/// Returns the hard (code) size in characters for a leading binary sextet.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — module is private but function is used across sibling modules"
)]
pub(crate) const fn get_hard_size_from_sextet(b: u8) -> Option<u8> {
    match b {
        0..=51 => Some(1),
        52 | 56 | 57 | 58 => Some(2),
        53 | 54 | 55 | 59 | 60 | 61 => Some(4),
        _ => None,
    }
}
```

- [ ] **Step 2: Register the module**

In `src/core/matter/code/mod.rs`, add (alphabetically, near the other `mod` lines):

```rust
pub(crate) mod hard;
```

- [ ] **Step 3: Update the caller's import**

In `src/core/matter/code/matter_code.rs`, change line 9 from
`use crate::core::utils::{get_hard_size_from_byte, get_hard_size_from_sextet};` to
`use super::hard::{get_hard_size_from_byte, get_hard_size_from_sextet};`.

- [ ] **Step 4: Remove the old module + file**

In `src/core/mod.rs`, delete line 23 `mod utils;`. Then:

```bash
git rm src/core/utils.rs
```

- [ ] **Step 5: Verify**

Run: `nix develop --command cargo nextest run --all-features core::matter keripy_diff`
Expected: PASS (matter code parsing round-trips + differential vectors).

- [ ] **Step 6: Commit**

```bash
git add src/core/
git commit -m "refactor(#57): move code-size lookups to core/matter/code/hard.rs

Deletes the third 'utils' dumping ground (core/utils.rs); co-locates the
hard-size lookups with their only caller, matter_code.rs."
```

---

## Task 5: Indexer's local `int_to_b64` delegates to `b64::encode_int`

**Files:**
- Modify: `src/core/indexer/indexer.rs`

- [ ] **Step 1: Replace the hand-rolled body**

In `src/core/indexer/indexer.rs`, replace the local `int_to_b64` fn (lines ~19-33) with a thin delegation:

```rust
fn int_to_b64(value: u32, len: usize) -> String {
    match NonZeroUsize::new(len) {
        Some(w) => encode_int(value, w),
        None => String::new(),
    }
}
```

Change the import on line 13 from `use crate::b64::alphabet::B64_ALPHABET;` to `use crate::b64::encode_int;`. Add `use core::num::NonZeroUsize;` if not already imported. (This removes the last hand-rolled Base64-integer loop; `encode_int` produces the identical left-'A'-padded output.)

- [ ] **Step 2: Verify**

Run: `nix develop --command cargo nextest run --all-features indexer keripy_diff::indexer`
Expected: PASS (indexer index/ondex encode round-trips + differential vectors).

- [ ] **Step 3: Commit**

```bash
git add src/core/indexer/indexer.rs
git commit -m "refactor(#57): indexer int_to_b64 delegates to b64::encode_int

Removes the last hand-rolled Base64 integer encoder."
```

---

## Task 6: Error de-collision — rename `indexer`'s two enums

**Files:**
- Modify: `src/core/indexer/error.rs`, `src/core/indexer/**` (all references), `src/stream/error.rs`

- [ ] **Step 1: Rename the type definitions**

In `src/core/indexer/error.rs`: rename `pub enum ParseError` → `pub enum IndexerParseError` and `pub enum ValidationError` → `pub enum IndexerValidationError`. Update every `Self::` / internal reference and the `impl From<...> for ParseError` blocks to the new names.

- [ ] **Step 2: Update all references within `src/core/indexer/`**

Replace `ParseError` → `IndexerParseError` and `ValidationError` → `IndexerValidationError` throughout `src/core/indexer/` (builder.rs, indexer.rs, code.rs, mod.rs, any re-exports). Watch word boundaries: do **not** rewrite `IndexerParseError` again. Update `use` imports, `OneOf<(ParseError, ValidationError)>` tuples, `ParseError::from(e)` calls, and any `pub use error::{ParseError, ValidationError}` re-exports in `indexer/mod.rs`.

- [ ] **Step 3: Update the `stream/error.rs` cross-reference**

In `src/stream/error.rs`, the aliases on lines 3-4 become direct imports (the alias is no longer needed):

```rust
use crate::core::indexer::error::IndexerParseError;
use crate::core::indexer::error::IndexerValidationError;
```

The rest of `stream/error.rs` already uses the names `IndexerParseError` / `IndexerValidationError`, so no further change there.

- [ ] **Step 4: Verify (build first — this surfaces every missed reference)**

Run: `nix develop --command cargo build --all-features`
Expected: builds clean. If the compiler flags a missed `ParseError`/`ValidationError` in the indexer tree or a consumer, fix it (rename to the `Indexer*` form).

Run: `nix develop --command cargo nextest run --all-features indexer keripy_diff`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/indexer/ src/stream/error.rs
git commit -m "refactor(#57)!: rename indexer ParseError/ValidationError -> Indexer*

BREAKING: de-collides the two error-enum name clashes (stream::ParseError and
matter::ValidationError are now unique). Variants and messages unchanged."
```

---

## Task 7: Docs — CLAUDE.md module table + naming/error rules + CHANGELOG

**Files:**
- Modify: `CLAUDE.md`, `CHANGELOG.md`

- [ ] **Step 1: Update the CLAUDE.md module table**

In `CLAUDE.md`, in the Modules & Features table, change the `utils` row to `b64`:
- `| `b64` | `b64` | — | `cesr-utils` |`
- In the `core` and `stream` "Internal deps" cells, change `utils` → `b64`.
- Update the "Default features" line: `["std", "core", "utils"]` → `["std", "core", "b64"]`.

- [ ] **Step 2: Add the naming + error conventions to CLAUDE.md**

Under the "Import Style" or a new "Naming Conventions" subsection, add:

```markdown
## Naming Conventions

- Functions are `verb_noun`; the owning module is the domain qualifier — no
  redundant `b64_`/`_b64` affixes inside `b64`. Codec pairs are
  `encode_<x>` / `decode_<x>` (e.g. `b64::encode_int` / `b64::decode_int`).
- One error enum per module domain. When two modules would share an error name,
  prefix with the domain (e.g. `IndexerParseError`).
```

- [ ] **Step 2b: Fix stale `utils` mentions in CLAUDE.md prose**

Search `CLAUDE.md` for other `utils` references tied to the module (not `test-utils`, which stays) and update to `b64` where they describe the module.

- [ ] **Step 3: Add the CHANGELOG entry**

Under `## [Unreleased]` in `CHANGELOG.md`:

```markdown
### Changed

- **refactor (#57)!:** Killed the remaining "utils" dumping grounds. `stream::util`
  is removed (its `int_to_b64`/`b64_to_int` now route through `b64::encode_int`/
  `b64::decode_int`); `core::utils`'s code-size lookups moved to
  `core::matter::code`; `stream::binary` is renamed `stream::qb2` (public
  `stream::qb64_to_qb2`/`qb2_to_qb64` paths unchanged). The single Base64 byte
  lookup is `b64::alphabet::b64_byte_to_index`.

### Breaking

- `b64::decode_to_int` → `b64::decode_int` (input bound widened to `AsRef<[u8]>`).
- `core::indexer::error::{ParseError, ValidationError}` →
  `{IndexerParseError, IndexerValidationError}`.
- `stream::util` module removed; `stream::binary` module renamed `stream::qb2`
  (re-exported functions keep their `stream::` paths).
```

- [ ] **Step 4: Full gate**

```bash
git add -A
nix flake check
```

Expected: all green (clippy, nextest, wasm, nostd, doctest, audit, deny, fmt, taplo). New/moved files are staged so nix sees them.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md CHANGELOG.md
git commit -m "docs(#57): update module table, naming + error conventions, CHANGELOG"
```

- [ ] **Step 6: Push + PR + close-out**

```bash
git push -u origin refactor/57-consolidate-utils
gh pr create --fill --base main
```

Enumerate the breaking renames in the PR body; add the PR to CESR Project #5; the PR closes #57 on merge (or tick the issue's acceptance boxes).

---

## Self-Review Notes

- **Spec coverage:** §1 naming → Tasks 1/2/5 + 7; §2 b64 shape → Task 1; §3 kill utils → Tasks 2/3/4/5; §4 error de-collision → Task 6; §5 execution/docs → Task 7. All spec sections map to a task.
- **Type consistency:** `b64_byte_to_index` (T1) is the only lookup used by qb2 (T3) and message (T2). `decode_int(AsRef<[u8]>)` (T1) is called by T2's `stream::message`. `encode_int` (existing) used by T2 (`encode_int_bytes`) and T5 (indexer). `IndexerParseError`/`IndexerValidationError` (T6) match the names already aliased in `stream/error.rs`.
- **No logic change:** every task is a move/rename/delegation; correctness is guarded by the unchanged `keripy_diff` vectors + full suite at each step.
- **Arithmetic/allocation:** no new arithmetic or allocation paths introduced; `encode_int`/`decode_int` internals are unchanged apart from `decode_int` iterating bytes instead of chars (equivalent for ASCII Base64).
