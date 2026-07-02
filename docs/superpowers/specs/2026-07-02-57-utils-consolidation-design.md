# #57 — Kill the "utils" dumping grounds + cohesive Base64 module (design)

> Issue: [#57 · Restructure modules + naming](https://github.com/devrandom-labs/cesr/issues/57)
> Status: approved design, pre-implementation
> Scope: the **remaining** #57 work. PR #60 already delivered part 1 (the
> `src/utils/` → `src/b64/` rename + split into `alphabet`/`int`/`binary`/
> `charset`). This spec covers everything still open.

## Problem (what PR #60 left)

- **Two "utils" dumping grounds remain:**
  - `src/stream/util.rs` — `int_to_b64` (→`Vec<u8>`), `b64_to_int` (→`u64`),
    `b64_char_to_value` (private). All are Base64 primitives wearing a generic
    "util" label.
  - `src/core/utils.rs` — `get_hard_size_from_byte` / `get_hard_size_from_sextet`
    (CESR code-size lookups).
- **The Base64 char→value lookup is triplicated:** `b64::alphabet::b64_char_to_index`
  (char), `stream::util::b64_char_to_value` (byte), and a *third* private copy
  `stream::binary::b64_val` (byte).
- **The integer encoder is triplicated:** the canonical `b64::encode_int`,
  `stream::util::int_to_b64` (thin `Vec` wrapper over it), and a hand-rolled
  `core::indexer::indexer::int_to_b64` (→`String`) that does not even delegate.
- **Inconsistent, non-descriptive names:** `encode_int` / `int_to_b64` /
  `b64_to_int` / `decode_to_int` — four names, overlapping concepts, no
  consistent verb/noun order. `stream/binary.rs` says "binary *what*?".
- **Colliding error-enum names:** `ParseError` exists in both `stream::error` and
  `core::indexer::error`; `ValidationError` exists in both `core::matter::error`
  and `core::indexer::error`.
- **CLAUDE.md's module table still documents `utils`,** not `b64`.

## Decisions (locked during brainstorming)

1. **Error taxonomy:** keep per-module error enums (a legitimate module boundary;
   `terrors::OneOf` already unions them at call sites). Document the rule and
   rename the genuine collisions so no two enums share a name.
2. **`b64` stays a pure, dependency-free primitive leaf.** qb64↔qb2 conversions
   are **code-aware** (they read the hard-size from the leading char/sextet) and
   therefore stay in the framing layer (`stream`), not `b64`. This deviates from
   the issue's literal "b64 owns qb64↔qb2" wording in favour of cleaner layering
   — and mirrors keripy, where `_infil`/`_binfil` live *on* `Matter` (code-aware),
   not in the alphabet primitive.

## § 1 — Naming convention (to document in CLAUDE.md)

**`verb_noun`, the module is the domain qualifier.** The four overlapping integer
names collapse to one symmetric pair:

| before | after |
|---|---|
| `b64::encode_int` | `b64::encode_int` (keep) |
| `b64::decode_to_int` | `b64::decode_int` (rename) |
| `stream::util::int_to_b64` | **removed** — callers use `b64::encode_int(..).into_bytes()` |
| `stream::util::b64_to_int` | **removed** — callers use `b64::decode_int` |
| `b64::encode_binary` | `b64::encode_binary` (keep) |

Rule text for CLAUDE.md: *functions are `verb_noun`; the owning module is the
domain, so no `b64_`/`_b64` prefixes/suffixes inside `b64`. Codec pairs are
`encode_<x>` / `decode_<x>`.*

## § 2 — `b64` module final shape (pure primitive leaf, zero deps)

```
b64/
  alphabet.rs   table + b64_char_to_index (char)
                + NEW b64_byte_to_index (byte)   ← absorbs the 3 byte-lookups
  int.rs        encode_int + decode_int (input widened to AsRef<[u8]>)
  binary.rs     encode_binary (raw bytes → b64 chars)   [unchanged]
  charset.rs    is_b64_url_safe_charset               [unchanged]
  error.rs      b64::Error                            [unchanged]
```

- `alphabet.rs` gains `b64_byte_to_index(b: u8) -> Result<u8, Error>` (the byte
  analogue of `b64_char_to_index`). `stream::util::b64_char_to_value` and
  `stream::binary::b64_val` are deleted and route here.
- `int.rs`: `decode_to_int` → `decode_int`, and its input bound widens from
  `AsRef<str>` to `AsRef<[u8]>` (Base64 is ASCII bytes; this lets the byte
  callers in `stream` use it directly). `encode_int` is unchanged.

## § 3 — Kill the two "utils" files + de-duplicate

- **`src/stream/util.rs` → deleted.**
  - `int_to_b64(v, w)` callers (only `stream::encode`, for the version string;
    the indexer has its *own* local copy handled below) →
    `b64::encode_int(v, w).into_bytes()`.
  - `b64_to_int(&[u8])` callers (`stream::message` version-string parse) →
    `b64::decode_int(..)`, mapping `b64::Error` → `stream::ParseError` at the call
    site (do **not** collapse with `|_|`; preserve the source).
  - `b64_char_to_value` → deleted (was private).
- **`src/core/utils.rs` → deleted.** `get_hard_size_from_byte` /
  `get_hard_size_from_sextet` move to a new `src/core/matter/code/hard.rs`
  (their only caller is `core/matter/code/matter_code.rs`), keeping their exact
  `pub(crate) const fn` signatures.
- **`core::indexer::indexer::int_to_b64`** (hand-rolled `String` encoder) →
  `b64::encode_int`.
- **`src/stream/binary.rs` → renamed `src/stream/qb2.rs`** (it owns qb64↔qb2 —
  the rename kills the generic name and disambiguates from `b64/binary.rs`). Its
  private `b64_val` → `b64::alphabet::b64_byte_to_index`. The `truncate_u32_to_u8`
  / `usize_from_u32` local helpers stay (framing-local, not Base64 primitives).

## § 4 — Error de-collision (keep per-module enums)

Rename only the genuine collisions; document the rule. No behavior change — enum
variants and messages are preserved, only the type names change.

| module | before | after |
|---|---|---|
| `core::indexer::error` | `ParseError` | `IndexerParseError` |
| `core::indexer::error` | `ValidationError` | `IndexerValidationError` |
| `core::matter::error` | `ValidationError` | `MatterValidationError` |
| `core::matter::error` | `ParsingError` | `ParsingError` (already unique) |
| `stream::error` | `ParseError` | `ParseError` (canonical "parse") |

CLAUDE.md rule text: *one error enum per module domain; when two would share a
name, prefix with the domain (`IndexerParseError`, `MatterValidationError`).*

## § 5 — Execution (behavior-preserving, gated)

A series of small, individually-gated commits — each is a pure move/rename/
delegation with **no logic change**, so the full suite (incl. `keripy_diff`
vectors, `cesr-nostd`, `cesr-wasm`) stays green throughout:

1. `b64::alphabet` gains `b64_byte_to_index`; `b64::int` renames `decode_to_int`
   → `decode_int` + widens input to `AsRef<[u8]>`.
2. Delete `stream/util.rs`; reroute its callers to `b64`.
3. Rename `stream/binary.rs` → `stream/qb2.rs`; reroute `b64_val` → `b64`.
4. Delete `core/utils.rs`; move hard-size lookups to `core/matter/code/hard.rs`.
5. Replace `indexer`'s local `int_to_b64` with `b64::encode_int`.
6. Error de-collision renames (§4) + all call-site updates.
7. CLAUDE.md: module table (`utils`→`b64`), naming convention (§1), error rule
   (§4). CHANGELOG: enumerate the breaking public path/type renames.

Public path changes (removed `stream::util::*`, renamed error types, renamed
`stream::binary`→`stream::qb2`, `decode_to_int`→`decode_int`) are **breaking**,
enumerated in the PR body + CHANGELOG (active-dev allows it; consumers pin by
tag).

## Constraints / acceptance

- **Behaviour-preserving.** All keripy vectors + `keripy_diff` + full suite green;
  `nix flake check` green incl. `cesr-nostd` / `cesr-wasm`.
- No lint relaxation; import-style rules hold (no inline `use`, no fully-qualified
  construction).
- No new `#[allow(...)]` without a `reason`, and none added at module/crate level.
- CLAUDE.md module table matches the final tree.

## Out of scope

- Consolidating error enums into shared/crate-wide types (decision 1: keep
  per-module).
- Moving qb64↔qb2 into `b64` (decision 2: it stays code-aware in `stream`).
- Any codec logic change or performance work (see #29 — the seams are already
  optimal at CESR sizes).
