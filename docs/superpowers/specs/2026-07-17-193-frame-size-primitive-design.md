# Design: decode-free `frame_size` primitive (#193 P1)

**Date:** 2026-07-17
**Feeds:** #193 (`cesr-stream` redesign pass) and the cesr substrate.
**Companion:** `docs/193-cross-crate-duplication-audit.md` (the audit that surfaced this).

## Problem

The stream framer (`cesr-stream/src/parse.rs`) re-derives qb64 size math the substrate
already computes, because `cesr` exposes no way to ask **"how many bytes does the primitive
at this stream head span?"** without paying for the full base64 raw-decode + canonicality
validation. Three helpers duplicate substrate logic:

- `matter_full_size` (parse.rs:89) ⟵ `MatterBuilder::from_qualified_base64` size prologue
- `indexer_full_size` (parse.rs:121) ⟵ `IndexerBuilder::from_qb64` size prologue
- `extract_hard` (parse.rs:57) ⟵ counter hard-size table (Counter lacks `from_base64_stream`)

The duplication already regressed a safety invariant: `matter_full_size:108` computes
`(size * 4) + cs` with **bare arithmetic** on the attacker-controlled soft field, where the
substrate original routes the same math through the checked `compute_full_size`
(builder.rs:505). Latent today (`ss ≤ 4` caps `size`), but a direct **Arithmetic Safety**
rule violation.

## Goal / non-goals

**Goal:** give `cesr` a decode-free sizing surface so the framer *calls* it instead of
re-deriving it, killing all three dups and closing the safety gap for free.

**Non-goals (deferred):**
- **Piece 2 — consumed-length on decode.** Making `from_qualified_base64` return
  `(Matter, consumed)` to erase `read_matter`'s double-compute is a separate, later change.
  **Builder signatures stay unchanged here.**
- No wire-behavior change. The keripy differential corpus + spine byte-identity tests remain
  law; `frame_size` must return exactly what the deleted helpers returned.

## Design — Grain A: the code owns sizing

The code enums already own "read code from stream" (`MatterCode::from_base64_stream`) and
"know my sizes" (`get_sizage`/`get_xizage`, `hard_size`/`soft_size`/`full_size`). Sizing
belongs there. The three types are **not uniform** — the primitive matches each type's shape:

| Code type | New public surface | Serves | Rationale |
|---|---|---|---|
| `MatterCode` | `frame_size(stream: &[u8]) -> Result<usize, MatterBuildError>` | `skip_matter`, `read_matter` pre-size | variable body ⇒ needs computed `fs` |
| `IndexedSigCode` | `frame_size(stream: &[u8]) -> Result<usize, IndexerParseError>` | `skip_indexer` | variable body ⇒ needs computed `fs` |
| `CounterCodeV1` / `CounterCodeV2` | `from_base64_stream(stream: &[u8]) -> Result<Self, CounterCodeError>` | `read_counter_v1/v2`, `skip_counter` | no body; code ⇒ `full_size()` already known. Closes the Matter/Counter asymmetry. |

Counter gets `from_base64_stream` (**not** `frame_size`): a counter has no variable body, so
its span is `full_size()` (already `hard_size + soft_size`) the moment the code is known. Its
only gap was reading the code off the stream — the exact method `MatterCode` already has.

### `frame_size` semantics (Matter / Indexer)

Decode-free full qb64 character size of the primitive at the stream head:
1. Read the hard code from the stream head (`from_base64_stream` / `hardage` + `from_hard`).
2. `get_sizage()` / `get_xizage()` → `hs`, `ss`, `cs = hs + ss`.
3. If `SizeType::Fixed(n)` → `fs = n`. Else read the soft field `stream[hs..cs]`, strip
   `xs`, `decode_int`, and `fs = compute_full_size(size, cs)` (**checked**).
4. Insufficient-length at any step → the type's existing truncation error variant.

It does **not** base64-decode the raw body and does **not** validate pad/lead bits — that is
the decoder's job. This is the one capability the substrate was missing.

### Internal DRY — one size implementation inside cesr

Adding `frame_size` must not create a *third* copy of the prologue inside cesr. Refactor so
there is exactly one checked sizer per family:

- Lift the size prologue out of `from_qualified_base64` into a `pub(crate)` method
  `MatterCode::frame_size_of(&self, stream) -> Result<usize, _>` that takes an
  already-known code. `frame_size` (associated) = `from_base64_stream(stream)?` then
  `frame_size_of`. `from_qualified_base64` reads the code once, calls `frame_size_of`, then
  decodes — no double code-read on the decode path.
- Same shape for `IndexedSigCode` ↔ `IndexerBuilder::from_qb64`.
- Relocate `compute_full_size` (today private in `builder.rs`) to a shared `pub(crate)`
  location next to the sizing logic so both the decoder and `frame_size` call the one checked
  impl. This is what makes the checked arithmetic flow to every caller.

### Errors

`frame_size` is a two-domain op (parse the header + validate the computed size), so it
returns the existing union rather than a fresh type: `MatterBuildError`
(`Parsing ∪ Validation`, overflow ⇒ `ValidationError::SizeOverflow`) for Matter, and
`IndexerParseError` for Indexer (which already unions its parse + validation cases). Counter
`from_base64_stream` is single-domain (parse only — fixed size, no overflow) and returns the
bare `CounterCodeError`. No new error enums. `cesr-stream` maps these into `ParseError` at
the call site as it already does for `from_qualified_base64` / `from_qb64`.

## `cesr-stream` migration (the payoff)

```
skip_matter   -> self.take(MatterCode::frame_size(rem)?)
skip_indexer  -> self.take(IndexedSigCode::frame_size(rem)?)
read_counter_v1 -> let code = CounterCodeV1::from_base64_stream(rem)?;  // then soft decode
skip_counter  -> read code (V1 else V2) via from_base64_stream; take(code.full_size())
```

Deleted: `extract_hard`, `matter_full_size`, `indexer_full_size`. `read_matter` keeps its
`frame_size` pre-size call (now the cesr checked one) + decode until Piece 2 lands.

**Safety fix falls out:** the migrated paths route through `compute_full_size`, so the bare
`(size*4)+cs` / `index*4+cs` disappears with the deleted helpers.

## Testing (CLAUDE.md categories)

1. **Round-trip / equivalence:** for every code in the Matter/Indexer tables,
   `frame_size(qb64) == qb64.len()` of a freshly-encoded primitive, and equals the byte count
   `from_qualified_base64` / `from_qb64` consume. This is the byte-identity guard against
   drift from the deleted helpers.
2. **Defensive boundary:** truncated stream at each step (empty, `< hs`, `< cs`, `< fs`) →
   the correct truncation error, never a panic; unknown code → typed error; non-UTF-8 soft →
   typed error.
3. **Overflow bug-probe:** a `frame_size` call whose decoded `size` would overflow `usize*4`
   returns `SizeOverflow` (fails while unchecked arithmetic exists; passes once checked). Since
   real tables cap `ss ≤ 4`, this is exercised via a `#[cfg(test)]` code/sizage stub or a
   direct `compute_full_size` boundary test (`MAX-1`, `MAX`).
4. **Cross-feature + no_std/wasm:** `frame_size` lives in the `core` feature and allocates
   nothing on the success path; it is available under the same feature/alloc requirements as
   the existing `from_base64_stream` / `from_qualified_base64` it shares code with (error
   variants may carry `String`, as they already do today). Verify it compiles and runs under
   the no_std + wasm gates.
5. **Differential:** the keripy corpus + spine byte-identity tests must stay green through the
   `cesr-stream` migration — the acceptance gate for "no wire change."

## Ratchet / budget impact

`frame_size` and `from_base64_stream` are **methods/associated fns on types**, not free
functions — the `cesr` free-fn budgets (`core = 0`) are unaffected. `cesr-stream` deletes
three module-private (`fn`, non-`pub`) helpers; its free-`pub fn` budget (2) is unchanged but
the deletion is recorded. Re-baseline only if a counted number actually moves.

## Open sub-decisions (call out in the plan, not blockers)

- **Name:** `frame_size` chosen. (`qb64_size` was the alternative — rejected to keep one name
  that also reads for a future qb2 variant; revisit if a qb2 sizer is added.)
- **Counter symmetry:** we add `from_base64_stream` to `CounterCodeV1`/`V2`. A future cleanup
  could give Counter its own `frame_size` convenience (`= from_base64_stream(s)?.full_size()`)
  for call-site uniformity, but it is not needed now (YAGNI).
