# P1.3 · Zero-copy stream parsing — design

- **Issue:** [#30](https://github.com/devrandom-labs/cesr/issues/30) (Phase 1 · Zero-copy & performance)
- **Date:** 2026-07-02
- **Status:** design approved, pre-implementation
- **Research:** 5-track parallel sweep (parser-arch, lifetimes, keripy, bytes-prior-art, codebase-audit) → synthesis. Findings posted as an issue comment.

## Problem

The `stream/` group parser copies the qb64 text of every attachment group into a
fresh allocation before iterating it. Each group parser (e.g.
`controller_idx_sigs::parse`) takes `&[u8]`, uses the size-only `skip_*` helpers to
find the frame boundary, then does `Bytes::copy_from_slice(&input[..offset])`. There
are **29** such `copy_from_slice` sites across `src/stream/` (21 files, excluding
tests). A message with *G* attachment groups therefore performs ≥*G* full-frame
copies of data it already holds.

This is pure overhead: `bytes::Bytes` is already a dependency, `GroupIter` is already
backed by `Bytes`, and the async codec already demonstrates the correct zero-copy
pattern (`buf.split_to(total).freeze()` then `.slice(counter_size..)`,
`src/stream/codec.rs:163-164`). The group parsers copy only because their entry type
is `&[u8]` rather than a shareable `Bytes`.

## What "zero-copy" means here (the hard wall)

Base64 **must** be decoded to binary, and the decoded bytes are a fresh allocation —
they cannot borrow the encoded input (`src/core/matter/builder.rs`: `raw` ends as
`Cow::Owned(buf)`). So zero-copy for CESR decomposes into:

- **(a) never copy the qb64 text** — the target of this issue.
- **(b) let consumers borrow `raw`/`soft`** — only `soft` (0–4 bytes) is borrowable;
  see *Out of scope* below.
- **(c) lazy-decode** — blocked by the hard wall; `raw` is always newly allocated.

This issue delivers **(a)** and nothing else. The `raw` allocations from base64 decode
are load-bearing and stay.

## Decision

| Dimension | Decision | Rationale |
|---|---|---|
| **Parser** | Keep the **hand-rolled** cursor parser | The bottleneck is copies, not parse logic. `winnow`/`nom` would add a dependency + audit surface and require re-proving no_std+alloc and wasm32, for zero throughput gain. (4 of 5 research tracks concur.) |
| **Ownership** | **`bytes::Bytes` + `.slice()`** as the sole vehicle | `Bytes` clone/slice are documented O(1) refcount ops, and `Bytes` is `'static` — so **no lifetime parameter leaks into the public API**. `raw` stays `Cow::Owned` (hard wall). |
| **Entry API** | **Copy once at the outermost `&[u8]` boundary; non-breaking public signature.** A `Bytes`-accepting core carries the codec path at zero copies. | Keeps the ergonomic `&[u8]` public API; a caller holding only a borrowed slice pays exactly one copy (down from ~*N*); the codec (which owns `BytesMut`) reaches true zero-copy. |

## Architecture

The internal parsing engine becomes entirely `Bytes`-slice based (0 copies); the
single copy for the sync path happens once at the outermost boundary.

### Layering

```
public  parse_group(&[u8]) -> (CesrGroup, &[u8])          [1 copy at entry, unchanged sig]
          └─ copies input into Bytes ONCE, calls core, maps consumed→remaining slice
core    parse_group_bytes(Bytes) -> (CesrGroup, usize)    [0 copies — slices only]
          └─ parse_counter → dispatch → per-group parser
group   <group>::parse(buf: Bytes, at: usize, count) -> (Group, usize)   [.slice(), no copy]
          └─ skip_* loop computes element boundaries; Group holds buf.slice(range)
codec   Decoder::decode  →  parse_group_bytes(frozen.slice(..))          [0 copies — already Bytes]
```

### Copy-once-per-stream

The copy must land at the **outermost** boundary, not inside each `parse_group` — a
message with *G* groups calls `parse_group` *G* times, so a per-call copy saves
nothing. Therefore:

- The multi-group drivers — the `Groups` / `GroupsV2` iterators and `parse_message` —
  copy the attachment region into `Bytes` **once**, then drive `parse_group_bytes` per
  group, slicing each from the shared buffer.
- Standalone `parse_group(&[u8])` copies once per call (correct for a single-group
  call); it is not on the multi-group hot path.
- The codec path never copies: it already owns `BytesMut`, calls `.split_to().freeze()`,
  and hands a `Bytes` slice straight to `parse_group_bytes`.

### Components changed

1. **`src/stream/parse.rs`** — `skip_matter`/`skip_indexer`/`skip_counter` lose their
   `#[allow(dead_code)]` (all three must be wired, or the clippy gate fails). Boundary
   arithmetic uses `checked_*` per the arithmetic-safety rule. They already return
   `Result<usize, ParseError>` — no panic on untrusted input.
2. **`src/stream/group/*` (each group parser)** — signature changes from
   `parse(&[u8], count) -> (Group, &[u8])` to a `Bytes`-based core that slices instead
   of `copy_from_slice`. The `skip_*` loop that finds the frame boundary stays; only
   the final `copy_from_slice` becomes `.slice(range)`.
3. **`src/stream/group/quadlet_group.rs`** — the two `copy_from_slice` sites become
   `.slice(...)`.
4. **`src/stream/group/mod.rs`** — add `parse_group_bytes(Bytes)` core; `parse_group`
   becomes the copy-once `&[u8]` wrapper. `dispatch_v1`/`dispatch_v2` thread `Bytes`.
5. **`src/stream/group/iter.rs`** — `GroupIter` already holds `Bytes`; ensure it slices
   the single parent buffer and does not clone per element.
6. **`src/stream/unwrap.rs`** — `unwrap_generic_group` (lines 45, 77) threads the
   parent `Bytes` through recursion via `.slice()` instead of `copy_from_slice`.
7. **`src/stream/codec.rs`** — call `parse_group_bytes` with the already-frozen
   `Bytes` slice (no behavioral change; it already produces `Bytes`).

Group **types** in `types.rs` keep holding `raw: Bytes` — they simply now hold a
`.slice()` view sharing the parent buffer instead of an independently-owned copy. No
public type gains a lifetime parameter.

## Out of scope (deferred, benchmark-gated)

- **Borrowed `Matter<'a>` / `Indexer<'a>` soft field.** The only borrowable field is
  `soft` (0–4 bytes), which the audit shows is <<1% of the base64-decode cost that
  dominates every primitive. Making it borrowed would ripple a **breaking** lifetime
  parameter through `CesrGroup`/`Groups`/`CesrMessage` for a negligible win. Revisit
  only if the P0.1 benchmark harness shows soft-clone cost matters. `parse_matter`/
  `parse_indexer` keep returning owned `raw` via `into_static()`.
- **Adopting a parser-combinator crate** (`winnow`/`nom`).

## Error handling & safety

- No new error variants anticipated. Boundary/offset math uses `checked_add`/
  `checked_sub` (no `saturating_*`, no bare arithmetic) per Mandatory Rule 2.
- `skip_*` and the group parsers must reject truncated / oversize frames as typed
  `ParseError` (`NeedBytes`, `Malformed`), never panic — Mandatory Rule 4 (parsers on
  untrusted input).
- Read-path/write-path parity: the encode path (`encode.rs`) is unaffected; decode
  behavior (which frames are accepted) does not change.

## Testing

Per the Testing-Categories rule, before per-function tests:

1. **Round-trip / sequence** — `encode → parse_group → re-encode` stability, and
   multi-group messages parsed then re-serialized. Assert byte-exact equality.
2. **Defensive boundary** — truncated group frames, oversize counts, invalid element
   codes, non-UTF-8 in soft fields → typed `ParseError`, no panic. Reuse existing
   fuzz/differential harnesses (P0.2/P0.3).
3. **Cross-feature** — the `nix flake check` matrix already runs nextest across feature
   combinations plus the wasm32 and no_std builds; the refactor must stay green on all.
4. **Aliasing correctness** — assert a sliced group's bytes equal the corresponding
   sub-slice of the parent, and that trailing bytes after a group are preserved
   (existing `trailing_bytes_preserved` tests must still pass).
5. **Allocation / throughput** — a before/after measurement on keripy conformance
   vectors via the P0.1 benchmark harness; the acceptance criterion is *reduced
   allocations / higher throughput*.

## Risks

- **Sync path still copies once.** A borrowed `&[u8]` caller has no ref-counted owner,
  so the outermost boundary must copy once. Only the codec path is truly zero-copy.
  Document this so it is not read as a regression.
- **Retained memory.** A small sliced group pins the whole parent `Bytes` alive.
  Acceptable for expected CESR message sizes; flagged for the maintainer if very large
  parents become a concern.
- **`skip_*` promotion.** Removing `#[allow(dead_code)]` fails the gate unless all three
  helpers are wired; they may want their own defensive-boundary tests before being
  relied on in the hot path.
- **`Indexer` has no `into_static()`** (asymmetry with `Matter`) — irrelevant to this
  Bytes-slice refactor, but a latent gap if the deferred borrowed-primitive work is
  ever pursued.

## Acceptance criteria (from the issue)

- [x] Research recommendation captured (this doc + issue comment).
- [ ] Stream parse shows reduced allocations / higher throughput on P0.1 benchmarks.
- [ ] Correctness guarded by P0.2/P0.3; `nix flake check` green; no_std/WASM intact.

## CHANGELOG note

The public `parse_group`/`parse_message` signatures are unchanged (non-breaking). If
any group **type**'s public surface shifts during implementation, call it out as an
intentional MINOR (0.x) breaking change per the active-development policy.
