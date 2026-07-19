# Autoresearch: CESR stream-parse throughput (`Groups::over`)

## Objective
Reduce the cost of parsing a **full multi-primitive CESR attachment stream** — the top-of-
pipeline hot path that drives counter, indexer, and matter decode. The bench builds a realistic
stream (a controller indexed-sig group of 2 sigs + a witness indexed-sig group of 1 sig) and
parses every group out of it via the `Groups::over()` iterator. This is where end-to-end decode
throughput is won or lost.

## ⛔ Off limits / proven dead ends
- The **base64 codec engine** (#29 — all replacements regressed; closed). Do not touch it or
  `crates/cesr/benches/base64.rs`.
- **`crates/cesr-stream/src/qb2.rs`** — already tuned by the merged Matter qb64↔qb2 seam
  effort. Out of scope here; do not touch or undo it.
- `keripy_diff/` conformance modules and any `test_vectors` / fixtures — ground truth, never
  edit to make a bench look faster.
- `benches/*.rs`, `flake.nix`, `Cargo.lock` dependency versions, `clippy.toml`, `[lints]`.

## Where the headroom is (in scope)
The stream parse pipeline itself:
- `crates/cesr-stream/src/parse.rs` — the core streaming parser.
- `crates/cesr-stream/src/group/{mod,kinds}.rs` — `Groups::over()` iterator + group dispatch.
- `crates/cesr-stream/src/codec.rs` — codec glue on the parse path.
- `crates/cesr-stream/src/cold.rs` — cold-start / tritet detection (per-frame, hot).
- `crates/cesr-stream/src/{unwrap,message}.rs` — framing.
Look for: redundant re-validation across group boundaries, per-group allocation/copy that could
borrow, branch layout in the iterator, and bounds/size math (keep it `checked_*`).

## Metrics
- **Primary**: `stream_parse_ns` (ns per full-stream parse, **lower is better**).
- **Secondary** (monitor, must not regress): `stream_parse_scaling_ns` (asymptotic behavior as
  the stream grows — catches "faster on the small fixture, worse at scale").

## How to Run
`./.auto/measure.sh` — runs the real `stream` criterion bench, emits `METRIC name=value` from
criterion's median point-estimate (ns). **Baseline check first**: it MUST print a non-zero
`METRIC stream_parse_ns=…` before you loop; if not, fix the bench invocation / `estimates.json`
glob in `measure.sh` (see its comments).

## Constraints (law — condensed from ~/.claude/CLAUDE.md + ./CLAUDE.md)
- Arithmetic safety: size/offset/length math uses `checked_*`, `Err` on overflow;
  `saturating_*` / `unwrap_or(sentinel)` banned on these paths.
- Parsing untrusted input never panics — return `Result`; no `unwrap`/`expect` (lint-barred).
- Errors: `thiserror`; never `|_|`; input-validation ≠ corruption variants; a retry-eligible
  error code must not be reused for an overflow/limit failure.
- Style: borrow-before-own, functional-first, `&str`/`&[u8]` over owned; `let..else`. Comments
  explain *why*.
- A change is KEPT only if `.auto/checks.sh` passes; never weaken a test/proptest to pass.

## The gate (per-iteration vs finalize)
- `.auto/checks.sh` runs a fast correctness subset (`cargo nextest run -p cesr -p cesr-stream`)
  every experiment — a `checks_failed` result auto-reverts the candidate.
- The full single gate `nix flake check` (clippy-as-law, taplo, deny, audit, **fuzz** — the
  `stream` fuzz target guards exactly this path) is slow; run it ONCE at
  `/skill:autoresearch-finalize`, which must not produce the reviewable branch until it's green.
  Per-iteration commits are experiment-local; the finalized branch is the real commit boundary.

## What's Been Tried
- **EXP-1 (KEPT, 2026-07-19):** elide redundant `Bytes` refcount bumps in the
  group-framing path. `Groups::over → CesrGroup::parse_bytes → dispatch →
  Group::parse` was slicing the shared buffer twice per group (the iterator's
  `buf.slice(cursor..)` plus an intermediate `elements` slice) on top of the
  unavoidable per-group `raw` span slice. Threaded `(buf, start)` through
  `dispatch_v1/v2/_frames/_seals`, `parse_kind`, `parse_frame/_v2`,
  `Group::parse`, `parse_quadlets/_v2`; added offset-aware private
  `parse_bytes_at/_v2_at` while keeping the public `parse_bytes/_v2` (used by
  `codec.rs` + the `QuadletGroup` parser) at offset 0.
  - Result: `stream_parse_ns` 94.1 → 82.6 ns (**~−12%**);
    `stream_parse_scaling_ns` ~2100 → 1830 ns (**~−13%**). Clear of the
    ~3 ns noise floor (3 baseline runs: 97.1 / 91.0 / 94.0 ns).
  - Correctness: all 1478 `cesr` + `cesr-stream` nextest pass.
  - Committed as `78af750`. **`nix flake check` (clippy/taplo/fuzz) NOT yet
    run** — must run at finalize before publishing the branch.
- **Setup fixes (KEPT):** `measure.sh` used `--features stream` (not a
  cesr-stream feature) → bench never ran; `checks.sh` used `-p cesr` (package
  is `cesr-rs`) → gate never ran. Both fixed (commits `ecb1a71` + seed
  `896495f`). These are infra repairs, not parse-path changes.
