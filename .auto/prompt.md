# Autoresearch: CESR Matter qb64↔qb2 seam throughput

## Objective
Reduce the per-operation cost of the **Matter primitive encode/decode + `qb64`↔`qb2`
conversion seam** in the `cesr`/`cesr-stream` crates, at real CESR primitive sizes
(Ed25519 verkey/sig, Blake3-256 digest, variable-size soft codes). This is the production
seam through which every CESR primitive passes.

## ⛔ Proven dead end — DO NOT re-run (issue #29)
Swapping the **base64 codec engine** is a *closed* experiment. Three replacements
(`base64-simd`, unsafe-free scalar, stack-buffer) were benchmarked end-to-end and **all
regressed** — the `base64` crate's `URL_SAFE_NO_PAD` engine has better ILP than any scalar
codec at 32/64 B, and allocation was shown *not* to be the bottleneck. See the docstring in
`crates/cesr/benches/base64.rs`. **Do not touch the base64 engine choice or `crates/cesr/benches/base64.rs`.**
Any perf win here must come from the seam's *own* work, not the codec.

## Where the headroom actually is (in scope)
The seam's non-codec work, which #29 never optimized:
- **Code-table lookup** — code→size/layout resolution in Matter decode.
- **Size / validation logic** — soft-size decode, length math (keep it `checked_*`, per rules).
- **Allocation & copy patterns** — borrow vs owned, buffer reuse in the builder / converters.
- **Control-flow / branch layout** on the hot decode path.

## Metrics
- **Primary**: `matter_decode_ns` (ns/op, **lower is better**) — the optimization target.
- **Secondary** (tradeoff monitors, must not regress meaningfully):
  `matter_encode_ns`, `qb64_to_qb2_ns`, `qb2_to_qb64_ns`.

## How to Run
`./.auto/measure.sh` — runs the real `matter` criterion bench and emits `METRIC name=value`
lines from criterion's median point-estimate (nanoseconds). **At baseline, confirm it prints a
stable non-zero `METRIC matter_decode_ns=…` before looping** — if the bench invocation or the
`estimates.json` path is off for this workspace, fix `measure.sh` first (see comments in it).

## Files in Scope
- `crates/cesr/src/core/matter/builder.rs` — `MatterBuilder` decode/encode seam.
- `crates/cesr-stream/src/qb2/` — `qb64_to_qb2`, `qb2_to_qb64`.
- `crates/cesr/src/b64/{charset,alphabet,int,binary}.rs` — CESR's own code tables / varint
  (the "code-table lookup" #29 explicitly isolated OUT of its base64 test).

## Off Limits
- `crates/cesr/benches/base64.rs` and the base64 **engine** choice (#29 — closed).
- `src/` at repo root is not a thing here; do NOT edit any `benches/*.rs`, `flake.nix`,
  `Cargo.lock` dependency versions, `clippy.toml`, or any `[lints]` table.
- `test_vectors.rs` fixtures — treat as ground truth, never edit to make a bench look faster.

## Constraints (the rules are law — condensed from ~/.claude/CLAUDE.md + ./CLAUDE.md)
- **Arithmetic safety**: size/offset/length math uses `checked_*`, returns `Err` on overflow;
  `saturating_*` and `unwrap_or(sentinel)` are banned on these paths.
- **No panics on parse**: decode of untrusted input returns `Result`, never `unwrap`/`expect`
  (the crate lint bars them even in benches).
- **Errors**: `thiserror`; never `|_|`; input-validation ≠ corruption variants.
- **Style**: borrow-before-own, functional-first, `&str`/`&[u8]` over owned. Comments explain *why*.
- **A change is only KEPT if `.auto/checks.sh` passes** (correctness gate — a `checks_failed`
  result auto-reverts). Do not weaken a test or proptest to make a change pass.

## The gate, honestly (per-iteration vs finalize)
- `.auto/checks.sh` runs a **fast correctness subset** (`cargo nextest run` for the two crates
  + the b64/matter proptests) on every experiment — enough to catch breakage cheaply.
- The **full single gate `nix flake check`** (clippy-as-law, taplo, deny, audit, fuzz) is slow;
  run it ONCE at the end. `/skill:autoresearch-finalize` must not produce the reviewable branch
  until `nix flake check` passes clean. The per-iteration autoresearch commits are experiment-
  local; the finalized branch is the real commit/push boundary and MUST pass the full gate.

## What's Been Tried
- (#29, pre-autoresearch) base64 engine swaps — ALL regressed; codec is optimal at CESR sizes.
- <append here as the loop runs: seam-level wins, dead ends, and why.>
