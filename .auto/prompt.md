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
- **iter1 (WIN, kept @ 2b45a29):** `from_qualified_base64` resolved the code→`Sizage`
  descriptor exactly once instead of 6× (5 direct field accesses + 1 inside the
  now-bypassed `frame_size_of` re-parse), and the per-decode `PAD.repeat(xs)`
  `String` allocation was replaced with a byte check (`xtra.iter().all(|&b| b == b'_')`).
  `matter_decode_ns` 54.05 → 43.59 (−19.4%); all 1478 nextest cases pass;
  `nix flake check` clean. (The qb2-convert secondaries also moved ~11–12% in the
  same run, but `qb2.rs` shares NO code with this fn → criterion variance, not causal.)
- **Dead end — `from_str` code lookup:** the only remaining fixed-code seam cost is
  `strum`'s generated `FromStr` (linear/chain match over 110 variants). Rewriting it
  as a 1-/2-/4-char dispatch risks mapping divergence across 110 variants and is out
  of proportion for the ~5 ns it might save; left untouched.
- **Dead end — `temp`/`buf` allocations:** two small `Vec` allocs per decode. #29 already
  proved allocation is NOT the bottleneck at 32/64 B (codec-dominated), so chasing them
  regresses nothing but also wins nothing. The base64 **engine** itself is closed (#29).
- **Net:** after iter1 the fixed-code decode path is codec-dominated; the variable-code
  path (`decode_int`/`compute_full_size`) is already tight. No further safe,
  primary-improving change exists without touching the closed base64 engine or risking
  the `from_str` mapping. Seam headroom captured.
