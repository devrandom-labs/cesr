# cesr — Development Strategy

Status: living document. This is the spine that turns the project's goals into
milestones and issues. We refine it here, then cut GitHub Milestones (one per
phase) and `cards` from it.

## Where we are (2026-06-30)

cesr is a correct, well-tested CESR + KERI primitives crate: zero `unsafe` across
~37k LOC, test vectors checked against the keripy reference, no_std/WASM-capable,
and gated by a god-level `nix flake check`. The keripy-sync watcher shows cesr is
already at **near-parity** with keripy 2.0 — the code-table gap is a single code
(`GramHead`), and all 59 CESR-2.0 counters are implemented.

So the leverage is **not** "catch up to keripy." It is: turn a faithful crate into
the *fastest, most pleasant* CESR/KERI crate in Rust, without regressing the
correctness that already exists.

## Goals (priority order, from the maintainer)

1. **Zero-copy + extreme performance** — paramount.
2. **Parity with the current keripy** — keep tracking it as it moves.
3. **Best-in-class DevX** — easy and great to use.
4. Always build on the **best cryptography, crates, and design methodology**.

## Guiding principle: foundation-first

Performance is the goal, which is exactly why the *first* work is not performance.
You cannot do "extreme performance" without a **speedometer** (benchmarks) and
**guardrails** (fuzzing + differential tests against keripy). Today the crate has
neither: no `benches/`, no `fuzz/`, no `examples/`, and proptest is used in only a
few files. Hand-optimizing the ~230 allocation sites in `core`+`stream` blind,
while a freshly-unfrozen API is in flux, is how you ship a fast crate that
silently breaks CESR interop.

The sequence that reaches fast *safely*: **build the instruments, then floor it.**

## The intelligence engine (the 4 pillars)

Each pillar is a deterministic, scheduled watcher that emits a reviewable doc and,
from it, labelled GitHub issues — a self-replenishing backlog. Same pattern,
swapped inputs.

| Pillar | Watches | Label | Status |
|--------|---------|-------|--------|
| keripy-sync | keripy CESR code tables + tests | `keripy-sync` | shipped |
| crypto-intel | best crypto crates/algorithms, RustSec, new versions | `crypto-intel` | planned |
| design-intel | Rust patterns/idioms for what we build | `design-intel` | planned |
| devx | API ergonomics, docs, examples | `devx` | planned |

## Phases

### Phase 0 — Instruments (unblocks everything; do first)

Prerequisite for credible performance work.

- **P0.1 Benchmark harness.** criterion (or divan) baselines for Matter
  encode/decode, Counter group parse, and full-stream parse; a perf-regression
  signal in CI. *Makes "is this faster?" answerable.*
- **P0.2 Fuzzing.** `cargo-fuzz` + `arbitrary` over the decode/parse entry points.
  Proves "no panic on untrusted bytes" and guards every later refactor. Builds on
  the existing 0-`unsafe` posture.
- **P0.3 Differential testing vs keripy.** Random round-trips asserting cesr and
  keripy agree byte-for-byte on encode and decode. This is *behavioral* parity —
  deeper than the code-table parity the watcher tracks.

### Phase 1 — Zero-copy / performance (the paramount goal)

Now safe to pursue, because Phase 0 measures and guards it.

- **P1.1 Allocation audit.** Triage the ~230 heap-op sites in `core`+`stream`;
  remove gratuitous `to_vec`/`format!`/`String` in decode loops; push
  `&[u8]`/`Cow` further. Benchmarks decide what actually matters.
- **P1.2 Base64 fast path.** Base64 is CESR's inner loop; evaluate a SIMD base64
  (or a hand-rolled codec for the CESR alphabet) against the current `base64`
  crate.
- **P1.3 Zero-copy stream parsing.** Make the `stream/` group parser yield borrowed
  views over the input rather than owned copies.

### Phase 2 — DevX / API (the window is now the freeze is lifted)

- **P2.1 Prelude + flattened re-exports.** Replace warts like
  `cesr::core::matter::matter::Matter` with `cesr::prelude::*` and a curated
  top-level surface.
- **P2.2 Examples.** A runnable `examples/` set (encode/verify a key, parse a
  stream, build an event) — adoption front door and integration tests in one.
- **P2.3 Error ergonomics.** Review the `terrors::OneOf` unions for matchability
  and documentation from a consumer's seat.

### Phase 3 — Crypto & dependency currency (ongoing, watcher-fed)

- **P3.1** Evaluate the deferred major bumps (`signature 3.0`, `sha2 0.11`,
  `sha3 0.12`) for performance/security wins.
- **P3.2** Track new algorithms keripy adopts (surfaced by keripy-sync).

## How we work

- This doc → GitHub Milestones (one per phase) → issues (`cards`) per item.
- Watchers keep the backlog replenished; the maintainer curates which doc rows
  become cards.
- Every change still passes `nix flake check` and the Mandatory Rules in
  `CLAUDE.md`. Breaking API changes are allowed (0.x) but intentional and
  recorded in the `CHANGELOG`.
