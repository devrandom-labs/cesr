# #64 — Reproducibly measure zero-copy stream parsing's allocation payoff

**Issue:** [#64](https://github.com/devrandom-labs/cesr/issues/64) — follow-up to #30 (zero-copy stream parsing).
**Status:** design approved 2026-07-03.

## Problem

#30 replaced per-group copying with copy-once + slice parsing in the `groups()` /
`groups_v2()` iterators. The allocation reduction (N allocs/stream → 1) is *proven*
(`tests/allocation.rs`, mutation-verified). The **payoff is not**: no benchmark shows
fewer allocations converting into a throughput or latency win anywhere. Single-thread
benches show a net regression (correct-but-slower). "Was #30 worth it?" is therefore a
belief, not a measurement — which violates the reproducibility bar.

The one place the reduction *should* pay off is under **multi-thread allocator
contention**: N allocs/stream hits the global allocator lock far more than 1
alloc/stream. This spec defines a reproducible measurement of exactly that.

## Non-goals

- Not a CI regression gate. Wall-clock is machine-dependent; this is a run-and-paste
  measurement, not a guard. The existing `benches/stream.rs::stream_parse_scaling`
  already gives CodSpeed a single-thread instruction-count guard.
- Not a CodSpeed benchmark. CodSpeed measures single-thread instruction counts in a
  simulator — it structurally cannot observe allocator contention, which is the entire
  effect under test. Putting a threaded benchmark on CodSpeed would report a
  meaningless (potentially misleading) number.
- no_std / constrained-allocator behavior: **out of scope for v1** (threads require
  std; a constrained-allocator model needs a separate custom allocator). Recorded as a
  possible follow-up.

## Artifact & command

A committed standalone binary `examples/concurrent_parse.rs`, gated
`required-features = ["stream"]`. One documented command:

```
cargo run --release --example concurrent_parse --features stream
```

It prints a table (thread count × strategy → throughput + allocs/stream) plus a
mechanical advisory verdict. Numbers are pasted into the issue and the CHANGELOG.

## The two comparison arms

Both arms are **real, public, production functions** — the only variable between them
is the allocation pattern. No git checkout, no reimplemented parse logic.

- **copy-once (this branch):** `groups(stream).collect::<Vec<_>>()`. `Groups::next()`
  copies the input into a shared `Bytes` **once** (`get_or_insert_with(|| Bytes::copy_from_slice(input))`,
  `src/stream/group/mod.rs:206`), then every group is an O(1) slice. **1 buffer
  alloc/stream.**
- **per-group copy (origin/main behavior):** a loop
  `let mut rest = stream; while !rest.is_empty() { let (_g, r) = parse_group(rest)?; rest = r; }`.
  `parse_group`'s inner (`parse_group_inner`, `src/stream/group/mod.rs:84`) *still*
  does `Bytes::copy_from_slice(input)` on **every call**, re-copying the shrinking
  remainder. **K buffer allocs/stream** — this reproduces the pre-#30 behavior exactly,
  using code that is still live on the branch.

`controller_idx_sigs::parse` only slices `Bytes` (no base64 decode at parse time), so
the alloc difference is clean: 1 vs K buffer allocs/stream, with nothing diluting the
signal.

## Workload

- Fixture: a stream of **K** back-to-back `ControllerIdxSigs` groups (2 sigs each),
  built with the existing `encode_counter_v1` + `IndexerBuilder` helpers (mirrors
  `benches/stream.rs::build_n_groups`). Default **K = 16** → per-stream gap = 1 vs 16
  allocs.
- Each thread parses the same pre-built stream **M** times. Default **M ≈ 50 000**,
  tuned so a run takes a couple of seconds per configuration.
- Thread sweep: **1, 2, 4, 8**, each capped at available parallelism
  (`std::thread::available_parallelism`).
- N = 1 is included deliberately: it captures the known single-thread regression, so
  the crossover to a copy-once win at higher thread counts is visible.

## Allocator instrumentation (honesty-critical)

A custom `#[global_allocator]` wrapping `System`, modelled on
`tests/allocation.rs`'s thread-local counting allocator, with an **armed gate**:

- Timing passes run **disarmed** → the alloc path is `System.alloc` + one relaxed
  atomic load ≈ zero overhead. Neither arm pays a counting penalty proportional to its
  alloc count, so wall-clock is clean and the comparison is fair. (Without the gate,
  the counter's per-alloc cost would inflate copy-once's apparent win, since per-group
  allocates more and would pay more counter overhead.)
- A separate **single-threaded armed pass** counts allocs/stream for each arm. This is
  a structural property that does not need concurrency to measure.

## Output & verdict

```
strategy    threads   streams/s      allocs/stream
copy-once   1         ...            1
per-group   1         ...            16
copy-once   2         ...
per-group   2         ...
...
VERDICT: copy-once/per-group throughput ratio — 1t: 0.9x  2t: 1.1x  4t: 1.4x  8t: 1.8x
=> [VINDICATED under concurrency | INCONCLUSIVE]
```

The mechanical verdict is **advisory** (wall-clock is machine-dependent), e.g.
"copy-once faster at every thread count ≥ 2". The human reads the table; the verdict
line is a convenience.

## Determinism

"Deterministic" here means **reproducible methodology** — same command, same workload,
same arms — not identical nanoseconds. Wall-clock inherently varies with machine, core
count, and load. This is stated in the file header and the CHANGELOG.

## Testing

The harness is a measurement tool, but:

- The fixture builder gets a unit test (K groups build → parse back to K groups).
- The armed alloc-count pass **asserts** 1 vs K allocs/stream, so a broken fixture or a
  regression to per-group copying in `groups()` fails loudly rather than printing
  garbage. (`tests/allocation.rs` already guards the same invariant independently.)

## Acceptance criteria (from the issue)

- [x] A committed benchmark + a single documented command anyone can run.
- [x] Before/after numbers pasted (branch vs origin/main behavior) across thread counts.
- [x] A clear, re-runnable verdict → updates CHANGELOG with the measured outcome.
- [ ] no_std/constrained-allocator: deferred (out of scope for v1, noted above).
