# #64 Concurrent-Parse Allocation-Payoff Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a committed, reproducible standalone harness that measures whether #30's copy-once stream parsing (1 buffer alloc/stream) beats the pre-#30 per-group copy (N allocs/stream) under multi-thread allocator contention, and record the verdict.

**Architecture:** A single `examples/concurrent_parse.rs` binary with its own armed counting `#[global_allocator]`. Two arms are real public production functions — `groups()` (copy-once) vs a `parse_group()` loop (per-group copy) — consumed symmetrically so the only variable is the allocation pattern. It runs a single-threaded armed pass that asserts the 1-vs-N allocation invariant (self-check), then a disarmed wall-clock throughput sweep across thread counts 1/2/4/8, and prints a table plus an advisory verdict.

**Tech Stack:** Rust 2024, `std::thread::scope`, `std::time::Instant`, `std::alloc::GlobalAlloc`, the crate's public `stream` API. Verified via `nix flake check`.

**Design doc:** `docs/superpowers/specs/2026-07-03-64-concurrent-parse-alloc-payoff-design.md`

**Refinement vs spec:** the spec's arm sketches showed `groups().collect::<Vec<_>>()` for copy-once and a bare loop for per-group. That asymmetry (a `Vec` allocation on only one arm) would pollute the comparison, so **both arms consume every group symmetrically without collecting** (iterate + `black_box`, no `Vec`). This is the honest form of the spec's intent.

---

## File Structure

- **Create:** `examples/concurrent_parse.rs` — the entire harness (allocator, fixture, two arms, alloc self-check, throughput sweep, verdict). One file, one responsibility: the measurement.
- **Modify:** `Cargo.toml` — add the `[[example]]` entry gating it on the `stream` feature.
- **Modify:** `CHANGELOG.md` — record the harness and the measured verdict under the unreleased section.

---

### Task 1: Wire up the example and write the harness

**Files:**
- Modify: `Cargo.toml` (after the existing `[[bench]]` blocks, before `[lints.rust]`)
- Create: `examples/concurrent_parse.rs`

- [ ] **Step 1: Add the `[[example]]` entry to `Cargo.toml`**

Insert immediately after the last `[[bench]]` block (the `stream` bench, currently ending at line 132) and before `[lints.rust]`:

```toml
[[example]]
name = "concurrent_parse"
required-features = ["stream"]
```

- [ ] **Step 2: Create `examples/concurrent_parse.rs` with the complete harness**

```rust
//! Concurrent-parse allocation-payoff harness for issue #64.
//!
//! Measures whether #30's copy-once stream parsing (1 buffer alloc/stream)
//! beats the pre-#30 per-group copy (N buffer allocs/stream) under multi-thread
//! allocator contention — the one place fewer allocations should convert to
//! throughput.
//!
//! Run with:
//!     cargo run --release --example concurrent_parse --features stream
//!
//! "Deterministic" here means reproducible *methodology* (same command,
//! workload, and arms), not identical nanoseconds: wall-clock varies with
//! machine and load.
//!
//! Both arms are real, public production functions; the only variable is the
//! allocation pattern:
//!   * copy-once — `groups()` copies the input into a shared `Bytes` once, then
//!     O(1)-slices every group.
//!   * per-group — `parse_group()` copies the shrinking remainder on every call
//!     (exactly the pre-#30 behavior, still live on this branch).

#![allow(
    unsafe_code,
    reason = "host-only measurement harness needs a counting #[global_allocator]; \
              the crate's no-unsafe rule applies to src/, not examples/"
)]
#![allow(
    clippy::print_stdout,
    clippy::expect_used,
    reason = "host-only example: it prints a report table, and expect() documents \
              fixture/measurement invariants — same convention as tests/allocation.rs"
)]

use cesr::core::counter::CounterCodeV1;
use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::stream::encode::encode_counter_v1;
use cesr::stream::{ParseError, groups, parse_group};
use core::cell::Cell;
use core::hint::black_box;
use core::num::NonZeroUsize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Instant;

// ── Counting global allocator with an armed gate ─────────────────────────
//
// Disarmed (the default), alloc is System.alloc + one relaxed atomic load, so
// timing passes are effectively uninstrumented. Armed (single-threaded pass
// only), it counts allocations on the calling thread. The gate matters: without
// it, the counter's per-alloc cost would inflate copy-once's apparent win, since
// per-group allocates more and would pay more counter overhead.

static ARMED: AtomicBool = AtomicBool::new(false);

thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

// ── Fixture (public API only; mirrors benches/stream.rs) ──────────────────

fn build_siger(index: u32) -> Vec<u8> {
    IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519)
        .with_index(index)
        .expect("index within Ed25519 max_index")
        .with_raw(vec![0u8; 64])
        .expect("64-byte raw matches Ed25519 raw_size")
        .to_qb64()
        .into_bytes()
}

/// A qb64 stream of `n` back-to-back `ControllerIdxSigs` groups (2 sigs each).
fn build_n_groups(n: usize) -> Vec<u8> {
    let mut input = Vec::new();
    for _ in 0..n {
        input.extend_from_slice(
            &encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 2)
                .expect("controller idx-sigs counter with count 2 encodes"),
        );
        input.extend_from_slice(&build_siger(0));
        input.extend_from_slice(&build_siger(1));
    }
    input
}

// ── The two arms ─────────────────────────────────────────────────────────
//
// Both consume every group symmetrically (iterate, black_box each; no collect),
// so the only difference is buffer allocation: copy-once = 1, per-group = N.

#[derive(Clone, Copy)]
enum Strategy {
    CopyOnce,
    PerGroup,
}

impl Strategy {
    const fn label(self) -> &'static str {
        match self {
            Self::CopyOnce => "copy-once",
            Self::PerGroup => "per-group",
        }
    }
}

fn parse_copy_once(stream: &[u8]) -> usize {
    let mut parsed = 0;
    for group in groups(stream) {
        black_box(&group);
        if group.is_ok() {
            parsed += 1;
        }
    }
    parsed
}

fn parse_per_group(stream: &[u8]) -> Result<usize, ParseError> {
    let mut rest = stream;
    let mut parsed = 0;
    while !rest.is_empty() {
        let (group, remainder) = parse_group(rest)?;
        black_box(&group);
        rest = remainder;
        parsed += 1;
    }
    Ok(parsed)
}

fn run_strategy(strategy: Strategy, stream: &[u8]) -> usize {
    match strategy {
        Strategy::CopyOnce => parse_copy_once(stream),
        Strategy::PerGroup => parse_per_group(stream).expect("fixture stream parses cleanly"),
    }
}

// ── Allocation-count self-check (armed, single-threaded) ──────────────────

/// Allocations made while parsing `stream` once with `strategy`.
fn count_allocs(strategy: Strategy, stream: &[u8]) -> usize {
    COUNT.with(|c| c.set(0));
    ARMED.store(true, Ordering::SeqCst);
    let parsed = run_strategy(strategy, black_box(stream));
    ARMED.store(false, Ordering::SeqCst);
    black_box(parsed);
    COUNT.with(Cell::get)
}

// ── Throughput (disarmed, multi-threaded) ─────────────────────────────────

/// Streams parsed per second: `threads` threads each parse `stream`
/// `iters_per_thread` times; wall-clock across the whole batch.
fn measure_throughput(
    strategy: Strategy,
    stream: &[u8],
    threads: usize,
    iters_per_thread: usize,
) -> f64 {
    let start = Instant::now();
    thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(move || {
                for _ in 0..iters_per_thread {
                    black_box(run_strategy(strategy, black_box(stream)));
                }
            });
        }
    });
    let elapsed = start.elapsed().as_secs_f64();
    let total = threads
        .checked_mul(iters_per_thread)
        .expect("threads * iters_per_thread must not overflow usize");
    let total = u32::try_from(total).expect("total stream count fits in u32");
    f64::from(total) / elapsed
}

fn main() {
    const K: usize = 16;
    const ITERS_PER_THREAD: usize = 50_000;
    let thread_counts = [1usize, 2, 4, 8];

    let max_par = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let stream_k = build_n_groups(K);
    let stream_2k = build_n_groups(K * 2);

    // Self-check: prove the arms still model 1-vs-N allocation before trusting
    // any timing. copy-once must be invariant to group count; per-group must
    // scale with it. A regression to per-group copying in groups(), or a broken
    // fixture, fails here loudly instead of printing meaningless numbers.
    let co_allocs = count_allocs(Strategy::CopyOnce, &stream_k);
    let co_allocs_2k = count_allocs(Strategy::CopyOnce, &stream_2k);
    let pg_allocs = count_allocs(Strategy::PerGroup, &stream_k);
    let pg_allocs_2k = count_allocs(Strategy::PerGroup, &stream_2k);

    assert_eq!(
        co_allocs, co_allocs_2k,
        "copy-once allocations must be invariant to group count (got {co_allocs} at K={K}, \
         {co_allocs_2k} at K={}); a regression to per-group copying broke #30",
        K * 2
    );
    assert!(
        pg_allocs_2k > pg_allocs,
        "per-group allocations must scale with group count (got {pg_allocs} at K={K}, \
         {pg_allocs_2k} at K={}); the per-group arm is not modelling origin/main",
        K * 2
    );
    assert!(
        pg_allocs >= K,
        "per-group must allocate at least once per group (got {pg_allocs} for {K} groups)"
    );

    println!("issue #64 — concurrent-parse allocation-payoff harness");
    println!("workload: {K} ControllerIdxSigs groups/stream, {ITERS_PER_THREAD} streams/thread");
    println!("allocations/stream: copy-once={co_allocs}, per-group={pg_allocs}\n");

    println!(
        "{:<11}{:>9}{:>14}{:>16}",
        "strategy", "threads", "streams/s", "allocs/stream"
    );
    let mut ratios = Vec::new();
    for &t in &thread_counts {
        if t > max_par {
            println!("(skipping {t} threads: only {max_par} available)");
            continue;
        }
        let co = measure_throughput(Strategy::CopyOnce, &stream_k, t, ITERS_PER_THREAD);
        let pg = measure_throughput(Strategy::PerGroup, &stream_k, t, ITERS_PER_THREAD);
        println!(
            "{:<11}{:>9}{:>14.0}{:>16}",
            Strategy::CopyOnce.label(),
            t,
            co,
            co_allocs
        );
        println!(
            "{:<11}{:>9}{:>14.0}{:>16}",
            Strategy::PerGroup.label(),
            t,
            pg,
            pg_allocs
        );
        ratios.push((t, co / pg));
    }

    print!("\nVERDICT: copy-once/per-group throughput ratio —");
    for (t, r) in &ratios {
        print!(" {t}t: {r:.2}x");
    }
    println!();

    let any_multi = ratios.iter().any(|(t, _)| *t >= 2);
    let wins_all_multi = ratios.iter().filter(|(t, _)| *t >= 2).all(|(_, r)| *r > 1.0);
    if any_multi && wins_all_multi {
        println!("=> VINDICATED: copy-once faster at every thread count >= 2 on this run");
    } else {
        println!("=> INCONCLUSIVE: copy-once did not win at every thread count >= 2 on this run");
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `nix develop --command cargo build --release --example concurrent_parse --features stream`
Expected: builds with no errors or warnings.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml examples/concurrent_parse.rs
git commit -m "feat(#64): concurrent-parse allocation-payoff harness

Standalone wall-clock harness comparing copy-once groups() vs per-group
parse_group()-loop across thread counts, with an armed counting allocator
so timing passes stay uninstrumented and a self-check asserting the
1-vs-N allocation invariant before any timing runs.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Run the harness and capture the verdict

**Files:** none (produces numbers to paste)

- [ ] **Step 1: Run the harness**

Run: `nix develop --command cargo run --release --example concurrent_parse --features stream`

Expected output shape (numbers are machine-dependent):

```
issue #64 — concurrent-parse allocation-payoff harness
workload: 16 ControllerIdxSigs groups/stream, 50000 streams/thread
allocations/stream: copy-once=1, per-group=16

strategy      threads     streams/s   allocs/stream
copy-once           1        ......               1
per-group           1        ......              16
copy-once           2        ......               1
per-group           2        ......              16
copy-once           4        ......               1
per-group           4        ......              16
copy-once           8        ......               1
per-group           8        ......              16

VERDICT: copy-once/per-group throughput ratio — 1t: ..x 2t: ..x 4t: ..x 8t: ..x
=> [VINDICATED|INCONCLUSIVE]: ...
```

Verify:
- The self-check `assert`s did NOT fire (the program reached the table).
- `allocations/stream` shows copy-once small and constant vs per-group ≈ K.
- The verdict line is printed.

- [ ] **Step 2: Save the raw output**

Copy the full stdout into the scratchpad for the CHANGELOG/issue paste:

Run: `nix develop --command cargo run --release --example concurrent_parse --features stream | tee /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/8fc9fc49-e6e9-4927-a4bd-8c7b2dd76aec/scratchpad/64-verdict.txt`
Expected: same output, now also in the file.

- [ ] **Step 3: No commit** (measurement only; numbers land in Task 3's CHANGELOG edit)

---

### Task 3: Record the verdict in the CHANGELOG and run the gate

**Files:**
- Modify: `CHANGELOG.md` (unreleased section)

- [ ] **Step 1: Read the current CHANGELOG top section**

Run: `nix develop --command sed -n '1,40p' CHANGELOG.md`
Expected: shows the unreleased/added section and its formatting conventions.

- [ ] **Step 2: Add an entry under the unreleased "Added" (or equivalent) heading**

Use the CHANGELOG's existing bullet style. Insert an entry naming the harness, the command, and the measured verdict from `64-verdict.txt`. Template (fill the bracketed numbers from the run — do NOT leave brackets):

```markdown
- **Concurrent-parse allocation-payoff harness** (`examples/concurrent_parse.rs`, #64):
  reproducibly measures whether #30's copy-once parsing (1 alloc/stream) beats the
  pre-#30 per-group copy (N allocs/stream) under multi-thread allocator contention.
  Run: `cargo run --release --example concurrent_parse --features stream`.
  Measured on [MACHINE, e.g. 14-core M-series]: copy-once/per-group throughput ratio
  [1t: X.XXx, 2t: X.XXx, 4t: X.XXx, 8t: X.XXx] → **[VINDICATED|INCONCLUSIVE]**.
  [If VINDICATED: #30's zero-copy is confirmed as a concurrency/memory-pressure win.
   If INCONCLUSIVE: #30's lasting value is the safeguards + bug fixes, not the
   sync-path zero-copy — see #64 for the revert decision.]
```

- [ ] **Step 3: Run the full gate**

Run: `nix flake check`
Expected: all checks pass (clippy incl. the example under `--all-targets`, rustfmt, taplo, audit, deny, nextest, doctest, wasm, no_std).

If clippy flags the example for a lint not covered by the two file-level `#![allow]`s, add that lint to the appropriate existing `#![allow(...)]` block **with a `reason`** (never a new bare allow, never relax `Cargo.toml`), then re-run `nix flake check`.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(#64): record concurrent-parse allocation-payoff verdict

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Follow-up on the verdict

**Files:** none (decision + issue update)

- [ ] **Step 1: Act on the measured verdict**

- **VINDICATED** → comment on issue #64 with the pasted table, check the acceptance boxes, and close it. #30 stands as a concurrency win.
- **INCONCLUSIVE** → comment on #64 with the table, then open the decision the issue calls for: "revert the sync-path zero-copy (keep codec + safeguards)". Leave #64 open pending that decision.

Run (VINDICATED example):
```bash
gh issue comment 64 --body-file /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/8fc9fc49-e6e9-4927-a4bd-8c7b2dd76aec/scratchpad/64-verdict.txt
```

- [ ] **Step 2: Confirm the acceptance criteria in the issue are addressed** (committed benchmark ✓, documented command ✓, before/after numbers across thread counts ✓, re-runnable verdict ✓; no_std deferred per spec).

---

## Self-Review

**Spec coverage:**
- Artifact & command → Task 1 (`examples/concurrent_parse.rs`, `[[example]]`), Task 2 (run command). ✓
- Two comparison arms (copy-once `groups()` / per-group `parse_group()`-loop) → Task 1 `parse_copy_once` / `parse_per_group`. ✓
- Workload (K=16 groups, M=50k, threads 1/2/4/8, capped at parallelism) → Task 1 `main` constants + `max_par`. ✓
- Armed allocator (disarmed timing, armed count pass) → Task 1 `Counting` + `ARMED` + `count_allocs`. ✓
- Output & advisory verdict → Task 1 table + verdict logic. ✓
- Determinism note → file header doc comment. ✓
- Testing (fixture + alloc-count self-check assertion) → Task 1 `main` self-check `assert`s (invariance + scaling), run in Task 2. ✓
- Acceptance criteria / CHANGELOG / verdict follow-up → Task 3, Task 4. ✓
- no_std deferred → noted, out of scope. ✓

**Placeholder scan:** the only brackets are in the CHANGELOG template (Task 3 Step 2) and issue-comment step, explicitly instructed to be filled from the run — not code placeholders. Code steps contain complete code.

**Type consistency:** `Strategy { CopyOnce, PerGroup }`, `Strategy::label`, `run_strategy(Strategy, &[u8]) -> usize`, `count_allocs(Strategy, &[u8]) -> usize`, `measure_throughput(Strategy, &[u8], usize, usize) -> f64`, `parse_copy_once(&[u8]) -> usize`, `parse_per_group(&[u8]) -> Result<usize, ParseError>` — names and signatures consistent across all call sites in `main`.
