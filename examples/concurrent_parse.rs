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
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::shadow_reuse,
    reason = "host-only example: it prints a report table, and expect() documents \
              fixture/measurement invariants — same convention as tests/allocation.rs; \
              stream_k/stream_2k are intentionally paired scale-variant fixture names, not \
              confusable unrelated bindings; the module doc references the `concurrent_parse` \
              binary target inline; and narrowing `total` from usize to u32 via try_from \
              immediately after computing it is deliberate reuse-shadowing, not accidental \
              variable reuse"
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
