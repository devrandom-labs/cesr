//! Allocation-count safeguard for zero-copy stream group parsing.
//!
//! `cesr::stream::group::Groups`/`GroupsV2` copy the attachment region into a
//! shared `Bytes` buffer exactly ONCE, lazily, on the first `next()` call;
//! every subsequent group is an O(1) slice of that buffer. A regression to
//! per-group copying (e.g. `Bytes::copy_from_slice` per `next()`) is
//! behaviorally invisible — decoded values are identical either way — so
//! conformance/round-trip tests cannot catch it. This test uses a counting
//! global allocator to make the allocation *count* an observable, asserted
//! invariant: it must not grow with the number of groups in the stream.
//!
//! Only compiled when the `stream` feature is enabled (it needs
//! `cesr::stream::groups`/`groups_v2` and the public `core`/`b64` builders
//! used to construct valid qb64 streams).
#![cfg(feature = "stream")]
#![allow(
    clippy::expect_used,
    reason = "integration test binary — entirely test code, same convention as \
              #[cfg(test)] mod tests in src/ (e.g. src/stream/group/mod.rs), which \
              this file mirrors for stream construction; expect() documents the \
              invariant that fails"
)]

use cesr::b64::encode_int;
use cesr::core::counter::{CounterCodeV1, CounterCodeV2};
use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::stream::{CesrGroup, Groups, GroupsV2};
use core::cell::Cell;
use core::num::NonZeroUsize;
use std::alloc::{GlobalAlloc, Layout, System};

// ── Counting global allocator ───────────────────────────────────────────
//
// Counters are THREAD-LOCAL, not global atomics: under a parallel test runner
// (plain `cargo test`, which is what `cargo llvm-cov` uses) the two tests run
// concurrently in one process, and global counters would let one test's
// allocations on another thread pollute the other test's `measure()` delta.
// Per-thread counters make each `measure()` see only its own thread's
// allocations, so the safeguard is robust under every runner (nextest's
// process isolation, serial, and thread-parallel alike).
//
// `const { Cell::new(0) }` init is non-lazy — accessing the thread-local never
// allocates, so it is safe to touch from inside the global allocator itself
// (no re-entrant allocation, no recursion; `Cell::get`/`set` don't allocate).

thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

#[allow(
    unsafe_code,
    reason = "test-only global allocator; crate's no-unsafe rule applies to src/, not tests/"
)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `try_with` (not `with`) so this is safe during TLS setup/teardown,
        // when the thread-local may be inaccessible.
        let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        let _ = BYTES.try_with(|b| b.set(b.get() + layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        let _ = BYTES.try_with(|b| b.set(b.get() + new_size));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Returns `(result, allocations, bytes)` for `f`, measured on this thread.
///
/// `f` runs on the calling thread, so the before/after delta of the
/// thread-local counters is exactly this thread's allocations — immune to
/// what other test threads are doing concurrently.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    let c0 = COUNT.with(Cell::get);
    let b0 = BYTES.with(Cell::get);
    let result = f();
    let allocs = COUNT.with(Cell::get) - c0;
    let bytes = BYTES.with(Cell::get) - b0;
    (result, allocs, bytes)
}

// ── Stream builders (public API only) ───────────────────────────────────

fn build_siger_qb64(index: u32) -> Vec<u8> {
    IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519)
        .with_index(index)
        .expect("index 0..=1 within Ed25519 max_index")
        .with_raw(&[0u8; 64][..])
        .expect("64-byte raw matches Ed25519 raw_size")
        .to_qb64()
        .into_bytes()
}

fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
    let hard = code.as_str();
    let ss = code.soft_size();
    let ss_nz = NonZeroUsize::new(ss).expect("counter soft sizes are always > 0");
    let soft = encode_int(count, ss_nz);
    format!("{hard}{soft}").into_bytes()
}

fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
    let hard = code.as_str();
    let ss = code.soft_size();
    let ss_nz = NonZeroUsize::new(ss).expect("counter soft sizes are always > 0");
    let soft = encode_int(count, ss_nz);
    format!("{hard}{soft}").into_bytes()
}

/// Builds a V1.0 qb64 stream of `k` adjacent single-element
/// `ControllerIdxSigs` groups (`-A<count=1><siger>` repeated `k` times).
fn build_controller_idx_sigs_stream(k: u32) -> Vec<u8> {
    let mut stream = Vec::new();
    for i in 0..k {
        stream.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1));
        stream.extend_from_slice(&build_siger_qb64(i % 2));
    }
    stream
}

/// Builds a V2.0 qb64 stream of `k` adjacent single-element
/// `ControllerIdxSigs` groups.
fn build_controller_idx_sigs_stream_v2(k: u32) -> Vec<u8> {
    let mut stream = Vec::new();
    for i in 0..k {
        stream.extend_from_slice(&build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1));
        stream.extend_from_slice(&build_siger_qb64(i % 2));
    }
    stream
}

// ── The invariance tests ────────────────────────────────────────────────

#[test]
fn groups_v1_iteration_allocation_count_invariant_to_group_count() {
    const K: u32 = 2;
    const BIG_K: u32 = 8;

    let stream_k = build_controller_idx_sigs_stream(K);
    let stream_big_k = build_controller_idx_sigs_stream(BIG_K);

    let (count_k, allocs_k, _bytes_k) = measure(|| {
        let mut n = 0u32;
        Groups::over(&stream_k).for_each(|r| {
            let _group: Result<CesrGroup, _> = r;
            n += 1;
        });
        n
    });
    let (count_big_k, allocs_big_k, bytes_big_k) = measure(|| {
        let mut n = 0u32;
        Groups::over(&stream_big_k).for_each(|r| {
            let _group: Result<CesrGroup, _> = r;
            n += 1;
        });
        n
    });

    assert_eq!(count_k, K, "sanity: K-stream must yield K groups");
    assert_eq!(
        count_big_k, BIG_K,
        "sanity: BIG_K-stream must yield BIG_K groups"
    );

    assert_eq!(
        allocs_k, allocs_big_k,
        "group-iteration allocations must be invariant to group count (copy-once); \
         got {allocs_k} allocs for {K} groups vs {allocs_big_k} allocs for {BIG_K} groups"
    );

    let bound = stream_big_k.len().saturating_mul(3);
    assert!(
        bytes_big_k < bound,
        "iterating {BIG_K} groups allocated {bytes_big_k} bytes, expected < {bound} \
         (~3x a single copy of the {}-byte input); a per-group re-copy of the \
         remaining buffer would allocate roughly K*(K+1)/2 times the input length",
        stream_big_k.len()
    );
}

#[test]
fn groups_v2_iteration_allocation_count_invariant_to_group_count() {
    const K: u32 = 2;
    const BIG_K: u32 = 8;

    let stream_k = build_controller_idx_sigs_stream_v2(K);
    let stream_big_k = build_controller_idx_sigs_stream_v2(BIG_K);

    let (count_k, allocs_k, _bytes_k) = measure(|| {
        let mut n = 0u32;
        GroupsV2::over(&stream_k).for_each(|r| {
            let _group: Result<CesrGroup, _> = r;
            n += 1;
        });
        n
    });
    let (count_big_k, allocs_big_k, bytes_big_k) = measure(|| {
        let mut n = 0u32;
        GroupsV2::over(&stream_big_k).for_each(|r| {
            let _group: Result<CesrGroup, _> = r;
            n += 1;
        });
        n
    });

    assert_eq!(count_k, K, "sanity: K-stream must yield K groups");
    assert_eq!(
        count_big_k, BIG_K,
        "sanity: BIG_K-stream must yield BIG_K groups"
    );

    assert_eq!(
        allocs_k, allocs_big_k,
        "GroupsV2 iteration allocations must be invariant to group count (copy-once); \
         got {allocs_k} allocs for {K} groups vs {allocs_big_k} allocs for {BIG_K} groups"
    );

    let bound = stream_big_k.len().saturating_mul(3);
    assert!(
        bytes_big_k < bound,
        "iterating {BIG_K} groups allocated {bytes_big_k} bytes, expected < {bound} \
         (~3x a single copy of the {}-byte input); a per-group re-copy of the \
         remaining buffer would allocate roughly K*(K+1)/2 times the input length",
        stream_big_k.len()
    );
}
