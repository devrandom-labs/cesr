//! Allocation-scaling safeguard for owned stream group parsing.
//!
//! `Groups<V1>`/`Groups<V2>` own each consumed frame independently, so
//! retaining one group cannot retain the rest of a concatenated stream.
//! Allocations grow with group count, but requested bytes must grow linearly
//! with equivalent input. A repeated copy of the remaining suffix violates
//! this property even when decoded values are unchanged.
//!
//! Compiled with the `std` feature; fixtures use the public CESR builders to
//! construct valid V1 and V2 qb64 streams.
#![cfg(feature = "std")]
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
use cesr_stream::{CesrGroup, FrameLimits, Groups, MessageFramer, V1, V2};
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

fn json_body_with_padding(padding: usize) -> Vec<u8> {
    let mut body = b"{\"v\":\"KERI10JSON000000_\",\"pad\":\"".to_vec();
    body.extend(core::iter::repeat_n(b'a', padding));
    body.extend_from_slice(b"\"}");
    let size = format!("{:06x}", body.len());
    body[16..22].copy_from_slice(size.as_bytes());
    body
}

fn nested_signature_group(count: u32) -> Vec<u8> {
    let mut group = build_counter_qb64(CounterCodeV1::TransIdxSigGroups, 1);
    for _ in 0..3 {
        group.push(b'D');
        group.extend_from_slice(&[b'A'; 43]);
    }
    group.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, count));
    let signature = build_siger_qb64(0);
    for _ in 0..count {
        group.extend_from_slice(&signature);
    }
    group
}

#[test]
fn bytewise_message_framing_allocates_no_input_copies() {
    for padding in [128, 4096] {
        let body = json_body_with_padding(padding);
        let limits = FrameLimits {
            max_body_bytes: body.len(),
            max_attachment_bytes: 0,
            max_attachment_groups: 0,
            max_group_elements: 0,
            max_signatures: 0,
            max_nested_groups: 0,
            max_nesting_depth: 0,
        };
        let (span, allocations, bytes) = measure(|| {
            let mut framer = MessageFramer::new(limits);
            for end in 1..=body.len() {
                assert_eq!(
                    framer.advance(&body[..end], false).expect("valid body"),
                    None
                );
            }
            framer.advance(&body, true).expect("valid final body")
        });
        assert_eq!(span.expect("EOF emits body").total_len, body.len());
        assert_eq!((allocations, bytes), (0, 0), "padding={padding}");
    }
}

#[test]
fn bytewise_variable_signature_group_keeps_no_input_copy() {
    for count in [64, 256] {
        let group = nested_signature_group(count);
        let limits = FrameLimits {
            max_body_bytes: 0,
            max_attachment_bytes: group.len(),
            max_attachment_groups: 1,
            max_group_elements: usize::try_from(count).expect("small fixture"),
            max_signatures: usize::try_from(count).expect("small fixture"),
            max_nested_groups: 0,
            max_nesting_depth: 0,
        };
        let (span, allocations, bytes) = measure(|| {
            let mut framer = MessageFramer::new(limits);
            for end in 1..group.len() {
                assert_eq!(
                    framer.advance(&group[..end], false).expect("valid prefix"),
                    None
                );
            }
            framer.advance(&group, true).expect("complete group")
        });
        assert_eq!(span.expect("group emits").total_len, group.len());
        assert_eq!((allocations, bytes), (0, 0), "signatures={count}");
    }
}

// ── The scaling tests ───────────────────────────────────────────────────

#[test]
fn groups_v1_iteration_requested_bytes_scale_linearly() {
    const K: u32 = 16;
    const BIG_K: u32 = 64;

    let stream_k = build_controller_idx_sigs_stream(K);
    let stream_big_k = build_controller_idx_sigs_stream(BIG_K);

    let (count_k, allocs_k, bytes_k) = measure(|| {
        let mut n = 0u32;
        Groups::<V1>::over(&stream_k).for_each(|r| {
            let _group: CesrGroup = r.expect("constructed group frames");
            n += 1;
        });
        n
    });
    let (count_big_k, allocs_big_k, bytes_big_k) = measure(|| {
        let mut n = 0u32;
        Groups::<V1>::over(&stream_big_k).for_each(|r| {
            let _group: CesrGroup = r.expect("constructed group frames");
            n += 1;
        });
        n
    });

    assert_eq!(count_k, K, "sanity: K-stream must yield K groups");
    assert_eq!(
        count_big_k, BIG_K,
        "sanity: BIG_K-stream must yield BIG_K groups"
    );

    assert!(
        allocs_big_k <= allocs_k * 6,
        "allocation count grew faster than group count"
    );
    assert!(
        bytes_big_k <= bytes_k * 6,
        "requested bytes grew faster than input"
    );

    let bound = stream_big_k.len().saturating_mul(3);
    assert!(
        bytes_big_k < bound,
        "iterating {BIG_K} groups allocated {bytes_big_k} bytes, expected < {bound} \
         (~3x the {}-byte input); a per-group re-copy of the \
         remaining buffer would allocate roughly K*(K+1)/2 times the input length",
        stream_big_k.len()
    );
}

#[test]
fn groups_v2_iteration_requested_bytes_scale_linearly() {
    const K: u32 = 16;
    const BIG_K: u32 = 64;

    let stream_k = build_controller_idx_sigs_stream_v2(K);
    let stream_big_k = build_controller_idx_sigs_stream_v2(BIG_K);

    let (count_k, allocs_k, bytes_k) = measure(|| {
        let mut n = 0u32;
        Groups::<V2>::over(&stream_k).for_each(|r| {
            let _group: CesrGroup = r.expect("constructed group frames");
            n += 1;
        });
        n
    });
    let (count_big_k, allocs_big_k, bytes_big_k) = measure(|| {
        let mut n = 0u32;
        Groups::<V2>::over(&stream_big_k).for_each(|r| {
            let _group: CesrGroup = r.expect("constructed group frames");
            n += 1;
        });
        n
    });

    assert_eq!(count_k, K, "sanity: K-stream must yield K groups");
    assert_eq!(
        count_big_k, BIG_K,
        "sanity: BIG_K-stream must yield BIG_K groups"
    );

    assert!(
        allocs_big_k <= allocs_k * 6,
        "allocation count grew faster than group count"
    );
    assert!(
        bytes_big_k <= bytes_k * 6,
        "requested bytes grew faster than input"
    );

    let bound = stream_big_k.len().saturating_mul(3);
    assert!(
        bytes_big_k < bound,
        "iterating {BIG_K} groups allocated {bytes_big_k} bytes, expected < {bound} \
         (~3x the {}-byte input); a per-group re-copy of the \
         remaining buffer would allocate roughly K*(K+1)/2 times the input length",
        stream_big_k.len()
    );
}
