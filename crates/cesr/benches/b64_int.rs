//! Microbenchmarks for the CESR Base64 variable-length integer codec
//! (`cesr::b64::{encode_int, decode_int}`) — the primitive hit on every counter
//! size, indexer index/ondex, and matter soft-size, so it is on the hot decode
//! and construction paths (see `core::indexer::*`, `core::matter::builder`).
//!
//! Run with: `cargo bench --bench b64_int`
//!
//! `b64_encode_hot` / `b64_decode_hot` are single-input groups used as the stable
//! autoresearch primary metrics; the `_range` groups monitor other magnitudes so a
//! change can't win on the 2-char case while regressing large values.

// The lints below fire only inside `codspeed-criterion-compat`'s
// `criterion_group!`/`criterion_main!` macro expansion — third-party macro code
// we cannot annotate per-item. Benches are host-only tooling, not shipped.
#![allow(
    missing_docs,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    reason = "fire only inside codspeed-criterion-compat macro expansion; not our code"
)]

use cesr::b64::{decode_int, encode_int};
use core::hint::black_box;
use core::num::NonZeroUsize;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

/// Non-panicking `NonZeroUsize` for known-good bench constants (host tooling).
fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN)
}

/// (label, value, `min_len`) — magnitudes spanning a 2-char count code up to a full
/// 11-char `u64`, plus a left-pad path.
const ENCODE_CASES: &[(&str, u64, usize)] = &[
    ("count_2char", 5, 2),                   // typical counter/index — the hot case
    ("padded_to_4", 3, 4),                   // left-pad branch
    ("u32_max", 4_294_967_295, 1),           // 6 chars
    ("u64_large", 0x0123_4567_89AB_CDEF, 1), // 11 chars, no padding
];

/// (label, qb64) decode fixtures — valid URL-safe Base64, decoded into `u64`.
const DECODE_CASES: &[(&str, &[u8])] = &[
    ("count_2char", b"Bk"),
    ("six_char", b"P_____"),
    ("u64_wide", b"H__________"),
];

fn bench_encode_hot(c: &mut Criterion) {
    c.bench_function("b64_encode_hot", |b| {
        b.iter(|| black_box(encode_int(black_box(5_u64), black_box(nz(2)))));
    });
}

fn bench_encode_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("b64_encode_range");
    for &(label, value, min_len) in ENCODE_CASES {
        group.bench_with_input(BenchmarkId::from_parameter(label), &value, |b, &v| {
            b.iter(|| black_box(encode_int(black_box(v), black_box(nz(min_len)))));
        });
    }
    group.finish();
}

fn bench_decode_hot(c: &mut Criterion) {
    c.bench_function("b64_decode_hot", |b| {
        b.iter(|| {
            let r: Result<u64, _> = decode_int(black_box(b"Bk".as_slice()));
            black_box(r)
        });
    });
}

fn bench_decode_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("b64_decode_range");
    for &(label, bytes) in DECODE_CASES {
        group.bench_with_input(BenchmarkId::from_parameter(label), &bytes, |b, &data| {
            b.iter(|| {
                let r: Result<u64, _> = decode_int(black_box(data));
                black_box(r)
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encode_hot,
    bench_encode_range,
    bench_decode_hot,
    bench_decode_range
);
criterion_main!(benches);
