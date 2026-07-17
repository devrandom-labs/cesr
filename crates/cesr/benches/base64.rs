//! Isolated Base64 codec microbenchmarks (issue #29 · P1.2).
//!
//! Run with: `cargo bench --bench base64`
//!
//! These bench the raw `base64` crate engine (`URL_SAFE_NO_PAD`) — the exact
//! engine used at the two production seams (`core::matter::builder` decode,
//! `stream::encode` encode) — in isolation from allocation, validation, and
//! code-table lookup. This is the **baseline**: any candidate codec
//! (`base64-simd`, `data-encoding`, a specialized scalar codec) is dropped into
//! the same size buckets and compared apples-to-apples.
//!
//! Sizes mirror real CESR payloads: 32 B (Ed25519 verkey / Blake3-256 digest),
//! 64 B (Ed25519 signature), and 1024 B (a large variable-size attachment) to
//! expose the small-input vs. asymptotic-SIMD crossover discussed on #29.
//!
//! ## #29 finding — no faster codec available at CESR sizes
//!
//! Three candidate replacements were implemented and benchmarked end-to-end
//! against this baseline via `benches/matter.rs` (the real Matter qb64 seams):
//!
//! | approach                          | decode 32 B | encode 32 B |
//! |-----------------------------------|-------------|-------------|
//! | unsafe-free scalar codec (tuned)  | +16 %       | +6 %        |
//! | base64 engine + large stack buf   | +9 %        | ~noise      |
//! | base64 engine + small stack buf   | +8 %        | ~noise      |
//!
//! All regressed. The `base64` engine has better instruction-level parallelism
//! than a serial scalar bit-accumulator, and the allocations the stack-buffer
//! approach removed turned out not to be the bottleneck (shrinking the buffer,
//! which slashes memset cost, changed nothing). At 32/64 B the seams are already
//! overhead-bound on the fast engine + thread-cached small allocations; there is
//! no headroom to reclaim. This bench stays as the reference any future codec
//! candidate must actually beat.

// The lints below fire only inside `codspeed-criterion-compat`'s
// `criterion_group!`/`criterion_main!` macro expansion — third-party macro code
// we cannot annotate per-item. Benches are host-only tooling, not shipped.
#![allow(
    missing_docs,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    reason = "fire only inside codspeed-criterion-compat macro expansion; not our code"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use core::hint::black_box;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Representative raw-payload sizes, labelled by the CESR primitive they model.
const SIZES: &[(&str, usize)] = &[
    ("32B_key_digest", 32),
    ("64B_signature", 64),
    ("1024B_attachment", 1024),
];

/// Deterministic byte fixture (pure `u8` arithmetic — no `as` casts, no `rand`
/// dev-dep) so `CodSpeed` sees a stable input across runs.
fn fixture(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut b: u8 = 0x5a;
    for _ in 0..len {
        b = b.wrapping_mul(31).wrapping_add(17);
        out.push(b);
    }
    out
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_encode");
    for &(label, size) in SIZES {
        let raw = fixture(size);
        let mut out = vec![0u8; B64.encode(&raw).len()];
        group.throughput(Throughput::Bytes(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(BenchmarkId::from_parameter(label), &raw, |b, input| {
            b.iter(|| black_box(B64.encode_slice(black_box(input), black_box(&mut out))));
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_decode");
    for &(label, size) in SIZES {
        let raw = fixture(size);
        let encoded = B64.encode(&raw);
        let mut out = vec![0u8; size];
        group.throughput(Throughput::Bytes(u64::try_from(encoded.len()).unwrap_or(0)));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            encoded.as_bytes(),
            |b, input| {
                b.iter(|| black_box(B64.decode_slice(black_box(input), black_box(&mut out))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
