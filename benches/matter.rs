//! Benchmarks for `Matter` primitive encode/decode and `qb64`<->`qb2` conversion.
//!
//! Run with: `cargo bench --features stream --bench matter`
//!
//! Fixtures are real `qb64` vectors from `src/core/matter/test_vectors.rs`
//! (generated from `KERIpy` v2.0.0-dev5), so they parse without contrivance.
//! Operations are benchmarked by `black_box`-ing the returned `Result` — the
//! crate's lint policy forbids `unwrap`/`expect` even in benches.

use cesr::core::matter::builder::MatterBuilder;
use cesr::stream::binary::{qb2_to_qb64, qb64_to_qb2};
use cesr::stream::encode::matter_to_qb64;
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

/// Fixed-size code (`Ed25519` non-transferable verkey, 32-byte raw, 44-char `qb64`).
const ED25519N_QB64: &str = "BDhylkfP3gHCziiybFdHJzf1w1YaF2EYW9hYmkPOC7p1";
/// Fixed-size code (`Blake3-256` digest, 32-byte raw, 44-char `qb64`).
const BLAKE3_256_QB64: &str = "ENfExg460gjOUGZEEDbp8ZHgt1A2p39l4uqkdSRDIz--";
/// Variable-size code (`StrB64` lead-0) — exercises the soft-size decode path.
const STRB64_L0_QB64: &str = "4AACnhE8oa_r";

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("matter_decode");
    group.bench_function("ed25519n_fixed", |b| {
        b.iter(|| {
            black_box(
                MatterBuilder::new().from_qualified_base64(black_box(ED25519N_QB64.as_bytes())),
            )
        });
    });
    group.bench_function("blake3_256_fixed", |b| {
        b.iter(|| {
            black_box(
                MatterBuilder::new().from_qualified_base64(black_box(BLAKE3_256_QB64.as_bytes())),
            )
        });
    });
    group.bench_function("strb64_l0_variable", |b| {
        b.iter(|| {
            black_box(
                MatterBuilder::new().from_qualified_base64(black_box(STRB64_L0_QB64.as_bytes())),
            )
        });
    });
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("matter_encode");
    // `matter_to_qb64` panics on variable-size codes by contract, so only
    // fixed-size primitives are encoded here.
    if let Ok(ed_matter) = MatterBuilder::new().from_qualified_base64(ED25519N_QB64.as_bytes()) {
        group.bench_function("ed25519n_to_qb64", |b| {
            b.iter(|| black_box(matter_to_qb64(black_box(&ed_matter))));
        });
    }
    if let Ok(blake_matter) = MatterBuilder::new().from_qualified_base64(BLAKE3_256_QB64.as_bytes())
    {
        group.bench_function("blake3_256_to_qb64", |b| {
            b.iter(|| black_box(matter_to_qb64(black_box(&blake_matter))));
        });
    }
    group.finish();
}

fn bench_convert(c: &mut Criterion) {
    let mut group = c.benchmark_group("matter_convert");
    group.bench_function("qb64_to_qb2", |b| {
        b.iter(|| black_box(qb64_to_qb2(black_box(ED25519N_QB64.as_bytes()))));
    });
    if let Ok(qb2) = qb64_to_qb2(ED25519N_QB64.as_bytes()) {
        group.bench_function("qb2_to_qb64", |b| {
            b.iter(|| black_box(qb2_to_qb64(black_box(qb2.as_slice()))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_decode, bench_encode, bench_convert);
criterion_main!(benches);
