//! Benchmarks for CESR counter encoding and counter-led group parsing.
//!
//! Run with: `cargo bench --features stream --bench counter`
//!
//! The parse fixture is built from the public API (counter + one indexed
//! signature) and guarded with `if let Some(..)` so a fixture failure skips
//! the bench rather than panicking — the lint policy forbids `unwrap`.

// The lints below fire only inside `codspeed-criterion-compat`'s
// `criterion_group!`/`criterion_main!` macro expansion (env::var read, a held
// temporary guard, undocumented generated harness fns) — third-party macro code
// we cannot annotate per-item. Benches are host-only tooling, not shipped.
#![allow(
    missing_docs,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    reason = "fire only inside codspeed-criterion-compat macro expansion; not our code"
)]

use cesr::core::counter::CounterCodeV1;
use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::stream::CesrGroup;
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

/// Build a `-A` (controller indexed sigs) counter followed by one Ed25519
/// indexed signature — the smallest realistic parseable group.
fn build_controller_group() -> Option<Vec<u8>> {
    let counter = CounterCodeV1::ControllerIdxSigs.encode_count(1).ok()?;
    let indexer = IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519)
        .with_index(0)
        .ok()?
        .with_raw(vec![0u8; 64])
        .ok()?;
    let mut input = counter;
    input.extend_from_slice(indexer.to_qb64().as_bytes());
    Some(input)
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("counter_encode");
    group.bench_function("v1_small", |b| {
        b.iter(|| black_box(CounterCodeV1::ControllerIdxSigs.encode_count(black_box(2))));
    });
    group.bench_function("v1_auto_big", |b| {
        b.iter(|| {
            black_box(CounterCodeV1::PathedMaterialCouples.encode_count_auto(black_box(10_000)))
        });
    });
    group.finish();
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("counter_group_parse");
    if let Some(input) = build_controller_group() {
        group.bench_function("controller_idx_sigs_1sig", |b| {
            b.iter(|| black_box(CesrGroup::parse(black_box(input.as_slice()))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_parse);
criterion_main!(benches);
