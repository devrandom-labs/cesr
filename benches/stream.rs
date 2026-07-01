//! Benchmark for parsing a full multi-primitive CESR attachment stream.
//!
//! Run with: `cargo bench --features stream --bench stream`
//!
//! Builds a realistic stream — a controller indexed-sig group (2 sigs) followed
//! by a witness indexed-sig group (1 sig) — and measures parsing every group
//! out of it via the `groups()` iterator. Fixture construction is guarded so a
//! failure skips the bench rather than panicking.

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
use cesr::stream::encode::encode_counter_v1;
use cesr::stream::groups;
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

fn build_siger(index: u32) -> Option<Vec<u8>> {
    let indexer = IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519)
        .with_index(index)
        .ok()?
        .with_raw(vec![0u8; 64])
        .ok()?;
    Some(indexer.to_qb64().into_bytes())
}

/// `-A` group with 2 indexed sigs, then a `-B` group with 1 indexed sig.
fn build_stream() -> Option<Vec<u8>> {
    let mut input = encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 2).ok()?;
    input.extend_from_slice(build_siger(0)?.as_slice());
    input.extend_from_slice(build_siger(1)?.as_slice());
    input.extend_from_slice(
        encode_counter_v1(CounterCodeV1::WitnessIdxSigs, 1)
            .ok()?
            .as_slice(),
    );
    input.extend_from_slice(build_siger(0)?.as_slice());
    Some(input)
}

fn bench_stream_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_parse");
    if let Some(input) = build_stream() {
        group.bench_function("multi_group_controller_witness", |b| {
            b.iter(|| black_box(groups(black_box(input.as_slice())).collect::<Vec<_>>()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_stream_parse);
criterion_main!(benches);
