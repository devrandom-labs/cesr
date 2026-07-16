//! Event-serialization benchmarks.
//!
//! Measures the production entry points (`serialize_inception` /
//! `serialize_interaction`) over the single direct JSON writer, plus the
//! strict-reader deserialize path. Fixtures are deterministic (fixed raw
//! bytes) for stable `CodSpeed` input.

// The lints below fire only inside `codspeed-criterion-compat`'s
// `criterion_group!`/`criterion_main!` macro expansion — third-party macro code
// we cannot annotate per-item. Benches are host-only tooling, not shipped.
#![allow(
    missing_docs,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    reason = "fire only inside codspeed-criterion-compat macro expansion; not our code"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::{Prefixer, Saider};
use cesr::keri::SigningThreshold;
use cesr::keri::{
    ConfigTrait, Identifier, InceptionEvent, InteractionEvent, Seal, SequenceNumber, ThresholdForm,
    Toad,
};
use cesr::serder::{deserialize_event, serialize_inception, serialize_interaction};
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

fn prefixer(byte: u8) -> Prefixer<'static> {
    let built = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(vec![byte; 32]);
    if let Ok(b) = built
        && let Ok(m) = b.build()
    {
        return m;
    }
    unreachable!("fixed 32-byte raw always builds an Ed25519 prefixer")
}

fn saider(byte: u8) -> Saider<'static> {
    let built = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(vec![byte; 32]);
    if let Ok(b) = built
        && let Ok(m) = b.build()
    {
        return m;
    }
    unreachable!("fixed 32-byte raw always builds a Blake3 saider")
}

fn single_witness_toad() -> Toad {
    if let Ok(toad) = Toad::exact(1, 1) {
        return toad;
    }
    unreachable!("toad 1 for a single witness is always in range")
}

/// A representative inception: two keys, two next-key digests, one witness,
/// one config trait, two anchors.
fn fixture_icp() -> InceptionEvent<'static> {
    InceptionEvent::new(
        Identifier::Basic(prefixer(0)),
        SequenceNumber::new(0),
        saider(1),
        vec![prefixer(2), prefixer(3)],
        SigningThreshold::Simple(2),
        vec![saider(4), saider(5)],
        SigningThreshold::Simple(2),
        vec![prefixer(6)],
        single_witness_toad(),
        vec![ConfigTrait::EstOnly],
        vec![
            Seal::Digest { d: saider(7) },
            Seal::Source {
                s: SequenceNumber::new(3),
                d: saider(8),
            },
        ],
        ThresholdForm::HexString,
    )
}

/// An anchor-heavy interaction: 16 digest seals (the value-array hot loop).
fn fixture_ixn() -> InteractionEvent<'static> {
    let anchors = (0..16_u8).map(|i| Seal::Digest { d: saider(i) }).collect();
    InteractionEvent::new(
        Identifier::Basic(prefixer(0)),
        SequenceNumber::new(1),
        saider(1),
        saider(2),
        anchors,
    )
}

fn bench_serialize(c: &mut Criterion) {
    let icp = fixture_icp();
    let ixn = fixture_ixn();

    let mut group = c.benchmark_group("serder_serialize");
    group.bench_function("icp_direct", |b| {
        b.iter(|| serialize_inception(black_box(&icp)));
    });
    group.bench_function("ixn16_direct", |b| {
        b.iter(|| serialize_interaction(black_box(&ixn)));
    });
    group.finish();
}

fn bench_deserialize(c: &mut Criterion) {
    let icp = fixture_icp();
    let Ok(serialized) = serialize_inception(&icp) else {
        unreachable!("fixture_icp always serializes")
    };
    let bytes = serialized.as_bytes();

    let mut group = c.benchmark_group("serder_deserialize");
    group.bench_function("icp", |b| {
        b.iter(|| deserialize_event(black_box(bytes)));
    });
    group.finish();
}

criterion_group!(benches, bench_serialize, bench_deserialize);
criterion_main!(benches);
