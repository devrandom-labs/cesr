//! Representative V1 JSON/text message parser workloads.
//!
//! Fixture construction and signature generation happen outside measurement.
//! The parser is measured on one signed inception, an inception with 16
//! attachment groups, and a batch of 16 framed messages.

#![allow(
    missing_docs,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    reason = "fire only inside codspeed-criterion-compat macro expansion; not our code"
)]

#[path = "../tests/common/mod.rs"]
mod common;

use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use keri_codec::{EventMessage, Message};

fn bench_messages(c: &mut Criterion) {
    let Ok(controller) = common::Key::new() else {
        unreachable!("benchmark controller setup failed")
    };
    let Ok(next_key) = common::Key::new() else {
        unreachable!("benchmark next key setup failed")
    };
    let Ok(inception) = common::genesis(&controller, &next_key) else {
        unreachable!("benchmark inception setup failed")
    };
    let Ok(signer_evidence) = controller.sign(&inception.bytes, 0) else {
        unreachable!("benchmark signature setup failed")
    };
    let signature = signer_evidence.to_qb64();
    let body_len = inception.bytes.len();
    let mut single = inception.bytes;
    single.extend_from_slice(b"-AAB");
    single.extend_from_slice(signature.as_bytes());

    let mut groups_16 = single.clone();
    for _ in 1..16 {
        groups_16.extend_from_slice(b"-AAB");
        groups_16.extend_from_slice(signature.as_bytes());
    }

    let mut framed = single.clone();
    framed.splice(body_len..body_len, b"-VAX".iter().copied());
    let batch_16 = framed.repeat(16);
    let limits = common::message_limits();

    assert!(EventMessage::parse(&single, limits).is_ok());
    assert!(EventMessage::parse(&groups_16, limits).is_ok());
    assert!(Message::parse(&batch_16, limits).is_ok());

    let mut group = c.benchmark_group("message_parse_v1");
    group.bench_function("signed_inception", |b| {
        b.iter(|| EventMessage::parse(black_box(&single), limits));
    });
    group.bench_function("signed_inception_16_groups", |b| {
        b.iter(|| EventMessage::parse(black_box(&groups_16), limits));
    });
    group.bench_function("framed_batch_16", |b| {
        b.iter(|| {
            let mut rest = black_box(batch_16.as_slice());
            while !rest.is_empty() {
                let Ok((_, remainder)) = Message::parse(rest, limits) else {
                    unreachable!("prevalidated benchmark frame failed")
                };
                rest = remainder;
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_messages);
criterion_main!(benches);
