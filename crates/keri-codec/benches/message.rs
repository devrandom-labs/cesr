//! Representative V1 JSON/text message parser workloads.
//!
//! Fixture construction and signature generation happen outside measurement.
//! The parser is measured on one signed inception, an inception with 16
//! attachment groups, a batch of 16 framed messages, and one signed IPEX
//! offer with pathed material.

#![allow(
    missing_docs,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    reason = "fire only inside codspeed-criterion-compat macro expansion; not our code"
)]

#[path = "../tests/common/mod.rs"]
mod common;

use cesr_stream::FrameLimits;
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use keri_codec::{EventMessage, ExnMessage, JsonLimits, Message, MessageLimits};

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

fn bench_exn(c: &mut Criterion) {
    let signed_offer = include_bytes!("fixtures/signed-ipex-offer");
    let limits = MessageLimits::new(
        FrameLimits {
            max_body_bytes: 4096,
            max_attachment_bytes: 4096,
            max_attachment_groups: 64,
            max_group_elements: 64,
            max_signatures: 2,
            max_nested_groups: 32,
            max_nesting_depth: 8,
        },
        JsonLimits::new(4096, 64),
    );
    let Ok((parsed, remainder)) = ExnMessage::parse(signed_offer, limits) else {
        unreachable!("signed IPEX offer benchmark fixture must parse")
    };
    assert!(remainder.is_empty());
    assert_eq!(parsed.sigs().len(), 1);
    assert_eq!(parsed.pathed().len(), 1);

    let mut group = c.benchmark_group("exn_parse_v1");
    group.bench_function("signed_ipex_offer_pathed", |b| {
        b.iter(|| ExnMessage::parse(black_box(signed_offer), limits));
    });
    group.finish();
}

criterion_group!(benches, bench_messages, bench_exn);
criterion_main!(benches);
