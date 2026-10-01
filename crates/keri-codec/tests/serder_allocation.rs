//! Allocation-count safeguards for serder's single writer and strict reader.
//!
//! The direct JSON writer exists to eliminate the `serde_json::Value` tree
//! and the intermediate `String` render from event serialization; the strict
//! reader keeps deserialization at one scratch copy plus domain-type
//! construction. Those wins are behaviorally invisible — output bytes stay
//! identical — so conformance tests cannot catch an allocation regression.
//! These tests set allocation ceilings for a fixed fixture so improvements
//! remain valid while an intermediate tree or per-field string regression fails.
//!
//! Mirrors the counting-allocator convention of `tests/allocation.rs`
//! (thread-local counters, separate test binary so the global allocator
//! does not interfere with other suites).
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "integration test binary — entirely test code, same convention as \
              #[cfg(test)] mod tests in src/, which use unwrap() to document the \
              invariant that fails"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::Number;
use core::cell::Cell;
use keri_codec::{Deserialize, Serialize};
use keri_events::KeriEvent;
use keri_events::SigningThreshold;
use keri_events::{
    BasicPrefix, ConfigTrait, Digest, Identifier, InceptionEvent, Said, Seal, ThresholdForm, Toad,
    VerifyingKey,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::time::Instant;

thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

#[allow(
    unsafe_code,
    reason = "test-only global allocator; crate's no-unsafe rule applies to src/, not tests/"
)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let c0 = COUNT.with(Cell::get);
    let result = f();
    (result, COUNT.with(Cell::get) - c0)
}

fn prefixer(byte: u8) -> BasicPrefix<'static> {
    BasicPrefix::from_matter(
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519N)
            .with_raw(vec![byte; 32])
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn verfer(byte: u8) -> VerifyingKey<'static> {
    VerifyingKey::from_matter(
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(vec![byte; 32])
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn saider(byte: u8) -> Said<'static> {
    Said::from_matter(
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(vec![byte; 32])
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn diger(byte: u8) -> Digest<'static> {
    Digest::from_matter(
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(vec![byte; 32])
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn fixture_icp() -> InceptionEvent<'static> {
    InceptionEvent::new_unchecked(
        Identifier::SelfAddressing(saider(0)),
        Number::new(0),
        saider(1),
        vec![verfer(2), verfer(3)],
        SigningThreshold::Simple(2),
        vec![diger(4), diger(5)],
        SigningThreshold::Simple(2),
        vec![prefixer(6)],
        Toad::exact(1, 1).unwrap(),
        vec![ConfigTrait::EstOnly],
        vec![
            Seal::Digest { d: saider(7) },
            Seal::Source {
                s: Number::new(3),
                d: saider(8),
            },
        ],
        ThresholdForm::HexString,
    )
}

/// A13's direct qb64 writer reduced this fixture from 38 to 22 allocations.
/// Remaining work includes output growth, digest ownership and hex fields.
const SERIALIZE_ALLOC_CEILING: usize = 22;

#[test]
fn serialize_allocation_ceiling() {
    let event = fixture_icp();

    // Warm once so lazy one-time setup does not skew the delta.
    let _ = event.serialize().unwrap();

    let (out, allocs) = measure(|| event.serialize().unwrap());
    drop(out);

    assert!(
        allocs <= SERIALIZE_ALLOC_CEILING,
        "serialize_inception allocated {allocs} times, above the direct-writer \
         ceiling of {SERIALIZE_ALLOC_CEILING}"
    );
}

#[test]
#[ignore = "release-only A13 measurement; run explicitly with --ignored --nocapture"]
#[allow(clippy::print_stdout, reason = "explicit release measurement output")]
fn serialize_release_measurement() {
    let event = fixture_icp();
    for _ in 0..4 {
        black_box(event.serialize().expect("fixture serializes"));
    }
    let (_, allocations) = measure(|| event.serialize().expect("fixture serializes"));
    println!("a13 serialize allocations={allocations}");
    for sample in 0..31 {
        let start = Instant::now();
        for _ in 0..1_000 {
            black_box(event.serialize().expect("fixture serializes"));
        }
        println!(
            "a13 serialize sample={sample} ns={}",
            start.elapsed().as_nanos()
        );
    }
}

/// Allocation ceiling for deserializing `fixture_icp`'s event: one raw
/// scratch copy for SAID verification plus the parsed domain-type
/// construction (Vecs of keys/digests/witnesses/seals, qb64 raw buffers,
/// error-free paths only). A lower count is welcome; an increase needs a
/// measured reason.
///
/// Re-derived for A01: a multi-key inception must use a self-addressing
/// prefix, so both `d` and `i` are digestive and the valid fixture costs
/// 41 allocations to deserialize on aarch64-darwin.
const DESERIALIZE_ALLOC_CEILING: usize = 41;

#[test]
fn deserialize_allocation_ceiling() {
    let event = fixture_icp();
    let serialized = event.serialize().expect("fixture serializes");
    let bytes = serialized.as_bytes();

    let _ = KeriEvent::deserialize(bytes, keri_codec::JsonLimits::new(4096, 64))
        .expect("fixture deserializes");

    let (parsed, allocs) = measure(|| {
        KeriEvent::deserialize(bytes, keri_codec::JsonLimits::new(4096, 64))
            .expect("fixture deserializes")
    });
    drop(parsed);

    assert!(
        allocs <= DESERIALIZE_ALLOC_CEILING,
        "deserialize_event allocated {allocs} times, above the strict-reader \
         ceiling of {DESERIALIZE_ALLOC_CEILING}"
    );
}
