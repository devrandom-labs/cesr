//! Allocation-count safeguards for serder's single writer and strict reader.
//!
//! The direct JSON writer exists to eliminate the `serde_json::Value` tree
//! and the intermediate `String` render from event serialization; the strict
//! reader keeps deserialization at one scratch copy plus domain-type
//! construction. Those wins are behaviorally invisible — output bytes stay
//! identical — so conformance tests cannot catch an allocation regression.
//! These tests pin the absolute allocation *counts* for a fixed fixture as
//! observable, asserted invariants.
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
use cesr::core::primitives::{Prefixer, Saider};
use cesr::keri::KeriEvent;
use cesr::keri::SigningThreshold;
use cesr::keri::{
    ConfigTrait, Identifier, InceptionEvent, Seal, SequenceNumber, ThresholdForm, Toad,
};
use core::cell::Cell;
use keri_codec::{KeriDeserialize, KeriSerialize};
use std::alloc::{GlobalAlloc, Layout, System};

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

fn prefixer(byte: u8) -> Prefixer<'static> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(vec![byte; 32])
        .unwrap()
        .build()
        .unwrap()
}

fn saider(byte: u8) -> Saider<'static> {
    MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(vec![byte; 32])
        .unwrap()
        .build()
        .unwrap()
}

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
        Toad::exact(1, 1).unwrap(),
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

/// Exact allocation count for serializing `fixture_icp` through the single
/// direct writer: the output buffer's growth plus per-field qb64/hex string
/// materialization. Deterministic for a fixed fixture; a change means the
/// write path's allocation shape changed — re-derive deliberately, don't
/// just bump the number.
const SERIALIZE_ALLOCS: usize = 36;

#[test]
fn serialize_allocation_count_is_pinned() {
    let event = fixture_icp();

    // Warm once so lazy one-time setup does not skew the delta.
    let _ = event.serialize().unwrap();

    let (out, allocs) = measure(|| event.serialize().unwrap());
    drop(out);

    assert_eq!(
        allocs, SERIALIZE_ALLOCS,
        "serialize_inception allocation count changed — the direct writer \
         must stay at buffer growth plus per-field string materialization; \
         a rise means an intermediate tree or render crept back in"
    );
}

/// Exact allocation count for deserializing `fixture_icp`'s event: one raw
/// scratch copy for SAID verification plus the parsed domain-type
/// construction (Vecs of keys/digests/witnesses/seals, qb64 raw buffers,
/// error-free paths only). Deterministic for a fixed fixture; a change means
/// the read path's allocation shape changed — re-derive deliberately, don't
/// just bump the number.
///
/// Re-derived for #144: the fixture's `Identifier::Basic` prefix now
/// serializes as the public key (single-SAID), so the parsed `i` narrows to
/// `Identifier::Basic` instead of falling through to `Saider` construction,
/// which drops three allocations versus the old forced-double-SAID bytes.
const DESERIALIZE_ALLOCS: usize = 35;

#[test]
fn deserialize_allocation_count_is_pinned() {
    let event = fixture_icp();
    let serialized = event.serialize().expect("fixture serializes");
    let bytes = serialized.as_bytes();

    let _ = KeriEvent::deserialize(bytes).expect("fixture deserializes");

    let (parsed, allocs) = measure(|| KeriEvent::deserialize(bytes).expect("fixture deserializes"));
    drop(parsed);

    assert_eq!(
        allocs, DESERIALIZE_ALLOCS,
        "deserialize_event allocation count changed — the strict read path \
         must stay at one scratch copy plus domain-type construction; a rise \
         means an intermediate tree or render crept back in"
    );
}
