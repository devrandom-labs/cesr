//! Allocation-count safeguard for the #79 serialization backend seam.
//!
//! The direct backend exists to eliminate the `serde_json::Value` tree and
//! the intermediate `String` render from event serialization. That win is
//! behaviorally invisible — both backends produce byte-identical output —
//! so the cross-backend conformance tests cannot catch an allocation
//! regression. This test makes the allocation *count* an observable,
//! asserted invariant: the direct backend must allocate strictly less than
//! the `serde_json` reference for the same event.
//!
//! Mirrors the counting-allocator convention of `tests/allocation.rs`
//! (thread-local counters, separate test binary so the global allocator
//! does not interfere with other suites).
#![cfg(feature = "serder")]
#![allow(
    clippy::unwrap_used,
    reason = "integration test binary — entirely test code, same convention as \
              #[cfg(test)] mod tests in src/, which use unwrap() to document the \
              invariant that fails"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::{Prefixer, Saider};
use cesr::keri::SigningThreshold;
use cesr::keri::{
    ConfigTrait, Identifier, InceptionEvent, Seal, SequenceNumber, ThresholdForm, Toad,
};
use cesr::serder::{DirectJson, EventRef, SerdeJson, deserialize_event, serialize_with};
use core::cell::Cell;
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

fn fixture_icp() -> InceptionEvent {
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

#[test]
fn direct_backend_allocates_strictly_less_than_serde_json() {
    let event = fixture_icp();

    // Warm both paths once so lazy one-time setup does not skew the deltas.
    let _ = serialize_with(&SerdeJson, EventRef::Inception(&event)).unwrap();
    let _ = serialize_with(&DirectJson, EventRef::Inception(&event)).unwrap();

    let (reference, serde_allocs) =
        measure(|| serialize_with(&SerdeJson, EventRef::Inception(&event)).unwrap());
    let (direct, direct_allocs) =
        measure(|| serialize_with(&DirectJson, EventRef::Inception(&event)).unwrap());

    assert_eq!(
        reference.as_bytes(),
        direct.as_bytes(),
        "sanity: backends must agree before comparing their allocation counts"
    );
    assert!(
        direct_allocs < serde_allocs,
        "direct backend must allocate strictly less than the serde_json reference; \
         got direct={direct_allocs} vs serde_json={serde_allocs} — a regression \
         reintroduced an intermediate tree or render"
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
    let serialized =
        serialize_with(&DirectJson, EventRef::Inception(&event)).expect("fixture serializes");
    let bytes = serialized.as_bytes();

    let _ = deserialize_event(bytes).expect("fixture deserializes");

    let (parsed, allocs) = measure(|| deserialize_event(bytes).expect("fixture deserializes"));
    drop(parsed);

    assert_eq!(
        allocs, DESERIALIZE_ALLOCS,
        "deserialize_event allocation count changed — the strict read path \
         must stay at one scratch copy plus domain-type construction; a rise \
         means an intermediate tree or render crept back in"
    );
}
