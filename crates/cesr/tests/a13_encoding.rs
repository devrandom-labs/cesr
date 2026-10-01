//! Direct CESR encoding regressions and explicit release measurements for A13.
#![cfg(feature = "std")]

use cesr::core::indexer::{IndexerBuilder, code::IndexedSigCode};
use cesr::core::matter::MatterPart;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::VerKeyCode;
use cesr::core::matter::error::{MatterBuildError, ValidationError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::mem::size_of_val;
use std::time::Instant;

thread_local! {
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

#[allow(unsafe_code, reason = "test-only allocation instrumentation")]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        let _ = REQUESTED_BYTES.try_with(|bytes| bytes.set(bytes.get() + layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        let _ = REQUESTED_BYTES.try_with(|bytes| bytes.set(bytes.get() + new_size));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCS.with(Cell::get);
    let result = f();
    (result, ALLOCS.with(Cell::get) - before)
}

fn measure_storage<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    let before_allocs = ALLOCS.with(Cell::get);
    let before_bytes = REQUESTED_BYTES.with(Cell::get);
    let result = f();
    (
        result,
        ALLOCS.with(Cell::get) - before_allocs,
        REQUESTED_BYTES.with(Cell::get) - before_bytes,
    )
}

#[test]
fn primitive_qb64_allocates_only_its_result() {
    let matter = MatterBuilder::new()
        .from_qualified_base64(b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .expect("known CESR key");
    let indexer = IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519Big)
        .with_indices(10, 20)
        .expect("valid indices")
        .with_raw(&[0xabu8; 64])
        .expect("valid signature");

    let _ = matter.to_qb64b();
    let _ = indexer.to_qb64();
    let (matter_bytes, matter_allocs) = measure(|| matter.to_qb64b());
    let (indexer_string, indexer_allocs) = measure(|| indexer.to_qb64());

    assert_eq!(
        matter_bytes,
        b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(indexer_string.len(), indexer.full_size());
    assert!(matter_allocs <= 1, "Matter allocated {matter_allocs} times");
    assert!(
        indexer_allocs <= 1,
        "Indexer allocated {indexer_allocs} times"
    );
}

#[test]
fn append_reuses_buffer_and_preserves_all_indexer_headers() {
    let codes = [
        IndexedSigCode::Ed25519,
        IndexedSigCode::Ed25519Crt,
        IndexedSigCode::ECDSA256k1,
        IndexedSigCode::ECDSA256k1Crt,
        IndexedSigCode::ECDSA256r1,
        IndexedSigCode::ECDSA256r1Crt,
        IndexedSigCode::Ed448,
        IndexedSigCode::Ed448Crt,
        IndexedSigCode::Ed25519Big,
        IndexedSigCode::Ed25519BigCrt,
        IndexedSigCode::ECDSA256k1Big,
        IndexedSigCode::ECDSA256k1BigCrt,
        IndexedSigCode::ECDSA256r1Big,
        IndexedSigCode::ECDSA256r1BigCrt,
        IndexedSigCode::Ed448Big,
        IndexedSigCode::Ed448BigCrt,
    ];
    for code in codes {
        let raw = vec![0xa5; code.raw_size()];
        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(1)
            .expect("valid index")
            .with_raw(raw.as_slice())
            .expect("valid raw size");
        let expected = indexer.to_qb64();
        let mut out = Vec::with_capacity(expected.len() + 8);
        out.extend_from_slice(b"prefix");
        let ((), allocations) = measure(|| indexer.append_qb64(&mut out));
        assert_eq!(allocations, 0, "code {code:?} allocated while appending");
        assert_eq!(&out[6..], expected.as_bytes(), "code {code:?}");
    }
}

#[test]
fn append_preserves_matter_leads_and_existing_bytes() {
    for qb64 in [
        "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "VAAt",
        "0J_A",
        "4AACnhE8oa_r",
        "4BABAQID",
        "5BABAAEC",
        "6BABAAAB",
        "7AABAAABAQID",
        "8AABAAABAAEC",
        "9AABAAABAAAB",
    ] {
        let matter = MatterBuilder::new()
            .from_qualified_base64(qb64.as_bytes())
            .expect("valid CESR vector");
        let mut out = Vec::with_capacity(qb64.len() + 8);
        out.extend_from_slice(b"prefix");
        let ((), allocations) = measure(|| matter.append_qb64(&mut out));
        assert_eq!(allocations, 0, "code {:?}", matter.code());
        assert_eq!(&out[6..], qb64.as_bytes());
    }
}

#[test]
fn nonzero_lead_bytes_and_pad_bits_remain_noncanonical() {
    let bad_lead = MatterBuilder::new()
        .from_qualified_base64(b"5BABBAEC")
        .expect_err("nonzero lead byte must fail");
    assert!(matches!(
        bad_lead,
        MatterBuildError::Validation(ValidationError::NonCanonicalEncoding(MatterPart::LeadBytes))
    ));

    let mut bad_pad = b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
    bad_pad[1] = b'Q';
    let error = MatterBuilder::new()
        .from_qualified_base64(bad_pad.as_slice())
        .expect_err("nonzero pad bits must fail");
    assert!(matches!(
        error,
        MatterBuildError::Validation(ValidationError::NonCanonicalEncoding(MatterPart::PadBits))
    ));
}

#[test]
#[ignore = "release-only A13 owned-material prototype; run explicitly"]
#[allow(clippy::print_stdout, reason = "explicit release measurement output")]
fn owned_key_representation_measurement() {
    const KEYS: usize = 1024;
    let make_cow = || {
        let mut keys = Vec::with_capacity(KEYS);
        for i in 0..KEYS {
            let raw = [u8::try_from(i % 256).expect("bounded byte"); 32];
            let key = MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(&raw[..])
                .expect("raw present")
                .build()
                .expect("valid raw size")
                .into_static();
            keys.push(key);
        }
        keys
    };
    let make_inline = || {
        let mut keys = Vec::with_capacity(KEYS);
        for i in 0..KEYS {
            let raw = [u8::try_from(i % 256).expect("bounded byte"); 32];
            keys.push((VerKeyCode::Ed25519, raw));
        }
        keys
    };
    let (cow, cow_allocs, cow_bytes) = measure_storage(make_cow);
    let (inline, inline_allocs, inline_bytes) = measure_storage(make_inline);
    println!(
        "a13 owned_key count={KEYS} matter_slot={} inline_slot={} cow_allocs={cow_allocs} cow_requested_bytes={cow_bytes} inline_allocs={inline_allocs} inline_requested_bytes={inline_bytes}",
        size_of_val(&cow[0]),
        size_of_val(&inline[0]),
    );
    black_box((cow, inline));

    for sample in 0..31 {
        let cow_start = Instant::now();
        black_box(make_cow());
        let cow_ns = cow_start.elapsed().as_nanos();
        let inline_start = Instant::now();
        black_box(make_inline());
        let inline_ns = inline_start.elapsed().as_nanos();
        println!("a13 owned_key sample={sample} cow_ns={cow_ns} inline_ns={inline_ns}");
    }
}

#[test]
#[ignore = "release-only A13 measurement; run explicitly with --ignored --nocapture"]
#[allow(clippy::print_stdout, reason = "explicit release measurement output")]
fn primitive_release_measurement() {
    let matter = MatterBuilder::new()
        .from_qualified_base64(b"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .expect("known CESR key");
    let indexer = IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519Big)
        .with_indices(10, 20)
        .expect("valid indices")
        .with_raw(&[0xabu8; 64])
        .expect("valid signature");
    let cases: [(&str, &dyn FnEncode); 2] = [("matter", &matter), ("indexer", &indexer)];
    for (name, work) in cases {
        for _ in 0..4 {
            black_box(work.encode());
        }
        for sample in 0..31 {
            let start = Instant::now();
            for _ in 0..10_000 {
                black_box(work.encode());
            }
            println!(
                "a13 {name} sample={sample} ns={}",
                start.elapsed().as_nanos()
            );
        }
    }
}

trait FnEncode {
    fn encode(&self) -> Vec<u8>;
}

impl<C: cesr::core::matter::code::CesrCode> FnEncode for cesr::core::matter::Matter<'_, C> {
    fn encode(&self) -> Vec<u8> {
        self.to_qb64b()
    }
}

impl FnEncode for cesr::core::indexer::Indexer<'_> {
    fn encode(&self) -> Vec<u8> {
        self.to_qb64().into_bytes()
    }
}
