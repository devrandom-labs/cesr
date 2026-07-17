//! Indexer differential replay vs keripy: decode keripy's bytes → assert cesr's
//! fields, and encode cesr's fields → assert keripy's exact bytes. Covers the
//! `CurrentOnly` `os` zero-fill that #47 fixed.

use std::eprintln;

use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;

use super::{DiffVector, from_hex, load};

/// Decode keripy's qb64 and assert every reconstructed field plus consumed length.
#[allow(
    clippy::panic,
    reason = "test-only differential harness: intentional panic on codec failure"
)]
fn assert_decode(v: &DiffVector, code: IndexedSigCode, index: u32) {
    let (decoded, consumed) = IndexerBuilder::new()
        .from_qb64(v.qb64.as_bytes())
        .unwrap_or_else(|e| panic!("from_qb64 {:?}: {e:?}", v.qb64));
    assert_eq!(
        decoded.code(),
        code,
        "decoded code mismatch for {:?}",
        v.qb64
    );
    assert_eq!(
        decoded.raw(),
        from_hex(&v.raw).as_slice(),
        "decoded raw mismatch for {:?}",
        v.qb64
    );
    assert_eq!(decoded.index(), index, "decoded index for {:?}", v.qb64);
    assert_eq!(decoded.ondex(), v.ondex, "decoded ondex for {:?}", v.qb64);
    assert_eq!(consumed, v.qb64.len(), "consumed len for {:?}", v.qb64);
}

/// Build from cesr fields and assert keripy's exact qb64 + qb2. Uses
/// `with_indices` only when keripy carries an explicit ondex differing from the
/// index; otherwise `with_index` (which derives the ondex per the code's mode).
#[allow(
    clippy::panic,
    reason = "test-only differential harness: intentional panic on codec failure"
)]
fn assert_encode(v: &DiffVector, code: IndexedSigCode, index: u32) {
    let expected_raw = from_hex(&v.raw);
    let staged = match v.ondex {
        Some(ondex) if ondex != index => IndexerBuilder::new()
            .with_code(code)
            .with_indices(index, ondex)
            .unwrap_or_else(|e| panic!("with_indices {:?}: {e:?}", v.code)),
        _ => IndexerBuilder::new()
            .with_code(code)
            .with_index(index)
            .unwrap_or_else(|e| panic!("with_index {:?}: {e:?}", v.code)),
    };
    let indexer = staged
        .with_raw(&expected_raw)
        .unwrap_or_else(|e| panic!("with_raw {:?}: {e:?}", v.code));
    assert_eq!(indexer.to_qb64(), v.qb64, "qb64 encode for {:?}", v.code);
    assert_eq!(
        indexer.to_qb2(),
        from_hex(&v.qb2),
        "qb2 encode for {:?}",
        v.code
    );
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only differential harness: intentional panic on codec failure and eprintln skip logging per task spec"
)]
fn indexer_differential_vs_keripy() {
    let vectors = load("indexer");
    assert!(!vectors.is_empty(), "indexer corpus is empty");

    let mut skipped = 0usize;
    for v in &vectors {
        let Ok(code) = IndexedSigCode::from_hard(&v.code) else {
            eprintln!("SKIP indexer: unimplemented code {:?}", v.code);
            skipped += 1;
            continue;
        };
        let index = v
            .index
            .unwrap_or_else(|| panic!("indexer vector {:?} missing index", v.code));

        assert_decode(v, code, index);
        assert_encode(v, code, index);
    }

    eprintln!(
        "indexer: {} vectors, {skipped} skipped (unimplemented codes)",
        vectors.len()
    );
}
