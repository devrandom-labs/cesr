//! Indexer differential replay vs keripy.
//!
//! FINDING (real cesr↔keripy disagreement): `Indexer::to_qb64` fills the
//! `os` (ondex) slot with `self.ondex.unwrap_or(self.index)`, so for
//! `CurrentOnly` codes with `os > 0` (`0B`, `2B`, `2D`, `2F`, `3B`) it writes
//! the *index* into that slot. keripy zero-fills it (e.g. `2D` index=63,
//! ondex=null serialises as `2DA_AAB…` — the `AA` after `A_` is a literal
//! zero, not the index). The encode disagreement is exercised by the
//! `#[ignore]`d bug-probe below; the main test still verifies decode for all
//! vectors and encode for every unaffected vector.

use std::eprintln;

use crate::core::indexer::IndexerBuilder;
use crate::core::indexer::code::IndexedSigCode;

use super::{from_hex, load};

/// True when cesr's `to_qb64` disagrees with keripy on the zero-filled `os`
/// slot: `CurrentOnly` code (corpus `ondex` is null), positive `os` width, and
/// a non-zero index (at index 0 both encodings agree).
fn hits_currentonly_os_bug(code: IndexedSigCode, index: u32, ondex: Option<u32>) -> bool {
    ondex.is_none() && code.get_xizage().os > 0 && index > 0
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
    let mut deferred_encode = 0usize;
    for v in &vectors {
        let Ok(code) = IndexedSigCode::from_hard(&v.code) else {
            eprintln!("SKIP indexer: unimplemented code {:?}", v.code);
            skipped += 1;
            continue;
        };
        let index = v
            .index
            .unwrap_or_else(|| panic!("indexer vector {:?} missing index", v.code));
        let expected_raw = from_hex(&v.raw);
        let expected_qb2 = from_hex(&v.qb2);

        // decode qb64 → assert reconstructed fields and consumed length
        let (decoded, consumed) = IndexerBuilder::new()
            .from_qb64(v.qb64.as_bytes())
            .unwrap_or_else(|e| panic!("from_qb64 {:?}: {e:?}", v.qb64));
        assert_eq!(decoded.code(), code, "decoded code mismatch for {:?}", v.qb64);
        assert_eq!(
            decoded.raw(),
            expected_raw.as_slice(),
            "decoded raw mismatch for {:?}",
            v.qb64
        );
        assert_eq!(
            decoded.index(),
            index,
            "decoded index mismatch for {:?}",
            v.qb64
        );
        assert_eq!(
            decoded.ondex(),
            v.ondex,
            "decoded ondex mismatch for {:?}",
            v.qb64
        );
        assert_eq!(
            consumed,
            v.qb64.len(),
            "consumed length mismatch for {:?}",
            v.qb64
        );

        // Encode disagreement for CurrentOnly `os` codes is covered by the
        // ignored bug-probe; defer their encode assertion here.
        if hits_currentonly_os_bug(code, index, v.ondex) {
            deferred_encode += 1;
            continue;
        }

        // encode cesr fields → assert keripy's exact qb64 and qb2.
        //
        // Use with_indices only when keripy carries an explicit ondex that
        // differs from index; otherwise with_index (which derives the ondex
        // per the code's mode).
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

        assert_eq!(
            indexer.to_qb64(),
            v.qb64,
            "qb64 encode mismatch for {:?}",
            v.code
        );
        assert_eq!(
            indexer.to_qb2(),
            expected_qb2,
            "qb2 encode mismatch for {:?}",
            v.code
        );
    }

    eprintln!(
        "indexer: {} vectors, {skipped} skipped (unimplemented codes), \
         {deferred_encode} encodes deferred to the CurrentOnly-os bug-probe",
        vectors.len()
    );
}

/// Bug-probe for the `CurrentOnly` `os` zero-fill disagreement. FAILS while the
/// bug exists (cesr writes the index into the `os` slot instead of zero), so it
/// stays `#[ignore]`d until cesr is fixed — never a green test hiding the bug.
#[test]
#[ignore = "FINDING: Indexer::to_qb64 writes the index into the os slot for CurrentOnly codes; keripy zero-fills it. Un-ignore once cesr matches keripy."]
#[allow(
    clippy::panic,
    reason = "test-only bug-probe: intentional panic on codec failure per task spec"
)]
fn indexer_currentonly_os_zerofill_vs_keripy() {
    let vectors = load("indexer");
    let mut probed = 0usize;
    for v in &vectors {
        let Ok(code) = IndexedSigCode::from_hard(&v.code) else {
            continue;
        };
        let index = v.index.expect("indexer vector missing index");
        if !hits_currentonly_os_bug(code, index, v.ondex) {
            continue;
        }
        probed += 1;
        let expected_raw = from_hex(&v.raw);
        let indexer = IndexerBuilder::new()
            .with_code(code)
            .with_index(index)
            .unwrap_or_else(|e| panic!("with_index {:?}: {e:?}", v.code))
            .with_raw(&expected_raw)
            .unwrap_or_else(|e| panic!("with_raw {:?}: {e:?}", v.code));
        assert_eq!(
            indexer.to_qb64(),
            v.qb64,
            "CurrentOnly os zero-fill: qb64 encode mismatch for {:?} index {index}",
            v.code
        );
        assert_eq!(
            indexer.to_qb2(),
            from_hex(&v.qb2),
            "CurrentOnly os zero-fill: qb2 encode mismatch for {:?} index {index}",
            v.code
        );
    }
    assert!(probed > 0, "no CurrentOnly-os vectors exercised the bug-probe");
}
