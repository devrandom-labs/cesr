//! Composed-stream differential replay vs keripy.
//!
//! Exercises a full attachment group: a V1 `-A` `ControllerIdxSigs` counter
//! whose count equals the number of trailing indexed-signature elements.

use std::eprintln;

use crate::parse::TextStream;
use crate::qb2::{Qb2, Qb64};
use cesr::core::counter::CounterCodeV1;

use super::{from_hex, load};

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only differential harness: intentional panic on codec failure and eprintln logging per task spec"
)]
fn stream_differential_vs_keripy() {
    let vectors = load("stream");
    assert!(!vectors.is_empty(), "stream corpus is empty");

    for v in &vectors {
        let expected_qb2 = from_hex(&v.qb2);

        // qb64 <-> qb2 transcode round-trips against keripy's bytes
        assert_eq!(
            Qb64(v.qb64.as_bytes())
                .decode()
                .unwrap_or_else(|e| panic!("decode: {e:?}")),
            expected_qb2,
            "qb64->qb2 mismatch for {:?}",
            v.qb64
        );
        assert_eq!(
            Qb2(&expected_qb2)
                .encode()
                .unwrap_or_else(|e| panic!("encode: {e:?}")),
            v.qb64.as_bytes(),
            "qb2->qb64 mismatch for {:?}",
            v.qb64
        );

        // outer V1 counter: code, element count, and non-empty payload
        let mut ts = TextStream::new(v.qb64.as_bytes());
        let (code, count) = ts
            .read_counter_v1()
            .unwrap_or_else(|e| panic!("read_counter_v1 {:?}: {e:?}", v.qb64));
        let rest = ts.remaining();
        assert_eq!(
            code,
            CounterCodeV1::ControllerIdxSigs,
            "outer counter code mismatch for {:?}",
            v.qb64
        );
        assert_eq!(
            usize::try_from(count).expect("count fits usize"),
            v.elements.len(),
            "counter count != element count for {:?}",
            v.qb64
        );
        assert!(
            !rest.is_empty(),
            "expected non-empty element payload after counter for {:?}",
            v.qb64
        );
    }

    eprintln!("stream: {} vector(s) replayed", vectors.len());
}
