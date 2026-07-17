//! Composed-stream differential replay vs keripy.
//!
//! Exercises a full attachment group: a V1 `-A` `ControllerIdxSigs` counter
//! whose count equals the number of trailing indexed-signature elements.

use std::eprintln;

use crate::core::counter::CounterCodeV1;
use crate::stream::parse::TextStream;
use crate::stream::{qb2_to_qb64, qb64_to_qb2};

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
            qb64_to_qb2(v.qb64.as_bytes()).unwrap_or_else(|e| panic!("qb64_to_qb2: {e:?}")),
            expected_qb2,
            "qb64->qb2 mismatch for {:?}",
            v.qb64
        );
        assert_eq!(
            qb2_to_qb64(&expected_qb2).unwrap_or_else(|e| panic!("qb2_to_qb64: {e:?}")),
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
