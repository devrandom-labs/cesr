//! Fuzz target for the qb64<->qb2 binary conversions. Feeds arbitrary bytes to
//! `qb64_to_qb2`; when that succeeds, asserts the qb2->qb64->qb2 direction is
//! stable (a successfully-decoded primitive must re-encode identically).

use cesr::stream::{qb2_to_qb64, qb64_to_qb2};

#[test]
fn qb64_qb2_roundtrip() {
    bolero::check!().for_each(|input: &[u8]| {
        let Ok(qb2) = qb64_to_qb2(input) else { return };
        let Ok(qb64) = qb2_to_qb64(&qb2) else {
            panic!("qb2 from a valid qb64 must convert back to qb64");
        };
        let Ok(qb2_again) = qb64_to_qb2(&qb64) else {
            panic!("re-encoded qb64 must convert back to qb2");
        };
        assert_eq!(qb2, qb2_again, "qb2->qb64->qb2 must be stable");
    });
}
