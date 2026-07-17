//! Counter v1 + v2 differential replay vs keripy.
//!
//! keripy resolves a counter's wire code from `(code, count)`: when the count
//! does not fit the requested code's soft field it promotes to the code's big
//! variant (e.g. `-V` + 4096 serialises as `--VAABAA`). cesr splits that into
//! `encode_count` (plain) and `encode_count_auto` (promoting) on the code enums; this
//! harness selects the matching one by whether the count fits the code's soft
//! size, then asserts byte-for-byte agreement with keripy.

use std::eprintln;

use crate::core::counter::{CounterCodeV1, CounterCodeV2};
use crate::stream::parse::TextStream;
use crate::stream::qb64_to_qb2;

use super::{from_hex, load};

fn max_count_for_ss(ss: usize) -> u64 {
    let exp = u32::try_from(ss).expect("counter soft size fits u32");
    64u64.pow(exp) - 1
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only differential harness: intentional panic on codec failure and eprintln skip logging per task spec"
)]
fn counter_v1_differential_vs_keripy() {
    let vectors = load("counter_v1");
    assert!(!vectors.is_empty(), "counter_v1 corpus is empty");

    let mut skipped = 0usize;
    for v in &vectors {
        let Ok(code) = CounterCodeV1::from_hard(&v.code) else {
            eprintln!("SKIP counter_v1: unimplemented code {:?}", v.code);
            skipped += 1;
            continue;
        };
        let count = v
            .count
            .unwrap_or_else(|| panic!("counter_v1 vector {:?} missing count", v.code));

        let fits = u64::from(count) <= max_count_for_ss(code.soft_size());

        // encode cesr fields → assert keripy's exact qb64 bytes
        let encoded = if fits {
            code.encode_count(count)
                .unwrap_or_else(|e| panic!("encode_count (v1) {:?}: {e:?}", v.code))
        } else {
            code.encode_count_auto(count).unwrap_or_else(|e| {
                panic!(
                    "encode_count_auto (v1) {:?} count {count}: {e:?} \
                     (cesr cannot promote a code keripy promotes)",
                    v.code
                )
            })
        };
        assert_eq!(
            encoded,
            v.qb64.as_bytes(),
            "qb64 encode mismatch for {:?} count {count}",
            v.code
        );

        // decode → assert code (resolved), count and empty remainder
        let expected_code = if fits {
            code
        } else {
            code.to_big()
                .unwrap_or_else(|| panic!("code {:?} overflows but has no big variant", v.code))
        };
        let mut ts = TextStream::new(v.qb64.as_bytes());
        let (dcode, dcount) = ts
            .read_counter_v1()
            .unwrap_or_else(|e| panic!("read_counter_v1 {:?}: {e:?}", v.qb64));
        let rest = ts.remaining();
        assert_eq!(
            dcode, expected_code,
            "decoded code mismatch for {:?}",
            v.qb64
        );
        assert_eq!(dcount, count, "decoded count mismatch for {:?}", v.qb64);
        assert!(rest.is_empty(), "non-empty remainder for {:?}", v.qb64);

        // qb64 → qb2 transcode matches keripy's qb2
        let qb2 = qb64_to_qb2(v.qb64.as_bytes())
            .unwrap_or_else(|e| panic!("qb64_to_qb2 {:?}: {e:?}", v.qb64));
        assert_eq!(
            qb2,
            from_hex(&v.qb2),
            "qb2 transcode mismatch for {:?}",
            v.qb64
        );
    }

    eprintln!(
        "counter_v1: {} vectors, {skipped} skipped (unimplemented codes)",
        vectors.len()
    );
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only differential harness: intentional panic on codec failure and eprintln skip logging per task spec"
)]
fn counter_v2_differential_vs_keripy() {
    let vectors = load("counter_v2");
    assert!(!vectors.is_empty(), "counter_v2 corpus is empty");

    let mut skipped = 0usize;
    for v in &vectors {
        let Ok(code) = CounterCodeV2::from_hard(&v.code) else {
            eprintln!("SKIP counter_v2: unimplemented code {:?}", v.code);
            skipped += 1;
            continue;
        };
        let count = v
            .count
            .unwrap_or_else(|| panic!("counter_v2 vector {:?} missing count", v.code));

        let fits = u64::from(count) <= max_count_for_ss(code.soft_size());

        let encoded = if fits {
            code.encode_count(count)
                .unwrap_or_else(|e| panic!("encode_count (v2) {:?}: {e:?}", v.code))
        } else {
            code.encode_count_auto(count).unwrap_or_else(|e| {
                panic!(
                    "encode_count_auto (v2) {:?} count {count}: {e:?} \
                     (cesr cannot promote a code keripy promotes)",
                    v.code
                )
            })
        };
        assert_eq!(
            encoded,
            v.qb64.as_bytes(),
            "qb64 encode mismatch for {:?} count {count}",
            v.code
        );

        let expected_code = if fits {
            code
        } else {
            code.to_big()
                .unwrap_or_else(|| panic!("code {:?} overflows but has no big variant", v.code))
        };
        let mut ts = TextStream::new(v.qb64.as_bytes());
        let (dcode, dcount) = ts
            .read_counter_v2()
            .unwrap_or_else(|e| panic!("read_counter_v2 {:?}: {e:?}", v.qb64));
        let rest = ts.remaining();
        assert_eq!(
            dcode, expected_code,
            "decoded code mismatch for {:?}",
            v.qb64
        );
        assert_eq!(dcount, count, "decoded count mismatch for {:?}", v.qb64);
        assert!(rest.is_empty(), "non-empty remainder for {:?}", v.qb64);

        let qb2 = qb64_to_qb2(v.qb64.as_bytes())
            .unwrap_or_else(|e| panic!("qb64_to_qb2 {:?}: {e:?}", v.qb64));
        assert_eq!(
            qb2,
            from_hex(&v.qb2),
            "qb2 transcode mismatch for {:?}",
            v.qb64
        );
    }

    eprintln!(
        "counter_v2: {} vectors, {skipped} skipped (unimplemented codes)",
        vectors.len()
    );
}
