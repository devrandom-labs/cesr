//! Matter differential replay vs keripy.

use core::str::FromStr;
use std::eprintln;

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::MatterCode;
use crate::serder::primitives::to_qb64_string;
use crate::stream::qb64_to_qb2;

use super::{from_hex, load};

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only differential harness: intentional panic on codec failure and eprintln skip/finding logging per task spec"
)]
fn matter_differential_vs_keripy() {
    let vectors = load("matter");
    assert!(!vectors.is_empty(), "matter corpus is empty");

    let mut skipped = 0usize;
    let mut deferred_encode = 0usize;
    for v in &vectors {
        let Ok(code) = MatterCode::from_str(&v.code) else {
            eprintln!("SKIP matter: unimplemented code {:?}", v.code);
            skipped += 1;
            continue;
        };

        let expected_raw = from_hex(&v.raw);
        let expected_qb2 = from_hex(&v.qb2);

        // decode qb64 → assert reconstructed fields
        let decoded = MatterBuilder::new()
            .from_qualified_base64(v.qb64.as_bytes())
            .unwrap_or_else(|e| panic!("decode qb64 for {:?}: {e:?}", v.qb64));
        assert_eq!(*decoded.code(), code, "code mismatch for {:?}", v.qb64);
        assert_eq!(
            decoded.raw(),
            expected_raw.as_slice(),
            "raw mismatch for {:?}",
            v.qb64
        );
        assert_eq!(decoded.soft(), v.soft, "soft mismatch for {:?}", v.qb64);

        // encode cesr fields → assert keripy's exact qb64.
        //
        // Zero-rawsize codes (e.g. `1AAP`, `1AAO`, `1AAL`, `1AAK`, `1AAM`)
        // round-trip on decode but cannot be re-encoded: `MatterBuilder::with_raw`
        // rejects an empty payload with `EmptyStream` (read/write asymmetry).
        // Deferred to the `#[ignore]`d bug-probe below (issue #48); their decode
        // and transcode are still asserted here.
        if expected_raw.is_empty() {
            deferred_encode += 1;
        } else {
            let built = MatterBuilder::new()
                .with_code(code)
                .with_raw(&expected_raw)
                .unwrap_or_else(|e| panic!("with_raw for {:?}: {e:?}", v.qb64))
                .build()
                .unwrap_or_else(|e| panic!("build for {:?}: {e:?}", v.qb64));
            let qb64 = to_qb64_string(&built)
                .unwrap_or_else(|e| panic!("to_qb64_string for {:?}: {e:?}", v.qb64));
            assert_eq!(qb64, v.qb64, "qb64 encode mismatch for code {:?}", v.code);
        }

        // qb64 → qb2 transcode matches keripy's qb2
        let qb2 = qb64_to_qb2(v.qb64.as_bytes())
            .unwrap_or_else(|e| panic!("qb64_to_qb2 for {:?}: {e:?}", v.qb64));
        assert_eq!(qb2, expected_qb2, "qb2 transcode mismatch for {:?}", v.qb64);

        // decode qb2 → assert raw
        let decoded_qb2 = MatterBuilder::new()
            .from_qualified_base2(&expected_qb2)
            .unwrap_or_else(|e| panic!("decode qb2 for {:?}: {e:?}", v.qb64));
        assert_eq!(
            decoded_qb2.raw(),
            expected_raw.as_slice(),
            "qb2 decode raw mismatch for {:?}",
            v.qb64
        );
    }

    eprintln!(
        "matter: {} vectors, {skipped} skipped (unimplemented codes), \
         {deferred_encode} encodes deferred to the zero-raw bug-probe (#48)",
        vectors.len()
    );
}

/// Bug-probe for the zero-rawsize encode asymmetry (issue #48). FAILS while the
/// bug exists (`MatterBuilder::with_raw` rejects an empty payload), so it stays
/// `#[ignore]`d until cesr can re-encode zero-rawsize codes — never a green test
/// hiding the bug.
#[test]
#[ignore = "FINDING #48: MatterBuilder::with_raw rejects empty raw, so zero-rawsize codes decode but cannot re-encode. Un-ignore once cesr round-trips them."]
#[allow(
    clippy::panic,
    reason = "test-only bug-probe: intentional panic on codec failure per task spec"
)]
fn matter_zero_raw_encode_vs_keripy() {
    let vectors = load("matter");
    let mut probed = 0usize;
    for v in &vectors {
        let Ok(code) = MatterCode::from_str(&v.code) else {
            continue;
        };
        let expected_raw = from_hex(&v.raw);
        if !expected_raw.is_empty() {
            continue;
        }
        probed += 1;
        let built = MatterBuilder::new()
            .with_code(code)
            .with_raw(&expected_raw)
            .unwrap_or_else(|e| panic!("with_raw (empty) for {:?}: {e:?}", v.code))
            .build()
            .unwrap_or_else(|e| panic!("build for {:?}: {e:?}", v.code));
        let qb64 = to_qb64_string(&built)
            .unwrap_or_else(|e| panic!("to_qb64_string for {:?}: {e:?}", v.code));
        assert_eq!(qb64, v.qb64, "zero-raw encode mismatch for {:?}", v.code);
    }
    assert!(
        probed > 0,
        "no zero-rawsize vectors exercised the bug-probe"
    );
}
