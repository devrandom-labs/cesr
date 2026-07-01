//! Matter differential replay vs keripy.

use core::str::FromStr;
use std::eprintln;

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::MatterCode;
use crate::serder::primitives::to_qb64_string;
use crate::stream::qb64_to_qb2;

use super::{from_hex, load};

#[test]
fn matter_differential_vs_keripy() {
    let vectors = load("matter");
    assert!(!vectors.is_empty(), "matter corpus is empty");

    let mut skipped = 0usize;
    let mut encode_findings = 0usize;
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
        // FINDING (issue candidate): `MatterBuilder::with_raw` rejects an
        // empty slice with `ParsingError::EmptyStream`, so the fixed-value
        // zero-raw codes (`1AAP`, `1AAO`, `1AAL`, `1AAK`, `1AAM`) that cesr
        // *decodes* correctly cannot be re-encoded through the builder —
        // a read/write-path asymmetry. Their decode + transcode is still
        // asserted above/below; only the builder encode step is recorded.
        if expected_raw.is_empty() {
            let attempt = MatterBuilder::new().with_code(code).with_raw(&expected_raw);
            assert!(
                attempt.is_err(),
                "empty-raw encode FINDING resolved for {:?} — remove the carve-out",
                v.code
            );
            eprintln!(
                "FINDING matter: cannot encode empty-raw code {:?} via MatterBuilder::with_raw \
                 (decode+transcode still verified)",
                v.code
            );
            encode_findings += 1;
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
         {encode_findings} empty-raw encode findings",
        vectors.len()
    );
}
