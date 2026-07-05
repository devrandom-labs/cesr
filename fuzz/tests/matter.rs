//! Fuzz targets for the `Matter` decode/encode surface.
//!
//! The two byte-in decode targets delegate to `fuzz-common` (shared with the
//! afl.rs harness). `matter_roundtrip` uses bolero's structured `[u8; 32]`
//! generator and stays bolero-only.

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::MatterCode;

#[test]
fn matter_from_qb64() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::matter_from_qb64(input));
}

#[test]
fn matter_from_qb2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::matter_from_qb2(input));
}

#[test]
fn matter_roundtrip() {
    // Ed25519N ('B') is a fixed-size code with a 32-byte raw — the canonical
    // choice for a clean encode -> decode round-trip.
    bolero::check!()
        .with_type::<[u8; 32]>()
        .for_each(|raw| {
            let Ok(builder) = MatterBuilder::new()
                .with_code(MatterCode::Ed25519N)
                .with_raw(&raw[..])
            else {
                return;
            };
            let Ok(matter) = builder.build() else { return };

            let qb64 = matter.to_qb64b();

            let Ok(decoded) = MatterBuilder::new().from_qualified_base64(&qb64[..]) else {
                panic!("re-decoding self-encoded Matter must succeed");
            };
            assert_eq!(
                decoded.raw(),
                &raw[..],
                "qb64 round-trip must preserve raw bytes",
            );
        });
}
