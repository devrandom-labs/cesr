//! Fuzz targets for the `Matter` decode/encode surface.
//!
//! Panic-hunters feed raw bytes to the decoders; any panic fails the test.
//! The round-trip target constructs a fixed-size primitive, encodes it, decodes
//! it back, and asserts raw-byte stability.

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::MatterCode;
use cesr::stream::encode::matter_to_qb64;

#[test]
fn matter_from_qb64() {
    bolero::check!().for_each(|input: &[u8]| {
        // Must return Ok/Err, never panic, on arbitrary bytes.
        let _ = MatterBuilder::new().from_qualified_base64(input);
    });
}

#[test]
fn matter_from_qb2() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = MatterBuilder::new().from_qualified_base2(input);
    });
}

#[test]
fn matter_roundtrip() {
    // Ed25519N ('B') is a fixed-size code with a 32-byte raw, so `matter_to_qb64`
    // is safe (it only panics on variable-size codes).
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

            let qb64 = matter_to_qb64(&matter);

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
