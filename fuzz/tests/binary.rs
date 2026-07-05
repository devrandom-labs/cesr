//! Fuzz target for the qb64<->qb2 binary conversions.

#[test]
fn qb64_qb2_roundtrip() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::qb64_qb2_roundtrip(input));
}
