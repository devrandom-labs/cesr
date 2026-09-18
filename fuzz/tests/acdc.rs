//! Fuzz target for the public ACDC read path (`Acdc::deserialize` over the
//! compact and expanded credential forms): no panic on untrusted bytes, a
//! parsed credential re-serializes, and the re-serialization is a
//! parse/serialize fixed point.

#[test]
fn acdc_deserialize_event() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::acdc_deserialize_event(input));
}
