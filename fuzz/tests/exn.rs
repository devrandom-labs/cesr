//! Fuzz target for the public exn read path (`Exn::deserialize` — the six
//! IPEX routes' envelope grammar): no panic on untrusted bytes, SAID
//! verification on the read path, a parsed envelope re-serializes, and the
//! re-serialization is a parse/serialize fixed point.

#[test]
fn exn_deserialize_event() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::exn_deserialize_event(input));
}
