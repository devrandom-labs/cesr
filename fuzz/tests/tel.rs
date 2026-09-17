//! Fuzz target for the public TEL event path (`TelEvent::deserialize` over
//! the six registry ilks): no panic on untrusted bytes, a parsed event
//! re-serializes, and the re-serialization is a parse/serialize fixed point.

#[test]
fn tel_deserialize_event() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::tel_deserialize_event(input));
}
