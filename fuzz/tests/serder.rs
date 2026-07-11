//! Fuzz target for strict canonical KERI event deserialization.

#[test]
fn serder_deserialize_event() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::serder_deserialize_event(input));
}
