//! Fuzz target for the public generic SAD SAID path (`saidify_sad` /
//! `verify_sad`): no panic on untrusted bytes, saidify output verifies, and
//! saidify is idempotent.

#[test]
fn sad_saidify_verify() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::sad_saidify_verify(input));
}
