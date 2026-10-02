//! Fuzz the selected EXN/IPEX full-message parser, including `-L` proof
//! material and the shared signature and element budgets.

#[test]
fn exn_parse_message() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::exn_parse_message(input));
}
