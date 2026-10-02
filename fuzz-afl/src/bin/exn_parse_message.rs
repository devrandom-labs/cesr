fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::exn_parse_message(data));
}
