fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_parse_message(data));
}
