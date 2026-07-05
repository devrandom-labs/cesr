fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_groups(data));
}
