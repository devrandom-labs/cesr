fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_groups_v2(data));
}
