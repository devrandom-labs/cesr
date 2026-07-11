fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::serder_deserialize_event(data));
}
