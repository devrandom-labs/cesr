fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::exn_deserialize_event(data));
}
