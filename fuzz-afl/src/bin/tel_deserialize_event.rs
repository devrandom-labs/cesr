fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::tel_deserialize_event(data));
}
