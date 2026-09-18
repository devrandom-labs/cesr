fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::acdc_deserialize_event(data));
}
