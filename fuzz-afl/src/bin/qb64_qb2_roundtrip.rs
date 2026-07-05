fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::qb64_qb2_roundtrip(data));
}
