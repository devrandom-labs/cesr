fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::matter_from_qb64(data));
}
