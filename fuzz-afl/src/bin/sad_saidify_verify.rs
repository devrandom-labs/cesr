fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::sad_saidify_verify(data));
}
