fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::indexer_from_qb2(data));
}
