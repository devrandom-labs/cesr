//! Fuzz targets for the `Indexer` (indexed-signature) decode surface.

#[test]
fn indexer_from_qb64() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::indexer_from_qb64(input));
}

#[test]
fn indexer_from_qb2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::indexer_from_qb2(input));
}
