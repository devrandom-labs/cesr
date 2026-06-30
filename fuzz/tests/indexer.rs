//! Fuzz targets for the `Indexer` (indexed-signature) decode surface.

use cesr::core::indexer::IndexerBuilder;

#[test]
fn indexer_from_qb64() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = IndexerBuilder::new().from_qb64(input);
    });
}

#[test]
fn indexer_from_qb2() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = IndexerBuilder::new().from_qb2(input);
    });
}
