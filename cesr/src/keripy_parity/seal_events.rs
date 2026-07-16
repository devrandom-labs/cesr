//! #150 seal-event vectors: keripy-generated v1 ixn events anchoring
//! `SealBack`, `SealKind`, and arbitrary dicts must deserialize on the
//! strict path and round-trip byte-identically.

use crate::keri::{InteractionEvent, Seal};
use crate::serder::deserialize::deserialize_interaction;
use crate::serder::serialize::serialize_interaction;

use super::{SealEventVector, load_seal_events};

#[allow(
    clippy::panic,
    reason = "test-only lookup: a missing corpus case is a harness bug"
)]
fn find(case: &str) -> SealEventVector {
    load_seal_events()
        .into_iter()
        .find(|v| v.case == case)
        .unwrap_or_else(|| panic!("{case} vector missing from corpus"))
}

#[allow(
    clippy::panic,
    reason = "test-only helper: an unreadable vector panics with case context"
)]
fn parse(case: &str) -> InteractionEvent<'static> {
    let v = find(case);
    deserialize_interaction(v.raw.as_bytes()).unwrap_or_else(|e| panic!("{case}: {e}"))
}

#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: failed vectors panic with case context"
)]
fn seal_event_vectors_roundtrip_byte_identically() {
    let vectors = load_seal_events();
    assert!(!vectors.is_empty(), "seal_events corpus is empty");
    for v in &vectors {
        let event = deserialize_interaction(v.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{}: read: {e}", v.case));
        let re = serialize_interaction(&event).unwrap_or_else(|e| panic!("{}: write: {e}", v.case));
        assert_eq!(
            re.as_bytes(),
            v.raw.as_bytes(),
            "{} must round-trip byte-identically",
            v.case
        );
    }
}

#[test]
fn seal_back_vector_parses_to_back_variant() {
    assert!(matches!(parse("seal_back").anchors(), [Seal::Back { .. }]));
}

#[test]
fn seal_kind_vector_parses_to_kind_variant() {
    assert!(matches!(parse("seal_kind").anchors(), [Seal::Kind { .. }]));
}

#[test]
fn arbitrary_anchor_vector_parses_to_opaque_variant() {
    assert!(matches!(
        parse("arbitrary_anchor").anchors(),
        [Seal::Opaque(_)]
    ));
}

#[test]
fn mixed_vector_parses_to_digest_back_opaque_in_order() {
    assert!(matches!(
        parse("mixed").anchors(),
        [Seal::Digest { .. }, Seal::Back { .. }, Seal::Opaque(_)]
    ));
}
