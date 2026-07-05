//! Shared fuzz-target bodies for the `cesr` parse surface.
//!
//! Each `pub fn` takes raw bytes and drives one CESR decoder/parser. A panic is
//! a finding (a parser must never panic on untrusted input). These functions are
//! the single source of truth for both engines: the bolero crate (`fuzz/`) calls
//! them from `check!().for_each(...)`, and the afl.rs crate (`fuzz-afl/`) calls
//! them from `afl::fuzz!(...)`.

use cesr::core::indexer::IndexerBuilder;
use cesr::core::matter::builder::MatterBuilder;
use cesr::stream::{
    groups, groups_v2, parse_group, parse_group_v2, parse_message, parse_version_string,
    parse_version_string_v2, qb2_to_qb64, qb64_to_qb2,
};

pub fn matter_from_qb64(data: &[u8]) {
    let _ = MatterBuilder::new().from_qualified_base64(data);
}

pub fn matter_from_qb2(data: &[u8]) {
    let _ = MatterBuilder::new().from_qualified_base2(data);
}

pub fn indexer_from_qb64(data: &[u8]) {
    let _ = IndexerBuilder::new().from_qb64(data);
}

pub fn indexer_from_qb2(data: &[u8]) {
    let _ = IndexerBuilder::new().from_qb2(data);
}

pub fn stream_parse_group(data: &[u8]) {
    let _ = parse_group(data);
}

pub fn stream_parse_group_v2(data: &[u8]) {
    let _ = parse_group_v2(data);
}

pub fn stream_groups(data: &[u8]) {
    for item in groups(data) {
        let _ = item;
    }
}

pub fn stream_groups_v2(data: &[u8]) {
    for item in groups_v2(data) {
        let _ = item;
    }
}

pub fn stream_parse_message(data: &[u8]) {
    let _ = parse_message(data);
}

pub fn stream_parse_version_string(data: &[u8]) {
    let _ = parse_version_string(data);
}

pub fn stream_parse_version_string_v2(data: &[u8]) {
    let _ = parse_version_string_v2(data);
}

pub fn qb64_qb2_roundtrip(data: &[u8]) {
    let Ok(qb2) = qb64_to_qb2(data) else {
        return;
    };
    let Ok(qb64) = qb2_to_qb64(&qb2) else {
        panic!("qb2 from a valid qb64 must convert back to qb64");
    };
    let Ok(qb2_again) = qb64_to_qb2(&qb64) else {
        panic!("re-encoded qb64 must convert back to qb2");
    };
    assert_eq!(qb2, qb2_again, "qb2->qb64->qb2 must be stable");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves every shared body is wired to a real cesr decoder (not a stub) and
    // returns without panic on empty input — the boundary case both engines hit
    // first. Each call would fail the build if the underlying cesr symbol were
    // renamed or removed.
    #[test]
    fn all_targets_accept_empty_without_panic() {
        matter_from_qb64(&[]);
        matter_from_qb2(&[]);
        indexer_from_qb64(&[]);
        indexer_from_qb2(&[]);
        stream_parse_group(&[]);
        stream_parse_group_v2(&[]);
        stream_groups(&[]);
        stream_groups_v2(&[]);
        stream_parse_message(&[]);
        stream_parse_version_string(&[]);
        stream_parse_version_string_v2(&[]);
        qb64_qb2_roundtrip(&[]);
    }
}
