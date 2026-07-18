//! Shared fuzz-target bodies for the `cesr` parse surface.
//!
//! Each `pub fn` takes raw bytes and drives one CESR decoder/parser. A panic is
//! a finding (a parser must never panic on untrusted input). These functions are
//! the single source of truth for both engines: the bolero crate (`fuzz/`) calls
//! them from `check!().for_each(...)`, and the afl.rs crate (`fuzz-afl/`) calls
//! them from `afl::fuzz!(...)`.

use cesr::core::indexer::IndexerBuilder;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::version::{VersionString, VersionStringV2};
use keri_events::KeriEvent;
use keri_codec::{Deserialize, Serialize};
use cesr_stream::{CesrGroup, CesrMessage, Groups, GroupsV2, qb2_to_qb64, qb64_to_qb2};

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
    let _ = CesrGroup::parse(data);
}

pub fn stream_parse_group_v2(data: &[u8]) {
    let _ = CesrGroup::parse_v2(data);
}

pub fn stream_groups(data: &[u8]) {
    for item in Groups::over(data) {
        let _ = item;
    }
}

pub fn stream_groups_v2(data: &[u8]) {
    for item in GroupsV2::over(data) {
        let _ = item;
    }
}

pub fn stream_parse_message(data: &[u8]) {
    let _ = CesrMessage::parse(data);
}

pub fn stream_parse_version_string(data: &[u8]) {
    let _ = VersionString::parse(data);
}

pub fn stream_parse_version_string_v2(data: &[u8]) {
    let _ = VersionStringV2::parse(data);
}

/// Idempotence oracle for the strict canonical KERI event deserializer: if
/// `data` parses, its re-serialization must also parse.
///
/// Deliberately does NOT assert byte-identity between `data` and the
/// re-serialized bytes. keripy-native integers (e.g. `"bt":0`) legally
/// re-render as hex strings (`"bt":"0"`) on serialize, per keripy's
/// intive/hex number rendering — so accepted-input bytes and re-serialized
/// bytes may differ even though both are valid encodings of the same event.
/// The invariant that must hold is parse -> serialize -> parse succeeding,
/// not byte-for-byte stability.
pub fn serder_deserialize_event(data: &[u8]) {
    if let Ok(event) = KeriEvent::deserialize(data) {
        let Ok(reser) = event.serialize() else {
            panic!("a strictly-parsed event must re-serialize");
        };
        if KeriEvent::deserialize(reser.as_bytes()).is_err() {
            panic!("a re-serialized event must re-parse");
        }
    }
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
        serder_deserialize_event(&[]);
    }
}
