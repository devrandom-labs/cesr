//! Differential-testing harness vs keripy (P0.3, issue #27).
//!
//! Replays a checked-in, keripy-generated JSONL corpus and asserts cesr
//! agrees with keripy byte-for-byte on both encode and decode. Test-only and
//! `stream`-gated: it exercises the CESR substrate (`core` primitives and
//! `stream` transcoding), so it travels with `stream` rather than the codec.

use serde::Deserialize;
use std::string::String;
use std::vec::Vec;

mod counter;
mod indexer;
mod matter;
mod stream;

#[derive(Debug, Deserialize)]
struct DiffVector {
    pub kind: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub raw: String,
    #[serde(default)]
    pub soft: String,
    pub index: Option<u32>,
    pub ondex: Option<u32>,
    pub count: Option<u32>,
    #[serde(default)]
    pub qb64: String,
    #[serde(default)]
    pub qb2: String,
    #[serde(default)]
    pub elements: Vec<Self>,
}

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

// The corpus is embedded at compile time via `include_str!` rather than read at
// runtime: the gate builds and runs tests in separate hermetic nix phases, so a
// runtime `CARGO_MANIFEST_DIR` path points at a build sandbox that no longer
// exists when nextest runs. Baking the bytes in keeps the harness hermetic.
#[allow(
    clippy::panic,
    reason = "test-only corpus loader: panics on malformed corpus fixtures per task spec"
)]
fn load(kind: &str) -> Vec<DiffVector> {
    let text = match kind {
        "matter" => include_str!("../../tests/corpus/keripy/matter.jsonl"),
        "counter_v1" => include_str!("../../tests/corpus/keripy/counter_v1.jsonl"),
        "counter_v2" => include_str!("../../tests/corpus/keripy/counter_v2.jsonl"),
        "indexer" => include_str!("../../tests/corpus/keripy/indexer.jsonl"),
        "stream" => include_str!("../../tests/corpus/keripy/stream.jsonl"),
        other => panic!("unknown corpus kind {other:?}"),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<DiffVector>(l).unwrap_or_else(|e| panic!("parse `{l}`: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod scaffold_tests {
    use super::{DiffVector, from_hex};
    use std::vec;

    #[test]
    fn parses_one_line_and_decodes_hex() {
        let line = r#"{"kind":"matter","code":"D","raw":"deadbeef","qb64":"Dxx","qb2":"0102"}"#;
        let v: DiffVector = serde_json::from_str(line).unwrap();
        assert_eq!(v.kind, "matter");
        assert_eq!(v.code, "D");
        assert_eq!(from_hex(&v.raw), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(from_hex(&v.qb2), vec![0x01, 0x02]);
        assert_eq!(v.soft, "");
        assert!(v.index.is_none());
    }
}
