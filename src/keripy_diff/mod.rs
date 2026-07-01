//! Differential-testing harness vs keripy (P0.3, issue #27).
//!
//! Replays a checked-in, keripy-generated JSONL corpus and asserts cesr
//! agrees with keripy byte-for-byte on both encode and decode. Test-only and
//! `serder`-gated so every codec path (incl. Matter encode via
//! `serder::primitives::to_qb64_string`) is in scope.

use serde::Deserialize;
use std::format;
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

#[allow(
    clippy::panic,
    reason = "test-only corpus loader: panics on unreadable/malformed corpus fixtures per task spec"
)]
fn load(kind: &str) -> Vec<DiffVector> {
    let path = format!(
        "{}/tests/corpus/keripy/{kind}.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
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
