//! Parity-gate harness vs keripy (issue #151).
//!
//! The "missing middle" between primitive byte-diffing (`keripy_diff`) and the
//! event-wire corpus (#145): replays checked-in, keripy-generated codex /
//! formula / validation vectors and asserts cesr agrees. Vectors carrying a
//! `divergence` marker are deliberate non-goals recorded in
//! `docs/keripy-parity/ledger.md`; temporarily-open gaps (#160 `TRACKED`
//! said-codes) live in Rust-side tracked tables next to `#[ignore]`d
//! bug-probe tests that FAIL while the gap exists. #149 (witness semantics)
//! and #150 (seal codex) are closed: probes deleted, tables emptied, and
//! their rows assert live in the validation, codex, and seal-event sweeps.

use serde::Deserialize;
use serde_json::Value;
use std::string::String;
use std::vec::Vec;

mod codex;
mod formulas;
mod said_codes;
mod seal_events;
mod validation;

#[derive(Debug, Deserialize)]
struct CodexVector {
    pub kind: String,
    pub family: String,
    pub name: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub qb64: String,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "corpus-carried keripy field list (full row representability); sweeps assert via code/qb64/sample instead"
    )]
    pub fields: Vec<String>,
    pub sample: Option<Value>,
    pub divergence: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FormulaVector {
    pub kind: String,
    pub formula: String,
    pub n: Option<u64>,
    pub weak: Option<bool>,
    pub m: Option<u64>,
    pub sith: Option<Value>,
    #[serde(default)]
    pub indices: Vec<u32>,
    pub satisfies: Option<bool>,
    #[allow(
        dead_code,
        reason = "corpus-carried keripy exception name (full row representability); no sweep asserts it yet"
    )]
    pub error: Option<String>,
    pub divergence: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidationVector {
    pub kind: String,
    pub factory: String,
    pub case: String,
    pub params: Value,
    pub raises: Option<String>,
    #[serde(default)]
    pub message: String,
    pub rust_static: Option<String>,
}

// Embedded at compile time (`include_str!`) for the same reason as
// `keripy_diff`: the nix gate builds and runs tests in separate hermetic
// phases, so runtime manifest-relative paths do not survive to nextest.
#[allow(
    clippy::panic,
    reason = "test-only corpus loader: panics on malformed corpus fixtures"
)]
fn parse_lines<T: serde::de::DeserializeOwned>(text: &str) -> Vec<T> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<T>(l).unwrap_or_else(|e| panic!("parse `{l}`: {e}")))
        .collect()
}

fn load_codex() -> Vec<CodexVector> {
    parse_lines(include_str!("../../tests/corpus/keripy/parity/codex.jsonl"))
}

fn load_formulas() -> Vec<FormulaVector> {
    parse_lines(include_str!(
        "../../tests/corpus/keripy/parity/formulas.jsonl"
    ))
}

fn load_validation() -> Vec<ValidationVector> {
    parse_lines(include_str!(
        "../../tests/corpus/keripy/parity/validation.jsonl"
    ))
}

#[derive(Debug, Deserialize)]
struct SaidCodeVector {
    pub kind: String,
    pub factory: String,
    pub case: String,
    #[serde(default)]
    pub code: String,
    pub raw_b64: String,
    pub said: String,
    pub pre: String,
}

fn load_said_codes() -> Vec<SaidCodeVector> {
    parse_lines(include_str!(
        "../../tests/corpus/keripy/parity/said_codes.jsonl"
    ))
}

#[derive(Debug, Deserialize)]
struct SealEventVector {
    pub kind: String,
    pub case: String,
    pub raw: String,
}

fn load_seal_events() -> Vec<SealEventVector> {
    parse_lines(include_str!(
        "../../tests/corpus/keripy/parity/seal_events.jsonl"
    ))
}

#[cfg(test)]
mod scaffold_tests {
    use super::*;

    #[test]
    fn corpus_families_load_and_are_nonempty() {
        assert!(!load_codex().is_empty(), "codex corpus is empty");
        assert!(!load_formulas().is_empty(), "formulas corpus is empty");
        assert!(!load_validation().is_empty(), "validation corpus is empty");
        assert!(!load_said_codes().is_empty(), "said_codes corpus is empty");
        assert!(
            !load_seal_events().is_empty(),
            "seal_events corpus is empty"
        );
    }

    #[test]
    fn kinds_are_homogeneous() {
        assert!(load_codex().iter().all(|v| v.kind == "codex"));
        assert!(load_formulas().iter().all(|v| v.kind == "formula"));
        assert!(load_validation().iter().all(|v| v.kind == "validation"));
        assert!(load_said_codes().iter().all(|v| v.kind == "said_code"));
        assert!(load_seal_events().iter().all(|v| v.kind == "seal_event"));
    }
}
