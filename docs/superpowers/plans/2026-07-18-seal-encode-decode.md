# Seal Encode/Decode Migration (Step 2 of the keri-codec pass) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce `pub(crate)` `Encode`/`Decode` traits (der-precedent) and migrate `Seal` so its wire grammar is stated once per direction in one co-located module, deleting the duplicated enumeration in `write_seal` (writer) and `seal_codex` (strict reader).

**Architecture:** Step 2 of the 3-step pass in `docs/superpowers/plans/2026-07-18-keri-codec-encode-decode-pass.md` (Step 1 = P3, merged in #200). A new internal `codec` module holds the traits plus a `JsonWriter` type (home of the JSON string escaper, as a type method to keep the free-fn ratchet at 58); `codec/seal.rs` holds `impl Encode for Seal` and `impl Decode for ParsedSeal` with each variant's write and read arms adjacent. **Design decisions already settled by evidence — do not revisit:** `Decode` targets `ParsedSeal<'a>`, NOT `Seal<'a>`, because the deserialize pipeline is scan → SAID-verify → qb64-lift and fusing the lift into decode would move qb64 parsing before SAID verification (a DoS-hardening regression); `ParsedSeal` is the der `*Ref` zero-copy analogue. Traits stay `pub(crate)` — Step 2 makes **zero public-surface change** (non-breaking PR); public promotion + the `KeriSerialize`→`Encode` rename is Step 3's owner decision. All moved bodies are copied **verbatim** — byte-identity on the wire is the law (keripy differential + spine suites must stay green).

**Tech Stack:** Rust 2024, no_std/alloc, existing `Scanner`/`OpaqueScan`/`SerderError` machinery in keri-codec. Verification: `nix develop --command cargo nextest run -p keri-codec` per task; `nix flake check` (committed state) as the final gate.

---

## File Structure

- `crates/keri-codec/src/codec.rs` — CREATE. The two traits + `JsonWriter` (escaper moved from `json.rs`). One responsibility: the internal codec vocabulary.
- `crates/keri-codec/src/codec/seal.rs` — CREATE. `impl Encode for Seal<'_>` + `impl<'a> Decode<'a> for ParsedSeal<'a>` + the moved private helpers (`seal_codex` logic inside `decode`, `seal_opaque` as helper) + round-trip tests. One responsibility: the seal wire grammar, both directions.
- `crates/keri-codec/src/lib.rs` — MODIFY. Add `pub(crate) mod codec;` (precedent: `pub(crate) mod event_strategies;` with the same `redundant_pub_crate` handling if clippy asks).
- `crates/keri-codec/src/serialize/json.rs` — MODIFY. `write_str` becomes a one-line delegate to `JsonWriter::write_str` (31 call sites untouched); `write_seal` deleted; `write_seal_array` becomes a loop over `seal.encode(buf)`.
- `crates/keri-codec/src/deserialize/canonical.rs` — MODIFY. `seal_codex`/`seal`/`seal_opaque` deleted; `seal_array` becomes `delimited_list(sc, ParsedSeal::decode)`; `OpaqueScan` import moves out; seal-specific tests move to `codec/seal.rs`.
- `crates/keri-codec/CHANGELOG.md` — MODIFY. Internal-refactor entry (no API change).

Ratchet math (counting rule `^pub(\(crate\)|\(super\))? fn` at column 0): every deleted fn (`write_seal`, `write_seal_array`, `seal_codex`, `seal`, `seal_opaque`, `write_str`) is private → count unchanged. Every added entry point is a trait method or type method (indented) → count unchanged. **keri-codec stays 58; `free-fn-budget.toml` untouched.**

---

## Task 1: `codec` module — traits + `JsonWriter`

**Files:**
- Create: `crates/keri-codec/src/codec.rs`
- Modify: `crates/keri-codec/src/lib.rs` (module decl)
- Modify: `crates/keri-codec/src/serialize/json.rs` (escaper delegates)

- [ ] **Step 1: Create `codec.rs`.** Traits + `JsonWriter`, with the `write_str` body and `HEX` table moved **verbatim** from `json.rs:208-234`:

```rust
//! The internal codec vocabulary: symmetric [`Encode`]/[`Decode`] traits over
//! the canonical JSON wire form, plus [`JsonWriter`], the shared JSON string
//! escaper. der-precedent (#193 step 2): one type declaration owns both wire
//! directions, stated once, co-located per type in `codec::*` submodules.
//!
//! Crate-internal by design: step 2 changes no public surface. Public
//! promotion (and the `KeriSerialize`/`KeriDeserialize` rename decision) is
//! step 3.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::deserialize::canonical::Scanner;
use crate::error::SerderError;

pub(crate) mod seal;

/// Append `self`'s canonical JSON wire form to `out`.
///
/// Infallible: encoding a well-formed in-memory value cannot fail (the
/// canonical form has no length prefixes to precompute — unlike der's TLV).
pub(crate) trait Encode {
    /// Append this value's canonical JSON bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

/// Parse one value from the scanner, advancing its cursor past the value.
///
/// Decodes to the borrowed scan-stage view (der's `*Ref` analogue), not the
/// qb64-lifted type: the pipeline is scan → SAID-verify → lift, and lifting
/// belongs after verification.
pub(crate) trait Decode<'a>: Sized {
    /// Parse one value at the scanner's cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] when the input at the cursor is not this
    /// type's canonical wire form.
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, SerderError>;
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// The canonical JSON byte writer (a namespace type — methods, not free
/// fns, so the `cesr-fn-ratchet` count is untouched).
pub(crate) struct JsonWriter;

impl JsonWriter {
    /// Write `s` as a JSON string with RFC 8259 escaping, byte-identical to
    /// `serde_json`'s escaper: `"`, `\`, and control characters below 0x20
    /// are escaped (short forms where they exist, `\u00xx` otherwise);
    /// everything else — including multi-byte UTF-8 — passes through raw.
    pub(crate) fn write_str(buf: &mut Vec<u8>, s: &str) {
        buf.push(b'"');
        for &byte in s.as_bytes() {
            match byte {
                b'"' => buf.extend_from_slice(b"\\\""),
                b'\\' => buf.extend_from_slice(b"\\\\"),
                0x08 => buf.extend_from_slice(b"\\b"),
                0x09 => buf.extend_from_slice(b"\\t"),
                0x0A => buf.extend_from_slice(b"\\n"),
                0x0C => buf.extend_from_slice(b"\\f"),
                0x0D => buf.extend_from_slice(b"\\r"),
                b if b < 0x20 => {
                    buf.extend_from_slice(b"\\u00");
                    buf.push(HEX[usize::from(b >> 4)]);
                    buf.push(HEX[usize::from(b & 0x0F)]);
                }
                b => buf.push(b),
            }
        }
        buf.push(b'"');
    }
}
```

Match the crate's `#[allow(clippy::redundant_pub_crate, reason = "…")]` pattern on `pub(crate)` items if clippy demands it (copy the exact reason string from `canonical.rs`'s `Spanned`). `codec/seal.rs` starts as a stub (`//! Seal wire grammar.` only) so the module tree compiles; its content is Tasks 2–3.

- [ ] **Step 2: Declare the module.** In `lib.rs`, next to the other internal module (`pub(crate) mod event_strategies;` at the module block): add `pub(crate) mod codec;`.

- [ ] **Step 3: Delegate the escaper.** In `json.rs`: delete the `HEX` const and the `write_str` body (`json.rs:208-234`), replace with:

```rust
use crate::codec::JsonWriter;

/// Delegates to the shared escaper in `codec` — single implementation.
fn write_str(buf: &mut Vec<u8>, s: &str) {
    JsonWriter::write_str(buf, s);
}
```

(`use` goes at the top of the file with the other `crate::` imports; verify first with `rg -n "HEX" crates/keri-codec/src/serialize/json.rs` that only `write_str` used `HEX` — if another user exists, `HEX` stays in json.rs too and only the escaper moves.)

- [ ] **Step 4: Verify byte-identity via the existing suite.**

Run: `nix develop --command cargo nextest run -p keri-codec`
Expected: PASS (521-ish tests, same count as baseline — this task changes no behavior).

- [ ] **Step 5: Commit.**

```bash
git add crates/keri-codec/src/codec.rs crates/keri-codec/src/codec crates/keri-codec/src/lib.rs crates/keri-codec/src/serialize/json.rs
git commit -m "refactor(keri-codec): codec module — Encode/Decode traits + JsonWriter escaper [#193 step 2]"
```

---

## Task 2: `impl Encode for Seal` — writer grammar moves

**Files:**
- Modify: `crates/keri-codec/src/codec/seal.rs` (the Encode impl + tests)
- Modify: `crates/keri-codec/src/serialize/json.rs` (delete `write_seal`, shrink `write_seal_array`)

- [ ] **Step 1: Write the golden encode test first** in `codec/seal.rs`'s `#[cfg(test)]` (build seals with the same `MatterBuilder` helpers used in `keri-events/src/seal.rs` tests — copy `make_saider`/`make_prefixer`/`make_verser` from there):

```rust
#[test]
fn encode_matches_golden_wire_form() {
    let mut buf = Vec::new();
    Seal::Digest { d: make_saider() }.encode(&mut buf);
    let digest_json = String::from_utf8(buf).unwrap();
    assert_eq!(
        digest_json,
        format!("{{\"d\":\"{}\"}}", to_qb64_string(&make_saider()))
    );

    let mut buf = Vec::new();
    Seal::Opaque(OpaqueSeal::new_unchecked("{\"x\":1}")).encode(&mut buf);
    assert_eq!(buf, b"{\"x\":1}", "opaque splices verbatim, no escaping");
}
```

Run: `nix develop --command cargo nextest run -p keri-codec codec::seal` — expected FAIL to compile (`Encode` not implemented for `Seal`).

- [ ] **Step 2: Move `write_seal` into the impl.** Copy the eight match arms from `json.rs::write_seal` (json.rs:336-388) **verbatim** into `codec/seal.rs`, only re-homing the helpers (`JsonWriter::write_str` for `write_str`, `crate::primitives::to_qb64_string` unchanged):

```rust
//! The seal wire grammar — both directions, one variant per block.

use crate::codec::{Encode, JsonWriter};
use crate::primitives::to_qb64_string;
use keri_events::Seal;

impl Encode for Seal<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Seal::Digest { d } => {
                out.extend_from_slice(b"{\"d\":");
                JsonWriter::write_str(out, &to_qb64_string(d));
                out.push(b'}');
            }
            // …the remaining six typed arms, copied verbatim from write_seal
            // with buf→out and write_str→JsonWriter::write_str…
            // Verbatim: the payload is compact JSON by `new_unchecked`'s caller
            // contract (the strict reader enforces it via `OpaqueScan` before
            // construction); re-escaping through `write_str` would corrupt it.
            Seal::Opaque(raw) => out.extend_from_slice(raw.as_str().as_bytes()),
        }
    }
}
```

(“Copied verbatim” includes the `Source`/`Event`/`Last`/`Back`/`Kind`/`Root` arms and the `s.to_string()` sequence-number rendering — do not re-derive any of it. Leave a blank line between variant arms; Task 3 slots each variant's decode logic adjacent.)

- [ ] **Step 3: Rewire the writer.** In `json.rs`: delete `fn write_seal` entirely; `write_seal_array` (json.rs:390-398) keeps its signature but loops the trait:

```rust
use crate::codec::Encode as _;

fn write_seal_array(buf: &mut Vec<u8>, seals: &[Seal]) {
    buf.push(b'[');
    for (idx, seal) in seals.iter().enumerate() {
        if idx > 0 {
            buf.push(b',');
        }
        seal.encode(buf);
    }
    buf.push(b']');
}
```

(Import the trait at the top of the file — `as _` since only the method is needed. If `json.rs` tests referenced `write_seal` directly, retarget them to `Seal::encode`.)

- [ ] **Step 4: Run the full crate suite (byte-identity check).**

Run: `nix develop --command cargo nextest run -p keri-codec`
Expected: PASS, including `serialize::tests` golden/differential suites — proving the moved writer is byte-identical.

- [ ] **Step 5: Commit.**

```bash
git add crates/keri-codec/src/codec/seal.rs crates/keri-codec/src/serialize/json.rs
git commit -m "refactor(keri-codec): Seal::encode — writer seal grammar moves to codec/seal [#193 step 2]"
```

---

## Task 3: `impl Decode for ParsedSeal` — reader grammar moves, co-located

**Files:**
- Modify: `crates/keri-codec/src/codec/seal.rs` (the Decode impl + helpers + tests)
- Modify: `crates/keri-codec/src/deserialize/canonical.rs` (delete the three seal fns, retarget `seal_array`, move seal tests out)

- [ ] **Step 1: Write the round-trip test first** in `codec/seal.rs`:

```rust
#[test]
fn decode_roundtrips_every_encoded_variant() {
    let seals = [
        Seal::Digest { d: make_saider() },
        Seal::Root { rd: make_saider() },
        Seal::Source { s: SequenceNumber::new(7), d: make_saider() },
        Seal::Event { i: make_prefixer(), s: SequenceNumber::new(1), d: make_saider() },
        Seal::Last { i: make_prefixer() },
        Seal::Back { bi: make_prefixer(), d: make_saider() },
        Seal::Kind { t: make_verser(), d: make_saider() },
        Seal::Opaque(OpaqueSeal::new_unchecked("{\"app\":[1,2]}")),
    ];
    for seal in &seals {
        let mut buf = Vec::new();
        seal.encode(&mut buf);
        let mut sc = Scanner::new(&buf);
        let parsed = ParsedSeal::decode(&mut sc).unwrap();
        sc.finish().unwrap();
        // Re-encode the parsed view's fields into the same wire form via the
        // string values — asserting the borrowed views address the input.
        match (seal, &parsed) {
            (Seal::Digest { d }, ParsedSeal::Digest { d: pd }) => {
                assert_eq!(*pd, to_qb64_string(d));
            }
            (Seal::Opaque(raw), ParsedSeal::Opaque { raw: praw }) => {
                assert_eq!(*praw, raw.as_str());
            }
            // …one arm per remaining variant, asserting each borrowed field
            // equals its typed source's rendering (s fields via .to_string())…
            (other, parsed) => panic!("variant mismatch: {other:?} → {parsed:?}"),
        }
    }
}
```

Run: `nix develop --command cargo nextest run -p keri-codec codec::seal` — expected FAIL to compile (`Decode` not implemented).

- [ ] **Step 2: Move the reader.** Into `codec/seal.rs`, **verbatim**: `seal_codex`'s body becomes a private `fn codex<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError>`; `seal_opaque`'s body becomes private `fn opaque<'a>(…)` (bringing the `use crate::deserialize::opaque_scan::OpaqueScan;` and `use core::str;` imports with it); the dispatch `fn seal` becomes the trait impl:

```rust
impl<'a> Decode<'a> for ParsedSeal<'a> {
    /// One seal object: the seven codex shapes parse typed; anything else
    /// falls back to a verbatim opaque capture of the whole object. A codex
    /// parse failure rewinds — the codex attempt and the opaque scan both
    /// start from the object's first byte.
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, SerderError> {
        let start = sc.pos;
        // The codex error is deliberately superseded: the opaque scan is the
        // outermost interpretation and produces its own typed error on failure.
        if let Ok(parsed) = codex(sc) {
            return Ok(parsed);
        }
        sc.pos = start;
        opaque(sc)
    }
}
```

`sc.pos` and `sc.input` are used cross-module here — check their field visibility in `canonical.rs` (`pub(crate)` already, or promote the fields the same way the methods are; a field promotion is invisible outside the crate). Physically interleave the file so each variant's encode arm and its `codex` branch sit adjacent (encode `Digest` / decode `"d":` branch, …) — this co-location is the point of the migration.

- [ ] **Step 3: Rewire the reader.** In `canonical.rs`: delete `seal_codex`, `seal`, `seal_opaque` and the `OpaqueScan` import; `seal_array` becomes:

```rust
use crate::codec::Decode as _;

fn seal_array<'a>(sc: &mut Scanner<'a>) -> Result<Vec<ParsedSeal<'a>>, SerderError> {
    delimited_list(sc, ParsedSeal::decode)
}
```

- [ ] **Step 4: Move the seal-specific tests.** From `canonical.rs`'s test module to `codec/seal.rs`'s: `truncated_opaque_anchor_is_invalid_anchor` (canonical.rs:1116) and `seal_array_shapes` (canonical.rs:1137) — retargeted at `ParsedSeal::decode` / the relocated `seal_array` path; the two proptest lines exercising `seal(...)`/`seal_array(...)` (canonical.rs:1558-1559) retarget to `ParsedSeal::decode` and stay in canonical.rs's `scanner_never_panics` property (they fuzz the whole scanner surface — keep them where the harness lives, just fix the call).

- [ ] **Step 5: Run the full crate suite.**

Run: `nix develop --command cargo nextest run -p keri-codec`
Expected: PASS — same differential/spine/property coverage, reader now behind the trait.

- [ ] **Step 6: Commit.**

```bash
git add crates/keri-codec/src/codec/seal.rs crates/keri-codec/src/deserialize/canonical.rs
git commit -m "refactor(keri-codec): ParsedSeal::decode — reader seal grammar joins codec/seal [#193 step 2]"
```

---

## Task 4: CHANGELOG, ratchet proof, full gate

**Files:**
- Modify: `crates/keri-codec/CHANGELOG.md`

- [ ] **Step 1: CHANGELOG entry** (internal, non-breaking — under `[Unreleased]` / `### Changed`, after the P3 entry):

```markdown
- Internal: the seal wire grammar is now stated once per direction — new
  crate-internal `Encode`/`Decode` traits (der-precedent, #193 step 2) with
  `Seal::encode` and `ParsedSeal::decode` co-located in `codec/seal.rs`,
  replacing the duplicated enumeration in the writer (`write_seal`) and the
  strict reader (`seal_codex`). No public API change; wire bytes unchanged.
```

- [ ] **Step 2: Ratchet proof.**

Run: `rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/keri-codec/src -g '*.rs' | wc -l`
Expected: `58` (unchanged — all moves were private fns → trait/type methods). If 59+, a helper leaked to file-scope `pub(crate)` — demote it.

- [ ] **Step 3: Commit, then the single gate on committed state.**

```bash
git add crates/keri-codec/CHANGELOG.md
git commit -m "docs(keri-codec): changelog for seal Encode/Decode migration [#193 step 2]"
nix flake check > /tmp/step2-gate.log 2>&1; echo "GATE EXIT: $?"
```

Expected: `GATE EXIT: 0`. (Never pipe the gate through head/tail — capture to file, echo the code.)

---

## Self-Review

- **Spec coverage:** duplicated seal grammar (write_seal ↔ seal_codex) → Tasks 2–3 co-locate both directions in `codec/seal.rs`; trait introduction → Task 1; non-breaking constraint → traits `pub(crate)`, no lib.rs export changes beyond the module decl; wire-guard → full suite each task + gate at the end.
- **Placeholder scan:** the two “…remaining arms…” elisions in Tasks 2–3 are verbatim-copy instructions with the source location pinned (json.rs:336-388, canonical.rs:445-535 pre-move) — the source is the tested in-tree code, not invention. Everything else is complete.
- **Type consistency:** `Encode::encode(&self, out: &mut Vec<u8>)` / `Decode::decode(sc: &mut Scanner<'a>)` used identically in Tasks 1–3; `JsonWriter::write_str` consistent between Task 1's definition and Task 2's calls.
- **Known risk:** `Scanner.pos`/`.input` field visibility for the cross-module `decode` — Task 3 Step 2 handles it explicitly (promote fields to `pub(crate)` if private; crate-internal, invisible outside).
