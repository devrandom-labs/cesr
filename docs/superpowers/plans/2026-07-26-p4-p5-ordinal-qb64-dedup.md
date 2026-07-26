# #193 P4 + P5 — ordinal & qb64↔qb2 de-duplication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove two ordinal/base64 duplications flagged by the #193 audit — collapse `keri-events::SequenceNumber` onto `cesr::Number` behind a new `Ordinal` trait, and relocate the qb64↔qb2 transcoders into `cesr::b64` with a shared block core.

**Architecture:** P4 deletes the codeless `SequenceNumber` shadow and makes the event/seal `s` field a `cesr::Number`, which grows `numh`/`LowerHex`/`Copy` and implements a new `Ordinal` trait that lives beside the existing `Matter` trait in `cesr::core::primitives`. P5 moves `Qb64`/`Qb2` down into `cesr::b64` (the crate that owns Base64), factors a single 3↔4 block routine shared with `encode_binary`, adds the missing `decode_binary`, and leaves `cesr-stream` re-exporting the old path.

**Tech Stack:** Rust 2024, pinned stable 1.95.0, no_std + alloc, `thiserror`, `nix flake check` as the sole gate.

**Spec:** `docs/superpowers/specs/2026-07-26-p4-p5-ordinal-qb64-dedup-design.md`

**Conventions for every task below:**
- Verify with `nix develop --command cargo nextest run -p <crate>` for fast local loops; the **only** gate before a PR is `nix flake check`.
- Never relax a clippy lint or edit `clippy.toml`/`[lints]`.
- All `use` imports at the top of the file (production code); no inline `use`.
- Conventional commits with scope. Breaking changes go in `CHANGELOG`.

---

## File Structure

**P4 (ordinal):**
- Create: `crates/cesr/src/core/primitives/ordinal.rs` — the `Ordinal` trait + private `NumHex` Display wrapper.
- Modify: `crates/cesr/src/core/primitives/mod.rs` — add `pub mod ordinal;` + `pub use ordinal::Ordinal;`.
- Modify: `crates/cesr/src/core/mod.rs` and `crates/cesr/src/lib.rs` — re-export `Ordinal` beside `Number`.
- Modify: `crates/cesr/src/core/primitives/number.rs` — add `Copy` derive, `impl LowerHex`, `impl Ordinal`.
- Delete: `crates/keri-events/src/sequence.rs`.
- Modify: `crates/keri-events/src/lib.rs` — drop `mod sequence` + `SequenceNumber` re-export.
- Modify: `crates/keri-events/src/event/{inception,rotation,interaction,delegation}.rs`, `crates/keri-events/src/event/mod.rs`, `crates/keri-events/src/seal.rs` — field type + accessor + fixtures `SequenceNumber` → `Number`.
- Modify: `crates/keri-codec/src/codec/event.rs` — 3 production render sites + fixtures.
- Modify: `crates/keri-codec/src/deserialize/reference.rs` — `SequenceNumber::new` → `Number::new`.
- Modify: `crates/keri-codec/src/{serialize.rs,traits.rs,builder/*.rs}`, `crates/keri-codec/benches/serder.rs` — fixtures.

**P5 (qb64↔qb2):**
- Modify: `crates/cesr/src/b64/error.rs` — add `Misaligned { len, unit }`.
- Create: `crates/cesr/src/b64/transcode.rs` — `Qb64`/`Qb2` + shared block core + `decode_binary`.
- Modify: `crates/cesr/src/b64/binary.rs` — `encode_binary` reuses the shared block core (or is re-homed beside it).
- Modify: `crates/cesr/src/b64/mod.rs` — export `Qb64`, `Qb2`, `decode_binary`.
- Modify: `crates/cesr-stream/src/qb2.rs` — becomes a thin re-export of `cesr::b64::{Qb64, Qb2}`.
- Modify: `crates/cesr-stream/src/error.rs` — refine `From<b64::Error> for ParseError` to route `Misaligned`.
- Modify: `crates/cesr-stream/benches/matter.rs`, `crates/cesr-stream/src/keripy_diff/*.rs` — import paths only.

**Docs:**
- Modify: `crates/cesr/CHANGELOG.md`, `crates/cesr-stream/CHANGELOG.md`, `crates/keri-events/CHANGELOG.md`, `crates/keri-codec/CHANGELOG.md`.

---

## Part A — P4: ordinal collapse

### Task 1: `Ordinal` trait + `NumHex` wrapper in cesr core

**Files:**
- Create: `crates/cesr/src/core/primitives/ordinal.rs`
- Modify: `crates/cesr/src/core/primitives/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/cesr/src/core/primitives/ordinal.rs` with only the test module first:

```rust
//! The ordinal-whole-number contract shared by `cesr` integer primitives.
//!
//! An ordinal renders two ways: as a `u128` value, and as minimal lowercase
//! hex (keripy's `Number.numh`) for embedding in JSON event bodies. The qb64
//! `Matter` rendering is a separate concern owned by each primitive.

use core::fmt;

/// An unsigned whole-number ordinal renderable as minimal lowercase hex.
pub trait Ordinal {
    /// The ordinal value.
    fn num(&self) -> u128;

    /// Minimal lowercase hex, no leading zeros; zero renders as `"0"`.
    ///
    /// Returns a `Display` adapter so callers can write directly into a buffer
    /// without allocating (no_std / alloc-free).
    fn numh(&self) -> impl fmt::Display
    where
        Self: Sized,
    {
        NumHex(self.num())
    }
}

/// Zero-allocation `Display` adapter rendering a `u128` as minimal lowercase hex.
struct NumHex(u128);

impl fmt::Display for NumHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    struct Bare(u128);
    impl Ordinal for Bare {
        fn num(&self) -> u128 {
            self.0
        }
    }

    #[test]
    fn numh_renders_minimal_lowercase_hex() {
        assert_eq!(Bare(0).numh().to_string(), "0");
        assert_eq!(Bare(1).numh().to_string(), "1");
        assert_eq!(Bare(10).numh().to_string(), "a");
        assert_eq!(Bare(255).numh().to_string(), "ff");
        assert_eq!(
            Bare(u128::MAX).numh().to_string(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn num_returns_value() {
        assert_eq!(Bare(42).num(), 42);
    }
}
```

Wire the module in `crates/cesr/src/core/primitives/mod.rs` — add next to the existing `pub mod number;` / `pub use number::Number;` block:

```rust
pub mod ordinal;
pub use ordinal::Ordinal;
```

- [ ] **Step 2: Run test to verify it fails / compiles**

Run: `nix develop --command cargo nextest run -p cesr-rs ordinal`
Expected: PASS (this task's trait+test are self-contained; if `alloc` import is missing under a feature combo, fix by gating the test module `use alloc::string::ToString;` behind `#[cfg(feature = "alloc")]` as the rest of the crate does).

- [ ] **Step 3: Confirm re-exports resolve**

Add `Ordinal` to the two aggregate re-exports so consumers can reach it beside `Number`:
- `crates/cesr/src/core/mod.rs`: add `Ordinal` to the `pub use ... primitives::{...}` list that already names `Number`.
- `crates/cesr/src/lib.rs`: add `Ordinal` to the crate-root `pub use` list that already names `Number`.

- [ ] **Step 4: Run the crate build across features**

Run: `nix develop --command cargo build -p cesr-rs --no-default-features --features alloc,core,b64`
Expected: builds clean.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr/src/core/primitives/ordinal.rs crates/cesr/src/core/primitives/mod.rs crates/cesr/src/core/mod.rs crates/cesr/src/lib.rs
git commit -m "feat(cesr): add Ordinal trait (num/numh) in core primitives (#193 P4)"
```

---

### Task 2: `Number` gains `Copy`, `LowerHex`, `Ordinal`

**Files:**
- Modify: `crates/cesr/src/core/primitives/number.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/cesr/src/core/primitives/number.rs`:

```rust
#[test]
fn number_renders_minimal_hex_via_ordinal_and_lowerhex() {
    use alloc::string::ToString;
    use crate::core::primitives::Ordinal;

    let n = Number::new(255);
    assert_eq!(n.numh().to_string(), "ff");
    assert_eq!(format!("{n:x}"), "ff");
    assert_eq!(Number::new(0).numh().to_string(), "0");
    assert_eq!(Number::new(u128::MAX).num(), u128::MAX);
}

#[test]
fn number_is_copy() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<Number>();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs number_renders_minimal_hex_via_ordinal_and_lowerhex`
Expected: FAIL — `numh`/`LowerHex` not implemented, `Number` not `Copy`.

- [ ] **Step 3: Implement**

In `crates/cesr/src/core/primitives/number.rs`:

Add `Copy` to the derive (line ~4):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Number {
    code: NumberCode,
    value: u128,
}
```

Add these impls after the `impl Number { ... }` block (add `use core::fmt;` and `use crate::core::primitives::ordinal::Ordinal;` at the top of the file):
```rust
impl fmt::LowerHex for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.value, f)
    }
}

impl Ordinal for Number {
    fn num(&self) -> u128 {
        self.value
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo nextest run -p cesr-rs -E 'test(number)'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr/src/core/primitives/number.rs
git commit -m "feat(cesr): Number gains Copy, LowerHex, Ordinal (#193 P4)"
```

---

### Task 3: Migrate keri-events to `cesr::Number`; delete `SequenceNumber`

**Files:**
- Delete: `crates/keri-events/src/sequence.rs`
- Modify: `crates/keri-events/src/lib.rs`
- Modify: `crates/keri-events/src/event/{inception,rotation,interaction,delegation,mod}.rs`, `crates/keri-events/src/seal.rs`

- [ ] **Step 1: Repoint the type across keri-events**

Replace the field type, accessor return type, and imports. In each of
`inception.rs`, `rotation.rs`, `interaction.rs`:
- Change import `use crate::sequence::SequenceNumber;` → `use cesr::core::primitives::Number;`
- Change field `sn: SequenceNumber,` → `sn: Number,`
- Change accessor `pub const fn sn(&self) -> SequenceNumber {` → `pub const fn sn(&self) -> Number {`

In `delegation.rs`, `event/mod.rs`, and `seal.rs`: change the import and any
`SequenceNumber` type/`SequenceNumber::new(` usages. For `seal.rs`,
`Seal::Source { s: SequenceNumber, .. }` and `Seal::Event { s: SequenceNumber, .. }`
→ `s: Number`.

Bulk-replace the constructor and type name across the crate (run from repo root):
```bash
fd -e rs . crates/keri-events/src -x sd 'SequenceNumber::new\(' 'Number::new(' {}
fd -e rs . crates/keri-events/src -x sd '\bSequenceNumber\b' 'Number' {}
```
Then fix the now-wrong imports: any file that ended with `use cesr::core::primitives::Number;` duplicated, or still importing from `crate::sequence`, must import `Number` from `cesr::core::primitives` exactly once at the top. Also update the `seal.rs` doc comment that referenced `SequenceNumber` / `Number(num=n).numh`.

- [ ] **Step 2: Delete the module and its re-export**

```bash
git rm crates/keri-events/src/sequence.rs
```
In `crates/keri-events/src/lib.rs`, remove the `pub mod sequence;` line and the
`pub use sequence::SequenceNumber;` (or `pub use sequence::SequenceNumber as ...`)
re-export line.

- [ ] **Step 3: Verify keri-events compiles + tests pass**

Run: `nix develop --command cargo nextest run -p keri-events`
Expected: PASS. Fixture assertions that previously relied on `SequenceNumber`'s
`Display` still pass because `Number`'s hex is only used at the codec layer; the
event structs just hold the value.

- [ ] **Step 4: Confirm no stragglers**

Run: `command rg -n "SequenceNumber|crate::sequence|sequence::" crates/keri-events`
Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add -A crates/keri-events
git commit -m "refactor(keri-events)!: event/seal sequence number is cesr::Number; delete SequenceNumber (#193 P4)"
```

---

### Task 4: Migrate keri-codec render + parse + fixtures to `Number`

**Files:**
- Modify: `crates/keri-codec/src/codec/event.rs`
- Modify: `crates/keri-codec/src/deserialize/reference.rs`
- Modify: `crates/keri-codec/src/serialize.rs`, `crates/keri-codec/src/traits.rs`, `crates/keri-codec/src/builder/*.rs`, `crates/keri-codec/benches/serder.rs`

- [ ] **Step 1: Fix the 3 production render sites**

In `crates/keri-codec/src/codec/event.rs`, the sequence number is written at three
sites (currently `JsonWriter::write_str(buf, &e.sn().to_string());` at lines ~577,
~634, ~687). `Number` intentionally has **no** `Display` (its natural display is
ambiguous between hex/decimal/qb64), so render explicitly via the `Ordinal`
contract. Add `use cesr::core::primitives::Ordinal;` at the top of the file, then
change each of the three sites to:

```rust
JsonWriter::write_str(buf, &e.sn().numh().to_string());
```

- [ ] **Step 2: Fix the deserialize construction**

In `crates/keri-codec/src/deserialize/reference.rs`, `parse_sn` already returns
`u128` (via `u128::from_str_radix(s, 16)`) — leave it. Change every
`SequenceNumber::new(sn)` construction to `Number::new(sn)`, and update the import:
- Remove `SequenceNumber` from the `use keri_events::{...}` list.
- Add `use cesr::core::primitives::Number;` at the top (the file already imports
  other `cesr::core::primitives` types, so extend that list instead of adding a
  second `use`).

- [ ] **Step 3: Bulk-migrate fixtures + imports across keri-codec**

```bash
fd -e rs . crates/keri-codec -x sd 'SequenceNumber::new\(' 'Number::new(' {}
# Replace the type name in remaining spots (imports, type positions):
fd -e rs . crates/keri-codec -x sd '\bSequenceNumber\b' 'Number' {}
```
Then repair imports: any `use keri_events::sequence::Number;` or
`use keri_events::{..., Number, ...};` produced by the rename is wrong — the type
now comes from cesr. Replace those with `use cesr::core::primitives::Number;`
(deduplicated, top of file). Search-and-fix:
```bash
command rg -n "keri_events::sequence|keri_events::\{[^}]*\bNumber\b" crates/keri-codec
```
Each hit: drop `Number` from the `keri_events` import, ensure `Number` is imported
from `cesr::core::primitives` once.

- [ ] **Step 4: Update the test that documents the render path**

`crates/keri-codec/src/codec/event.rs` around line ~1209 has a comment referencing
"`SequenceNumber`'s hex `Display`" and test JSON building `"s": e.sn().to_string()`
(lines ~1298, ~1318, ~1363). Update the comment to reference `Number.numh` and
change those three test expressions to `"s": e.sn().numh().to_string()`.

- [ ] **Step 5: Run keri-codec tests**

Run: `nix develop --command cargo nextest run -p keri-codec`
Expected: PASS — byte output for the `s` field is identical (`numh` == the old
`SequenceNumber` `{:x}` Display), so golden/round-trip vectors are unchanged.

- [ ] **Step 6: Confirm no stragglers + commit**

```bash
command rg -n "SequenceNumber" crates/keri-codec   # expect: no matches
git add -A crates/keri-codec
git commit -m "refactor(keri-codec): render/parse sequence number via cesr::Number + Ordinal::numh (#193 P4)"
```

---

### Task 5: P4 CHANGELOG + full gate

**Files:**
- Modify: `crates/cesr/CHANGELOG.md`, `crates/keri-events/CHANGELOG.md`, `crates/keri-codec/CHANGELOG.md`

- [ ] **Step 1: Add CHANGELOG entries**

`crates/cesr/CHANGELOG.md` (Unreleased → Added):
```markdown
- `Ordinal` trait (`num`/`numh`) in `core::primitives`; `Number` now implements it
  plus `Copy` and `LowerHex` (minimal lowercase hex). (#193 P4)
```
`crates/keri-events/CHANGELOG.md` (Unreleased → Changed / **BREAKING**):
```markdown
- **BREAKING:** removed `SequenceNumber`; event and seal sequence numbers are now
  `cesr::core::primitives::Number`. (#193 P4)
```
`crates/keri-codec/CHANGELOG.md` (Unreleased → Changed):
```markdown
- Sequence-number rendering/parse now flows through `cesr::Number` +
  `Ordinal::numh`. (#193 P4)
```

- [ ] **Step 2: Run the full gate**

Run: `nix flake check 2>&1 | tee /tmp/p4-gate.log; echo "exit=$?"`
Expected: `exit=0`. (Never pipe the gate through `head`/`tail` — redirect to a file
and check the exit code, per repo convention.)

- [ ] **Step 3: If the fn-ratchet check fails**

Deleting `sequence.rs` lowers a per-module free-`pub fn` count. Open
`free-fn-budget.toml`, find the `keri-events` module budget, and **lower** it to the
new count reported by the failing check (never raise a budget).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(changelog): P4 ordinal collapse; re-baseline fn-ratchet (#193 P4)"
```

---

## Part B — P5: qb64↔qb2 relocation

### Task 6: Add `Misaligned` variant to `b64::Error`

**Files:**
- Modify: `crates/cesr/src/b64/error.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/cesr/src/b64/error.rs`:
```rust
#[test]
fn misaligned_display_names_len_and_unit() {
    let err = Error::Misaligned { len: 3, unit: 4 };
    let msg = err.to_string();
    assert!(msg.contains('3') && msg.contains('4'), "got: {msg}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs misaligned_display_names_len_and_unit`
Expected: FAIL — no `Misaligned` variant.

- [ ] **Step 3: Implement**

Add the variant to `enum Error` in `crates/cesr/src/b64/error.rs`:
```rust
    /// The input length is not a whole multiple of the conversion unit
    /// (4 Base64 chars per 3 binary bytes).
    #[error("Misaligned: length {len} is not a multiple of {unit}.")]
    Misaligned {
        /// The offending input length.
        len: usize,
        /// The required alignment unit (3 or 4).
        unit: usize,
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo nextest run -p cesr-rs misaligned_display_names_len_and_unit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr/src/b64/error.rs
git commit -m "feat(cesr)!: b64::Error gains Misaligned variant (#193 P5)"
```

---

### Task 7: Relocate `Qb64`/`Qb2` + shared block core + `decode_binary` into `cesr::b64`

**Files:**
- Create: `crates/cesr/src/b64/transcode.rs`
- Modify: `crates/cesr/src/b64/mod.rs`
- Modify: `crates/cesr/src/b64/binary.rs`

- [ ] **Step 1: Create the transcode module with migrated tests**

Create `crates/cesr/src/b64/transcode.rs` porting the whole-blob transcoders from
`crates/cesr-stream/src/qb2.rs`, but returning `crate::b64::error::Error` instead of
`ParseError`, and factoring the per-block routines. Full module:

```rust
//! Whole-blob conversion between the CESR text (qb64) and binary (qb2) domains.
//!
//! Every 4 qb64 characters encode 3 qb2 bytes. Modelled as borrowed newtypes so
//! the verbs hang off the value being converted, each offering an owned result
//! and a `*_into` variant that appends into a caller buffer (hot paths reuse one
//! allocation). The single-primitive fixed-length encoder is
//! [`super::binary::encode_binary`]; both share the 3↔4 block routines here.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec::Vec;

use super::alphabet::{B64_ALPHABET, b64_byte_to_index};
use super::error::Error;

/// A borrowed span of qb64 (Base64 text) awaiting conversion to qb2 binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qb64<'a>(pub &'a [u8]);

/// A borrowed span of qb2 (binary) awaiting conversion to qb64 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qb2<'a>(pub &'a [u8]);

/// Decode one aligned block of 4 Base64 bytes into 3 binary bytes, appending to `out`.
fn decode_block(chunk: &[u8; 4], out: &mut Vec<u8>) -> Result<(), Error> {
    let v0 = b64_byte_to_index(chunk[0])?;
    let v1 = b64_byte_to_index(chunk[1])?;
    let v2 = b64_byte_to_index(chunk[2])?;
    let v3 = b64_byte_to_index(chunk[3])?;
    let bits =
        (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);
    out.push(truncate_u32_to_u8(bits >> 16));
    out.push(truncate_u32_to_u8(bits >> 8));
    out.push(truncate_u32_to_u8(bits));
    Ok(())
}

/// Encode one aligned block of 3 binary bytes into 4 Base64 bytes, appending to `out`.
fn encode_block(chunk: &[u8; 3], out: &mut Vec<u8>) {
    let bits = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
    out.push(B64_ALPHABET[usize_from_u32((bits >> 18) & 0x3F)]);
    out.push(B64_ALPHABET[usize_from_u32((bits >> 12) & 0x3F)]);
    out.push(B64_ALPHABET[usize_from_u32((bits >> 6) & 0x3F)]);
    out.push(B64_ALPHABET[usize_from_u32(bits & 0x3F)]);
}

impl Qb64<'_> {
    /// Decode this qb64 text to qb2 binary. Length must be a multiple of 4.
    ///
    /// # Errors
    /// [`Error::Misaligned`] if the length is not a multiple of 4, or
    /// [`Error::InvalidBase64Char`]/[`Error::InvalidBase64Value`] on a bad character.
    pub fn decode(self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.decode_into(&mut out)?;
        Ok(out)
    }

    /// Decode this qb64 text to qb2 binary, appending to `out` (never cleared).
    ///
    /// # Errors
    /// [`Error::Misaligned`] (before touching `out`) if the length is not a
    /// multiple of 4, or a character error partway through.
    pub fn decode_into(self, out: &mut Vec<u8>) -> Result<(), Error> {
        let qb64 = self.0;
        if !qb64.len().is_multiple_of(4) {
            return Err(Error::Misaligned {
                len: qb64.len(),
                unit: 4,
            });
        }
        out.reserve(qb64.len() / 4 * 3);
        for chunk in qb64.chunks_exact(4) {
            let block: &[u8; 4] = chunk.try_into().expect("chunks_exact(4) yields 4");
            decode_block(block, out)?;
        }
        Ok(())
    }
}

impl Qb2<'_> {
    /// Encode this qb2 binary to qb64 text. Length must be a multiple of 3.
    ///
    /// # Errors
    /// [`Error::Misaligned`] if the length is not a multiple of 3.
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Encode this qb2 binary to qb64 text, appending to `out` (never cleared).
    ///
    /// # Errors
    /// [`Error::Misaligned`] (before touching `out`) if the length is not a
    /// multiple of 3.
    pub fn encode_into(self, out: &mut Vec<u8>) -> Result<(), Error> {
        let qb2 = self.0;
        if !qb2.len().is_multiple_of(3) {
            return Err(Error::Misaligned {
                len: qb2.len(),
                unit: 3,
            });
        }
        out.reserve(qb2.len() / 3 * 4);
        for chunk in qb2.chunks_exact(3) {
            let block: &[u8; 3] = chunk.try_into().expect("chunks_exact(3) yields 3");
            encode_block(block, out);
        }
        Ok(())
    }
}

/// Decode an aligned qb64 byte slice to raw bytes (the byte-base64 inverse of
/// [`super::binary::encode_binary`]'s aligned case). Convenience free function.
///
/// # Errors
/// [`Error::Misaligned`] if `qb64.len()` is not a multiple of 4, or a character error.
pub fn decode_binary(qb64: &[u8]) -> Result<Vec<u8>, Error> {
    Qb64(qb64).decode()
}

#[allow(
    clippy::as_conversions,
    reason = "masked to u8 range; `as` is the only option for bit truncation"
)]
const fn truncate_u32_to_u8(v: u32) -> u8 {
    (v & 0xFF) as u8
}

#[allow(
    clippy::as_conversions,
    reason = "value masked to 6 bits, always fits in usize"
)]
const fn usize_from_u32(v: u32) -> usize {
    v as usize
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics acceptable"
)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn decode_counter() {
        assert_eq!(Qb64(b"-AAB").decode().unwrap(), vec![0xF8, 0x00, 0x01]);
    }

    #[test]
    fn roundtrip_multi_block() {
        let original = b"-AAB-AAC";
        let binary = Qb64(original).decode().unwrap();
        assert_eq!(binary.len(), 6);
        assert_eq!(&Qb2(&binary).encode().unwrap(), original);
    }

    #[test]
    fn decode_rejects_misaligned() {
        assert_eq!(
            Qb64(b"ABC").decode().unwrap_err(),
            Error::Misaligned { len: 3, unit: 4 }
        );
    }

    #[test]
    fn encode_rejects_misaligned() {
        assert_eq!(
            Qb2(&[0u8, 1]).encode().unwrap_err(),
            Error::Misaligned { len: 2, unit: 3 }
        );
    }

    #[test]
    fn decode_into_leaves_buffer_untouched_on_misaligned() {
        let mut buf = vec![0x01, 0x02];
        assert!(Qb64(b"ABC").decode_into(&mut buf).is_err());
        assert_eq!(buf, vec![0x01, 0x02]);
    }

    #[test]
    fn decode_binary_free_fn_matches_newtype() {
        assert_eq!(decode_binary(b"-AAB").unwrap(), Qb64(b"-AAB").decode().unwrap());
    }

    #[test]
    fn decode_invalid_character() {
        assert!(Qb64(b"-A!B").decode().is_err());
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(Qb64(b"").decode().unwrap(), Vec::<u8>::new());
        assert_eq!(Qb2(&[]).encode().unwrap(), Vec::<u8>::new());
    }
}
```

- [ ] **Step 2: Export from `b64/mod.rs`**

In `crates/cesr/src/b64/mod.rs` add:
```rust
pub mod transcode;
pub use transcode::{Qb2, Qb64, decode_binary};
```

- [ ] **Step 3: Share the block core with `encode_binary` (optional consolidation)**

`encode_binary` (single-primitive, produces exactly `length` chars, uses a bit
accumulator to emit partial tails) is a different contract from the aligned
whole-block `Qb2::encode`. Keep `encode_binary`'s accumulator (it must handle
non-multiple-of-3 lengths), but for the aligned full-block portion it may call
`encode_block`. If a clean shared call is not possible without regressing
`encode_binary`'s partial-tail handling, leave `encode_binary` as-is and record in
the commit body that the shared core covers the whole-blob path only. Do **not**
force a merge that complicates the single-primitive encoder.

- [ ] **Step 4: Run cesr b64 tests across features**

Run: `nix develop --command cargo nextest run -p cesr-rs -E 'test(transcode) + test(binary)'`
Then no_std sanity: `nix develop --command cargo build -p cesr-rs --no-default-features --features alloc,core,b64`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr/src/b64/transcode.rs crates/cesr/src/b64/mod.rs crates/cesr/src/b64/binary.rs
git commit -m "feat(cesr): qb64<->qb2 transcoders + decode_binary in b64, shared block core (#193 P5)"
```

---

### Task 8: `cesr-stream::qb2` becomes a re-export; route the error

**Files:**
- Modify: `crates/cesr-stream/src/qb2.rs`
- Modify: `crates/cesr-stream/src/error.rs`

- [ ] **Step 1: Replace qb2.rs body with a re-export**

Replace the entire contents of `crates/cesr-stream/src/qb2.rs` with:
```rust
//! Binary domain (qb2) conversion — re-exported from the `cesr` primitive crate,
//! which owns all Base64-domain math. See [`cesr::b64::transcode`].

pub use cesr::b64::{Qb2, Qb64};
```
Keep `pub mod qb2;` in `crates/cesr-stream/src/lib.rs` unchanged so existing
consumers' `cesr_stream::qb2::Qb64` / `cesr_stream::qb2::Qb2` paths still resolve.

- [ ] **Step 2: Route `Misaligned` through the ParseError From impl**

In `crates/cesr-stream/src/error.rs`, the existing `From<CesrUtilsError> for
ParseError` maps everything to `ParseError::Base64`. Refine it so a `Misaligned`
b64 error becomes `ParseError::Misaligned` (preserving the existing typed
distinction). Locate the impl (around line 308) and change it to match on the
variant:
```rust
impl From<CesrUtilsError> for ParseError {
    fn from(e: CesrUtilsError) -> Self {
        match e {
            CesrUtilsError::Misaligned { len, unit } => Self::Misaligned { len, unit },
            other => Self::Base64(other),
        }
    }
}
```
(`CesrUtilsError` is the crate's alias for `cesr::b64::Error`; confirm the alias
name at the top of `error.rs` and use it consistently.)

- [ ] **Step 3: Verify cesr-stream compiles + tests pass**

Run: `nix develop --command cargo nextest run -p cesr-stream`
Expected: PASS. The old qb2 unit tests that lived in `qb2.rs` now live in
`cesr::b64::transcode`; the re-export smoke is covered by consumers.

- [ ] **Step 4: Add a re-export smoke test**

Append to `crates/cesr-stream/src/qb2.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::{Qb2, Qb64};

    #[test]
    fn reexport_paths_resolve_and_roundtrip() {
        let bin = Qb64(b"-AAB").decode().unwrap();
        assert_eq!(&Qb2(&bin).encode().unwrap(), b"-AAB");
    }
}
```
Run: `nix develop --command cargo nextest run -p cesr-stream reexport_paths_resolve_and_roundtrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cesr-stream/src/qb2.rs crates/cesr-stream/src/error.rs
git commit -m "refactor(cesr-stream)!: qb2 re-exports cesr::b64; route Misaligned to ParseError::Misaligned (#193 P5)"
```

---

### Task 9: Update cesr-stream benches/keripy_diff imports; CHANGELOG; full gate

**Files:**
- Modify: `crates/cesr-stream/benches/matter.rs`, `crates/cesr-stream/src/keripy_diff/{stream,counter,matter}.rs`
- Modify: `crates/cesr/CHANGELOG.md`, `crates/cesr-stream/CHANGELOG.md`

- [ ] **Step 1: Confirm consumer imports still resolve**

The consumers use `cesr_stream::qb2::{Qb64, Qb2}` / `crate::qb2::...`, which still
resolve through the re-export. Verify nothing imported an internal item that moved:
```bash
command rg -n "qb2::" crates/cesr-stream/benches crates/cesr-stream/src/keripy_diff
```
If any referenced `ParseError` from a qb2 call site, note the return type is now
`cesr::b64::Error` at the primitive layer but the re-exported newtypes' methods
still return `cesr::b64::Error`; keripy_diff call sites that `?`-propagate must map
via `ParseError::from` (the refined `From` handles it). Fix any that assumed
`ParseError` directly.

- [ ] **Step 2: Add CHANGELOG entries**

`crates/cesr/CHANGELOG.md` (Unreleased → Added / **BREAKING**):
```markdown
- `b64::{Qb64, Qb2}` whole-blob transcoders and `b64::decode_binary` moved into the
  `cesr` crate; `b64::Error` gains a **BREAKING** `Misaligned` variant. (#193 P5)
```
`crates/cesr-stream/CHANGELOG.md` (Unreleased → Changed):
```markdown
- `qb2::{Qb64, Qb2}` now re-export `cesr::b64`; alignment errors surface as
  `ParseError::Misaligned`. (#193 P5)
```

- [ ] **Step 3: Full gate**

Run: `nix flake check 2>&1 | tee /tmp/p5-gate.log; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 4: Re-baseline fn-ratchet if needed**

Moving free items (`decode_binary`, and the removal of qb2's free helpers from
cesr-stream) changes per-module `pub fn` counts. If the ratchet check fails, lower
the affected `cesr` / `cesr-stream` module budgets in `free-fn-budget.toml` to the
reported counts (lower only).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs(changelog): P5 qb64<->qb2 relocation; re-baseline fn-ratchet (#193 P5)"
```

---

## Self-Review

**Spec coverage:**
- P4 delete `SequenceNumber` → Tasks 3, 4. ✔
- P4 `Ordinal` trait in core → Task 1. ✔
- P4 `numh`/`LowerHex`/`Copy` on `Number` → Task 2. ✔
- P4 `Seqner` left dormant (no `Ordinal` impl) → not touched by any task (intentional). ✔
- P4 body/seal `s` becomes `Number`, render via `numh` → Tasks 3, 4. ✔
- P5 relocate `Qb64`/`Qb2` to `cesr::b64` → Task 7. ✔
- P5 shared block core → Task 7 Step 1/3. ✔
- P5 `decode_binary` added → Task 7. ✔
- P5 `Misaligned` on `b64::Error` + ParseError routing → Tasks 6, 8. ✔
- P5 cesr-stream re-export → Task 8. ✔
- Breaking-change CHANGELOG entries → Tasks 5, 9. ✔
- Testing categories (round-trip, boundary, cross-feature, property) → Tasks 1,2,6,7,8; property tests fold into existing proptest suites during the gate. ✔
- fn-ratchet re-baseline → Tasks 5, 9. ✔

**Placeholder scan:** no TBD/TODO; every code step shows code; every command shows expected result. ✔

**Type consistency:** `Ordinal::num`/`numh` (Task 1) used identically in Tasks 2/4; `Number::new` (Task 2) matches deserialize (Task 4); `Error::Misaligned { len, unit }` (Task 6) matches `ParseError::Misaligned { len, unit }` routing (Task 8) and the transcoder call sites (Task 7). ✔

**Note on property tests:** the crate runs proptest suites under the gate; the boundary values called for in the spec (`0/1/MAX-1/MAX`, empty/max/max+1 byte strings) are covered by the migrated `transcode` tests + existing `number`/`binary` proptests. If the gate surfaces a missing boundary, add it to the nearest existing proptest rather than a new file.
