# #150 — rot/drt config removal + seal codex parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #150 — make non-empty rot/drt config unrepresentable, add `Seal::Back`/`Seal::Kind`/`Seal::Opaque` across both writers and both readers, close the `TRACKED_SEALS` parity gap, and check in keripy-generated seal-event vectors.

**Architecture:** Part A deletes the dead `config` field from rotation types end-to-end and makes both read paths reject a `c` key on rot/drt (KERI v1 wire has no `c` there). Part B adds two typed seal variants (types per keripy `structing.py:243-245` casts: `bi`→Prefixer, `t`→Verser) plus an opaque raw-JSON variant with a validated constructor; the strict scanner falls back to a hand-rolled iterative compact-JSON object scanner when an anchor doesn't match any codex shape, and both writers re-emit the opaque span verbatim.

**Tech Stack:** Rust (edition 2024, pinned 1.95.0), thiserror, proptest, serde_json (`preserve_order` is on), keripy checkout at `/Users/joel/Code/keripy` (pin in `scripts/KERIPY_PIN`) for vector generation. Verification: `nix develop --command cargo nextest run` per task, `nix flake check` as the final gate (after committing — the flake sees only committed state).

**Spec:** `docs/superpowers/specs/2026-07-13-150-seal-codex-rot-config-design.md`

**Conventions that apply to every task:** no inline `use` (imports at top of file, `as` aliases for collisions); checked arithmetic for offsets/lengths; every `#[allow]` carries a `reason`; test modules are exempt from import placement; commit messages use `!` for breaking commits (release-plz derives the 0.x MINOR bump).

---

### Task 1: `UnexpectedField` error + both readers reject `c` on rot/drt

The tolerant oracle currently parses an optional `c` on rot (`reference.rs:125-128`) that the writer can never produce. keripy v1 `rotate()` has no `cnfg`, so any `c` on a v1 rot/drt is malformed — reject it typed.

**Files:**
- Modify: `cesr/src/serder/error.rs` (new variant)
- Modify: `cesr/src/serder/deserialize/reference.rs:125-128`
- Test: `cesr/src/serder/deserialize.rs` (tests module, near `resaid` at line ~1208)

- [ ] **Step 1.1: Add the error variant**

In `cesr/src/serder/error.rs`, after the `MissingField` variant:

```rust
    /// A field present on the wire that the event's v1 grammar forbids
    /// (e.g. `c` on `rot`/`drt` — config traits are inception-only in KERI v1).
    #[error("unexpected field `{0}` for this event type")]
    UnexpectedField(&'static str),
```

- [ ] **Step 1.2: Write the failing bug-probe tests**

In the tests module of `cesr/src/serder/deserialize.rs`, next to the intive probes (after `resaid`). `probe_rot()` and `resaid` already exist there; `reference` fns are reachable as `super::reference::…` — check the existing test imports and reuse their style:

```rust
    /// Bug-probe #150: a SAID-valid rot carrying a `c` field must be
    /// rejected by BOTH read paths — the v1 rot grammar has no `c` slot.
    #[test]
    fn rot_with_config_field_is_rejected_by_both_paths() {
        let raw = serialize_rotation(&probe_rot()).unwrap().as_bytes().to_vec();
        let pos = raw.windows(5).position(|w| w == b",\"a\":").unwrap();
        let mut mutated = Vec::with_capacity(raw.len() + 7);
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b",\"c\":[]");
        mutated.extend_from_slice(&raw[pos..]);
        let canonical = resaid(mutated);

        assert!(matches!(
            deserialize_rotation(&canonical),
            Err(SerderError::NonCanonical { .. })
        ));
        assert!(matches!(
            reference::deserialize_rotation(&canonical),
            Err(SerderError::UnexpectedField("c"))
        ));
    }
```

If `reference` is not already imported in the tests module, add `use super::reference;` inside the `#[cfg(test)]` module.

- [ ] **Step 1.3: Run to verify the oracle half fails**

Run: `nix develop --command cargo nextest run -E 'test(rot_with_config_field_is_rejected_by_both_paths)'`
Expected: FAIL — the oracle currently *accepts* `c` (parses it into config), so the second `matches!` is false. The strict half already passes (fixed grammar).

- [ ] **Step 1.4: Make the oracle reject `c`**

In `cesr/src/serder/deserialize/reference.rs::deserialize_rotation`, replace lines 125-128:

```rust
    let config = match val.get("c") {
        Some(c_val) => parse_config_array(c_val)?,
        None => vec![],
    };
```

with:

```rust
    if val.get("c").is_some() {
        return Err(SerderError::UnexpectedField("c"));
    }
```

and change the `RotationEvent::new(...)` call's `config,` argument to `vec![],` (Task 2 deletes it entirely). If `vec` is now unused in imports, leave it — other fns in the file use it.

- [ ] **Step 1.5: Run to verify green**

Run: `nix develop --command cargo nextest run -E 'test(rot_with_config_field_is_rejected_by_both_paths)'`
Expected: PASS. Then the full serder suite: `nix develop --command cargo nextest run serder` — expected: PASS (no existing test feeds `c` to the rot oracle; if one does, it is asserting the asymmetry this issue kills — rewrite it to assert `UnexpectedField`).

- [ ] **Step 1.6: Commit**

```bash
git add -A && git commit -m "fix(serder)!: reject c field on v1 rot/drt read paths (#150)"
```

---

### Task 2: Remove `config` from rotation builders and events

A v1 rotation cannot carry config traits — delete the state so accept-and-drop is unrepresentable. Purely mechanical after the two setters and the struct field go; let the compiler enumerate call sites.

**Files:**
- Modify: `cesr/src/keri/event/rotation.rs` (field, ctor param, getter, test)
- Modify: `cesr/src/serder/builder/rot.rs` (field at :62, init :83, four state-transition copies :104/:133/:156/:187, setter :238-242, build call :328, test :447)
- Modify: `cesr/src/serder/builder/drt.rs` (same shape: :64, :85, :110/:139/:162/:193, :244-246, :335, :476)
- Modify: `cesr/src/serder/event_strategies.rs:208` (drop `vec![],` in `build_rot`)
- Modify: every `RotationEvent::new` call site (all pass `vec![]` as the 12th arg — the one before `anchors`)
- Test: `cesr/src/serder/serialize/rot.rs`, `cesr/src/serder/serialize/drt.rs` (writer pinning tests)

- [ ] **Step 2.1: Delete the state**

- `rotation.rs`: remove `config: Vec<ConfigTrait>` from the struct (line 26), the `config` parameter and field init in `new` (lines 50, 65), the `config()` getter (lines 136-140), the `use crate::keri::config::ConfigTrait;` import (line 9), the `vec![]` config arg and `assert!(event.config().is_empty())` in the test (lines 206, 224).
- `builder/rot.rs` and `builder/drt.rs`: remove the `config` field, its `Vec::new()` init, the `config: self.config,` line in each typestate transition, the `config()` setter, the `self.config,` argument in `build()`, and the `.config(vec![])` line in the builder test. Drop `ConfigTrait` from imports if now unused.

- [ ] **Step 2.2: Let the compiler find the rest**

Run: `nix develop --command cargo build --all-features 2>&1 | head -50`

Every remaining error is a `RotationEvent::new` call with 13 args — delete the `vec![],` immediately before the anchors argument. Known sites (from `rg -n "RotationEvent::new" cesr/src`): `keri/event/delegation.rs:125`, `serder/serialize.rs:616,672,792`, `serder/serialize/rot.rs:159,246`, `serder/serialize/drt.rs:165`, `serder/traits.rs:198`, `serder/deserialize.rs:216,614,712,770,840,1097`, `serder/deserialize/canonical.rs:1085`, `serder/deserialize/reference.rs:131,661`, `serder/event_strategies.rs:196`. At `deserialize.rs:214` also delete the now-stale comment "`rot`/`drt` carry no `c` field on the wire; the config is always empty." — replace with nothing (the signature now says it).

Repeat the build until clean, `--all-features` and default features both.

- [ ] **Step 2.3: Pin the writer output**

In `cesr/src/serder/serialize/rot.rs` tests (a `make_*`-helper-equipped module already exists):

```rust
    #[test]
    fn rot_wire_has_no_config_field() {
        let event = /* reuse the existing test constructor in this module
                       (the one feeding serialize_rotation) */;
        let out = serialize_rotation(&event).unwrap();
        let json = core::str::from_utf8(out.as_bytes()).unwrap();
        assert!(!json.contains("\"c\":"), "v1 rot must not emit a c field");
    }
```

Mirror it in `serialize/drt.rs` tests with `serialize_delegated_rotation`. Use each module's existing event-construction helper verbatim (they differ slightly per file) — the assertion is the point.

- [ ] **Step 2.4: Full test run**

Run: `nix develop --command cargo nextest run`
Expected: PASS. Any failure is a test that asserted rot-config round-trip behavior — such a test documents the silent drop and must be deleted, not appeased (check `deserialize.rs` tests near lines 568/639/966 — those are icp config tests and should be untouched; only rot/drt ones go).

- [ ] **Step 2.5: Commit**

```bash
git add -A && git commit -m "fix(serder)!: remove unrepresentable config from rotation builders and events (#150)"
```

---

### Task 3: `Seal::Back`, `Seal::Kind`, `Seal::Opaque` + compact-JSON scanner + both writers

Adding variants breaks the two exhaustive writer matches, so the enum, `OpaqueSeal`, the scanner, and both writer arms land together.

**Files:**
- Modify: `cesr/src/keri/seal.rs` (variants, `OpaqueSeal`, `OpaqueSealError`, `scan_object`, tests)
- Modify: `cesr/src/keri/mod.rs:37` (export)
- Modify: `cesr/src/serder/serialize/direct.rs:294-330` (`write_seal` arms)
- Modify: `cesr/src/serder/serialize.rs:458-481` (`seal_to_json` → `Result`) and its five callers: `serialize/icp.rs:62`, `serialize/rot.rs:54`, `serialize/ixn.rs:41`, `serialize/dip.rs:67`, `serialize/drt.rs:59`

- [ ] **Step 3.1: Write failing scanner/constructor tests first**

Append to the tests module in `cesr/src/keri/seal.rs`:

```rust
    #[test]
    fn opaque_accepts_compact_objects() {
        for raw in [
            "{}",
            "{\"x\":1}",
            "{\"a\":\"b\",\"c\":[1,-2.5e+10,true,false,null],\"d\":{\"e\":[]}}",
            "{\"q\":\"say \\\"hi\\\"\\n\",\"u\":\"\\u00e9\"}",
        ] {
            let seal = OpaqueSeal::new(raw.to_owned())
                .unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(seal.as_str(), raw);
        }
    }

    #[test]
    fn opaque_rejects_malformed_payloads() {
        use crate::keri::seal::OpaqueSealError as E;
        let cases: &[(&str, fn(&E) -> bool)] = &[
            ("", |e| matches!(e, E::NotAnObject)),
            ("[1]", |e| matches!(e, E::NotAnObject)),
            ("\"str\"", |e| matches!(e, E::NotAnObject)),
            ("{", |e| matches!(e, E::Truncated)),
            ("{\"a\":1", |e| matches!(e, E::Truncated)),
            ("{\"a\":\"unterminated", |e| matches!(e, E::Truncated)),
            ("{\"a\":1}x", |e| matches!(e, E::TrailingBytes { .. })),
            ("{\"a\":01}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\" :1}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":1,}", |e| matches!(e, E::UnexpectedByte { .. })),
            ("{\"a\":\"\\x\"}", |e| matches!(e, E::InvalidEscape { .. })),
            ("{\"a\":\"\\u12g4\"}", |e| matches!(e, E::InvalidEscape { .. })),
            ("{\"a\":\u{0009}1}", |e| matches!(e, E::UnexpectedByte { .. })),
        ] ;
        for (raw, is_expected) in cases {
            let err = OpaqueSeal::new((*raw).to_owned())
                .expect_err(&alloc::format!("{raw} must be rejected"));
            assert!(is_expected(&err), "{raw}: wrong error {err}");
        }
    }

    #[test]
    fn opaque_deep_nesting_is_iterative_not_recursive() {
        let depth = 20_000;
        let mut raw = String::from("{\"a\":");
        for _ in 0..depth {
            raw.push('[');
        }
        for _ in 0..depth {
            raw.push(']');
        }
        raw.push('}');
        let seal = OpaqueSeal::new(raw.clone()).unwrap();
        assert_eq!(seal.as_str(), raw);
    }

    #[test]
    fn seal_back_and_kind_carry_typed_fields() {
        let Seal::Back { bi, d } = (Seal::Back {
            bi: make_prefixer(),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*bi.code(), VerKeyCode::Ed25519);
        assert_eq!(*d.code(), DigestCode::Blake3_256);

        let Seal::Kind { t, d } = (Seal::Kind {
            t: make_verser(),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*t.code(), VerserCode::Tag7);
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }
```

Add the test helper next to `make_prefixer` (test module — inline paths fine there):

```rust
    fn make_verser() -> Verser<'static> {
        MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<crate::core::matter::code::VerserCode>()
            .unwrap()
            .into_static()
    }
```

(`YKERIBAA` = keripy `Verser(proto='KERI', pvrsn=Vrsn_1_0).qb64` — Tag7 code `Y` + soft `KERIBAA`; the Tag7 parse pattern is pinned in `stream/parse.rs:977`. Import `VerserCode`/`String`/`format` in the test module as needed.)

- [ ] **Step 3.2: Verify they fail to compile**

Run: `nix develop --command cargo build --features keri 2>&1 | head`
Expected: unresolved `OpaqueSeal`, `Seal::Back`, `Seal::Kind`.

- [ ] **Step 3.3: Implement in `cesr/src/keri/seal.rs`**

Replace the imports at the top of the file with:

```rust
use crate::core::primitives::{Prefixer, Saider, Seqner, Verser};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{string::String, vec, vec::Vec};
use thiserror::Error;
```

Append to the `Seal` enum (after `Last`):

```rust
    /// Registrar-backer seal — nontransferable backer prefix plus a digest
    /// of the anchored backer metadata (keripy `SealBack`).
    Back {
        /// Backer identifier prefix.
        bi: Prefixer<'static>,
        /// Digest of the anchored backer metadata.
        d: Saider<'static>,
    },
    /// Typed digest seal — a version/type tag plus a SAID (keripy `SealKind`).
    Kind {
        /// Type of the digest.
        t: Verser<'static>,
        /// The digest value.
        d: Saider<'static>,
    },
    /// A non-codex anchor preserved verbatim.
    Opaque(OpaqueSeal),
```

Then the new types and scanner (top-level items in the same file):

```rust
/// A non-codex anchor: an arbitrary compact-JSON object preserved verbatim.
///
/// keripy validates event anchors (`data`) only as being a list — the dicts
/// inside are arbitrary. This type carries such an anchor through cesr
/// unmodified: the write path re-emits the stored text byte-for-byte, so
/// decode → encode round-trips keripy events exactly.
///
/// The payload must be one well-formed *compact* JSON object (no whitespace
/// between tokens — the form keripy's canonical
/// `json.dumps(..., separators=(",", ":"))` emits), enforced at construction.
pub struct OpaqueSeal(String);

impl OpaqueSeal {
    /// Validate and wrap a compact-JSON object payload.
    ///
    /// # Errors
    ///
    /// Returns [`OpaqueSealError`] when `raw` is not exactly one well-formed
    /// compact JSON object.
    pub fn new(raw: String) -> Result<Self, OpaqueSealError> {
        let len = scan_object(raw.as_bytes())?;
        if len != raw.len() {
            return Err(OpaqueSealError::TrailingBytes { offset: len });
        }
        Ok(Self(raw))
    }

    /// The verbatim JSON object text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Rejections from [`OpaqueSeal::new`]'s compact-JSON object validation.
#[derive(Debug, Error)]
pub enum OpaqueSealError {
    /// The payload does not start with `{`.
    #[error("opaque seal payload must be a JSON object")]
    NotAnObject,
    /// A byte that no compact-JSON production allows at its position
    /// (this includes any whitespace between tokens).
    #[error("unexpected byte at offset {offset} in opaque seal payload")]
    UnexpectedByte {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// Input ended before the object closed.
    #[error("opaque seal payload is truncated")]
    Truncated,
    /// An unescaped control character inside a string.
    #[error("control character at offset {offset} in opaque seal string")]
    ControlCharacter {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// A malformed `\` escape inside a string.
    #[error("invalid escape sequence at offset {offset} in opaque seal string")]
    InvalidEscape {
        /// Byte offset into the payload.
        offset: usize,
    },
    /// Bytes remain after the object closed.
    #[error("trailing bytes after opaque seal object at offset {offset}")]
    TrailingBytes {
        /// Byte offset of the first trailing byte.
        offset: usize,
    },
    /// A position computation overflowed `usize`.
    #[error("offset overflow while scanning opaque seal payload")]
    OffsetOverflow,
}

fn bump(pos: usize) -> Result<usize, OpaqueSealError> {
    pos.checked_add(1).ok_or(OpaqueSealError::OffsetOverflow)
}

enum ScanState {
    /// Just after `{`: a key string or `}`.
    FirstKey,
    /// Just after `,` inside an object: a key string.
    NextKey,
    /// Start of any JSON value.
    Value,
    /// Just after `[`: a value or `]`.
    FirstValue,
    /// Just after a complete value: `,` or the container's closer.
    AfterValue,
}

/// Byte length of one complete compact-JSON object at the start of `input`.
///
/// Iterative — nesting depth costs heap (one container-kind entry per open
/// bracket, bounded by input length), never call stack, so adversarially
/// deep anchors cannot overflow the stack. Used by [`OpaqueSeal::new`] and
/// by the strict event reader's opaque-anchor fallback.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — callable from serder's strict reader but not part of the public API"
)]
pub(crate) fn scan_object(input: &[u8]) -> Result<usize, OpaqueSealError> {
    if input.first() != Some(&b'{') {
        return Err(OpaqueSealError::NotAnObject);
    }
    // `true` = object, `false` = array.
    let mut containers = vec![true];
    let mut pos = 1_usize;
    let mut state = ScanState::FirstKey;
    loop {
        match state {
            ScanState::FirstKey | ScanState::NextKey => {
                match input.get(pos).ok_or(OpaqueSealError::Truncated)? {
                    b'}' if matches!(state, ScanState::FirstKey) => {
                        pos = bump(pos)?;
                        containers.pop();
                        if containers.is_empty() {
                            return Ok(pos);
                        }
                        state = ScanState::AfterValue;
                    }
                    b'"' => {
                        pos = scan_string(input, pos)?;
                        if input.get(pos) != Some(&b':') {
                            return Err(OpaqueSealError::UnexpectedByte { offset: pos });
                        }
                        pos = bump(pos)?;
                        state = ScanState::Value;
                    }
                    _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
                }
            }
            ScanState::Value => {
                match input.get(pos).ok_or(OpaqueSealError::Truncated)? {
                    b'{' => {
                        containers.push(true);
                        pos = bump(pos)?;
                        state = ScanState::FirstKey;
                    }
                    b'[' => {
                        containers.push(false);
                        pos = bump(pos)?;
                        state = ScanState::FirstValue;
                    }
                    b'"' => {
                        pos = scan_string(input, pos)?;
                        state = ScanState::AfterValue;
                    }
                    b'-' | b'0'..=b'9' => {
                        pos = scan_number(input, pos)?;
                        state = ScanState::AfterValue;
                    }
                    b't' => {
                        pos = scan_lit(input, pos, b"true")?;
                        state = ScanState::AfterValue;
                    }
                    b'f' => {
                        pos = scan_lit(input, pos, b"false")?;
                        state = ScanState::AfterValue;
                    }
                    b'n' => {
                        pos = scan_lit(input, pos, b"null")?;
                        state = ScanState::AfterValue;
                    }
                    _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
                }
            }
            ScanState::FirstValue => {
                if input.get(pos).ok_or(OpaqueSealError::Truncated)? == &b']' {
                    pos = bump(pos)?;
                    containers.pop();
                    if containers.is_empty() {
                        return Ok(pos);
                    }
                    state = ScanState::AfterValue;
                } else {
                    state = ScanState::Value;
                }
            }
            ScanState::AfterValue => {
                let byte = *input.get(pos).ok_or(OpaqueSealError::Truncated)?;
                // Invariant: the loop returns the moment `containers` empties,
                // so a container is always open here; `Truncated` is a
                // defensive mapping, not a reachable state.
                let in_object = *containers.last().ok_or(OpaqueSealError::Truncated)?;
                match (byte, in_object) {
                    (b',', true) => {
                        pos = bump(pos)?;
                        state = ScanState::NextKey;
                    }
                    (b',', false) => {
                        pos = bump(pos)?;
                        state = ScanState::Value;
                    }
                    (b'}', true) | (b']', false) => {
                        pos = bump(pos)?;
                        containers.pop();
                        if containers.is_empty() {
                            return Ok(pos);
                        }
                    }
                    _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
                }
            }
        }
    }
}

/// Advance past one JSON string (cursor on the opening `"`); returns the
/// position after the closing `"`. Escapes are validated, not decoded.
fn scan_string(input: &[u8], start: usize) -> Result<usize, OpaqueSealError> {
    let mut pos = bump(start)?;
    loop {
        let byte = *input.get(pos).ok_or(OpaqueSealError::Truncated)?;
        match byte {
            b'"' => return bump(pos),
            b'\\' => {
                let esc_at = bump(pos)?;
                let esc = *input.get(esc_at).ok_or(OpaqueSealError::Truncated)?;
                pos = match esc {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => bump(esc_at)?,
                    b'u' => {
                        let mut hex_pos = bump(esc_at)?;
                        for _ in 0_u8..4 {
                            let hex = *input.get(hex_pos).ok_or(OpaqueSealError::Truncated)?;
                            if !hex.is_ascii_hexdigit() {
                                return Err(OpaqueSealError::InvalidEscape { offset: hex_pos });
                            }
                            hex_pos = bump(hex_pos)?;
                        }
                        hex_pos
                    }
                    _ => return Err(OpaqueSealError::InvalidEscape { offset: esc_at }),
                };
            }
            b if b < 0x20 => return Err(OpaqueSealError::ControlCharacter { offset: pos }),
            _ => pos = bump(pos)?,
        }
    }
}

/// Advance past one JSON number (cursor on `-` or a digit); returns the
/// position after its last byte.
fn scan_number(input: &[u8], start: usize) -> Result<usize, OpaqueSealError> {
    let mut pos = start;
    if input.get(pos) == Some(&b'-') {
        pos = bump(pos)?;
    }
    match input.get(pos) {
        Some(b'0') => pos = bump(pos)?,
        Some(b'1'..=b'9') => {
            pos = bump(pos)?;
            while matches!(input.get(pos), Some(b'0'..=b'9')) {
                pos = bump(pos)?;
            }
        }
        _ => return Err(OpaqueSealError::UnexpectedByte { offset: pos }),
    }
    if input.get(pos) == Some(&b'.') {
        pos = bump(pos)?;
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(OpaqueSealError::UnexpectedByte { offset: pos });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos = bump(pos)?;
        }
    }
    if matches!(input.get(pos), Some(b'e' | b'E')) {
        pos = bump(pos)?;
        if matches!(input.get(pos), Some(b'+' | b'-')) {
            pos = bump(pos)?;
        }
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(OpaqueSealError::UnexpectedByte { offset: pos });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos = bump(pos)?;
        }
    }
    Ok(pos)
}

/// Expect the exact literal at `pos`; returns the position after it.
fn scan_lit(input: &[u8], pos: usize, lit: &'static [u8]) -> Result<usize, OpaqueSealError> {
    let end = pos
        .checked_add(lit.len())
        .ok_or(OpaqueSealError::OffsetOverflow)?;
    if input.get(pos..end) == Some(lit) {
        Ok(end)
    } else {
        Err(OpaqueSealError::UnexpectedByte { offset: pos })
    }
}
```

Export in `cesr/src/keri/mod.rs`: change line 37 to `pub use seal::{OpaqueSeal, OpaqueSealError, Seal};`.

- [ ] **Step 3.4: Extend both writers (compiler now demands it)**

`cesr/src/serder/serialize/direct.rs::write_seal` — add before the closing brace of the match, mirroring the fixed field orders (`bi,d` and `t,d` per keripy's namedtuple order; corpus rows `codex.jsonl:64,67` confirm):

```rust
        Seal::Back { bi, d } => {
            buf.extend_from_slice(b"{\"bi\":");
            write_str(buf, &to_qb64_string(bi));
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        Seal::Kind { t, d } => {
            buf.extend_from_slice(b"{\"t\":");
            write_str(buf, &to_qb64_string(t));
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        // Verbatim: the payload is pre-validated compact JSON; re-escaping
        // through `write_str` would corrupt it.
        Seal::Opaque(raw) => buf.extend_from_slice(raw.as_str().as_bytes()),
```

`cesr/src/serder/serialize.rs::seal_to_json` — change the signature to `pub(crate) fn seal_to_json(seal: &Seal) -> Result<Value, SerderError>`, wrap the final expression as `Ok(Value::Object(map))`, and add the arms:

```rust
        Seal::Back { bi, d } => {
            map.insert("bi".to_owned(), Value::String(to_qb64_string(bi)));
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)));
        }
        Seal::Kind { t, d } => {
            map.insert("t".to_owned(), Value::String(to_qb64_string(t)));
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)));
        }
        // `preserve_order` keeps the parsed key order, so the reparse
        // round-trips the payload's own field order.
        Seal::Opaque(raw) => {
            return serde_json::from_str(raw.as_str()).map_err(SerderError::from);
        }
```

Update the five callers (`icp.rs:62`, `rot.rs:54`, `ixn.rs:41`, `dip.rs:67`, `drt.rs:59`): `anchors_json.push(seal_to_json(seal)?);` — each enclosing fn already returns `Result<_, SerderError>`. Fix any test callers of `seal_to_json` the compiler flags with `.unwrap()`.

- [ ] **Step 3.5: Run seal + serialize tests**

Run: `nix develop --command cargo nextest run -E 'test(opaque) or test(seal)'`
Expected: PASS, including the three new seal.rs tests and Step 2.3's pinning tests.

- [ ] **Step 3.6: Commit**

```bash
git add -A && git commit -m "feat(keri)!: SealBack, SealKind, and opaque anchor seal variants (#150)"
```

---

### Task 4: Strict reader + conversion + tolerant oracle

**Files:**
- Modify: `cesr/src/serder/error.rs` (one more variant)
- Modify: `cesr/src/serder/deserialize/canonical.rs` (`ParsedSeal` + `seal()` fallback)
- Modify: `cesr/src/serder/deserialize.rs` (`seal_from_parsed`, `parse_qb64_verser`)
- Modify: `cesr/src/serder/deserialize/reference.rs::seal_from_json`
- Test: `cesr/src/serder/deserialize.rs` (Matrix A extension + defensive tests)

- [ ] **Step 4.1: Write failing round-trip tests (Matrix A extension)**

In `deserialize.rs` tests after `seal_last_variant_is_pinned` (~line 1615), reusing `ixn_with_anchor` / `ixn_strict_eq_oracle`:

```rust
        #[test]
        fn seal_back_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Back {
                bi: make_prefixer(),
                d: make_saider(),
            });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Back { .. }));
        }

        #[test]
        fn seal_kind_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Kind {
                t: make_verser(),
                d: make_saider(),
            });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Kind { .. }));
        }

        #[test]
        fn seal_opaque_variant_is_pinned() {
            let raw = "{\"purpose\":\"demo\",\"nested\":{\"n\":[1,null,true]}}";
            let bytes = ixn_with_anchor(Seal::Opaque(
                OpaqueSeal::new(raw.to_owned()).unwrap(),
            ));
            let strict = ixn_strict_eq_oracle(&bytes);
            let Seal::Opaque(opaque) = &strict.anchors()[0] else {
                unreachable!("expected Opaque seal")
            };
            assert_eq!(opaque.as_str(), raw);
        }

        /// A codex-SHAPED seal whose primitive fails to parse is an error,
        /// not an opaque fallback — recorded divergence from keripy (which
        /// accepts any dict). See docs/keripy-parity/ledger.md (#150).
        #[test]
        fn codex_shaped_seal_with_bad_primitive_errors() {
            let good = ixn_with_anchor(Seal::Digest { d: make_saider() });
            let pos = good.windows(6).position(|w| w == b"\"d\":\"E").unwrap();
            let mut mutated = good.clone();
            mutated[pos + 5] = b'!';
            let resealed = resaid(mutated);
            assert!(matches!(
                deserialize_interaction(&resealed),
                Err(SerderError::UnparseablePrimitive { .. })
                    | Err(SerderError::InvalidPrimitive { .. })
            ));
        }
```

Add a `make_verser` helper to this test module (same body as Task 3's) and import `OpaqueSeal`. Note `ixn_with_anchor`'s anchor `d` differs from the event's own `"d"` — the `windows` search in the bad-primitive test must target the anchor's digest, not the event SAID: search within the `"a":[` suffix (find `b"\"a\":["` first, then search from there). Adjust exactly that way.

Then defensive scanner tests in the same module:

```rust
        #[test]
        fn truncated_opaque_anchor_is_rejected() {
            let bytes = ixn_with_anchor(Seal::Opaque(
                OpaqueSeal::new("{\"x\":{\"y\":1}}".to_owned()).unwrap(),
            ));
            // Chop inside the anchor object; the size field now lies, but
            // the anchor error must surface before/independently of it.
            let a_pos = bytes.windows(6).position(|w| w == b"\"a\":[{").unwrap();
            let truncated = &bytes[..a_pos + 8];
            assert!(deserialize_interaction(truncated).is_err());
        }
```

- [ ] **Step 4.2: Verify red**

Run: `nix develop --command cargo nextest run -E 'test(seal_back_variant) or test(seal_kind_variant) or test(seal_opaque_variant)'`
Expected: FAIL — strict reader rejects the unknown shapes today.

- [ ] **Step 4.3: Add the `InvalidAnchor` error variant**

In `cesr/src/serder/error.rs` (imports: add `use crate::keri::seal::OpaqueSealError;` at top):

```rust
    /// An anchor (`a` array element) that is neither a codex seal shape nor
    /// a well-formed compact-JSON object.
    #[error("invalid anchor object at offset {offset}: {source}")]
    InvalidAnchor {
        /// Byte offset of the anchor object's start in the raw event.
        offset: usize,
        /// The compact-JSON scan rejection.
        #[source]
        source: OpaqueSealError,
    },
```

- [ ] **Step 4.4: Extend the strict scanner (`canonical.rs`)**

Imports: add `use crate::keri::seal::scan_object;`.

`ParsedSeal` gains (after `Last`):

```rust
    /// Registrar-backer seal.
    Back {
        /// Backer identifier prefix, qb64.
        bi: &'a str,
        /// Metadata digest, qb64.
        d: &'a str,
    },
    /// Typed digest seal.
    Kind {
        /// Digest type tag, qb64 (Verser).
        t: &'a str,
        /// SAID digest, qb64.
        d: &'a str,
    },
    /// Non-codex anchor: the verbatim compact-JSON object span.
    Opaque {
        /// Raw object text.
        raw: &'a str,
    },
```

Rename the current `seal` fn to `seal_codex`, add the two typed branches before its final `Err(...)` line (and update that line's expected message):

```rust
    if sc.take_lit("\"bi\":") {
        let bi = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Back { bi, d });
    }
    if sc.take_lit("\"t\":") {
        let t = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Kind { t, d });
    }
    Err(sc.err("seal object key (\"d\", \"rd\", \"s\", \"i\", \"bi\", or \"t\")"))
```

New dispatching `seal` + opaque fallback (same file, so `Scanner`'s private fields are in scope):

```rust
/// One seal object: the seven codex shapes parse typed; anything else
/// falls back to a verbatim opaque capture of the whole object. A codex
/// parse failure rewinds — the codex attempt and the opaque scan both
/// start from the object's first byte.
fn seal<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    let start = sc.pos;
    // The codex error is deliberately superseded: the opaque scan is the
    // outermost interpretation and produces its own typed error on failure.
    if let Ok(parsed) = seal_codex(sc) {
        return Ok(parsed);
    }
    sc.pos = start;
    seal_opaque(sc)
}

/// Capture a non-codex anchor object verbatim.
fn seal_opaque<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    let start = sc.pos;
    let rest = sc
        .input
        .get(start..)
        .ok_or(SerderError::InvalidEventLayout("anchor span out of bounds"))?;
    let len = scan_object(rest).map_err(|source| SerderError::InvalidAnchor {
        offset: start,
        source,
    })?;
    let end = start
        .checked_add(len)
        .ok_or(SerderError::InvalidEventLayout("anchor span overflow"))?;
    let bytes = sc
        .input
        .get(start..end)
        .ok_or(SerderError::InvalidEventLayout("anchor span out of bounds"))?;
    let raw = str::from_utf8(bytes).map_err(|e| {
        start.checked_add(e.valid_up_to()).map_or(
            SerderError::InvalidEventLayout("UTF-8 error offset overflow"),
            |offset| sc.err_at(offset, "UTF-8 anchor object"),
        )
    })?;
    sc.pos = end;
    Ok(ParsedSeal::Opaque { raw })
}
```

- [ ] **Step 4.5: Conversion layer (`deserialize.rs`)**

Imports: add `VerserCode` to the `crate::core::matter::code` import, `Verser` to the primitives import, and `OpaqueSeal` to the keri import.

Next to `parse_qb64_saider`:

```rust
fn parse_qb64_verser(s: &str, field: &'static str) -> Result<Verser<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let narrowed = matter
        .narrow::<VerserCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(narrowed.into_static())
}
```

`seal_from_parsed` gains:

```rust
        ParsedSeal::Back { bi, d } => Ok(Seal::Back {
            bi: parse_qb64_prefixer(bi, "bi")?,
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Kind { t, d } => Ok(Seal::Kind {
            t: parse_qb64_verser(t, "t")?,
            d: parse_qb64_saider(d, "d")?,
        }),
        // Defensively re-validated: the scanner already proved the span is
        // one well-formed compact object, so this construction cannot fail
        // on scanner-produced input.
        ParsedSeal::Opaque { raw } => Ok(Seal::Opaque(
            OpaqueSeal::new((*raw).to_owned())
                .map_err(|source| SerderError::InvalidAnchor { offset: 0, source })?,
        )),
```

- [ ] **Step 4.6: Tolerant oracle (`reference.rs::seal_from_json`)**

Imports: the file pulls helpers from `super::` — add `parse_qb64_verser` there and `OpaqueSeal` from the keri module. Insert before the final `else`:

```rust
    } else if has("bi") && has("d") && n == 2 {
        let bi = parse_qb64_prefixer(
            obj["bi"].as_str().ok_or(SerderError::MissingField("bi"))?,
            "bi",
        )?;
        let digest = parse_qb64_saider(
            obj["d"].as_str().ok_or(SerderError::MissingField("d"))?,
            "d",
        )?;
        Ok(Seal::Back { bi, d: digest })
    } else if has("t") && has("d") && n == 2 {
        let t = parse_qb64_verser(
            obj["t"].as_str().ok_or(SerderError::MissingField("t"))?,
            "t",
        )?;
        let digest = parse_qb64_saider(
            obj["d"].as_str().ok_or(SerderError::MissingField("d"))?,
            "d",
        )?;
        Ok(Seal::Kind { t, d: digest })
```

and replace the final `else { Err(SerderError::MissingField("a")) }` with:

```rust
    } else {
        // Non-codex anchor: keep it verbatim. `preserve_order` keeps the
        // wire key order through the serde_json round-trip.
        let raw = serde_json::to_string(val).map_err(SerderError::from)?;
        let opaque = OpaqueSeal::new(raw)
            .map_err(|source| SerderError::InvalidAnchor { offset: 0, source })?;
        Ok(Seal::Opaque(opaque))
    }
```

(Keep the leading `as_object` check — a non-object anchor list item stays rejected; that residual strictness goes in the ledger entry.)

- [ ] **Step 4.7: Green + full suite**

Run: `nix develop --command cargo nextest run`
Expected: PASS. The strict-vs-oracle differential tests now exercise the new arms too. If a differential test compares opaque seals across paths and fails on escaping, the payload used non-minimal escaping — that is the documented SerdeJson-backend caveat; use a minimally-escaped payload in the fixture and note it in the ledger entry (Task 6). **[Superseded: the shipped SerdeJson backend is verbatim via `RawValue`; only the test-only tolerant *oracle* normalizes — see the ledger.]**

- [ ] **Step 4.8: Commit**

```bash
git add -A && git commit -m "feat(serder)!: read SealBack/SealKind and opaque anchors on strict and oracle paths (#150)"
```

---

### Task 5: Proptest strategy coverage

**Files:**
- Modify: `cesr/src/serder/event_strategies.rs`

- [ ] **Step 5.1: Extend the shared seal strategy**

Imports: add `Verser` to the primitives import, `VerserCode` to a new `use crate::core::matter::code::VerserCode;` (extend the existing code import), and `OpaqueSeal` to the keri import. Add helpers after `saider`:

```rust
const VERSER_POOL: &[&str] = &["YKERIBAA", "YKERICAA", "YACDCBAA"];

/// Compact-JSON opaque anchor payloads: empty, flat, codex-key-prefixed
/// (exercises the strict reader's rewind), nested/escaped.
const OPAQUE_POOL: &[&str] = &[
    "{}",
    "{\"x\":1}",
    "{\"d\":\"EJPymiKPV7UD9EmynqY9j8c-mBRcH0vQ-7jD3nqa-z9-\",\"extra\":true}",
    "{\"i\":\"not-qb64\",\"note\":\"arbitrary\"}",
    "{\"nested\":{\"deep\":[1,-2.5e+10,{\"q\":\"say \\\"hi\\\"\"}]},\"n\":null}",
];

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn verser(pick: u8) -> Verser<'static> {
    let qb64 = VERSER_POOL[usize::from(pick) % VERSER_POOL.len()];
    MatterBuilder::new()
        .from_qualified_base64(qb64.as_bytes())
        .unwrap()
        .narrow::<VerserCode>()
        .unwrap()
        .into_static()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn opaque(pick: u8) -> OpaqueSeal {
    let raw = OPAQUE_POOL[usize::from(pick) % OPAQUE_POOL.len()];
    OpaqueSeal::new(raw.to_owned()).unwrap()
}
```

Extend `build_seal` (insert before the `_ => Seal::Last` arm) and widen `seal_strategy` from `0_u8..5` to `0_u8..8`:

```rust
        5 => Seal::Back {
            bi: prefixer(b),
            d: saider(a),
        },
        6 => Seal::Kind {
            t: verser(a[0]),
            d: saider(a),
        },
        7 => Seal::Opaque(opaque(a[0])),
```

Also update the `SealSpec` doc comment (`/// (variant selector, raw a, raw b, sn) -> Seal` — note selector range 0..8).

- [ ] **Step 5.2: Run the property suites**

Run: `nix develop --command cargo nextest run -E 'test(proptest) or test(differential) or test(roundtrip)'` then the full `cargo nextest run`.
Expected: PASS — the existing write-backend and strict-vs-oracle differential properties now fuzz the three new variants.

- [ ] **Step 5.3: Commit**

```bash
git add -A && git commit -m "test(serder): fuzz SealBack/SealKind/opaque through shared event strategies (#150)"
```

---

### Task 6: keripy corpus — fix `t` sample, add `seal_events` family, close `TRACKED_SEALS`

The checked-in `SealKind` sample (`codex.jsonl:67`) carries `t":"icp"` — a generator-invented value that keripy's own `Castage(Verser)` cast rejects; it was never exercised because `TRACKED_SEALS` skipped the row. Fix the generator, regenerate, and add real keripy event vectors.

**Files:**
- Modify: `scripts/keripy_parity_gen.py`
- Regenerate: `cesr/tests/corpus/keripy/parity/codex.jsonl`; create `cesr/tests/corpus/keripy/parity/seal_events.jsonl`
- Modify: `cesr/src/keripy_parity/codex.rs`, `cesr/src/keripy_parity/mod.rs`
- Create: `cesr/src/keripy_parity/seal_events.rs`

- [ ] **Step 6.1: keripy env**

```bash
uv venv /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/*/scratchpad/keripy-venv --python 3.14
uv pip install --python /private/tmp/.../keripy-venv/bin/python "git+file:///Users/joel/Code/keripy@$(cat scripts/KERIPY_PIN)"
SODIUM=$(nix build --no-link --print-out-paths nixpkgs#libsodium)
# every python invocation below: DYLD_LIBRARY_PATH="$SODIUM/lib" <venv>/bin/python ...
```

(If `scripts/KERIPY_PIN` holds a different name/format, read it first; the local checkout at `/Users/joel/Code/keripy` is already at the pin.)

- [ ] **Step 6.2: Generator changes**

In `scripts/keripy_parity_gen.py`:

1. Fix the invented sample — replace `"t": "icp"` in `seal_field_samples` with a keripy-derived Verser (add the imports the script needs, following its existing import style):

```python
from keri.core.coring import Verser
from keri.kering import Protocols, Vrsn_1_0, Kinds
```
```python
sample_verser = Verser(proto=Protocols.keri, pvrsn=Vrsn_1_0).qb64
seal_field_samples = {
    "d": sample_dig, "rd": sample_dig, "i": sample_pre,
    "bi": sample_pre, "s": "0", "t": sample_verser,
}
```

2. Add a `seal_events` family (a new function alongside the existing families, wired into `main` the same way they are, updating the script docstring):

```python
def gen_seal_events(out):
    """v1 JSON ixn events anchoring the #150 seal shapes (feeds #145)."""
    from keri.core.eventing import interact
    pre = Matter(raw=bytes(32), code=PreDex.Ed25519N).qb64
    dig = Diger(ser=b"keripy-parity-seal-events", code=DigDex.Blake3_256).qb64
    verser = Verser(proto=Protocols.keri, pvrsn=Vrsn_1_0).qb64
    cases = [
        ("seal_back", [{"bi": pre, "d": dig}]),
        ("seal_kind", [{"t": verser, "d": dig}]),
        ("arbitrary_anchor", [{"purpose": "demo", "count": 3, "nested": {"ok": True}}]),
        ("mixed", [{"d": dig}, {"bi": pre, "d": dig}, {"anything": ["a", 1, None]}]),
    ]
    written = 0
    with (out / "seal_events.jsonl").open("w") as fh:
        for name, data in cases:
            serder = interact(pre=pre, dig=dig, sn=1, data=data,
                              pvrsn=Vrsn_1_0, kind=Kinds.json)
            emit(fh, {"kind": "seal_event", "case": name,
                      "raw": serder.raw.decode()})
            written += 1
    return written
```

Adapt names to the script's actual structure (read it first — `emit`, `Matter`, `Diger`, `PreDex`, `DigDex` already exist there; check how existing `gen_*` functions receive `out`/`rng` and whether `interact`'s kwarg is `pvrsn` at the pinned commit — `eventing.py:905-913` says it is).

- [ ] **Step 6.3: Regenerate and inspect**

Run the script exactly as its header documents (same `--seed` as the checked-in corpus; check `git log`/script `--help` for the invocation), with `DYLD_LIBRARY_PATH` set. Then:

Run: `git diff --stat cesr/tests/corpus/`
Expected: `codex.jsonl` changes ONLY in the `SealKind` row (`t` now a `Y…` qb64) and `seal_events.jsonl` is new with 4 rows. Any other diff means nondeterminism — stop and investigate before committing.

- [ ] **Step 6.4: Close the tracked gap in `codex.rs`**

- `TRACKED_SEALS` becomes `&[]`; update its doc comment to say the #150 burn-down completed and the table stays for the next tracked shape.
- Delete the `tracked_seal_shapes_parse_150` probe fn entirely (its doc says to do exactly this).
- `seal_variant_matches` gains `("SealBack", Seal::Back { .. }) | ("SealKind", Seal::Kind { .. })` arms.
- Update the sweep's `eprintln!` tracked-count message to drop the `(#150)` tag.

- [ ] **Step 6.5: New sweep `cesr/src/keripy_parity/seal_events.rs`**

```rust
//! #150 seal-event vectors: keripy-generated v1 ixn events anchoring
//! `SealBack`, `SealKind`, and arbitrary dicts must deserialize on the
//! strict path and round-trip byte-identically.

#[cfg(test)]
mod tests {
    use crate::keri::Seal;
    use crate::serder::{deserialize_interaction, serialize_interaction};

    use super::super::load_seal_events;

    #[test]
    fn seal_event_vectors_roundtrip_byte_identically() {
        let vectors = load_seal_events();
        assert!(!vectors.is_empty());
        for v in &vectors {
            let event = deserialize_interaction(v.raw.as_bytes())
                .unwrap_or_else(|e| panic!("{}: {e}", v.case));
            let re = serialize_interaction(&event)
                .unwrap_or_else(|e| panic!("{}: {e}", v.case));
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
        let v = find("seal_back");
        let event = deserialize_interaction(v.raw.as_bytes()).unwrap();
        assert!(matches!(event.anchors(), [Seal::Back { .. }]));
    }

    #[test]
    fn seal_kind_vector_parses_to_kind_variant() {
        let v = find("seal_kind");
        let event = deserialize_interaction(v.raw.as_bytes()).unwrap();
        assert!(matches!(event.anchors(), [Seal::Kind { .. }]));
    }

    #[test]
    fn arbitrary_anchor_vector_parses_to_opaque_variant() {
        let v = find("arbitrary_anchor");
        let event = deserialize_interaction(v.raw.as_bytes()).unwrap();
        assert!(matches!(event.anchors(), [Seal::Opaque(_)]));
    }

    fn find(case: &str) -> super::super::SealEventVector {
        load_seal_events()
            .into_iter()
            .find(|v| v.case == case)
            .unwrap_or_else(|| panic!("{case} vector missing from corpus"))
    }
}
```

In `mod.rs`: add `mod seal_events;`, the vector struct + loader:

```rust
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
```

and extend both scaffold tests (`corpus_families_load_and_are_nonempty`, `kinds_are_homogeneous`) with the new family (`kind == "seal_event"`). Check whether `deserialize_interaction`/`serialize_interaction` re-export from `crate::serder` — if they live at `crate::serder::deserialize::…`, import from there (mirror how `codex.rs` imports).

- [ ] **Step 6.6: Run the parity suite**

Run: `nix develop --command cargo nextest run keripy_parity`
Expected: PASS — codex sweep now asserts SealBack/SealKind rows (tracked-skip count 0), all four seal-event vectors round-trip.

- [ ] **Step 6.7: Commit**

```bash
git add -A && git commit -m "test(parity): #150 seal-event corpus, SealKind Verser sample, TRACKED_SEALS burn-down"
```

---

### Task 7: Parity ledger + spec cross-link

**Files:**
- Modify: `docs/keripy-parity/ledger.md` (the "Arbitrary anchor dicts" section, ~line 89)

- [ ] **Step 7.1: Replace the pending ledger entry**

```markdown
## Arbitrary anchor dicts (#150 — decided)

keripy accepts fully arbitrary dicts as anchors (`data` is validated only
as being a list). cesr reads the seven codex shapes typed
(`SealBack`/`SealKind` landed with #150) and captures any other JSON
*object* verbatim as `Seal::Opaque` — the strict reader stores the raw
span and the write path re-emits it byte-for-byte, so keripy events with
arbitrary anchors round-trip byte-identically.

Residual divergences, deliberate:

- A codex-*shaped* seal whose primitive fails to parse (e.g. invalid qb64
  in `d`) is a typed error, not an opaque fallback. keripy would accept
  the dict; cesr refuses to mis-type it.
- Anchor list items that are not JSON objects (strings, numbers) are
  rejected; keripy allows any list item.
- Opaque payloads must be compact JSON (keripy's canonical form). The
  `SerdeJson` write backend reparses opaque payloads, so byte identity
  through that backend additionally assumes keripy-minimal string
  escaping; the direct backend is verbatim and unconditional.
  **[Superseded during implementation:** review found the reparse
  violated the backend byte-identity contract; the shipped SerdeJson
  backend injects opaque payloads verbatim via `serde_json::value::RawValue`,
  making BOTH backends unconditional. `docs/keripy-parity/ledger.md` is
  the source of truth.**]**
- `c` on v1 `rot`/`drt` is rejected on both read paths
  (`SerderError::UnexpectedField`); config traits are inception-only in
  KERI v1 and the rotation types no longer carry the field.

Pinned by: `keripy_parity::seal_events` (corpus vectors),
`deserialize.rs` Matrix A (all eight `ParsedSeal` arms),
`rot_with_config_field_is_rejected_by_both_paths`.
```

- [ ] **Step 7.2: Commit**

```bash
git add -A && git commit -m "docs(keripy-parity): record #150 anchor policy and rot config outcome"
```

---

### Task 8: Gate, changelog callout, PR

- [ ] **Step 8.1: Full gate on committed state**

Run: `nix flake check`
Expected: all checks green (clippy god-level, fmt, taplo, audit, deny, nextest across feature combos, doctests, wasm, no_std). Fix fallout with follow-up commits — likely spots: clippy `nursery` on the scan-state machine, unused-import fallout from the config removal, `#[must_use]` suggestions on `OpaqueSeal::new`.

- [ ] **Step 8.2: PR**

Push and open a PR against `main` titled `fix(serder)!: #150 rot/drt config silent drop + seal codex parity`. Body must call out the breaking changes explicitly: `RotationEvent::new`/builders lost `config`; `Seal` gained three variants (breaks exhaustive matches); `SerderError` gained `UnexpectedField` and `InvalidAnchor`; `seal_to_json` is crate-internal. Reference the spec and this plan; note release-plz derives the 0.x MINOR bump from the `!` commits. Attach to org Project #5 (use `gh` as `joeldsouzax`; `gh auth switch --user joeldsouzax` if needed).

---

## Self-review notes

- **Spec coverage:** Part A (Task 1-2), Part B variants/writers (Task 3), readers (Task 4), fallback-policy nuance (Task 4 test + Task 7 ledger), proptests (Task 5), keripy `bi` vector + corpus (Task 6), ledger (Task 7), gate/changelog (Task 8). All four issue-acceptance boxes map: config drop → Task 1-2; Back/Kind round-trips → Task 3-4; `bi` vector deserializes → Task 6; policy recorded → Task 7.
- **Type consistency:** `OpaqueSeal::new(String) -> Result<Self, OpaqueSealError>` / `as_str(&self) -> &str`; `scan_object(&[u8]) -> Result<usize, OpaqueSealError>` (pub(crate)); `seal_to_json(&Seal) -> Result<Value, SerderError>`; `parse_qb64_verser(&str, &'static str) -> Result<Verser<'static>, SerderError>`; `ParsedSeal::{Back{bi,d}, Kind{t,d}, Opaque{raw}}` — used identically across Tasks 3-6.
- **Known judgment calls an executor may hit:** exact helper names inside existing test modules differ per file (`make_*` constructors) — reuse what's there; the keripy generator's `main`/arg wiring must be read before extending; clippy may demand small mechanical reshuffles of the scanner match arms.
