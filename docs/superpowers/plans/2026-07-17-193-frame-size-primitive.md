# frame_size Primitive Implementation Plan (#193 P1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `cesr` a decode-free `frame_size` sizing surface on its code enums so the `cesr-stream` framer calls it instead of re-deriving qb64 size math, deleting three duplicated helpers and closing the latent arithmetic-overflow gap — reusing core's existing hardened helpers, not inventing parallel ones.

**Architecture:** "Grain A — the code owns sizing." `MatterCode`/`IndexedSigCode` gain `frame_size(stream) -> Result<usize>`; `CounterCodeV1`/`V2` gain `from_base64_stream(stream) -> Result<Self>` (counters have no variable body, so `full_size()` already gives their span). Matter's sizing methods live in `builder.rs` next to and **reusing** the existing checked `compute_full_size`. The indexer's currently-**bare** `from_qb64` arithmetic gets hardened with the same idiom. Builder signatures unchanged (Piece 2 deferred).

**Tech Stack:** Rust 2024, no_std/alloc, `cargo nextest`, the `nix flake check` gate. Spec: `docs/superpowers/specs/2026-07-17-193-frame-size-primitive-design.md`.

---

## Guiding principles (Joel's directive)

**Reuse core, don't invent. Harden what isn't hard enough. Type-safe / compile-time-safe.**

- **REUSE the existing checked `compute_full_size`** (private in `matter/builder.rs:505`) — do
  NOT add parallel `Sizage::compute_full_size` / `Xizage::compute_full_size` methods. Matter's
  new sizing methods live in `builder.rs` (same file) so they call the existing helper directly.
- **REUSE `get_hard_size_from_byte` (hard.rs) and existing accessors** (`get_sizage`,
  `get_xizage`, `from_hard`, `hard_size`/`soft_size`/`full_size`, `from_base64_stream`).
- **HARDEN the under-hardened existing code:** `IndexerBuilder::from_qb64` computes `idx*4+cs`
  with **bare** arithmetic. Fix it with the same checked idiom Matter already has (a private
  `compute_full_size` in `indexer/builder.rs`, mirroring matter's) + `IndexerParseError::SizeOverflow`.
  **Breaking change to a public error enum — note in PR + CHANGELOG.**
- **`frame_size` does pure sizing, not canonicality validation.** Equivalence is guaranteed by
  the existing builder + keripy-differential + spine byte-identity suites staying green.
- Methods/associated fns only (no free fns in `core` — fn-ratchet budget is 0).

## File map

- `crates/cesr/src/core/matter/builder.rs` — add `MatterCode::frame_size` + `frame_size_of` (reuse existing `compute_full_size`); refactor `from_qualified_base64` to call `frame_size_of`.
- `crates/cesr/src/core/indexer/error.rs` — add `IndexerParseError::SizeOverflow`.
- `crates/cesr/src/core/indexer/builder.rs` — add private checked `compute_full_size` (the hardening) + `IndexedSigCode::frame_size`/`frame_size_of`; refactor `from_qb64` to use them.
- `crates/cesr/src/core/counter/code.rs` — add `CounterCodeV1::stream_hard_size` + `from_base64_stream`.
- `crates/cesr/src/core/counter/v2.rs` — add `CounterCodeV2::from_base64_stream`.
- `crates/cesr-stream/src/parse.rs` — migrate consumers; delete `extract_hard`, `matter_full_size`, `indexer_full_size`.

---

## Task 1: `MatterCode::frame_size` reusing existing `compute_full_size`; refactor `from_qualified_base64`

**Files:**
- Modify: `crates/cesr/src/core/matter/builder.rs`
- Test: same file `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test** (builder.rs tests):
```rust
#[test]
fn matter_frame_size_fixed_and_truncated() {
    // 'B' = Ed25519 non-transferable verkey, fixed fs = 44
    let full = "B".to_string() + &"A".repeat(43);
    assert_eq!(MatterCode::frame_size(full.as_bytes()).unwrap(), 44);
    assert!(MatterCode::frame_size(b"").is_err());       // empty -> error, no panic
    assert!(MatterCode::frame_size(b"\x00\x00").is_err()); // unknown code -> error
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs matter_frame_size`
Expected: FAIL — `no function frame_size`.

- [ ] **Step 3: Add `frame_size` + `frame_size_of` as an `impl MatterCode` block in builder.rs** (legal — inherent impl may live in any module of the defining crate; placed here to reuse the private `compute_full_size` directly):
```rust
impl MatterCode {
    /// Full qb64 character size of the Matter primitive at the head of `stream`,
    /// without decoding the raw body or validating pad/lead bits.
    ///
    /// # Errors
    /// `MatterBuildError` on unknown code, short soft field, non-UTF-8 soft, or size overflow.
    pub fn frame_size(stream: &[u8]) -> Result<usize, MatterBuildError> {
        let code = MatterCode::from_base64_stream(stream)?;
        code.frame_size_of(stream)
    }

    /// `frame_size` for an already-known code — shared with `from_qualified_base64`
    /// so there is exactly one size implementation.
    pub(crate) fn frame_size_of(&self, stream: &[u8]) -> Result<usize, MatterBuildError> {
        let sizage = self.get_sizage();
        if let SizeType::Fixed(fixed) = sizage.fs() {
            return Ok(usize::from(*fixed));
        }
        let hs = sizage.hs();
        let ss = sizage.ss();
        let cs = hs + ss;
        if stream.len() < cs {
            return Err(MatterBuildError::from(ParsingError::StreamTooShort(MatterPart::Soft)));
        }
        let xs = sizage.xs();
        let soft_tail = str::from_utf8(&stream[hs + xs..cs])
            .map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?;
        let size: usize = decode_int(soft_tail)
            .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
        compute_full_size(size, cs).map_err(MatterBuildError::from) // REUSE the existing checked fn
    }
}
```
Ensure imports at top of builder.rs cover the names used (they already exist for `from_qualified_base64`).

- [ ] **Step 4: Refactor `from_qualified_base64` to reuse `frame_size_of`.** Replace its inline fs block (builder.rs ~127–133):
```rust
let fs = if let SizeType::Fixed(fixed) = code.get_sizage().fs() {
    usize::from(*fixed)
} else {
    let size: usize = decode_int(soft_str)
        .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
    compute_full_size(size, cs)?
};
```
with:
```rust
let fs = code.frame_size_of(&stream)?;
```
(The xtra-prepad validation directly above stays — `frame_size_of` recomputes hs/ss/soft internally; if you prefer to keep the already-decoded `soft_str`, leave the old block and skip this refactor for a smaller diff. Either way behavior is identical; the refactor is the DRY win.)

- [ ] **Step 5: Run the full matter suite**

Run: `nix develop --command cargo nextest run -p cesr-rs matter`
Expected: PASS — existing builder + overflow tests green, byte behavior unchanged.

- [ ] **Step 6: Commit**
```bash
git add crates/cesr/src/core/matter/builder.rs
git commit -m "feat(matter): add decode-free MatterCode::frame_size reusing compute_full_size"
```

---

## Task 2: Harden the indexer + `IndexedSigCode::frame_size`

**Files:**
- Modify: `crates/cesr/src/core/indexer/error.rs`, `crates/cesr/src/core/indexer/builder.rs`

- [ ] **Step 1: Add the error variant** in `indexer/error.rs` `IndexerParseError`:
```rust
/// The computed full size overflowed `usize` (soft-field index too large).
#[error("indexer full size overflow")]
SizeOverflow,
```

- [ ] **Step 2: Write the failing frame_size test** (indexer/builder.rs tests):
```rust
#[test]
fn indexer_frame_size_fixed_and_truncated() {
    // 'A' = Ed25519 indexed sig; confirm exact fixed fs from get_xizage() before asserting.
    let full = "AA".to_string() + &"A".repeat(86);
    assert_eq!(IndexedSigCode::frame_size(full.as_bytes()).unwrap(), 88);
    assert!(IndexedSigCode::frame_size(b"").is_err());
    assert!(IndexedSigCode::frame_size(b"9").is_err()); // '9' -> hardage None
}
```

- [ ] **Step 3: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs indexer_frame_size`
Expected: FAIL.

- [ ] **Step 4: Add the private checked `compute_full_size` (the hardening) + `frame_size`/`frame_size_of`** in `indexer/builder.rs`, mirroring matter's checked idiom:
```rust
/// Checked full char size `fs = index * 4 + cs`. `index` is attacker-controlled,
/// so the arithmetic is checked (mirrors matter's `compute_full_size`).
#[inline]
fn compute_full_size(index: usize, cs: usize) -> Result<usize, IndexerParseError> {
    index
        .checked_mul(4)
        .and_then(|quad| quad.checked_add(cs))
        .ok_or(IndexerParseError::SizeOverflow)
}

impl IndexedSigCode {
    /// Full qb64 character size of the indexed primitive at the head of `stream`,
    /// without decoding raw bytes.
    ///
    /// # Errors
    /// `IndexerParseError` on unknown code, short stream, bad UTF-8, or size overflow.
    pub fn frame_size(stream: &[u8]) -> Result<usize, IndexerParseError> {
        let &first = stream.first().ok_or(IndexerParseError::EmptyStream)?;
        let hard_size = hardage(char::from(first))
            .ok_or_else(|| IndexerParseError::UnknownCode(format!("{}", char::from(first))))?;
        if stream.len() < hard_size {
            return Err(IndexerParseError::StreamTooShort { need: hard_size, got: stream.len() });
        }
        let hard = core::str::from_utf8(&stream[..hard_size])
            .map_err(|_| IndexerParseError::InvalidBase64)?;
        IndexedSigCode::from_hard(hard)
            .map_err(IndexerParseError::from)?
            .frame_size_of(stream)
    }

    pub(crate) fn frame_size_of(&self, stream: &[u8]) -> Result<usize, IndexerParseError> {
        let xizage = self.get_xizage();
        let hs = usize::from(xizage.hs);
        let ss = usize::from(xizage.ss);
        let os = usize::from(xizage.os);
        let cs = hs + ss;
        let ms = ss - os;
        match xizage.fs {
            XizageSize::Fixed(n) => Ok(usize::from(n)),
            XizageSize::Variable => {
                if stream.len() < cs {
                    return Err(IndexerParseError::StreamTooShort { need: cs, got: stream.len() });
                }
                let index_str = core::str::from_utf8(&stream[hs..hs + ms])
                    .map_err(|_| IndexerParseError::InvalidBase64)?;
                let index: usize = decode_int(index_str).map_err(IndexerParseError::from)?;
                compute_full_size(index, cs)
            }
        }
    }
}
```

- [ ] **Step 5: Harden `from_qb64`** — replace its bare `XizageSize::Variable => { ... idx * 4 + cs }` block with:
```rust
XizageSize::Variable => compute_full_size(index as usize, cs)?,
```
(keep the existing `#[allow(clippy::as_conversions ...)]` on the cast as needed; the ondex logic above is untouched).

- [ ] **Step 6: Run the indexer suite**

Run: `nix develop --command cargo nextest run -p cesr-rs indexer`
Expected: PASS.

- [ ] **Step 7: Commit**
```bash
git add crates/cesr/src/core/indexer
git commit -m "feat(indexer)!: add IndexedSigCode::frame_size; harden from_qb64 size math

BREAKING: adds IndexerParseError::SizeOverflow. Replaces bare idx*4+cs with checked arithmetic."
```

---

## Task 3: Counter — `from_base64_stream` on V1 and V2 (reuse hard-size pattern)

**Files:**
- Modify: `crates/cesr/src/core/counter/code.rs`, `crates/cesr/src/core/counter/v2.rs`

- [ ] **Step 1: Write the failing test** (counter/code.rs tests):
```rust
#[test]
fn counter_from_base64_stream() {
    assert_eq!(CounterCodeV1::from_base64_stream(b"-AAB").unwrap(), CounterCodeV1::ControllerIdxSigs);   // hs=2
    assert_eq!(CounterCodeV1::from_base64_stream(b"--LAAA").unwrap(), CounterCodeV1::BigPathedMaterialCouples); // hs=3
    assert_eq!(CounterCodeV1::from_base64_stream(b"-_AAABAA").unwrap(), CounterCodeV1::KERIACDCGenusVersion);  // hs=5
    assert!(CounterCodeV1::from_base64_stream(b"").is_err());
    assert!(CounterCodeV1::from_base64_stream(b"-").is_err());
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs counter_from_base64_stream`
Expected: FAIL.

- [ ] **Step 3: Implement** in `impl CounterCodeV1` (code.rs) — the shared const dispatch + reader:
```rust
/// Hard-code length from the two lead bytes of a counter stream: `--` → 3 (big),
/// `-_` → 5 (genus/version), `-x` → 2. Shared V1/V2 grammar; compile-time `const`.
pub(crate) const fn stream_hard_size(stream: &[u8]) -> Result<usize, CounterCodeError> {
    match stream {
        [b'-', b'-', ..] => Ok(3),
        [b'-', b'_', ..] => Ok(5),
        [b'-', _, ..] => Ok(2),
        _ => Err(CounterCodeError::NotACounter),
    }
}

/// Read a V1 counter code from a qb64 stream head (code only, no count).
///
/// # Errors
/// `CounterCodeError` if the lead bytes are not a counter or the code is unknown.
pub fn from_base64_stream(stream: &[u8]) -> Result<Self, CounterCodeError> {
    let hs = Self::stream_hard_size(stream)?;
    let hard = stream
        .get(..hs)
        .and_then(|b| core::str::from_utf8(b).ok())
        .ok_or(CounterCodeError::NotACounter)?;
    Self::from_hard(hard)
}
```
Add a `#[error("not a counter code")] NotACounter` variant to `CounterCodeError` if none fits (single-domain parse error; note in commit). If a suitable variant already exists, reuse it instead of adding one.

- [ ] **Step 4: Implement V2** (v2.rs), delegating the shared dispatch:
```rust
/// Read a V2 counter code from a qb64 stream head (code only, no count).
///
/// # Errors
/// `CounterCodeError` if the lead bytes are not a counter or the code is unknown.
pub fn from_base64_stream(stream: &[u8]) -> Result<Self, CounterCodeError> {
    let hs = CounterCodeV1::stream_hard_size(stream)?;
    let hard = stream
        .get(..hs)
        .and_then(|b| core::str::from_utf8(b).ok())
        .ok_or(CounterCodeError::NotACounter)?;
    Self::from_hard(hard)
}
```
Add a V2 test: `CounterCodeV2::from_base64_stream(b"-AAB")` → `CounterCodeV2::GenericGroup`.

- [ ] **Step 5: Run the counter suite**

Run: `nix develop --command cargo nextest run -p cesr-rs counter`
Expected: PASS.

- [ ] **Step 6: Commit**
```bash
git add crates/cesr/src/core/counter
git commit -m "feat(counter): add CounterCodeV1/V2::from_base64_stream (closes Matter/Counter asymmetry)"
```

---

## Task 4: Migrate `cesr-stream/parse.rs`; delete the three helpers

**Files:**
- Modify: `crates/cesr-stream/src/parse.rs`

- [ ] **Step 1: Rewrite the consumers** to call the cesr primitives (map cesr errors → `ParseError` as `read_matter` already does).

`skip_matter`:
```rust
pub(crate) fn skip_matter(&mut self) -> Result<(), ParseError> {
    let fs = MatterCode::frame_size(self.remaining()).map_err(|err| match err {
        MatterBuildError::Parsing(pe) => ParseError::from(pe),
        MatterBuildError::Validation(ve) => ParseError::from(ve),
    })?;
    self.take(fs)?;
    Ok(())
}
```
`read_matter`: replace `let fs = matter_full_size(self.remaining())?;` with the same mapped `MatterCode::frame_size(...)` call.

`skip_indexer`:
```rust
pub(crate) fn skip_indexer(&mut self) -> Result<(), ParseError> {
    let fs = IndexedSigCode::frame_size(self.remaining()).map_err(ParseError::from)?;
    self.take(fs)?;
    Ok(())
}
```
(Reuse the existing `From<IndexerParseError> for ParseError` that `read_indexer` relies on; add it if missing.)

`read_counter_v1`:
```rust
pub(crate) fn read_counter_v1(&mut self) -> Result<(CounterCodeV1, u32), ParseError> {
    let input = self.remaining();
    let code = CounterCodeV1::from_base64_stream(input)?;
    let hs = code.hard_size();
    let fs = hs + code.soft_size();
    if input.len() < fs {
        return Err(ParseError::NeedBytes(fs - input.len()));
    }
    let count_str = core::str::from_utf8(&input[hs..fs])
        .map_err(|_| ParseError::Malformed("invalid UTF-8 in counter soft field".into()))?;
    let count: u32 = decode_int(count_str)?;
    self.take(fs)?;
    Ok((code, count))
}
```
`read_counter_v2`: identical with `CounterCodeV2`.

`skip_counter`:
```rust
pub(crate) fn skip_counter(&mut self) -> Result<(), ParseError> {
    let input = self.remaining();
    let fs = if let Ok(code) = CounterCodeV1::from_base64_stream(input) {
        code.full_size()
    } else if let Ok(code) = CounterCodeV2::from_base64_stream(input) {
        code.full_size()
    } else {
        return Err(ParseError::UnknownCounterCode(
            core::str::from_utf8(input.get(..2).unwrap_or(b"")).unwrap_or("").to_owned(),
        ));
    };
    self.take(fs)?;
    Ok(())
}
```
(`full_size()` is verified to equal `hard_size + soft_size` for counters.)

- [ ] **Step 2: Delete** `extract_hard`, `matter_full_size`, `indexer_full_size` (parse.rs:57–160) and any now-unused imports (`hardage`, `SizeType`, `XizageSize`, etc.).

- [ ] **Step 3: Run the cesr-stream suite**

Run: `nix develop --command cargo nextest run -p cesr-stream`
Expected: PASS — round-trip, boundary, and keripy-diff parse tests green (byte-identity preserved).

- [ ] **Step 4: Commit**
```bash
git add crates/cesr-stream/src/parse.rs
git commit -m "refactor(cesr-stream): parse.rs uses cesr frame_size/from_base64_stream; delete 3 re-derived helpers"
```

---

## Task 5: Overflow boundary probes + fn-ratchet re-baseline + full gate

**Files:**
- Modify: matter/indexer test modules; `free-fn-budget.toml` if a counted number moved.

- [ ] **Step 1: Overflow bug-probe tests** (fail if arithmetic ever reverts to bare). In matter/builder.rs tests, the existing `compute_full_size_rejects_overflow` covers matter; add the indexer analogue in indexer/builder.rs tests:
```rust
#[test]
fn indexer_compute_full_size_rejects_overflow() {
    assert!(compute_full_size(usize::MAX / 4, 4).is_err());
    assert!(compute_full_size(usize::MAX, 0).is_err());
    assert_eq!(compute_full_size(1, 4).unwrap(), 8);
}
```

- [ ] **Step 2: Re-baseline the fn-ratchet** if a counted number changed:
```bash
rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/cesr/src/core -g '*.rs' | wc -l
rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/cesr-stream/src -g '*.rs' | wc -l
```
Expected: `core` stays `0` (all additions are methods/assoc fns). `cesr-stream` stays `2` (deleted helpers were non-`pub`). If a number dropped, lower the budget in `free-fn-budget.toml` to the exact count; never raise one.

- [ ] **Step 3: Run the single gate**

Run: `nix flake check > /tmp/flake-check.log 2>&1; echo "exit: $?"`
Expected: exit `0`. Confirms clippy (no new bare arithmetic), fmt, taplo, audit, deny, nextest across feature combos, doctests, wasm, no_std, version-owner, and fn-ratchet.

- [ ] **Step 4: Commit**
```bash
git add crates/cesr free-fn-budget.toml
git commit -m "test(indexer): overflow boundary probe; re-baseline fn-ratchet"
```

---

## Self-review notes

- **Reuse:** matter reuses the existing `compute_full_size` (no new size type/method); counter reuses `from_hard`/`hard_size`/`soft_size`/`full_size`; the only genuinely new helpers are `frame_size` entry points, the counter stream dispatch, and the indexer's hardening copy of the checked idiom.
- **Hardening:** the indexer's bare `idx*4+cs` is fixed (Task 2) — the one place core wasn't hard enough.
- **Breaking change:** only `IndexerParseError::SizeOverflow` (+ possibly `CounterCodeError::NotACounter`) — flag in PR + CHANGELOG.
- **Naming consistency:** `frame_size` / `frame_size_of` / `compute_full_size` / `from_base64_stream` / `stream_hard_size` used identically across tasks.
- **Confirm exact fixed sizes** (`44` for `B`, `88` for `AA`) against `get_sizage()`/`get_xizage()` before asserting; truncation/unknown-code assertions hold regardless.
