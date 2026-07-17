# frame_size Primitive Implementation Plan (#193 P1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `cesr` a decode-free `frame_size` sizing surface on its code enums so the `cesr-stream` framer calls it instead of re-deriving qb64 size math, deleting three duplicated helpers and closing the latent arithmetic-overflow gap.

**Architecture:** "Grain A — the code owns sizing." `MatterCode`/`IndexedSigCode` gain `frame_size(stream) -> Result<usize>`; `CounterCodeV1`/`V2` gain `from_base64_stream(stream) -> Result<Self>` (counters have no variable body, so `full_size()` already gives their span once the code is known). Size math is centralized as a **checked method on the size-descriptor types** (`Sizage`/`Xizage`), which both the decoders and `frame_size` call — one checked implementation, no third copy. Builder signatures are unchanged (Piece 2 / consumed-length-on-decode is deferred).

**Tech Stack:** Rust 2024, no_std/alloc, `cargo nextest`, the `nix flake check` gate. Spec: `docs/superpowers/specs/2026-07-17-193-frame-size-primitive-design.md`.

---

## Load-bearing decisions made from reading the code (review these first)

1. **`compute_full_size` moves onto the size-descriptor types as a method returning `Option<usize>`.** The fn-ratchet counts `pub(crate) fn` at column 0 (`core` budget = 0), so it cannot be a shared free function. As a method (indented, inside `impl`) it costs zero budget. `Option` (not `Result`) decouples it from each caller's error enum — callers map `None` to their own overflow error.
2. **`IndexerParseError` gains a `SizeOverflow` variant.** `IndexerBuilder::from_qb64` currently computes `idx * 4 + cs` with **bare** arithmetic (indexer/builder.rs) — unlike the Matter side. Routing it through the checked method hardens it, but needs an overflow variant. **This is a breaking change to a public error enum — call it out in the PR + CHANGELOG.**
3. **`frame_size` does pure sizing, not canonicality validation.** It computes `fs` and guards the soft-field length; it does *not* validate the xtra prepad or decode raw bytes — those stay in `from_qualified_base64`. The equivalence guarantee is the existing builder + keripy-differential + spine byte-identity suites staying green.
4. **Counter hard-size dispatch** (`-`→3, `_`→5, else→2) is shared grammar between V1 and V2. It lives as a `pub(crate)` associated fn on `CounterCodeV1` (`stream_hard_size`); `V2::from_base64_stream` delegates to it. Associated fn ⇒ no free-fn-budget cost.

## File map

- `crates/cesr/src/core/matter/sizage.rs` — add `Sizage::compute_full_size` method (checked, `Option`).
- `crates/cesr/src/core/matter/code/matter_code.rs` — add `MatterCode::frame_size` (assoc) + `frame_size_of` (pub(crate) method).
- `crates/cesr/src/core/matter/builder.rs` — refactor `from_qualified_base64` to call `frame_size_of`; delete the private `compute_full_size` free fn.
- `crates/cesr/src/core/indexer/xizage.rs` — add `Xizage::compute_full_size` method.
- `crates/cesr/src/core/indexer/code.rs` — add `IndexedSigCode::frame_size` (assoc) + `frame_size_of`.
- `crates/cesr/src/core/indexer/builder.rs` — refactor `from_qb64` fs computation to the checked method; map overflow.
- `crates/cesr/src/core/indexer/error.rs` — add `IndexerParseError::SizeOverflow`.
- `crates/cesr/src/core/counter/code.rs` — add `CounterCodeV1::stream_hard_size` + `from_base64_stream`.
- `crates/cesr/src/core/counter/v2.rs` — add `CounterCodeV2::from_base64_stream`.
- `crates/cesr-stream/src/parse.rs` — migrate consumers; delete `extract_hard`, `matter_full_size`, `indexer_full_size`.

---

## Task 1: `Sizage::compute_full_size` (checked size math as a method)

**Files:**
- Modify: `crates/cesr/src/core/matter/sizage.rs` (add method in `impl Sizage`)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

Add to `sizage.rs` tests:
```rust
#[test]
fn compute_full_size_checked() {
    // hs=1, ss=2 -> cs=3; size=5 -> 5*4+3 = 23
    let s = Sizage::new(1, 2, 0, SizeType::Small, 0);
    assert_eq!(s.compute_full_size(5), Some(23));
    assert_eq!(s.compute_full_size(0), Some(3));
    // overflow: size * 4 must not wrap
    assert_eq!(s.compute_full_size(usize::MAX), None);
    assert_eq!(s.compute_full_size(usize::MAX / 4), None);
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs compute_full_size_checked`
Expected: FAIL — `no method named compute_full_size`.

- [ ] **Step 3: Add the method** in `impl Sizage` (sizage.rs), mirroring the checked formula currently in `builder.rs:505`:
```rust
/// Checked full character size `fs = size * 4 + cs` for a variable-size
/// primitive, where `cs = hs + ss`. `size` is decoded from the
/// attacker-controlled soft field, so the arithmetic is checked; `None`
/// signals overflow (callers map it to their own size-overflow error).
#[inline]
#[must_use]
pub(crate) const fn compute_full_size(&self, size: usize) -> Option<usize> {
    let cs = self.hs() + self.ss();
    match size.checked_mul(4) {
        Some(quad) => quad.checked_add(cs),
        None => None,
    }
}
```
(`const fn` cannot use `?`/`and_then`, hence the explicit `match`.)

- [ ] **Step 4: Run it, verify it passes**

Run: `nix develop --command cargo nextest run -p cesr-rs compute_full_size_checked`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/cesr/src/core/matter/sizage.rs
git commit -m "feat(matter): add checked Sizage::compute_full_size method"
```

---

## Task 2: `MatterCode::frame_size` + `frame_size_of`

**Files:**
- Modify: `crates/cesr/src/core/matter/code/matter_code.rs` (add to `impl MatterCode`)
- Test: same file tests

- [ ] **Step 1: Write the failing test** (in matter_code.rs tests). Uses an ed25519 verkey qb64 (fixed, fs=44) and a variable code if available; start with the fixed case + truncation:
```rust
#[test]
fn frame_size_fixed_and_truncated() {
    // 'B' = Ed25519 non-transferable verkey, fixed fs = 44
    let full = "B".to_string() + &"A".repeat(43);
    assert_eq!(MatterCode::frame_size(full.as_bytes()).unwrap(), 44);
    // empty stream -> parsing error, never a panic
    assert!(MatterCode::frame_size(b"").is_err());
    // unknown code -> error
    assert!(MatterCode::frame_size(b"\x00\x00").is_err());
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs frame_size_fixed_and_truncated`
Expected: FAIL — `no function frame_size`.

- [ ] **Step 3: Implement** `frame_size` (associated) + `frame_size_of` (pub(crate) method) in `impl MatterCode`. Body extracted from `from_qualified_base64`'s prologue (builder.rs:105–133), using `Sizage::compute_full_size`:
```rust
/// Full qb64 character size of the Matter primitive at the head of
/// `stream`, without decoding the raw body or validating pad/lead bits.
///
/// # Errors
/// `MatterBuildError` if the code is unknown, the stream is too short for
/// the soft field, the soft field is not UTF-8, or the computed size
/// overflows `usize`.
pub fn frame_size(stream: &[u8]) -> Result<usize, MatterBuildError> {
    let code = Self::from_base64_stream(stream)?;
    code.frame_size_of(stream)
}

/// `frame_size` for an already-known code (shared with the decoder so
/// there is one size implementation).
pub(crate) fn frame_size_of(&self, stream: &[u8]) -> Result<usize, MatterBuildError> {
    let sizage = self.get_sizage();
    if let SizeType::Fixed(fixed) = sizage.fs() {
        return Ok(usize::from(*fixed));
    }
    let hs = sizage.hs();
    let ss = sizage.ss();
    let cs = hs + ss;
    if stream.len() < cs {
        return Err(MatterBuildError::from(ParsingError::StreamTooShort(
            MatterPart::Soft,
        )));
    }
    let xs = sizage.xs();
    let soft_tail = str::from_utf8(&stream[hs + xs..cs])
        .map_err(|err| MatterBuildError::from(ParsingError::InvalidUtf8(err)))?;
    let size: usize = decode_int(soft_tail)
        .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
    sizage
        .compute_full_size(size)
        .ok_or(MatterBuildError::from(ValidationError::SizeOverflow))
}
```
Add any missing imports at the top of `matter_code.rs` (`MatterBuildError`, `ParsingError`, `ValidationError`, `MatterPart`, `SizeType`, `decode_int`, `str`) — do not add inline `use`.

- [ ] **Step 4: Run it, verify it passes**

Run: `nix develop --command cargo nextest run -p cesr-rs frame_size`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/cesr/src/core/matter/code/matter_code.rs
git commit -m "feat(matter): add decode-free MatterCode::frame_size"
```

---

## Task 3: Refactor `from_qualified_base64` to reuse the shared sizer (DRY)

**Files:**
- Modify: `crates/cesr/src/core/matter/builder.rs` (`from_qualified_base64`, delete `compute_full_size`)

- [ ] **Step 1: Replace the inline fs computation.** In `from_qualified_base64` (builder.rs ~127–133), the block:
```rust
let fs = if let SizeType::Fixed(fixed) = code.get_sizage().fs() {
    usize::from(*fixed)
} else {
    let size: usize = decode_int(soft_str)
        .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
    compute_full_size(size, cs)?
};
```
becomes (reuse the decoded `size` path via the new method — keep the xtra check above it unchanged):
```rust
let fs = if let SizeType::Fixed(fixed) = code.get_sizage().fs() {
    usize::from(*fixed)
} else {
    let size: usize = decode_int(soft_str)
        .map_err(|err| MatterBuildError::from(ParsingError::Conversion(err)))?;
    code.get_sizage()
        .compute_full_size(size)
        .ok_or(MatterBuildError::from(ValidationError::SizeOverflow))?
};
```

- [ ] **Step 2: Delete the now-unused private `compute_full_size` free fn** (builder.rs:505–511). Leave `compute_bfs`/other helpers intact.

- [ ] **Step 3: Run the full matter builder suite + overflow tests**

Run: `nix develop --command cargo nextest run -p cesr-rs matter`
Expected: PASS — including `compute_full_size_rejects_overflow` if it still references the fn; if those tests referenced the free fn directly, repoint them at `Sizage::compute_full_size` (they live in builder.rs tests). Byte behavior unchanged.

- [ ] **Step 4: Commit**
```bash
git add crates/cesr/src/core/matter/builder.rs
git commit -m "refactor(matter): from_qualified_base64 reuses Sizage::compute_full_size"
```

---

## Task 4: Indexer side — `Xizage::compute_full_size`, `IndexerParseError::SizeOverflow`, `IndexedSigCode::frame_size`, harden `from_qb64`

**Files:**
- Modify: `crates/cesr/src/core/indexer/error.rs`, `xizage.rs`, `code.rs`, `builder.rs`

- [ ] **Step 1: Add the error variant** in `indexer/error.rs` `IndexerParseError`:
```rust
/// The computed full size overflowed `usize` (soft-field index too large).
#[error("indexer full size overflow")]
SizeOverflow,
```

- [ ] **Step 2: Add `Xizage::compute_full_size`** (xizage.rs, `impl Xizage`), same checked formula (`cs = hs + ss`):
```rust
#[inline]
#[must_use]
pub(crate) const fn compute_full_size(&self, index: usize) -> Option<usize> {
    let cs = self.hs as usize + self.ss as usize;
    match index.checked_mul(4) {
        Some(quad) => quad.checked_add(cs),
        None => None,
    }
}
```

- [ ] **Step 3: Write the failing frame_size test** (indexer/code.rs tests):
```rust
#[test]
fn frame_size_indexer_fixed_and_truncated() {
    // 'A' = Ed25519 indexed sig, fixed fs = 88
    let full = "AA".to_string() + &"A".repeat(86);
    assert_eq!(IndexedSigCode::frame_size(full.as_bytes()).unwrap(), 88);
    assert!(IndexedSigCode::frame_size(b"").is_err());
    assert!(IndexedSigCode::frame_size(b"9").is_err()); // '9' -> hardage None
}
```
(Confirm the exact fixed `fs` for `A` from `get_xizage()` before asserting; adjust `88` if the table differs.)

- [ ] **Step 4: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs frame_size_indexer`
Expected: FAIL — no `frame_size`.

- [ ] **Step 5: Implement `frame_size` + `frame_size_of`** in `impl IndexedSigCode` (code.rs), extracted from `from_qb64`'s prologue (builder.rs:81–151), using `hardage` + `from_hard`:
```rust
/// Full qb64 character size of the indexed primitive at the head of
/// `stream`, without decoding raw bytes.
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
    IndexedSigCode::from_hard(hard).map_err(IndexerParseError::from)?.frame_size_of(stream)
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
            xizage.compute_full_size(index).ok_or(IndexerParseError::SizeOverflow)
        }
    }
}
```

- [ ] **Step 6: Harden `from_qb64`** — replace its `XizageSize::Variable => { ... idx * 4 + cs }` block (builder.rs) with `xizage.compute_full_size(index as usize).ok_or(IndexerParseError::SizeOverflow)?`. Keep the ondex logic above it untouched.

- [ ] **Step 7: Run indexer suite**

Run: `nix develop --command cargo nextest run -p cesr-rs indexer`
Expected: PASS.

- [ ] **Step 8: Commit**
```bash
git add crates/cesr/src/core/indexer
git commit -m "feat(indexer)!: add IndexedSigCode::frame_size; harden from_qb64 size math

BREAKING: adds IndexerParseError::SizeOverflow variant."
```

---

## Task 5: Counter — `from_base64_stream` on V1 and V2

**Files:**
- Modify: `crates/cesr/src/core/counter/code.rs`, `crates/cesr/src/core/counter/v2.rs`

- [ ] **Step 1: Write the failing test** (counter/code.rs tests):
```rust
#[test]
fn counter_from_base64_stream() {
    // "-A.." controller idx sigs: hs=2
    assert_eq!(
        CounterCodeV1::from_base64_stream(b"-AAB").unwrap(),
        CounterCodeV1::ControllerIdxSigs
    );
    // big code "--L.." hs=3
    assert_eq!(
        CounterCodeV1::from_base64_stream(b"--LAAA").unwrap(),
        CounterCodeV1::BigPathedMaterialCouples
    );
    // genus "-_AAA" hs=5
    assert_eq!(
        CounterCodeV1::from_base64_stream(b"-_AAABAA").unwrap(),
        CounterCodeV1::KERIACDCGenusVersion
    );
    assert!(CounterCodeV1::from_base64_stream(b"").is_err());
    assert!(CounterCodeV1::from_base64_stream(b"-").is_err());
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `nix develop --command cargo nextest run -p cesr-rs counter_from_base64_stream`
Expected: FAIL.

- [ ] **Step 3: Implement** in `impl CounterCodeV1` (code.rs): the shared hard-size dispatch + the stream reader:
```rust
/// Hard-code character length from the two lead bytes of a counter stream:
/// `--` → 3 (big), `-_` → 5 (genus/version), otherwise 2. Shared V1/V2 grammar.
pub(crate) fn stream_hard_size(stream: &[u8]) -> Result<usize, CounterCodeError> {
    match stream {
        [b'-', b'-', ..] => Ok(3),
        [b'-', b'_', ..] => Ok(5),
        [b'-', _, ..] => Ok(2),
        _ => Err(CounterCodeError::UnknownCode(
            alloc::string::String::from_utf8_lossy(stream).into_owned(),
        )),
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
        .ok_or_else(|| CounterCodeError::UnknownCode(
            alloc::string::String::from_utf8_lossy(stream).into_owned(),
        ))?;
    Self::from_hard(hard)
}
```
Add needed imports at top of file (`alloc::string::String` if not present) — no inline `use`.

- [ ] **Step 4: Implement V2** in `impl CounterCodeV2` (v2.rs), delegating the shared dispatch:
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
        .ok_or_else(|| CounterCodeError::UnknownCode(
            alloc::string::String::from_utf8_lossy(stream).into_owned(),
        ))?;
    Self::from_hard(hard)
}
```
Add a V2 test mirroring Step 1 (`CounterCodeV2::from_base64_stream(b"-AAB")` → `CounterCodeV2::GenericGroup`).

- [ ] **Step 5: Run counter suite**

Run: `nix develop --command cargo nextest run -p cesr-rs counter`
Expected: PASS.

- [ ] **Step 6: Commit**
```bash
git add crates/cesr/src/core/counter
git commit -m "feat(counter): add CounterCodeV1/V2::from_base64_stream (closes Matter/Counter asymmetry)"
```

---

## Task 6: Migrate `cesr-stream/parse.rs`; delete the three helpers

**Files:**
- Modify: `crates/cesr-stream/src/parse.rs`

- [ ] **Step 1: Rewrite the consumers** to call the cesr primitives. Map cesr errors into `ParseError` (add `From` impls or `map_err` matching the existing `read_matter` pattern).

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
`read_matter`: replace `let fs = matter_full_size(self.remaining())?;` with the same `MatterCode::frame_size(...)` call (mapped), keeping the rest.

`skip_indexer`:
```rust
pub(crate) fn skip_indexer(&mut self) -> Result<(), ParseError> {
    let fs = IndexedSigCode::frame_size(self.remaining()).map_err(ParseError::from)?;
    self.take(fs)?;
    Ok(())
}
```
(Add a `From<IndexerParseError> for ParseError` if absent — mirror the existing indexer error mapping used by `read_indexer`.)

`read_counter_v1`:
```rust
pub(crate) fn read_counter_v1(&mut self) -> Result<(CounterCodeV1, u32), ParseError> {
    let input = self.remaining();
    let code = CounterCodeV1::from_base64_stream(input)?;
    let hs = code.hard_size();
    let ss = code.soft_size();
    let fs = hs + ss;
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
`read_counter_v2`: identical shape with `CounterCodeV2`.

`skip_counter`:
```rust
pub(crate) fn skip_counter(&mut self) -> Result<(), ParseError> {
    let input = self.remaining();
    let fs = if let Ok(code) = CounterCodeV1::from_base64_stream(input) {
        code.full_size()
    } else if let Ok(code) = CounterCodeV2::from_base64_stream(input) {
        code.full_size()
    } else {
        let hs = CounterCodeV1::stream_hard_size(input).unwrap_or(0);
        return Err(ParseError::UnknownCounterCode(
            core::str::from_utf8(input.get(..hs).unwrap_or(b"")).unwrap_or("").to_owned(),
        ));
    };
    self.take(fs)?;
    Ok(())
}
```
(Confirm `full_size()` equals `hard_size + soft_size` for counters — verified: it returns 4/8 = hs+ss. If `stream_hard_size` is not accessible as `pub(crate)` across crates, expose the error mapping differently; simplest is to keep the prior `UnknownCounterCode(...)` string built from the raw lead bytes.)

- [ ] **Step 2: Delete** `extract_hard`, `matter_full_size`, `indexer_full_size` (parse.rs:57–160) and any now-unused imports (`hardage`, `IndexedSigCode::from_hard` if unused, `SizeType`, `XizageSize`, `MatterCode::from_base64_stream` if unused).

- [ ] **Step 3: Run the cesr-stream suite**

Run: `nix develop --command cargo nextest run -p cesr-stream`
Expected: PASS — the round-trip, boundary, and keripy-diff parse tests all green (byte-identity preserved).

- [ ] **Step 4: Commit**
```bash
git add crates/cesr-stream/src/parse.rs
git commit -m "refactor(cesr-stream): parse.rs uses cesr frame_size/from_base64_stream; delete 3 re-derived helpers"
```

---

## Task 7: Overflow bug-probe + fn-ratchet re-baseline + full gate

**Files:**
- Modify: a `cesr` test module (e.g. sizage.rs tests) for the boundary probe; `free-fn-budget.toml` if a counted number moved.

- [ ] **Step 1: Bug-probe test** proving the checked path (fails while unchecked arithmetic exists, passes now). `Sizage::compute_full_size` boundary at `usize::MAX`:
```rust
#[test]
fn compute_full_size_boundaries() {
    let s = Sizage::new(2, 2, 0, SizeType::Small, 0); // cs = 4
    assert_eq!(s.compute_full_size(0), Some(4));
    assert_eq!(s.compute_full_size(1), Some(8));
    assert_eq!(s.compute_full_size(usize::MAX / 4), None); // *4 overflows
    assert_eq!(s.compute_full_size(usize::MAX), None);
}
```
Add the analogous `Xizage::compute_full_size` boundary test in xizage.rs.

- [ ] **Step 2: Re-baseline the fn-ratchet** if any counted number changed. Recount per the rule in `free-fn-budget.toml`:
```bash
for m in core; do rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/cesr/src/$m -g '*.rs' | wc -l; done
rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/cesr-stream/src -g '*.rs' | wc -l
```
Expected: `core` stays `0` (all additions are methods/assoc fns). `cesr-stream` stays `2` (deleted helpers were non-`pub`). If a number dropped, lower the budget in `free-fn-budget.toml` to the exact count; never raise one.

- [ ] **Step 3: Run the single gate**

Run: `nix flake check 2>&1 | tee /tmp/flake-check.log; echo "exit: ${PIPESTATUS[0]}"`
Expected: exit `0`. Confirms clippy (incl. no new bare-arithmetic), fmt, taplo, audit, deny, nextest across feature combos, doctests, wasm, no_std, version-owner, and fn-ratchet all pass.

- [ ] **Step 4: Commit**
```bash
git add crates/cesr free-fn-budget.toml
git commit -m "test(matter,indexer): overflow boundary probes; re-baseline fn-ratchet"
```

---

## Self-review notes

- **Spec coverage:** Matter `frame_size` (T2), Indexer `frame_size` (T4), Counter `from_base64_stream` (T5), internal DRY / one checked sizer (T1+T3+T4), arithmetic-safety fix (T1 method + T3/T4/T6 migration), cesr-stream migration + deletions (T6), test categories round-trip/boundary/overflow/no_std (T2,T4,T5,T7), ratchet (T7). Builder signatures unchanged (Piece 2 deferred) — honored.
- **Breaking change:** only `IndexerParseError::SizeOverflow` (T4) — flagged in the commit and must appear in the PR description + CHANGELOG.
- **Naming consistency:** `frame_size` / `frame_size_of` / `compute_full_size` / `from_base64_stream` / `stream_hard_size` used identically across tasks.
- **Before asserting exact fixed sizes** (`44` for `B`, `88` for `AA`) confirm against `get_sizage()`/`get_xizage()` — adjust the literal if the table differs; the truncation/unknown-code assertions hold regardless.
