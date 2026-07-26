# #193 P4 + P5 — ordinal & qb64↔qb2 de-duplication

**Date:** 2026-07-26
**Issue:** #193 (workspace split phase 2 — per-crate redesign), duplication-audit items P4 & P5
**Status:** design approved (Joel), pending spec review → implementation plan

## Context

The #193 cross-crate duplication audit flagged two suspected redundancies. Both were
investigated against the keripy reference implementation before deciding, so the design
is grounded in how KERI actually models these concepts — not copied from keripy, but
informed by it.

- **P4** — `keri-events::SequenceNumber` vs `cesr::Number`: the same `u128` ordinal
  modelled twice.
- **P5** — `cesr-stream::qb2` (`Qb64`/`Qb2` whole-blob transcoders) vs
  `cesr::b64::encode_binary`: overlapping Base64↔binary conversion, mis-layered (the
  base64-domain math lives in the stream crate, above the crate that owns Base64).

## keripy findings (grounding)

### Ordinals
- keripy has **two** ordinal `Matter` primitives in `coring.py`: `Number` (dynamic
  width, smallest code by magnitude) and `Seqner` (fixed 24-char qb64, code `0A`
  `Salt_128`). They share **identical value semantics** (`u128`, capped at `MaxON`) and
  the **identical minimal-hex renderer** (`f"{num:x}"`).
- The split is purely **width policy**: `Seqner` forces fixed width so ordinals sort
  correctly as lexicographic database keys / fixed attachment elements; `Number` is
  dynamic and is what the compact JSON body and CESR wire want.
- The **JSON event body `"s"` / `"bt"` / `"f"` fields always render via `Number.numh`**
  (minimal lowercase hex). qb64 is a *separate* method (`.qb64b`) on the same object.
- keripy has **no codeless bare-ordinal type** — the body simply uses `Number.numh` and
  ignores the code.

### qb64 ↔ qb2
- keripy has **two distinct conversion families**: the integer/radix path
  (`intToB64`/`b64ToInt`, our `encode_int`/`decode_int`) for fixed-width small integers
  (codes, counts), and the byte-base64 path (stdlib `encodeB64`/`decodeB64`) for
  arbitrary-length blobs (raw material, whole composable group frames).
- Within the **byte-base64 family, ONE function serves both scales** — single-primitive
  raw *and* whole group frames. Our `encode_binary` and the `qb2` transcoders are both
  this family; keripy would use one routine for both.

## Current state (this workspace)

Three ordinal types exist:

| type | role | encoding | consumers |
|---|---|---|---|
| `cesr::core::primitives::Number` | coded ordinal | dynamic code; body wants `numh` | the live body/seal ordinal (after P4) |
| `cesr::core::primitives::Seqner` | fixed-width ordinal | fixed 24-char qb64 | **none — dormant public API** |
| `keri-events::SequenceNumber` | codeless body ordinal | minimal hex only | duplicate of `Number` → **delete** |

- Every sibling field in the event body is already a `cesr` `Matter` primitive (`Saider`,
  `Verfer`, `Diger`, `Prefixer`); `SequenceNumber` was the lone bespoke newtype.
- `NumberCode` is `Copy`, so `Number` can derive `Copy` — the historical reason to keep a
  lean `Copy` `SequenceNumber` no longer holds.
- `Seqner` is `pub` (intentional primitives-crate API for a future storage/attachment
  path), so it is not dead-code — it is kept, dormant, until its first caller.

For qb64↔qb2:
- `cesr-stream::qb2` holds `Qb64<'a>(&[u8]).decode()` / `Qb2<'a>(&[u8]).encode()` —
  whole-blob 4:3 / 3:4 transcode, multiple-of-N, `Vec<u8>` + `_into` buffer reuse. Already
  imports `cesr::b64::alphabet`. Consumers: `cesr-stream` benches + `keripy_diff` only.
- `cesr::b64::encode_binary(stream, length)` — single-primitive byte→`String`,
  bit-accumulator. There is **no `decode_binary`** counterpart in `cesr::b64`; `qb2` has
  both directions.

## Decisions

### P4 — collapse `SequenceNumber` onto `cesr::Number`; add `Ordinal` trait in core

1. **Delete `keri-events::SequenceNumber`** (`crates/keri-events/src/sequence.rs`). The
   event/seal `s` (`sn`) field becomes `cesr::core::primitives::Number`. This matches
   keripy (the body uses `Number.numh`) and makes `s` consistent with its already-`Matter`
   sibling fields.
2. **Add an `Ordinal` trait in `cesr::core::primitives`** (new
   `crates/cesr/src/core/primitives/ordinal.rs`, `pub use ordinal::Ordinal` in
   `primitives/mod.rs`):
   ```rust
   pub trait Ordinal {
       fn num(&self) -> u128;
       fn numh(&self) -> impl core::fmt::Display
       where
           Self: Sized,
       {
           NumHex(self.num())
       }
   }
   ```
   with a private zero-alloc `NumHex(u128)` Display wrapper rendering `write!(f, "{:x}")`.
   RPITIT is available on the pinned 1.95.0 toolchain.
3. **`impl Ordinal for Number`** and **`impl core::fmt::LowerHex for Number`** (so both
   `Number.numh()` and `{:x}` work; satisfies the audit's literal "numh()/LowerHex" ask).
   Add `Copy` to `Number`'s derives (`NumberCode` is `Copy`).
4. **`Seqner` is left untouched and dormant** — no `Ordinal` impl until it gains a real
   caller (respects "land modules/impls with their first caller"). It remains the
   keripy-parity fixed-width primitive for the future storage/attachment path.
5. **Update consumers** — all `SequenceNumber::new(n)` → `Number::new(n)`; the codec
   serialize path renders the body `s` via `Number`'s `numh`/`LowerHex` instead of
   `SequenceNumber`'s `Display`; the deserialize path parses minimal hex into `Number`.
   Blast radius: `keri-events` event structs (`inception`/`rotation`/`interaction`/
   `delegation`), `keri-events::seal`, and ~10 `keri-codec` sites (builders, `serialize`,
   `deserialize/reference`, `traits`, `codec/event`, `codec/seal`) + benches.

**Rationale for keeping the types split at the primitive layer but collapsing the third
type:** keripy's `Number`/`Seqner` split (width policy) is real and preserved. Our
`SequenceNumber` was *not* that split — it was a codeless shadow of `Number`, which keripy
does not have. The `Ordinal` trait unifies the shared value+hex contract in core (beside
the existing `Matter` trait precedent) without inverting layering (a KERI-named
"sequence number" type never enters the KERI-agnostic `cesr` substrate).

**Breaking changes (P4):** `keri-events::SequenceNumber` removed (public type deleted);
`cesr::Number` gains `Copy`/`LowerHex`/`Ordinal` (additive). CHANGELOG entry required.

### P5 — relocate `Qb64`/`Qb2` into `cesr::b64` with a shared block core + `decode_binary`

1. **Move the `Qb64`/`Qb2` whole-blob transcoders down into `cesr::b64`** (the primitive
   crate that owns Base64), so all base64-domain conversion lives in one place.
   `cesr-stream::qb2` becomes a thin re-export (`pub use cesr::b64::{Qb64, Qb2};` or an
   equivalent re-export module) so its benches/`keripy_diff` consumers keep compiling.
2. **Extract one shared 3↔4 block core** in `cesr::b64` that both the relocated
   transcoders and `encode_binary` build on (single sextet/block routine; no duplicated
   bit-twiddling). `encode_int`/`decode_int` (the radix family) stay separate — keripy
   confirms these are a genuinely different core.
3. **Add the missing `decode_binary` direction** to `cesr::b64` (the `Qb64::decode`
   direction has no primitive-layer counterpart today), giving the byte-base64 family both
   directions at the primitive layer.
4. **Error type:** the relocated transcoders return `cesr::b64::Error`. `b64::Error`
   currently has no alignment variant, so **add `Misaligned { len, unit }` to
   `cesr::b64::Error`** (alignment is a base64-domain concern). Refine
   `cesr-stream`'s `From<b64::Error> for ParseError` (currently maps everything to
   `Base64`) to map `b64::Error::Misaligned → ParseError::Misaligned`, other variants →
   `ParseError::Base64`, so the existing typed distinction (`ParseError::Misaligned` vs
   `ParseError::Base64`) is preserved for `cesr-stream` consumers.

**Breaking changes (P5):** `cesr::b64::Error` gains a `Misaligned` variant (breaking on a
public enum); `Qb64`/`Qb2` move crate (re-exported from `cesr-stream` to preserve the old
path). CHANGELOG entry required.

## Testing

Per the repo's categories-first rule, both changes must land with:

1. **Round-trip / sequence tests.**
   - P4: `Number::new(n).numh()` and `{:x}` render minimal lowercase hex for `0`, `1`,
     `10→"a"`, `255→"ff"`, `u128::MAX`; body encode→decode→re-encode stability for the `s`
     field (byte-identical to the pre-collapse output — a golden vector guards parity).
   - P5: `decode(encode(x)) == x` and `encode(decode(bytes)) == bytes` for the relocated
     transcoders and for `encode_binary`/`decode_binary`; the shared core produces
     byte-identical output to the pre-refactor `qb2` (golden vectors).
2. **Defensive boundary tests.**
   - P4: parsing an out-of-range / non-hex `s` returns a typed error, never panics.
   - P5: misaligned lengths (not multiple of 3 / 4) return `Misaligned`; invalid Base64
     chars return the char error; `_into` leaves the buffer untouched on the pre-touch
     error paths (existing `qb2` tests migrate with the code).
3. **Cross-feature-combination tests** — `numh`/`LowerHex` and the transcoders compile and
   pass under no_std + alloc and wasm (they are `core::fmt` / byte-slice based; no `std`).
4. **Property-based tests** — `Number` numh over `0`, `1`, `MAX-1`, `MAX`; transcoder
   round-trips over empty / max-length / max-length+1 byte strings with alignment
   boundaries.

Existing `qb2` tests move with the code into `cesr::b64`; the `cesr-stream` re-export gets
a smoke test proving the old path still resolves.

## Out of scope

- The full `keri-events` design pass (keripy-lexicon renames: `Verfer→VerifyingKey`,
  `Diger→Digest`, `Siger→IndexedSignature`, `Saider→Said`, `Ilk→EventKind`) — separate
  #193 item, Joel's per-crate call.
- Wiring `Seqner`'s first consumer (storage/attachment seq-num path) — future work; this
  spec only keeps it dormant.
- Any change to `encode_int`/`decode_int` (radix family stays as-is).

## Gate

`nix flake check` (clippy god-level, fmt, taplo, audit, deny, nextest across feature
combinations, doctest, wasm build, no_std build, version-owner + fn-ratchet tripwires).
Re-baseline the per-module free-`pub fn` budgets in `free-fn-budget.toml` if counts drop
(they may, as `qb2` free items move and `SequenceNumber` is deleted) — lower budgets only,
never raise.
