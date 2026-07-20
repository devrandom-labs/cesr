# Autoresearch: CESR b64 varint codec (`encode_int` / `decode_int`)

## Objective
Reduce the per-call cost of `cesr::b64::encode_int` (and, if there's headroom, `decode_int`)
in `crates/cesr/src/b64/int.rs`. This varint is hit on **every** counter size, indexer
index/ondex, and matter soft-size (callers: `core::indexer::*`, `core::matter::builder`) — so
it's on the hot construction AND parse paths.

## Headroom — CONFIRMED by baseline (ns, `cargo bench -p cesr-rs --bench b64_int`)
- `b64_encode_hot` (2-char) = **22.3 ns**; padded=24.4, u32_max=28.2, u64_large=32.5.
- `b64_decode_hot` = **1.03 ns** (six_char=2.25). Decode is at the noise floor — **already
  optimal; do NOT chase it.** Optimize ENCODE only. Target: cut the ~22 ns toward decode-class.

## Why encode is slow (the fix)
`encode_int` currently allocates **twice**:
```rust
let mut buffer = vec![b'A'; final_length];        // heap alloc #1
...
buffer.into_iter().map(char::from).collect()      // char→String: heap alloc #2
```
The bytes are already valid ASCII Base64. Hypotheses to try (keep the rules):
- Build into a **stack buffer** (`[u8; 11]` covers all of `u64`) and return via a single
  `String::from_utf8` / `str`-based path — eliminate both heap ops on the common short case.
- Or at least drop the `.map(char::from).collect()` second allocation.
`decode_int` is already a lean checked-arithmetic byte loop — likely little to gain; confirm
with `b64_decode_hot`, don't force it.

## THIS TARGET HAS NO BENCH YET — first job is to make one green
A criterion bench has been scaffolded at `crates/cesr/benches/b64_int.rs` and wired into
`crates/cesr/Cargo.toml` (`[[bench]]` name=`b64_int`, `required-features=["b64"]`). **Step 0:
get it compiling clean under the lint law and producing a stable baseline** (`./.auto/measure.sh`
must print a non-zero `METRIC b64_encode_ns=…`). If the bench trips a clippy-as-law lint, fix
the *bench* (host tooling) — never relax `[lints]`/`clippy.toml`.

## Metrics
- **Primary**: `b64_encode_ns` (ns/call, **lower is better**) — group `b64_encode_hot`
  (the canonical 2-char count-code encode).
- **Secondary** (monitors, must not regress): `b64_decode_ns` (`b64_decode_hot`), and the
  `b64_encode_range`/`b64_decode_range` magnitudes (so a win on 2-char doesn't cost large values).

## Files in Scope
- `crates/cesr/src/b64/int.rs` — `encode_int`, `decode_int` (the code under optimization).
- `crates/cesr/src/b64/alphabet.rs` — `B64_ALPHABET`, `b64_byte_to_index` (lookup on the path).
- `crates/cesr/benches/b64_int.rs` — the bench (fix to compile/measure; do NOT rig fixtures).

## Off Limits
- The `base64` **crate engine** and `crates/cesr/benches/base64.rs` (#29 — closed).
- `crates/cesr-stream/src/qb2.rs` (already tuned; out of scope).
- Any `[lints]` table, `clippy.toml`, `flake.nix`, `Cargo.lock` dep versions.
- The proptest suites in `int.rs` — they are the correctness guard; never weaken them to pass.

## Constraints (law — condensed from ~/.claude/CLAUDE.md + ./CLAUDE.md)
- Arithmetic safety: length/shift/size math uses `checked_*`, `Err` on overflow;
  `saturating_*` and `unwrap_or(sentinel)` banned on production paths (the bench may use
  `unwrap_or` for host-only constants — production code may not).
- `encode_int` is documented **infallible by construction** — keep it so, or if the shape
  changes, prove the invariant; no `unwrap`/`expect` on any real path.
- `decode_int` overflow handling must stay exact (`checked_shl`/`checked_add` + the
  `leading_zeros() < 6` pre-check). Do not trade correctness for a branch.
- Errors: `thiserror`; input-validation (`InvalidBase64Char`) ≠ overflow (`IntegerOverflow`) —
  keep them distinct. Style: borrow-before-own, functional-first, comments say *why*.
- KEEP only if `.auto/checks.sh` passes; a `checks_failed` result auto-reverts.

## The gate (per-iteration vs finalize)
- `.auto/checks.sh` runs `cargo nextest run -p cesr-rs -p cesr-stream` (incl. the int.rs
  roundtrip/overflow/boundary proptests) every experiment — cheap breakage guard.
- Full single gate `nix flake check` (clippy-as-law, taplo, deny, audit, fuzz) runs ONCE at
  `/skill:autoresearch-finalize`; it must be green before the reviewable branch is produced.

## What's Been Tried
- <append: stack-buffer result, from_utf8 result, decode attempts, dead ends, and why.>
