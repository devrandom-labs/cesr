# #274 — 12-word BIP-39 mnemonic encoding for Salt128

## Context

Human-transcribable backup for the 16-byte root `Salt` (`crates/cesr/src/crypto/salt.rs:57`).
BIP-39 wordlist + checksum encoding of exactly 128 bits ↔ 12 words.

**Deliberately NOT BIP-39-seed-compatible**: the recovered raw entropy feeds cesr's
existing argon2id stretch (`Salt::stretch`, salt.rs:136), never PBKDF2-2048. The words
encode the SALT itself; recovering keys additionally requires the `Tier` and the
derivation-path convention — the docs must say so.

Encoding math (BIP-39, 128-bit case only):
- checksum = top 4 bits of `SHA-256(entropy)` (first byte `>> 4`).
- bit stream = 128 entropy bits ++ 4 checksum bits = 132 bits.
- word index `i` (0..12) = bits `[11*i, 11*i+11)` of that stream, MSB-first, as
  an 11-bit integer indexing the 2048-word English list.
- Decode is the inverse: 12 words → 12×11 bits → first 128 bits are entropy,
  last 4 bits must equal the recomputed checksum, else typed error.

Dependency decision (evaluated, final — do not revisit):
- **No new dependency, prod or dev.** rust-bitcoin `bip39` is CC0-1.0 — not in
  `deny.toml` allowlist, fails `cargo deny` even as dev-dep. `tiny-bip39` is MIT
  but dep-heavy. `sha2` is already a `crypto` dependency (Cargo.toml:77).
- Wordlist is vendored as a plain text file + `include_str!`. Differential anchor
  = the 8 official 128-bit Trezor reference vectors, hardcoded (fetched from
  trezor/python-mnemonic vectors.json 2026-07-31; listed in Step 4).

Invariants that must hold:
- no_std-clean: the `crypto` feature builds `--no-default-features --features alloc,core,b64,crypto`
  for wasm32 (flake wasm check). No `std` items. `include_str!`, `split_ascii_whitespace`,
  `eq_ignore_ascii_case`, `sha2` are all core/alloc-safe.
- Secret hygiene: mnemonic text and intermediate entropy/index buffers are secret
  material. Returned phrase is `Zeroizing<String>`; intermediate entropy buffer and
  the 12-index buffer are held in `Zeroizing` (zeroize impls exist for `[u8; N]` /
  `[u16; N]`). **Error values must NEVER carry offending word text** — only the
  zero-based word position — otherwise a typo'd secret word leaks into logs.
- fn-ratchet: `free-fn-budget.toml` counts `^pub(\(crate\)|\(super\))? fn` at column 0;
  crypto budget is 6 and must not rise. Therefore: public surface = **methods on `Salt`**
  (inside `impl Salt`), file-scope helpers in the new module are plain `fn` (private,
  column-0 `fn` without `pub` is not counted).
- Arithmetic: all sizes/indices here are compile-time-constant-bounded (11-bit
  indices < 2048, fixed 16/32-byte buffers). Use plain shifts/masks with fixed
  constants; no runtime-length arithmetic that can overflow. No `as` truncation that
  can lose bits — indices fit `u16`, prove by masking with `0x7FF`.
- Import style: all `use` at top of file; no inline `use`, no fully-qualified
  construction paths. Comments only for why.

## Steps

### Step 1 — vendor wordlist (SEQUENTIAL, first)

Create `crates/cesr/src/crypto/bip39_english.txt` by copying the pre-fetched,
verified file:

```bash
cp /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/bc851a78-c5a5-4dde-b278-35199a4ef4c2/scratchpad/english.txt \
   crates/cesr/src/crypto/bip39_english.txt
shasum -a 256 crates/cesr/src/crypto/bip39_english.txt
```

Expected sha256: `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
(exact upstream bytes of bitcoin/bips `bip-0039/english.txt`: 2048 lines,
one lowercase word per line, sorted, `abandon` first, `zoo` last, trailing newline).
If the copy or hash fails: STOP, report blocked — do not substitute a list from
model memory.

### Step 2 — `MnemonicError` in `crates/cesr/src/crypto/error.rs` (SEQUENTIAL — after 1)

New bare error enum (single-domain op ⇒ bare error, not a union), `thiserror`,
following the file's existing style:

```rust
/// Errors from decoding a 12-word mnemonic back into a [`Salt`](crate::crypto::salt::Salt).
#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    /// The phrase does not contain exactly 12 words.
    #[error("mnemonic must be exactly 12 words, got {actual}")]
    WordCount {
        /// Number of whitespace-separated words found.
        actual: usize,
    },
    /// A word is not in the BIP-39 English wordlist. Carries only the
    /// zero-based position — never the word itself, which is secret material.
    #[error("word at position {index} is not a BIP-39 English word")]
    UnknownWord {
        /// Zero-based position of the unrecognized word.
        index: usize,
    },
    /// All words are valid but the embedded 4-bit checksum does not match
    /// SHA-256 of the decoded entropy — a transcription error.
    #[error("mnemonic checksum mismatch")]
    Checksum,
}
```

Add `MnemonicError` to the `pub use error::{...}` list in
`crates/cesr/src/crypto/mod.rs` (line 29).

Also add display/`matches!` tests for the three variants in error.rs's existing
`#[cfg(test)] mod tests`, matching the file's established test style.

### Step 3 — `crates/cesr/src/crypto/mnemonic.rs` (SEQUENTIAL — after 2)

New module registered in `crates/cesr/src/crypto/mod.rs` as **private** `mod mnemonic;`
(its only public surface is an `impl Salt` block, which needs no public module).
Module doc must state: words encode the SALT only; key recovery additionally needs
tier + path convention; deliberately not BIP-39-seed/PBKDF2 compatible (raw entropy
feeds `Salt::stretch`).

Contents:

- `const WORDLIST: &str = include_str!("bip39_english.txt");` with a provenance
  doc comment (upstream URL + pinned sha256 from Step 1).
- Private column-0 `fn` helpers (NOT `pub`, NOT `pub(crate)` — fn-ratchet):
  word-by-index lookup (`WORDLIST.split_ascii_whitespace().nth(i)` — cold path,
  O(n) scan is fine), word-to-index lookup using `eq_ignore_ascii_case` (input is
  matched ASCII-case-insensitively), checksum nibble computation via `sha2::Sha256`.
  Exact decomposition is yours.
- `impl Salt` block with the two public methods (rustdoc on both; prose only, no
  doctests — `crypto` is off in default features so doc examples would rot unrun):

```rust
impl Salt {
    /// Encodes the salt as a 12-word BIP-39 English mnemonic (lowercase,
    /// single-space separated). Words encode the SALT only — recovering keys
    /// also requires the argon2id `Tier` and path convention used at derivation.
    /// Not a wallet seed phrase: no PBKDF2; entropy feeds `Salt::stretch`.
    pub fn to_mnemonic(&self) -> Zeroizing<String> { ... }

    /// Decodes a 12-word mnemonic back into a salt. Accepts any ASCII case and
    /// arbitrary whitespace between words.
    ///
    /// # Errors
    /// [`MnemonicError::WordCount`] / [`MnemonicError::UnknownWord`] /
    /// [`MnemonicError::Checksum`].
    pub fn from_mnemonic(phrase: &str) -> Result<Self, MnemonicError> { ... }
}
```

Behavioral spec:
- `to_mnemonic`: entropy = `self.raw`; build 132-bit stream (entropy ++ 4-bit
  SHA-256 checksum); emit 12 lowercase words joined by single spaces, as
  `Zeroizing<String>`. Infallible.
- `from_mnemonic` validation ORDER: (1) split on ASCII whitespace, count must be
  exactly 12 else `WordCount { actual }`; (2) look up each word case-insensitively,
  first miss yields `UnknownWord { index }` (zero-based); (3) reassemble 132 bits,
  recompute checksum over the 16 entropy bytes, mismatch yields `Checksum`;
  (4) construct via existing internals (a `[u8; SALT_LEN]` into `Zeroizing` — reuse
  `Salt::from_raw` or build the array directly; either way no panic path).
- Intermediate entropy bytes and the `[u16; 12]` index buffer wrapped in `Zeroizing`.
- No new free `pub fn`, no changes to existing `Salt` methods.

### Step 4 — tests in `mnemonic.rs` `#[cfg(test)]` (SEQUENTIAL — after 3)

All tests call the real SUT and assert exact values. `Salt` has no `PartialEq`
(secret) — compare via `salt.primitive().unwrap().to_qb64()`. `hex` is an existing
dev-dependency.

1. **Trezor differential vectors** (all 8 official 128-bit English vectors,
   trezor/python-mnemonic `vectors.json`) — both directions:
   `Salt::from_raw(&hex::decode(entropy)?)` → `to_mnemonic()` == phrase exactly, and
   `Salt::from_mnemonic(phrase)` qb64 == `from_raw` qb64:

   | entropy (hex) | mnemonic |
   |---|---|
   | `00000000000000000000000000000000` | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
   | `7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f` | `legal winner thank year wave sausage worth useful legal winner thank yellow` |
   | `80808080808080808080808080808080` | `letter advice cage absurd amount doctor acoustic avoid letter advice cage above` |
   | `ffffffffffffffffffffffffffffffff` | `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong` |
   | `9e885d952ad362caeb4efe34a8e91bd2` | `ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic` |
   | `c0ba5a8e914111210f2bd131f3d5e08d` | `scheme spot photo card baby mountain device kick cradle pact join borrow` |
   | `23db8160a31d3e0dca3688ed941adbf3` | `cat swing flag economy stadium alone churn speed unique patch report train` |
   | `f30f8c1da665478f49b001d94c5fc452` | `vessel ladder alter error federal sibling chat ability sun glass valve picture` |

   Use `rstest` cases (existing dev-dep) — one case per vector.
2. **Round-trip proptest** (`proptest` dev-dep, in-module like salt.rs style):
   for any `[u8; 16]`, `from_mnemonic(&to_mnemonic())` qb64 == original qb64.
3. **Boundary / defensive** (each asserts the exact variant via `matches!`):
   - 11 words → `WordCount { actual: 11 }`; 13 words → `WordCount { actual: 13 }`;
     empty string → `WordCount { actual: 0 }`.
   - `"abandon abandon abandon abandon abandon qwerty abandon abandon abandon abandon abandon about"`
     → `UnknownWord { index: 5 }`.
   - `"abandon"` ×12 → `Checksum` (all-zero entropy requires final word `about`).
   - Uppercase/mixed case of the `ffffffff…` vector (`"ZOO ZOO … WRONG"`) decodes
     to the same qb64 as lowercase (case-insensitivity).
   - Phrase with leading/trailing/multiple internal whitespace (tabs + double
     spaces) around the all-zero vector decodes fine (whitespace tolerance).
4. **Wordlist integrity**: word count == 2048; strictly sorted ascending; first ==
   `"abandon"`, last == `"zoo"`; `Sha256` of `WORDLIST.as_bytes()` == the pinned
   digest `2f5eed…dbda` (hex-compare via `hex::encode`).

### Step 5 — CHANGELOG (SEQUENTIAL — after 3, may run with 4)

`crates/cesr/CHANGELOG.md` under `## [Unreleased]` / `### Added`, style-matched to
the existing `crypto::salt` entry:

- `Salt::to_mnemonic` / `Salt::from_mnemonic` — 12-word BIP-39 English mnemonic
  backup of the 128-bit salt (raw entropy + 4-bit checksum; deliberately not
  PBKDF2/wallet-seed compatible), plus `MnemonicError` (#274).

## Verification

Sandbox rule: NO `cargo test` / `cargo nextest` in this session — tests run in the
unsandboxed commit-hook `nix flake check`, driven by the controller. You run only:

```bash
cargo check -p cesr-rs --features crypto,test-utils
cargo check -p cesr-rs --no-default-features --features alloc,core,b64,crypto
cargo clippy -p cesr-rs --features crypto,test-utils --all-targets
cargo fmt --check -p cesr-rs
```

All must pass warning-free (clippy is deny-everything; fix code, never `#[allow]`
without a compelling `reason` on a specific item).

## Out of scope

- No changes to `Salt` stretch/derivation logic, `SaltError`, `Tier`, or any
  existing public API.
- No `deny.toml`, `clippy.toml`, `[lints]`, or `free-fn-budget.toml` changes.
- No new dependencies (prod or dev).
- No 15/18/21/24-word support — 12 words / 128 bits only.
- No touching other crates.
