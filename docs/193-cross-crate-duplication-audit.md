# Cross-crate duplication audit (feeds #193)

**Date:** 2026-07-17
**Scope:** Does production code in `cesr-stream`, `keri-events`, `keri-codec` re-derive
logic that the `cesr` substrate already provides? Cross-check every re-derivation
against the substrate primitive it duplicates.
**Method:** Body-level comparison, not name matching. Name-collision analysis found
**zero** production overlap and was discarded as insufficient — every finding below was
confirmed by reading both function bodies. Each is reproducible from the commands in the
appendix. Test scaffolding excluded (`#[cfg(test)]`, `keripy_diff/`, `keripy_parity/`,
`test_vectors*`).

---

## Verdict at a glance

| Crate         | Confirmed dup | Suspected | Verdict |
|---------------|:-------------:|:---------:|---------|
| `keri-events` | 0             | 0         | Clean consumer. Two architectural notes (below). |
| `keri-codec`  | 0             | 2 (both justified) | Clean consumer. Delegates all substrate ops. |
| `cesr-stream` | **3**         | 2         | The single locus of real duplication — all in `parse.rs`. |

The #192 split partitioned the crates cleanly at the *vocabulary* seam. Duplication
clustered at one *encoding* seam: the stream framer re-deriving qb64 size math because
the substrate exposes no decode-free sizing primitive.

---

## The `cesr` reuse catalog (what already exists)

- **b64** (`cesr::b64`): `encode_int` / `decode_int`, `encode_binary`, `b64_byte_to_index`, `is_b64_url_safe_charset`
- **Matter**: `Matter::{code,soft,raw,to_qb64,to_qb64b}`, `MatterBuilder::{from_qualified_base64,from_qualified_base2,with_raw,with_soft,build}`, `MatterCode::from_base64_stream`, sizage `{hs,ss,ls,fs,xs}`, `compute_full_size` (checked)
- **Counter**: `CounterCodeV1/V2::from_hard`, `{hard_size,soft_size,full_size}` — **no `from_base64_stream`**
- **Indexer**: `IndexerBuilder::{from_qb64 → (Indexer, consumed_len), from_qb2, with_indices, with_raw}`, `Indexer::{raw,full_size,to_qb64,to_qb2,code}`, `hardage(char)`, xizage
- **Crypto**: `digest`, `Diger::{digest,verify}`, `verify`/`verify_indexed`, `KeyPair`/`Ed25519`/`Secp256k1`/`Secp256r1`
- **Version** grammar (`cesr::core::version`) — owner-gated; out of scope

---

## Confirmed duplication — `cesr-stream/src/parse.rs`

| cesr-stream | duplicates (cesr) | proof |
|---|---|---|
| `extract_hard` (parse.rs:57) | counter hard-size table — `code.rs:139` / `v2.rs:278` | Both encode the identical three-way split: `-`→3, `-_`→5, else→2. Re-derived off the wire because Counter has no stream-head reader. |
| `matter_full_size` (parse.rs:89) | `MatterBuilder::from_qualified_base64` size prologue — `builder.rs:105-133` | Step-identical: `from_base64_stream` → `get_sizage()` → `hs`,`ss`,`cs=hs+ss` → `Fixed(n)` else `decode_int(soft[xs..])` then `size*4+cs`. |
| `indexer_full_size` (parse.rs:121) | `IndexerBuilder::from_qb64` size prologue — `builder.rs:81-151` | Step-identical: `hardage` → `IndexedSigCode::from_hard` → `get_xizage()` → `hs`,`ss`,`os`,`cs`,`ms` → `Fixed(n)` else `index*4+cs`. Same calls, same order. |

**Suspected (both in `qb2.rs`, low blast radius — only test-scaffold callers):**

| cesr-stream | overlaps (cesr) | note |
|---|---|---|
| `qb2_to_qb64` (qb2.rs:55) | `b64::encode_binary` (binary.rs:22) | Same RFC-4648 encode; qb2 lacks the partial-length/pad path, so not a structural clone. Alphabet table *is* reused. |
| `qb64_to_qb2` (qb2.rs:24) | base64 decode (used via `Indexer::to_qb2`) | Hand-rolls the 4→3 decode instead of calling the `base64` crate. Reuses `b64_byte_to_index`; re-derives the bit packing. |

### 🔴 The duplication already regressed a safety invariant

`matter_full_size` (parse.rs:108) computes `(size * 4) + cs` with **bare arithmetic** on
`size`, decoded from the attacker-controlled wire soft field. The cesr original it was
copied from routes the identical math through `compute_full_size` (builder.rs:505):

```rust
size.checked_mul(4).and_then(|q| q.checked_add(cs)).ok_or(ValidationError::SizeOverflow)
```

whose doc comment states *"derives from the attacker-controlled soft field, so the
multiplication is checked."* `indexer_full_size` (parse.rs:154) has the same bare
`index * 4 + cs`. This violates the shared **Arithmetic Safety** rule directly. It is
**latent, not live** — current code tables cap `ss ≤ 4` (≤24-bit `size`), so it cannot
overflow `usize` today (32-bit wasm included) — but it is a landmine and the concrete
proof that re-derivation drifts from the hardened source.

Secondary: `read_matter` (parse.rs:232) calls `matter_full_size` to size the `take`, then
hands the exact slice to `from_qualified_base64`, which recomputes `hs/ss/fs` **again** —
the size prologue runs twice per matter read.

---

## `keri-codec` — clean, two justified borderline items

No confirmed duplication. Delegates every substrate op: matter decode via
`from_qualified_base64().narrow::<C>()`; matter encode via `to_qb64()`; hashing via
`cesr::crypto::digest`; stream read/write via `CesrMessage`/`CesrGroup`/`ColdCode` and
`encode_cesr`; version grammar via `VersionString`.

- `verify_said_spans` (said.rs:121) — recomputes a digest and compares, but reuses
  `cesr::crypto::digest` for the crypto; the re-derived step is only the equality, and it
  is justified (takes a caller-supplied `code` to reject weaker algorithms — `Diger::verify`
  locks to the SAID's own code; returns a typed `SaidMismatch`; avoids parsing the borrowed
  `&str` into a `Diger` on the hot path).
- Size backpatch `format!("{size_u32:06x}")` (serialize.rs:288) — cannot call
  `VersionString::with_size` before the body exists; the single-pass offset backpatch is the
  point. The owner tripwire gates grammar tokens, not integer formatting.

---

## `keri-events` — clean consumer, two architectural notes

No cesr-logic duplication (imports/delegates `Prefixer`, `Saider`, `Verfer`, `Diger`,
`Verser`, `Matter`). Two notes, both real, neither a cesr dup:

1. **`SequenceNumber` (sequence.rs:16) is a structural twin of `cesr::core::primitives::Number`.**
   Both wrap `u128` with `new`/`value`. They are separate by *render context* only —
   `SequenceNumber` renders minimal lowercase hex (event-body `s` field, keripy `Number.numh`)
   while `cesr::Number` is the qb64 Matter primitive with `code`/`with_code` but **no hex
   render**. Latent consolidation: collapses if `cesr::Number` grows `numh()` / `LowerHex`.

2. **`seal.rs` carries a ~231-LoC production JSON object scanner** (`scan_object` +
   `scan_string`/`scan_number`/`scan_unicode_escape`/`scan_hex4`/`scan_lit`, seal.rs:219-450,
   all above the `#[cfg(test)]` at 461). The workspace table describes `keri-events` as
   *"pure data, no serialization."* This is a layering violation — see the JSON-scanner pain
   point below.

---

## Cross-crate: two hand-rolled JSON scanners

Neither agent compared the crates against *each other*; this was verified directly.
`keri-events/seal.rs` and `keri-codec/deserialize/canonical.rs` both hand-roll JSON
scanning, but they are **not the same algorithm**:

- `seal.rs::scan_string` — full **RFC-8259**: `\"\\\/`, `\b\f\n\r\t`, `\u` escapes **with
  UTF-16 surrogate pairing**; permissive (opaque/untrusted seal payloads).
- `canonical.rs::Scanner::string` — **strict canonical**: *"no escapes, no control
  characters"*; **rejects** escapes outright.

So this is **partial structural overlap** (object/number/literal walking duplicated across
two crates), not verbatim duplication. The problem is architectural: the permissive scanner
lives in `keri-events`, which sits *below* `keri-codec` in the dependency graph and so
cannot share the codec's scanner upward.

---

## Extracted pain points (ranked)

### P1 — `cesr` has no decode-free "frame size" primitive *(keystone)*
The root cause of every confirmed cesr-stream dup **and** the latent overflow **and** the
double-compute. The framer needs "how many bytes does the primitive at this stream head
span?" without paying for the full base64 raw-decode + canonicality validation.
The substrate offers this **asymmetrically**: `IndexerBuilder::from_qb64` returns the
consumed length, but the Matter builder returns only a `Matter`, and Counter has no
stream-head reader at all. Fixing this one gap collapses `extract_hard`,
`matter_full_size`, and `indexer_full_size` into calls — and, because the shared impl lives
in cesr behind `compute_full_size`, the latent overflow dies for free.

### P2 — Arithmetic-safety regression in `parse.rs`
Bare `size*4+cs` / `index*4+cs` on attacker-controlled input (P1 §). Latent today but a
direct rule violation. Closed automatically when P1 lands; hotfixable now in ~2 lines if we
want it shut independently of the refactor.

### P3 — JSON scanning is scattered and mis-layered
Two hand-rolled JSON scanners in the workspace; the permissive RFC-8259 one lives in a crate
documented as "pure data, no serialization" and below the crate that owns JSON. Not a clean
dedup (different acceptance rules), so this is a *layering/ownership* decision, not a
mechanical merge. Separate workstream from P1.

### P4 — Type twin: `SequenceNumber` vs `cesr::Number`
Same `u128` ordinal concept modeled twice, split by render context. Latent consolidation,
lowest urgency.

### P5 — `qb2.rs` transcoders (suspected)
Whole-stream qb64↔qb2 converters overlapping `encode_binary` / the `base64` crate. Low blast
radius (no production caller). Fold in opportunistically when P1's frame API is designed.

---

## Recommended sequencing

1. **Design the frame-size primitive (P1)** — public cesr API change (#193). Open question is
   the return shape (`fs` only / `(fs, hs)` / a `Frame { hs, ss, ls, fs }` struct), which
   affects all three call sites. Bring options → decision before implementing.
2. **Migrate `parse.rs`** to call it; delete the three helpers; lower the `cesr-stream`
   fn-budget. P2 resolves here.
3. **Decide JSON-scanner ownership (P3)** — independent; likely "move `seal.rs` scanning into
   `keri-codec`" or "extract a minimal shared scanner crate," pending a layering decision.
4. **P4 / P5** — opportunistic, when the adjacent APIs are already open.

---

## Appendix — reproducible commands

```bash
# Confirmed dup — read both bodies side by side:
sed -n '89,115p'  crates/cesr-stream/src/parse.rs           # matter_full_size
sed -n '105,140p' crates/cesr/src/core/matter/builder.rs    # from_qualified_base64
sed -n '121,160p' crates/cesr-stream/src/parse.rs           # indexer_full_size
sed -n '80,150p'  crates/cesr/src/core/indexer/builder.rs   # from_qb64

# Arithmetic-safety drift:
sed -n '105,110p' crates/cesr-stream/src/parse.rs           # (size * 4) + cs  (bare)
rg -n 'fn compute_full_size' -A4 crates/cesr/src/core/matter/builder.rs  # checked

# Counter has only from_hard, no stream-head reader (the asymmetry):
rg -n 'fn from_base64_stream|fn from_hard' crates/cesr/src/core/counter crates/cesr/src/core/matter/code

# Two JSON scanners:
rg -n '^\s*fn scan_\w+' crates/keri-events/src/seal.rs
rg -n 'fn string|struct Scanner' crates/keri-codec/src/deserialize/canonical.rs
```
