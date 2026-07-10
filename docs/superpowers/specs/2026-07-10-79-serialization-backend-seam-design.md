# #79 · Pluggable serialization backend — research write-up & seam design

**Status:** research write-up for review — no production code lands until this is approved
(per the card's research-first rule).
**Issue:** [#79](https://github.com/devrandom-labs/cesr/issues/79)
**Builds on:** #67/PR #78 (infallible qb64 encoding), the P1.3 zero-copy stream parsing
design (`2026-07-02-30-zerocopy-stream-parsing-design.md`), and the P0.3 differential
testing architecture (`2026-07-01-p0.3-differential-testing-design.md`).

---

## 1 · Problem

`serder` serializes KERI events through `serde_json`, allocating aggressively on both
hot paths. The crate's stated goals are zero-copy and allocate-last; `serde_json` is a
conformance-convenient default, not a requirement — CESR field ordering and framing are
spec-defined and deterministic, so the wire format does not need serde's general-purpose
data model. We want the serialization backend to be a pluggable component behind a
trait seam: `serde_json` stays the default/reference backend, and an optimized
direct-write backend becomes selectable at the call site, with byte-identical output.

## 2 · Status-quo architecture evaluation

### 2.1 Serialize path (event → bytes): three full JSON renders per event

Every event serializer (`serialize/{icp,rot,ixn,dip,drt}.rs`) follows the same
four-phase pattern (e.g. `serialize_inception`, `serialize/icp.rs:30–94`):

1. **Measure** — build a `serde_json::Map`, insert fields in spec order with a
   `#`-filled SAID placeholder and a zero-size version string, render with
   `serde_json::to_string()` → owned `String`, discarded after `.len()`.
2. **Correct size** — rebuild and render again with the measured size →
   second `String`, discarded.
3. **Compute SAID** — hash the phase-2 bytes (Blake3-256).
4. **Splice** — rebuild and render a third time with the final SAID →
   third `String`, converted to the returned `Vec<u8>`.

Per event that is **three complete JSON serializations**, plus a `.to_owned()` per map
key and `.clone()` per composite `Value` (key lists, seals, thresholds) on every phase
(`serialize/icp.rs:108–128`). `tholder_to_json` (`serialize.rs:168–195`) adds
per-threshold `format!` allocations; `matters_to_json_array` (`serialize.rs:200+`)
allocates one `String` per qb64 primitive.

### 2.2 Deserialize path (bytes → event): re-parse + re-render to verify SAIDs

`deserialize_event` (`deserialize.rs:41–59`) parses the input to a full
`serde_json::Value` tree to dispatch on ilk; the per-ilk function parses **again**;
SAID verification (`verify_said_single`/`verify_said_double`,
`deserialize.rs:287–343`) then mutates the tree (placeholder over `d`, and `i` for
icp/dip) and **re-serializes the whole event** with `serde_json::to_string()` just to
hash it. Net: 2–3 `Value` trees and one full re-render per event ingested.

### 2.3 What is genuinely coupled vs incidental

- **No serde derives exist on any domain type.** All serialization is manual
  `Map::insert` in spec order; all deserialization is manual `Value::get()` field
  extraction. The serde *data model* carries no expressiveness we use.
- **Every scalar in an event body is a JSON string** — sequence numbers and witness
  thresholds are hex strings via `sn_to_hex` (`serialize/icp.rs:34,39`,
  `serialize.rs:146`), keys/digests are qb64 strings, ilks and config traits are
  ASCII constants. There are **no JSON numbers and no floats** on the write path.
- The only load-bearing properties are **spec field order** (today: manual insertion
  order + serde_json's `preserve_order`/indexmap) and **byte determinism**. Both are
  properties of *canonical JSON emission*, not of serde. Verdict: the coupling is
  incidental at the architecture level; `serde_json` is one implementation of a
  deterministic canonical-JSON writer.

### 2.4 The enabling fixed-width facts

- The version string is **fixed 17 bytes**; its size field is `{:06x}`
  (`version.rs:159–170`).
- The SAID placeholder has **the same width as the final qb64 SAID** (44 chars for
  Blake3-256) — that is what makes the current phase-1/phase-2 sizes stable.

Consequence: a backend that records the byte offsets of the size and SAID slots while
writing can serialize **once** and backpatch both slots in place, replacing three
renders with one render + two in-place patches + one hash. The same offsets idea
applies to SAID *verification* on the read path (copy raw once, overwrite the SAID
byte range with `#`s, hash) — no parse-mutate-re-render.

### 2.5 Latent defect found during research (fix under this card)

`VersionString::to_str()` renders `{:06x}` with an unguarded `u32` size
(`version.rs:161–170`). A size above `0xFF_FFFF` silently emits ≥7 hex digits,
breaking the documented 17-byte invariant and corrupting the frame. Same for `{:x}`
major/minor above 15. Per the arithmetic-safety rule this must be a runtime `Err`,
not a silent widening. The seam work touches this exact code, so the guard lands
with it (called out in CHANGELOG; it adds an error condition to serialization).

## 3 · Decision — the seam

### 3.1 Options considered

| Option | Shape | Verdict |
|--------|-------|---------|
| A. Low-level sink trait (`begin_object`/`key`/`value` events) | Backends implement a SAX-style writer; event serializers drive it | Rejected: forces the serde_json backend through an unnatural adapter; the per-ilk field order logic still lives above the seam, so the seam buys nothing A' below doesn't |
| B. High-level backend trait (one `serialize_inception` … per ilk, per backend) | Each backend owns the whole 4-phase pipeline | Rejected: duplicates the SAID/version orchestration per backend — the exact code where a conformance divergence would be catastrophic |
| **C. Body-encoder seam (recommended)** | SAID/version orchestration stays central in `serder`; the seam abstracts only "render this event's canonical JSON into a caller-provided buffer and report the layout (size-slot and SAID-slot byte ranges)" | Orchestration (placeholder, backpatch, hash, splice) is written once and shared; backends only differ in *how bytes get produced*, which is precisely the pluggable part |

### 3.2 Recommended seam (Option C)

```rust
/// Renders one event's canonical JSON body into `buf`, appending.
/// Returns where the fixed-width version-size and SAID slots landed,
/// so the shared orchestration can backpatch and hash.
pub trait EventSerializer {
    /// # Errors
    /// Returns `SerderError` if the event cannot be rendered
    /// (e.g. version-size overflow per §2.5).
    fn render(
        &self,
        event: &KeriEvent<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError>;
}

/// Byte ranges of the backpatchable slots inside the rendered body.
pub struct EventLayout {
    pub size_slot: Range<usize>,       // 6 hex chars inside the version string
    pub said_slots: SaidSlots,         // `d` only, or `d` + `i` for icp/dip
}
```

- **Buffer:** caller-provided `&mut Vec<u8>` (append-only render, then indexed
  backpatch). No `std::io::Write` — the seam must be pure `alloc` for the
  no_std/wasm gates. A caller can reuse one buffer across events (scratch-buffer
  pattern).
- **Backend selection:** plug-and-play at the call site —
  `serialize_with(&backend, &event)`; the existing `serialize(&event)` keeps its
  signature and delegates to the default backend. Purely additive.
- **Two backends in scope:**
  - `SerdeJsonSerializer` — today's `Map` + `to_string` path refactored behind the
    seam with **zero behavior change** (it may keep rendering internally however it
    likes, as long as it reports the layout; locating the fixed-width placeholder
    slots in its output is deterministic).
  - `DirectSerializer` — writes canonical JSON straight into `buf`: field names and
    structure are compile-time constants per ilk; values are qb64/hex/ASCII strings
    (§2.3), so emission is `extend_from_slice` plus a minimal RFC 8259 string
    escaper. One render, two backpatches, one hash. Naming note: final names to
    follow the name-by-domain convention — bikeshed in review, not after.
- **Orchestration after the seam (shared, written once):** render with placeholder →
  backpatch size (checked: `Err` on overflow, §2.5) → hash → splice SAID(s) into
  their recorded slots → wrap in `SerializedEvent`. `SerializedEvent`'s public shape
  (`as_bytes()`, `size()`, `said()`) is unchanged.

### 3.3 Deserialization symmetry — decided: not in the seam, follow-up card

The read-path waste (§2.2) is real but **backend-independent**: offset-based SAID
verification (locate the `d`/`i` value byte ranges, copy raw once into a scratch
buffer, overwrite with `#`s, hash) needs no serialization backend at all — it is an
independent optimization of `verify_said_*`. Making the seam symmetric now would
couple two orthogonal changes and widen this card's blast radius. Decision: the seam
covers the write path; file a follow-up card for offset-based SAID verification on
the read path (it reuses `EventLayout`'s slot vocabulary).

### 3.4 Distinct axis kept out of scope: serialization *kind*

keripy supports JSON/CBOR/MGPK serialization kinds; cesr is JSON-only. Backends here
are **byte-identical implementations of the same kind** — a different axis from
adding CBOR/MGPK (different bytes). The seam's shape (render + layout) would carry a
future kind axis, but nothing in this card designs for it beyond not precluding it
(`SerKind` already exists in `version.rs`). YAGNI applies until a kind card exists.

## 4 · Prior art / crate survey

- **Repo precedent:** the P1.3 zero-copy design evaluated winnow/nom and chose a
  hand-rolled cursor over `bytes::Bytes` — small spec-fixed grammar, no parser
  framework payoff. The same reasoning holds for emission: the grammar is five
  fixed field layouts of string/array/object values.
- **serde_json internals** (Cargo.lock): pulls `itoa 1.0.18` (integer formatting)
  and `zmij 1.0.21` (double-to-string, Schubfach-based, MIT — serde_json's float
  path). KERI event bodies contain no JSON numbers (§2.3), so a direct backend
  needs **neither**; it also drops `indexmap`'s role (field order is emission
  order by construction).
- **[struson](https://lib.rs/crates/struson)** (streaming JSON reader/writer,
  MIT OR Apache-2.0, v0.7.2): self-described experimental with acknowledged
  performance limitations; `std::io`-oriented writer. Rejected.
- **[json-escape](https://crates.io/crates/json-escape)** (no_std, zero-copy escape/
  unescape) and **[json-streaming](https://crates.io/crates/json-streaming)**
  (no_std-capable blocking writer traits): closest external fits. However, the
  escaping surface in KERI events is qb64 (`A–Z a–z 0–9 - _`), hex, and ASCII
  constants — none of which require escaping; a defensive in-house escaper is
  ~a screenful of match arms with exhaustive tests. Taking a dependency to avoid
  that does not clear the bar (and every new dep must pass the `deny.toml`
  allowlist — moot if we add none).

**Survey conclusion:** hand-rolled direct writer, zero new dependencies.

## 5 · Conformance strategy — every backend, byte-identical

Ranked gates, all running under `nix flake check`:

1. **Cross-backend differential property test (primary):** proptest over
   builder-generated events of every ilk (boundary counts: 0/1/many keys, seals,
   witnesses; thresholds simple/weighted) asserting
   `direct_bytes == serde_json_bytes` exactly. Any divergence is a red build.
2. **Existing suites parameterized over backends:** the kel_chain round-trips
   (`cesr/tests/kel_chain.rs`) and serder-path keripy differential coverage run
   per-backend, so keripy stays the external oracle for both.
3. **Cross-path check:** events rendered by the direct backend must deserialize and
   SAID-verify through the *unchanged* serde_json read path.
4. **Allocation budget:** extend the counting-allocator harness
   (`cesr/tests/allocation.rs`) with a per-event serialize test — the direct
   backend's allocation count must not scale with the number of renders (exactly
   one buffer growth path), guarding the regression this card exists to fix.
5. **Benchmarks:** CodSpeed benches for event serialization per backend
   (`cesr/benches/`), reported in the implementation PR (throughput + allocations,
   per the reproducibility rule).
6. **no_std + wasm:** the seam and both backends compile in the existing
   `cesr-wasm` (alloc, no std, serder on) and are exercised by the feature matrix
   in nextest.

## 6 · Migration & compatibility

- `serialize(&event)` / `KeriSerialize` keep their exact signatures and default to
  the serde_json backend → **zero behavior change** for existing consumers.
- New surface: the seam trait, `EventLayout`, `serialize_with`, and the two backend
  types — **additive** (PATCH under 0.x). The §2.5 size-overflow guard adds a new
  error condition on inputs that previously produced corrupt frames — called out in
  CHANGELOG.
- `serde_json` is **not** removed and remains the default; dropping it (or demoting
  it behind a feature) is a separate future decision once the direct backend has
  soaked.
- The keri crate uses serde only in dev-dependencies — unaffected.

## 7 · Error handling & safety

- Slot backpatching uses `checked_*` arithmetic for all offset/range math; any
  layout inconsistency is a typed `Err`, never a panic or `debug_assert`.
- Version-size overflow (> `0xFF_FFFF`) is a runtime `Err` in both backends (§2.5).
- The seam returns the module's bare `SerderError` (single-domain rule); new
  variants (e.g. size overflow) are named by failure domain.
- The direct writer escapes strings per RFC 8259 unconditionally — correctness does
  not depend on the qb64-only observation in §2.3 (that only informs performance).

## 8 · Risks

| Risk | Mitigation |
|------|------------|
| Direct backend silently diverges from serde_json on an untested shape | Gate 1 proptest over builder-reachable event space + keripy oracle (gate 2); divergence fails the flake |
| Layout offsets drift from rendered bytes (backpatch corrupts frame) | Offsets come from the writer itself, not re-scanning; checked-range splices; round-trip + SAID-verify tests catch any corruption immediately |
| Seam shape wrong for a future CBOR/MGPK kind | Explicitly out of scope (§3.4); seam is internal-enough (render + layout) that a kind axis composes later without breaking the trait's users |
| Refactoring serde_json behind the seam changes behavior | Its rendered bytes are asserted identical to pre-refactor fixtures before the direct backend even exists (commit-ordered implementation) |

## 9 · Acceptance criteria (mirrors the card)

- [ ] This write-up reviewed and merged before implementation.
- [ ] Seam exists; `serde_json` refactored behind it with zero behavior change as
      the default.
- [ ] Direct zero-copy backend implemented and selectable plug-and-play.
- [ ] Every backend passes cross-backend differential, keripy differential, and
      round-trip suites (byte-identical).
- [ ] CodSpeed shows the direct backend's allocation/throughput win in the PR.
- [ ] no_std+alloc and wasm green; full `nix flake check` passes.
- [ ] Version-size overflow guard (§2.5) lands with a bug-probe test.
- [ ] Follow-up card filed: offset-based SAID verification on the read path (§3.3).

## 10 · CHANGELOG note (for the implementation PR)

> feat(serder): pluggable serialization backend seam — serde_json remains the
> default backend (unchanged output); new direct zero-copy backend selectable via
> `serialize_with`; serialization now errors on events whose size exceeds the
> version string's 6-hex-digit capacity (previously produced a corrupt frame).
