# #150 — rot/drt config silent drop + seal codex parity

**Issue:** [devrandom-labs/cesr#150](https://github.com/devrandom-labs/cesr/issues/150)
**Date:** 2026-07-13
**Status:** approved

## Problem

Two coupled gaps found by the builder-expressiveness audit:

1. **Write footgun.** `RotationBuilder::config()` (`cesr/src/serder/builder/rot.rs`)
   and `DelegatedRotationBuilder::config()` (`drt.rs`) accept `Vec<ConfigTrait>`
   and store it into `RotationEvent`/`DelegatedRotationEvent`, but the rot/drt
   serializers never emit a `c` field. That is correct for the KERI v1 wire
   (keripy v1 `rotate()` has no `cnfg` parameter; `c` on rot is v2-only), but
   accept-and-silently-drop violates the round-trip rule. The tolerant oracle
   (`deserialize/reference.rs`) additionally accepts an optional `c` on rot that
   the writer can never produce — a read/write asymmetry.

2. **Read-path blocker.** keripy's seal codex (`structing.py`) defines seven
   shapes; cesr implements five. Missing: `SealBack { bi, d }`
   (registrar-backer) and `SealKind { t, d }` (typed digest). keripy also
   accepts fully arbitrary dicts as anchors (`data` is validated only as a
   list). cesr's strict reader (`deserialize/canonical.rs::seal`) rejects any
   unknown seal shape, so a keripy event anchoring a backer seal fails cesr
   deserialization outright — while cesr already supports the
   `RegistrarBackers` ConfigTrait whose matching seal it cannot read.

## Decisions (user-approved)

- **Config: remove entirely** (not a build-time error). A v1 rotation cannot
  carry config, so the type must not represent it — same
  "unrepresentable invalid state" principle already recorded in the parity
  ledger for `cnfg`/`data` list validation. Breaking change → MINOR bump.
- **Arbitrary anchors: opaque raw variant** (not a documented-strict
  divergence). Unknown anchor shapes are captured as raw JSON and re-emitted
  verbatim, preserving decode→encode byte identity and keripy interop.

## Design

### Part A — remove rot/drt config

- Delete the `config` field and `.config()` setter from `RotationBuilder` and
  `DelegatedRotationBuilder`.
- Delete the `config` constructor parameter, field, and getter from
  `RotationEvent` and `DelegatedRotationEvent`
  (`cesr/src/keri/event/rotation.rs`, delegated counterpart).
- Tolerant oracle: a `c` key present on a rot/drt event becomes a typed error
  (keripy v1 never emits it; rejecting is parity-faithful and removes the
  asymmetry). The strict canonical reader already has no `c` slot for rot.
- Update `event_strategies.rs` rot/drt strategies to drop config.
- Bug-probe tests: reader rejects rot/drt JSON carrying `c`; writer output for
  rot/drt asserted to contain no `"c"` key.
- CHANGELOG entry + PR callout (breaking).

### Part B — seal codex parity

New `Seal` variants (`cesr/src/keri/seal.rs`), types per keripy's `Structor`
casts (`structing.py:243-245`: `bi` → Prefixer, `t` → Verser):

```rust
/// Registrar-backer seal — nontrans backer prefix + metadata digest.
Back { bi: Prefixer<'static>, d: Saider<'static> },
/// Typed digest seal — digest type tag + SAID.
Kind { t: Verser<'static>, d: Saider<'static> },
/// Non-codex anchor — raw JSON object preserved verbatim.
Opaque(OpaqueSeal),
```

`OpaqueSeal` is a newtype over the raw JSON object text with a validated
constructor (must be a well-formed JSON object; construction returns
`Result`). No unvalidated public construction.

Wire-through, all four surfaces:

- **Writers** — both `serialize/direct.rs::write_seal` and its mirror
  `seal_to_json` gain `Back`/`Kind` arms (fixed field order `bi,d` / `t,d`)
  and an `Opaque` arm that emits the stored span verbatim.
- **Strict reader** — `canonical.rs::seal` gains `"bi":` and `"t":` first-key
  branches (no prefix collisions with existing `d`/`rd`/`s`/`i`). If an anchor
  object fails codex-shape parsing, the scanner rewinds to the object start
  and captures it with a string/escape-aware balanced-brace skipper →
  `ParsedSeal::Opaque(raw_span)`.
- **Conversion** — `deserialize.rs::seal_from_parsed` parses `bi` as Prefixer,
  `t` as Verser qb64, `d` as Saider; Opaque passes the span through
  `OpaqueSeal`.
- **Tolerant oracle** — `reference.rs` seal parsing gains both typed shapes
  and the opaque fallback.

**Fallback policy (recorded in the parity ledger as the #150 outcome):** only
objects that do not match any codex *shape* fall back to Opaque. A
codex-shaped seal whose primitives fail to parse (e.g. invalid qb64 in `d`)
still errors. keripy would accept even that malformed case; the residual
divergence is documented, not hidden.

### Corpus

Generate a keripy event anchoring a `bi` (SealBack) seal with the local keripy
env and add it as a checked-in vector (feeds the #145 event corpus); test
asserts it deserializes and round-trips byte-identically.

### Ledger

Replace the pending entry in `docs/keripy-parity/ledger.md` ("Arbitrary anchor
dicts") with the decided policy: opaque round-trip for unknown shapes,
documented residual divergence for shape-matched-but-invalid primitives, `c`
on v1 rot/drt rejected.

## Testing

Per the repo's category-first rules:

1. **Round-trip** — encode→decode→encode byte identity for `Back`, `Kind`,
   `Opaque`, and mixed seal arrays.
2. **Defensive boundary** — truncated opaque object, unbalanced braces,
   escaped quotes and nested objects/arrays inside opaque spans, non-object
   anchor entries, codex-shaped seal with invalid primitives (errors),
   rot/drt JSON carrying `c` (errors).
3. **Cross-feature** — existing nextest feature matrix covers the new arms;
   no new feature gates introduced.
4. **Property-based** — proptest over seal arrays mixing all eight parse
   outcomes, opaque payloads including empty object, deep nesting, and
   escape-heavy strings.
5. **Bug-probe** — writer output for rot/drt contains no `"c"`;
   keripy-generated `bi` vector deserializes (fails while the codex gap
   exists).
