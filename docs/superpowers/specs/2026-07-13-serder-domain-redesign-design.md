# serder Domain Redesign — Design (#171)

**Problem.** The `serder` module is keripy `eventing.py` transliterated into Rust over a
`serde_json` substrate — "python in JSON" — while `keri/src/state.rs` demonstrates the
house style this workspace is converging on: extracted domain types with owned invariants
(`authority().verify()`, `commitment().opened_by()`, typed `Rejection`). This design brings
serder up to that bar without changing a single wire byte.

**Non-negotiable gate.** The #145 differential suite — 26 keripy byte-identity event
vectors, the parity families, and the fold KELs — must stay green at every step. Any
behavioral drift is a red build. This suite is what makes the refactor cheap to attempt.

## Decisions (settled in brainstorm, 2026-07-13)

| Axis | Decision |
|------|----------|
| Type home | `cesr::keri` owns the domain vocabulary; serder = pure codec; core = CESR encoding only |
| Writer | Promote `DirectJson` to the only writer; delete `SerdeJson` + `Value`-tree machinery |
| Intive model | Event-level `ThresholdForm` field (mirrors keripy's single `intive` flag) |
| Migration | Rung ladder — six independently-green PRs |

## 1. Layering

- `cesr::core` — CESR encoding primitives only (`Matter`, qb64/qb2, `Diger`, `Seqner` as a
  CESR Matter, counters). No KERI governance logic.
- `cesr::keri` — the KERI domain: events, `Identifier`, `Seal`, `ConfigTrait`, and (new)
  `Toad`, `SigningThreshold`, `SequenceNumber`, `ThresholdForm`.
- `cesr::serder` — codec only: strict canonical parser, canonical writer, SAID
  verification/computation, version strings. Consumes `cesr::keri` types; owns none of the
  domain vocabulary.
- `keri-rs` (`KeyState` fold) adopts the same vocabulary as a follow-on (its
  `witness_threshold: u32` becomes `Toad`, thresholds become `SigningThreshold`).

`Tholder` migrates out of `cesr::core::primitives` into `cesr::keri` as part of the
`SigningThreshold` redesign. Breaking; called out in CHANGELOG per convention.

## 2. Type vocabulary (all in `cesr::keri`)

### `Toad` — witness threshold
u32 newtype. Constructors own the invariants:
- `Toad::ample(witness_count) -> Toad` — the BFT sufficient-majority formula (moves from
  the free `serder::ample()` function; same checked arithmetic).
- `Toad::exact(value, witness_count) -> Result<Toad, _>` — enforces the keripy rule
  confirmed empirically at pin `de59bc7d` during #145: `value == 0` iff
  `witness_count == 0`, else `1 <= value <= witness_count`. Today this invariant lives
  nowhere in the type system (keripy raises `ValueError`; cesr accepted any u32 at
  construction).
Replaces the bare `witness_threshold: u32` on `InceptionEvent`, `RotationEvent`, the
builders, and (follow-on) `KeyState`.

### `SigningThreshold` — signing threshold (absorbs #130 C-b)
The evolved `Tholder`: `Simple(u64)` / `Weighted(..)` with the leaner clause
representation and `satisfied_by(indices)` from #130. Pure numbers — wire encoding lives
on the event (`ThresholdForm`), never inside the threshold value, so equality stays
arithmetic.

### `SequenceNumber`
u128 newtype whose `Display` renders keripy's minimal lowercase hex (zero renders as
`"0"`, never as an empty string).
Used by events **and** seals: `Seal::Source.s` and `Seal::Event.s` render as hex strings
(`"s":"0"`) in JSON — they were never qb64 in the event body, so carrying the CESR
`Seqner` Matter there was a layering mismatch. `Seqner` remains in `cesr::core` for
genuinely qb64 contexts (streams, receipts). The free `sn_to_hex` helper is deleted.

### `ThresholdForm` — the intive wire fact (#168 by construction)
```rust
pub enum ThresholdForm {
    HexString, // "kt":"2", "bt":"0"  (keripy default)
    Integer,   // "kt":2,  "bt":1    (keripy intive=True)
}
```
One field per establishment event (`InceptionEvent`, `RotationEvent`; delegated wrappers
inherit through their inner event), default `HexString`. Grounded in the #145 findings:
- keripy has ONE `intive` flag per event covering `kt`/`nt`/`bt` together
  (`eventing.py`, `MaxIntThold = 2^32 - 1`);
- `bt`'s wire form is the reliable read-side signal (always numeric-capable, always
  present in v1 icp/rot);
- mixed forms are not in keripy's output language.

Parser: infer the form from `bt`; a simple-numeric `kt`/`nt` whose form disagrees is
rejected as non-canonical (strict-parser philosophy: accept exactly keripy's language).
Writer: render all three fields from the event's form; `Integer` requires the value fit
`u32::MAX` (`MaxIntThold`), enforced at build time.
Builders: `.threshold_form(ThresholdForm)` setter, default `HexString`.
Interaction events have no thresholds and carry no form.

## 3. Writer

`DirectJson` (`serialize/direct.rs`) is already a typed canonical emitter — no `Value`
tree, codex-ordered fields, byte-identical to the reference backend under proptest. It is
promoted to **the** writer and restructured to speak the new vocabulary.

Deleted outright: `SerdeJson`, the `EventSerializer` trait and `serialize_with` plumbing,
`AnchorJson`, `EventBody`, `tholder_to_json`, `seal_to_json`, `matters_to_json_array`,
and the `find_subslice`/`patch_slot`/`abs_range` splice helpers. The dummy-SAID-then-patch
two-pass remains — it is inherent to SAID computation — but the writer records slot spans
by construction as it emits, never by searching the buffer.

`serde_json` leaves the production write path entirely. It remains in the test-only
tolerant reference reader (`deserialize/reference.rs`) and in `OpaqueSeal` handling on the
read side where verbatim JSON text is the domain value.

## 4. Errors

`SerderError::Validation(String)` is split into typed variants, one per failure domain
(e.g. `ToadOutOfRange { toad: u32, witnesses: usize }`,
`IntiveThresholdOverflow { value: u64 }`). No string payloads for domain rule violations.
Each new/changed public variant is a called-out breaking change.

## 5. Test gates

- **Byte-identity corpora unchanged and green at every rung** — `parity/events.jsonl`
  (26 vectors), `said_codes`, `seal_events`, `keystate.jsonl`, `kels.jsonl`.
- The retired cross-backend proptest (`DirectJson` vs `SerdeJson`) is replaced by
  **write→read→write fixpoint properties** against the strict reader over the
  builder-reachable event space (`event_strategies.rs` already provides the strategies).
- Rung 3 flips #168's tracked reds: delete the `TRACKED` entries in
  `keripy_parity/events.rs`, un-`#[ignore]` the probe — the not-stale guard added in #145
  goes red at that moment and forces exactly this cleanup.
- New unit/property coverage per type: `Toad::exact` boundary sweep (0/1/n/n+1),
  `SequenceNumber` display (0, 1, u128::MAX), `ThresholdForm` mixed-form rejection.

## 6. Rung ladder (six independently-green PRs)

1. **`Toad` + typed errors** — new type in `cesr::keri`; `ample()` becomes
   `Toad::ample`; `Validation(String)` split; events/builders adopt `Toad`.
2. **`SequenceNumber`** — events and seals adopt it; `sn_to_hex` deleted.
3. **`ThresholdForm` end-to-end** — field on events, parser inference + mixed-form
   rejection, writer rendering, builder knob. **Closes #168**; tracked reds flip green.
4. **`SigningThreshold`** — Tholder migrates to `cesr::keri` with the lean
   representation + `satisfied_by`. **Closes #130.**
5. **Writer promotion** — `DirectJson` becomes the writer; `SerdeJson` + `Value`
   machinery deleted; fixpoint properties replace the cross-backend gate.
6. **Zero-copy `KeriEvent`** — borrow-ify events across serder. **Closes #129.**

Follow-on (keri-rs): `KeyState` adopts `Toad`/`SigningThreshold` after rungs 3–4.

Each rung: full `nix flake check` green, breaking changes in CHANGELOG, conventional
commit with scope. Every rung leaves the module more domain-typed than it found it; no
rung introduces a compatibility shim that a later rung must remove.

## Out of scope

- CBOR/MGPK/KERI-v2 emitters (permanent v1-JSON scope per `docs/keripy-parity/ledger.md`;
  a general emitter abstraction was considered and rejected as speculative surface).
- Semantic-tier work (#95 K-series) — orthogonal; this epic is representation, not
  verdicts.
- The strict parser's scanner architecture (`deserialize/canonical.rs`) — already the
  right shape; only its conversion layer learns the new types.
