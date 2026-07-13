# keripy Parity — Divergence Ledger

Deliberate, documented divergences between cesr and the pinned keripy
(`scripts/KERIPY_PIN`). Every `divergence`-marked corpus row under
`cesr/tests/corpus/keripy/parity/` and every skipped-row class in
`cesr/src/keripy_parity/` maps to an entry here. **Documented divergence ≠
discovered divergence** — anything the sweeps surface that is not listed
here is a bug.

Temporarily-open gaps are NOT listed here — they live in Rust-side tracked
tables (`TRACKED_SEALS` → #150, said-codes `TRACKED` → #160) beside `#[ignore]`d bug-probes that fail
while the gap exists. #149 (witness semantics) is closed: its
`TRACKED`/`INEXPRESSIBLE` tables are emptied, its probe deleted, and its
rows now assert live in the validation sweep. Per the porting doctrine, a
fix that makes an invalid state unrepresentable at the type level satisfies
the gate — stronger than keripy's runtime `ValueError`.

## Ilks: non-KEL-core message types

cesr implements the 9 KEL-core ilks (`icp` `rot` `ixn` `dip` `drt` `rct`
`qry` `rpy` `exn`). keripy's `Ilks` at the pin carries 21 more — TEL
registry, ACDC, and exchange/disclosure message types: `xip` `pro` `bar`
`vcp` `vrt` `iss` `rev` `bis` `brv` `rip` `bup` `upd` `acm` `act` `acg`
`ace` `sch` `att` `agg` `edg` `rul`. All 21 are carried in `codex.jsonl`
as `divergence`-marked rows. Out of scope for a KEL-core primitives crate.

## Tholder.satisfy: duplicate signer indices (fail-closed dedup)

keripy counts duplicate index entries toward numeric thresholds:
`Tholder(sith=2).satisfy([0, 0]) == True` at the pin. cesr's
`Tholder::satisfy` deduplicates the index list before counting
(`cesr/src/core/primitives/tholder.rs`) — a threshold counts **distinct**
verified signers, so the same row is `false` in cesr. Deliberate
fail-closed security choice, adjudicated to keep cesr's behavior. The
corpus carries the keripy verdict as a marked row
(`formulas.jsonl`: `tholder_satisfy`, `sith=2`, `indices=[0,0]`), and the
anti-rot guard
(`formulas.rs::satisfy_divergences_are_marked_not_dropped`) fails if cesr
ever silently starts agreeing — the marker can only be removed
deliberately.

## Strong-majority ample

keripy `ample(n, weak=False)` maximizes `m`; cesr implements only the weak
form (`ample(n)`, `cesr/src/serder/ample.rs`) and no cesr call site
consumes the strong form — cesr's witness-threshold default is the weak
form, matching keripy's own factory defaults (`ample(n, f=None,
weak=True)`). The 257 `weak=false` rows (n = 0..=256) are carried in
`formulas.jsonl` and counted-and-skipped by
`formulas.rs::ample_matches_keripy_table`; the 257 weak rows are asserted
exactly.

## PreDex: Ed448_Sig (1AAE) self-signing prefix derivation

keripy's `PreDex` includes `1AAE` (`Ed448_Sig`, self-signing Ed448
derivation). In cesr `1AAE` exists only as a signature code
(`SignatureCode::Ed448Sig` / `MatterCode::Ed448Sig`), and `Identifier`
models `Basic | SelfAddressing` derivations only — there is no
self-signing identifier derivation. Ed448 crypto is deferred under the
RustCrypto stable-generation policy (no stable-generation Ed448 crate).
The other 17 `PreDex` codes — the Ed25519/Ed448/ECDSA verkey codes
(including non-transferable variants) and all 9 digest codes — parse and
roundtrip in the `pre` sweep (`codex.rs::codex_tables_match_keripy`).

## Type-system-enforced factory rejections

keripy validates at runtime that `cnfg` and `data` are lists
(`ValueError` otherwise); cesr's builders take `Vec<ConfigTrait>` (config
traits) and `Vec<Seal>` (anchors), so the malformed inputs are
unrepresentable — the invalid state cannot be constructed. The 3 corpus
rows (`validation.jsonl`: `incept/cnfg_not_list`, `incept/data_not_list`,
`interact/data_not_list`) carry `rust_static` markers;
`validation.rs::builder_validation_matches_keripy` counts and skips them,
and `tracked_tables_match_corpus` forbids them from ever appearing in the
runtime-tracked tables.

## intive write emission

keripy `intive=True` is a write-emission option: `kt`/`nt`/`bt` (sith,
nsith, toad) are serialized as JSON integers instead of hex strings
(`eventing.py`; keripy itself notes it is "not standard KERI" and slated
for removal). cesr models this as `keri::ThresholdForm` on the
establishment events (rung 3 of #171): the strict parser infers the form
from `bt`'s wire shape and both writer backends render `kt`/`nt`/`bt` from
it, so intive events round-trip byte-identically (see the resolved #168
note under [Event-tier wire parity](#event-tier-wire-parity-145)). Read-path
integer-form acceptance landed with the #142 strict canonical parser
(`cesr/src/serder/deserialize/canonical.rs`: `ParsedTholder::Number` /
`ParsedCount::Number` accept the integer form).

## Arbitrary anchor dicts (#150 — decided)

keripy accepts fully arbitrary dicts as anchors (`data` is validated only
as being a list). cesr reads the seven codex shapes typed
(`SealBack`/`SealKind` landed with #150) and captures any other JSON
*object* verbatim as `Seal::Opaque` — the strict reader stores the raw
span and both write backends re-emit it byte-for-byte (the SerdeJson
backend injects it via `serde_json::value::RawValue`), so keripy events
with arbitrary anchors round-trip byte-identically.

An anchor object takes the typed path only when it matches a codex shape
at the value level — exact key set, canonical key order, all values JSON
strings. A codex key set with a non-string value or non-canonical key
order falls back to `Seal::Opaque` on the strict path (the tolerant
oracle mirrors the value-level check; key order it cannot see).

Residual divergences from keripy, deliberate:

- A codex-shaped seal whose string values fail primitive parsing (e.g.
  `{"t":"icp","d":<valid SAID>}` — `t` must be a Verser qb64 per keripy's
  own `Castage(Verser)` cast) is a typed error, not an opaque fallback.
  keripy would accept the dict unvalidated; cesr refuses to mis-type it.
  Pinned by `kind_shaped_anchor_with_invalid_verser_errors_on_both_paths`.
- Anchor list items that are not JSON objects (strings, numbers) are
  rejected; keripy allows any list item.
- Opaque payloads must be *compact* JSON (keripy's canonical
  `json.dumps(..., separators=(",", ":"))` form) whose numbers are finite
  f64 values and whose `\u` escapes are valid UTF-16 (surrogates paired) —
  the `OpaqueSeal` scanner is aligned with `serde_json`'s `Value`
  semantics (`float_roundtrip` enabled), property-tested by
  `opaque_scanner_accepts_subset_of_serde_json`. Python-side
  out-of-range values (`json.dumps` emitting `Infinity`/`NaN` or integers
  beyond f64 range) are rejected.
- `c` on v1 `rot`/`drt` is rejected on both read paths (strict:
  `SerderError::NonCanonical`; tolerant oracle:
  `SerderError::UnexpectedField`); config traits are inception-only in
  KERI v1 and the rotation types no longer carry the field.

Pinned by: `keripy_parity::seal_events` (keripy-generated corpus vectors,
byte-identical round-trip), `deserialize.rs` Matrix A (all eight
`ParsedSeal` arms), `mistyped_codex_key_sets_are_opaque_on_both_paths`,
`rot_with_config_field_is_rejected_by_both_paths`.

## Event-tier wire parity (#145)

The event-wire differential (`cesr/src/keripy_parity/events.rs`, corpus
`parity/events.jsonl`) reads every KEL event shape keripy emits at the pin —
all 5 ilks, basic and self-addressing derivations, simple/weighted/multi-clause
thresholds, witnesses with `br`/`ba` and boundary `toad`, every `TraitDex`
config trait, and event-seal anchors — and writes each back byte-identically.

### intive integer thresholds (#168 — resolved)

keripy `intive=True` serializes numeric `kt`/`nt`/`bt` as JSON integers
(`"kt":2`, `"bt":1`); the default serializes them as hex strings (`"kt":"2"`).
`keri::ThresholdForm` on the establishment events retains the wire form (rung 3
of #171): the strict parser infers it from `bt`'s wire shape and both writer
backends render `kt`/`nt`/`bt` from it. The `icp_intive`/`rot_intive` corpus
rows now assert byte-identity in the main
`event_corpus_reserializes_byte_identically` sweep like every other row — the
old `TRACKED` table, `#[ignore]`d probe, and not-stale guard are removed. #168
is closed.

**Live divergence (strictness):** cesr rejects *mixed* wire forms — an event
whose numeric threshold fields disagree (e.g. `"kt":2` with `"bt":"0"`) — as
`SerderError::MixedThresholdForms`. keripy's one-`intive`-flag-per-event model
never emits a mixed event, so this rejects only non-keripy input; it is a
fail-loud strictness choice, pinned by
`deserialize.rs::intive_{bt,kt}_only_is_rejected_as_mixed_form` and
`intive_fixture_bt_flipped_to_hex_is_rejected_as_mixed_form`.

### intive `MaxIntThold` fallback (divergence — fail loud)

keripy renders a numeric threshold as an integer only when `intive` is set AND
the value fits `MaxIntThold = 2^32 - 1`; above that it **silently falls back**
to the hex-string form (`eventing.py`: `kt=(tholder.num if intive and ... num
<= MaxIntThold else tholder.sith)`; keripy's own source comments flag `intive`
as "not standard KERI" and slated for removal). cesr instead treats the
integer form as an explicit, honored constraint: a builder configured with
`ThresholdForm::Integer` and a `Tholder::Simple(n)` where `n > u32::MAX`
returns `SerderError::IntegerFormOverflow` rather than silently switching the
wire form. The caller opted into integer form; a silent hex fallback would
violate that stated intent. On the read path the same magnitude in integer
wire form is rejected as `MixedThresholdForms` (an integer `kt` above
`MaxIntThold` cannot be keripy output). Pinned by
`icp.rs::builder_integer_form_rejects_threshold_above_max_int_thold`.

### JSON-only, KERI/CESR v1 (permanent)

The event corpus is `KERI10JSON` (v1 JSON) only. keripy can also emit CBOR and
MGPK serializations and v2 (`KERICBOR`/`KERIMGPK`, `KERI20…`); cesr's serder
models v1 JSON, matching the KEL-core scope. CBOR/MGPK/v2 event shapes are out
of scope for this crate and are not carried in the corpus.
