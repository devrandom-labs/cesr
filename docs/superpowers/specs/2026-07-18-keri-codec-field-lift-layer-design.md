# keri-codec — the lift/lower layer: `FromWire` + `Field` pipeline

**Date:** 2026-07-18
**Card:** #193 (per-crate redesign). This is the follow-up the ticked
`keri-codec` box did not cover — see "Why the checkbox missed this" below.
**Working mode:** owner-driven (#193). Design decisions below were made by Joel;
this document records them for implementation.

## Problem

`keri-codec`'s read path is three layers:

```
scan (Decode → Parsed* views)  →  SAID-verify (raw bytes)  →  LIFT (Parsed* → domain)
```

`#202` gave layers 1–2 a typed home: the `Encode`/`Decode` traits and the
`ThresholdField`/`CountField`/`ParsedSeal` wire-views, co-located per type under
`codec/*`. **Layer 3 — lift — never got one.** It is a pile of ~32 private
free functions in `deserialize.rs`:

- `parse_qb64_prefixer` / `parse_qb64_verfer` / `parse_qb64_diger` /
  `parse_qb64_saider` / `parse_qb64_verser` / `parse_qb64_identifier`
- `verfers_from_parsed` / `prefixers_from_parsed` / `digers_from_parsed` /
  `anchors_from_parsed`
- `tholder_from_parsed` / `parse_weight` / `witness_threshold_wire` / `parse_sn`
- `seal_from_parsed` / `config_from_parsed`
- the `build_inception` / `build_rotation` / `build_interaction` /
  `build_delegated_*` orchestration that calls them

The write mirror is `primitives.rs` (`to_qb64_string`,
`identifier_to_qb64_string`) plus the same qb64 rendering inlined across ~10
files (103 callsites).

Two concrete smells:

1. **Redundant per-type functions.** `Verfer` **is** `Prefixer` (both
   `Matter<'a, VerKeyCode>`); `Saider` **is** `Diger` (both
   `Matter<'a, DigestCode>`) — verified in `cesr/src/core/primitives/mod.rs`.
   So `parse_qb64_verfer` literally delegates to `parse_qb64_prefixer`: two
   names for one operation. The four `*_from_parsed` collectors are the same
   `iter().map(parse).collect()` shape differing only in the inner fn.

2. **The field name is threaded as a loose positional arg** (`field: &'static
   str`) through every call, only to reach `SerderError::InvalidPrimitive {
   field }`.

### Why the checkbox missed this

The `cesr-fn-ratchet` gate counts only `^pub(\(crate\)|\(super\))? fn` at column
0. The lift pile is **private `fn`** — invisible to the ratchet. That is why
#202 could report "ratchet steady" and tick the `keri-codec` design box while
this layer survived untouched. The gate is blind to private-fn composability
rot by construction; this refactor is the manual catch.

## Goal

Give the lift layer (and its write inverse) a typed, composable home, so client
code in `deserialize.rs`/the writer reads as a uniform pipeline keyed by the
target type — no per-type functions, and the field name travelling **with** the
value it tags rather than as a separate argument.

Wire behaviour is frozen: the keripy differential corpus and the spine
byte-identity tests are the law. This is an internal-representation change only;
the public `Serialize`/`Deserialize` surface is unchanged.

## Decisions (Joel, 2026-07-18)

1. **Trait name: `FromWire` for lift; reuse the existing `Encode` for lower.**
   Only one new trait. `FromWire` echoes `TryFrom` (Rust-native); the crate's
   own `Decode` doc already calls this step "lift", so the intent is documented.
2. **Unify scope: primitives + `SequenceNumber` + seals + list-blanket now;
   thresholds/counts read-only.** `SigningThreshold`/`Toad` get a `FromWire`
   impl for the read/lift side, but keep `ThresholdField`/`CountField` for
   write — those carry the `ThresholdForm` (hex-vs-integer) context that plain
   primitives lack, and #202 just built them. Not re-opened.
3. **Placement: co-located per type (der principle).** Matter-primitive impls in
   a new `codec/field.rs`; `Seal`'s impl beside its `Decode` in `codec/seal.rs`;
   threshold/count lift beside `ParsedTholder`/`ParsedCount` in
   `codec/threshold.rs`. Each type owns all its wire code in one place.

## Design

### The lift trait — `codec/field.rs`

```rust
/// Lift a scanned wire-view `W` into its domain type, tagging any failure with
/// the JSON field it came from. The third pipeline layer: runs after SAID
/// verification, over borrowed scan-stage views.
pub(crate) trait FromWire<'a, W>: Sized {
    fn from_wire(field: &'static str, wire: W) -> Result<Self, SerderError>;
}
```

### The `Field` ergonomic wrapper — `codec/field.rs`

```rust
/// A wire value tagged with the JSON field it belongs to. The field name
/// travels with the value through the lift pipeline, so it is never a loose
/// positional argument and never a bespoke per-type function.
pub(crate) struct Field<'a, W>(pub(crate) &'static str, pub(crate) W);

impl<'a, W> Field<'a, W> {
    pub(crate) fn decode<T: FromWire<'a, W>>(self) -> Result<T, SerderError> {
        T::from_wire(self.0, self.1)
    }
}

impl<'a, W> Field<'a, &'a [W]>
where W: Copy {
    /// Tag a slice of wire values with one field name for list lift.
    pub(crate) fn each(field: &'static str, items: &'a [W]) -> Self { Field(field, items) }
}
```

Client code (in `deserialize.rs`, after SAID verify):

```rust
let said  = Field("d", p.said.value).decode::<Diger>()?;
let keys  = Field::each("k", &p.keys).decode::<Verfer>()?;      // -> Vec<Verfer>
let next  = Field::each("n", &p.next_keys).decode::<Diger>()?;  // -> Vec<Diger>
let sn    = Field("s", p.sn).decode::<SequenceNumber>()?;
let kt    = Field("kt", &p.threshold).decode::<SigningThreshold>()?;
```

### The impls — each deletes a bespoke fn

| `FromWire` impl | Wire `W` | Replaces | Home |
|---|---|---|---|
| `Matter<'a, VerKeyCode>` | `&'a str` | `parse_qb64_prefixer` **+** `parse_qb64_verfer` | `codec/field.rs` |
| `Matter<'a, DigestCode>` | `&'a str` | `parse_qb64_diger` **+** `parse_qb64_saider` | `codec/field.rs` |
| `Matter<'a, VerserCode>` | `&'a str` | `parse_qb64_verser` | `codec/field.rs` |
| `Identifier<'a>` | `&'a str` | `parse_qb64_identifier` | `codec/field.rs` |
| `SequenceNumber` | `&str` | `parse_sn` | `codec/field.rs` |
| `SigningThreshold` | `&ParsedTholder<'a>` | `tholder_from_parsed` + `parse_weight` | `codec/threshold.rs` |
| `Toad` (count) | `&ParsedCount<'a>` | `witness_threshold_wire` | `codec/threshold.rs` |
| `Seal<'a>` | `&ParsedSeal<'a>` | `seal_from_parsed` | `codec/seal.rs` |
| `Vec<ConfigTrait>` | `&[&'a str]` | `config_from_parsed` | `codec.rs` (beside `impl Encode for [ConfigTrait]`) |
| **`Vec<T>` where `T: FromWire<'a, W>`** | `&'a [W]` | **all four `*_from_parsed` collectors** | `codec/field.rs` |

The `Matter<VerKeyCode>` / `Matter<DigestCode>` impls each cover both alias
names because the aliases are the same type — the type-keyed dispatch does what
the delegating functions did by hand.

### Lower (write) side

`to_qb64_string` / `identifier_to_qb64_string` become `Encode` impls (or a thin
`Field(key, &value).encode(out)` per the writer's existing pattern);
`primitives.rs` dissolves into `codec/field.rs` + the existing
`impl Encode for [Matter<C>]` in `codec.rs`. Thresholds/counts keep
`ThresholdField`/`CountField` unchanged (decision 2). The writer's field-emit
seam is unchanged; only the value-rendering helper moves.

### `deserialize.rs` after

Loses the entire lift pile. The `Deserialize` impls stay; the `build_*`
functions remain (they orchestrate a whole event) but their bodies become
`Field(...).decode()?` pipelines. SAID verification
(`verify_single_said`/`verify_inception_said`) stays exactly where it is —
between scan and lift — preserving the ordering the `Decode` contract documents.

## Invariants preserved

- **Byte-identity:** keripy differential corpus + spine byte-identity suites are
  the acceptance gate; every existing roundtrip/tamper test in `deserialize.rs`
  calls the public `Serialize`/`Deserialize` surface and must stay green
  unchanged (they are SUT-level, blind to this internal move).
- **Ordering:** scan → SAID-verify → lift. `FromWire` is strictly the lift step;
  it cannot run before verification because it operates on the already-scanned
  views the verified path produces.
- **Error field-tagging:** `SerderError::InvalidPrimitive { field }` /
  `UnparseablePrimitive { field }` unchanged — the field now arrives via
  `Field.0` instead of a threaded arg. `map_qb64_error` moves into
  `codec/field.rs` as the shared lift-error mapper.
- **Borrow / `into_static`:** `FromWire` returns borrowed `Matter<'a, _>` exactly
  as the current functions do; detachment stays in the `Deserialize` impls.
- **no_std/alloc + WASM:** no new deps; `Field`/`FromWire` are alloc-only where
  the current helpers are (`Vec` results), gated identically.

## Accounting — honest

- **Ratchet:** `keri-codec` 51 → **49** (the two `pub fn`s in `primitives.rs`
  become trait methods). Small, because the pile is private and the gate does
  not count it. Lower the budget to 49 in `free-fn-budget.toml` in the same PR
  (only-down rule).
- **Composability (the actual win):** ~15 of the 32 private free `fn`s in
  `deserialize.rs` collapse into `FromWire` impls + the `Vec` blanket; the four
  `*_from_parsed` collectors become one blanket impl; the two qb64 render
  helpers leave `primitives.rs`. Client code becomes one uniform, type-keyed
  pipeline. Not visible to any gate — measured by reading `deserialize.rs`
  before/after.

## Testing

1. **Round-trip / byte-identity (highest value):** the existing
   `deserialize.rs` roundtrip + tamper + boundary suite must pass unchanged;
   the keripy differential + spine byte-identity suites are the law.
2. **Per-impl unit tests:** one `FromWire` test per impl asserting the exact
   lifted value (and the exact `SerderError` variant + `field` on malformed
   input) — the specific-value rule, not `contains`.
3. **`Vec` blanket test:** `Field::each(...).decode::<Verfer>()` over an empty
   slice, a one-element slice, and a slice with one malformed element (asserts
   the field tag propagates from the blanket).
4. **Boundary / defensive:** feed each `FromWire` impl a non-qb64 string, a
   truncated qb64, a wrong-code qb64 (e.g. a digest where a verkey is expected)
   — must return the typed error, never panic.
5. **Property:** proptest the primitive lift round-trips
   (`encode` then `Field(k, .).decode::<T>()` is identity) with the standard
   boundary corpus (empty / max-length / max-length+1 raw).

## Out of scope

- P4 (`SequenceNumber` vs `cesr::Number` twin) — a separate `keri-events`-pass
  item; this design keeps `SequenceNumber` and only relocates its lift.
- Thresholds/counts write path (`ThresholdField`/`CountField`) — kept as-is per
  decision 2.
- `cesr-stream` and `keri-events` per-crate passes — separate #193 items.
- Any wire-format change — forbidden here.

## Tracking

File as an explicit follow-up on #193 (candidate: "P6 — read/write lift layer
has no typed home") so the ticked `keri-codec` box does not hide it. One PR,
after this spec + plan are approved.
