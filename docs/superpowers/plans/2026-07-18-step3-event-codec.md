# Step 3: Event Grammar → codec/* — Implementation Plan (#193)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the keri-codec grammar migration: thresholds, witness count, qb64/config arrays, version head, and the five event bodies all become `Encode`/`Decode` impls in `codec/*`; `serialize/json.rs` and `deserialize/canonical.rs` **cease to exist** (owner direction: no shims, no preserved shells). `EventLayout` slot-tracking folds into a stateful `BodyWriter`.

**Architecture:** Same verbatim-move discipline as Steps 1–2 (all bodies copied from the in-tree tested code; byte-identity is the law — keripy differential + spine suites green at every task). New modules: `codec/threshold.rs` (threshold/count grammar, with `ThresholdForm`-carrying wrapper types per der's context-wrapper precedent), `codec/event.rs` (BodyWriter + the five event grammars + head + parse entry points + the `Parsed*` view types), `codec/scanner.rs` (Scanner + list combinators move out of the dissolving canonical.rs). The public serde surface (`KeriSerialize`/`KeriDeserialize`, `SerializedEvent`, SAID computation in `serialize.rs`/`deserialize.rs`) is unchanged until the final rename task, which is presented to Joel as a decision. Ratchet: moving free fns between files keeps counts; converting them to impls/methods LOWERS the count — re-baseline down at the end.

**Tech Stack:** as Steps 1–2. Verification per task: `nix develop --command cargo nextest run -p keri-codec`; final gate `nix flake check` on committed state.

---

## End-state file map

- `codec.rs` — traits + `JsonWriter` (unchanged) + `pub(crate) mod threshold; pub(crate) mod event; pub(crate) mod scanner;`
- `codec/scanner.rs` — `Scanner`, `Spanned`, `tail_list`, `delimited_list`, `string_array` (moved verbatim from canonical.rs).
- `codec/threshold.rs` — `ParsedTholder`/`ParsedCount` (defs moved), `impl Decode for ParsedTholder/ParsedCount` (from `tholder`/`weighted`/`count`), `ThresholdField<'_>`/`CountField` wrapper structs implementing `Encode` (bodies from `write_tholder`/`write_toad`/`write_weight_clause`/`weight_to_string`).
- `codec/seal.rs` — unchanged (Step 2).
- `codec/event.rs` — `ParsedIcp/ParsedDip/ParsedRot/ParsedIxn/ParsedEvent` (defs moved), `BodyWriter` (buf + placeholder + recorded slots; `write_head` folds in as a method), event-body encode via `EventRef` impl (from `render`/`render_icp`/`render_rot`/`render_ixn`), `impl Decode for ParsedIcp/...` (from `icp_fields`/`*_body`), `head`, `require_ilk`, `parse_event`/`parse_*` entry fns (moved verbatim, still free `pub(crate) fn` — already counted, no increase), `write_qb64_array`/`write_config_array` as private fns.
- `serialize/json.rs` — **DELETED** (its `render` entry moves to `codec/event.rs`; `serialize.rs` calls `codec::event::render`). Its tests move to `codec/event.rs`.
- `deserialize/canonical.rs` — **DELETED** (its tests move to `codec/event.rs` / `codec/scanner.rs`; `deserialize.rs` imports switch to `crate::codec::{event, scanner}` paths).
- `free-fn-budget.toml` — keri-codec budget LOWERED to the recount (several `write_*`/grammar free fns become impls/private).
- `CHANGELOG.md` — internal-refactor entry; plus the rename-decision outcome if taken.

## Sequenced tasks (each: move verbatim → retarget call sites → nextest green → commit)

### Task 1: `codec/threshold.rs`
- Move `ParsedTholder`, `ParsedCount` defs from canonical.rs; `impl<'a> Decode<'a> for ParsedTholder<'a>` (body of `tholder`, with `weighted` as private fn), `impl<'a> Decode<'a> for ParsedCount<'a>` (body of `count`).
- Wrapper encodes (der ContextSpecific precedent — the wire form of `kt`/`nt`/`bt` is (value, form)):
```rust
pub(crate) struct ThresholdField<'a> {
    pub(crate) threshold: &'a SigningThreshold,
    pub(crate) form: ThresholdForm,
}
impl Encode for ThresholdField<'_> { /* verbatim write_tholder body */ }
pub(crate) struct CountField {
    pub(crate) toad: Toad,
    pub(crate) form: ThresholdForm,
}
impl Encode for CountField { /* verbatim write_toad body */ }
```
  with `weight_to_string`/`write_weight_clause` as private fns alongside.
- Retarget: json.rs `write_tholder(buf, e.threshold(), form)` → `ThresholdField { threshold: e.threshold(), form }.encode(buf)`; `write_toad(buf, t, form)` → `CountField { toad: t, form }.encode(buf)`; canonical.rs `tholder(sc)` → `ParsedTholder::decode(sc)`, `count(sc)` → `ParsedCount::decode(sc)`. Move the threshold-specific tests (canonical.rs `weighted_*`, `tholder_*`, json.rs threshold render tests) into codec/threshold.rs.

### Task 2: array encodes into codec
- `impl<C: CesrCode> Encode for [Matter<'_, C>]` (verbatim `write_qb64_array`) and `impl Encode for [ConfigTrait]` (verbatim `write_config_array`) — in codec.rs (small, shared) or codec/event.rs; retarget json.rs call sites to `e.keys().encode(buf)` etc.

### Task 3: `codec/scanner.rs` + `codec/event.rs` — the dissolution
- Move `Scanner`+`Spanned`+list combinators to codec/scanner.rs (verbatim; canonical.rs shrinks to the event grammar).
- Create codec/event.rs: move `Parsed*` defs, `head`, `require_ilk`, `icp_fields`, `*_body`, `parse_*` (verbatim); `string_array` private here (or scanner.rs, wherever it lands cleanly).
- `BodyWriter` folds `write_head` + slot recording:
```rust
pub(crate) struct BodyWriter<'b> {
    buf: &'b mut Vec<u8>,
    placeholder: &'b str,
    size: Range<usize>,
    said: Range<usize>,
    prefix: Option<Range<usize>>,
}
```
  `render_icp/rot/ixn` bodies move as `BodyWriter` methods or `EventRef`-matched fns producing `EventLayout` exactly as today (verbatim byte emission; only the plumbing of slot ranges changes shape). `serialize.rs::render` call site retargets; `EventLayout` stays where its consumers are (serialize.rs) or moves — whichever keeps the diff verbatim; NO behavior change.
- Delete `serialize/json.rs` and `deserialize/canonical.rs`; move their remaining tests to the new modules (verbatim, retargeted paths); fix `deserialize.rs`/`serialize.rs` imports.

### Task 4: rename decision (JOEL DECIDES — prepare options, do not execute unilaterally)
- The card flags `KeriSerialize`/`KeriDeserialize` → `Encode`/`Decode` (der precedent). Complication discovered in execution: crate-internal `codec::Encode`/`Decode` now exist and are *wire-grammar* traits; the public traits are the *SAID-computing serde surface* — different contracts. Present options: (a) rename public traits `Encode`/`Decode` and rename the internal pair (e.g. `WireEncode`/`WireDecode`); (b) keep public names, defer; (c) unify surface. Recommendation prepared at execution time with the code in front of us.

### Task 5: CHANGELOG + ratchet re-baseline (downward) + `nix flake check` gate + independent review, then PR.

## Constraints carried forward
- Verbatim moves only; the keripy differential + spine byte-identity suites are the law.
- No public-surface change except the (owner-decided) Task-4 rename.
- Ratchet never raised; lowered to the exact recount in the same PR.
- Tests move WITH their grammar; each invariant keeps one canonical location.
