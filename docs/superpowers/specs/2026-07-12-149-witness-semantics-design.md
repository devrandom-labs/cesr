# Witness semantics parity in establishment-event builders (#149)

**Date:** 2026-07-12
**Issue:** [#149](https://github.com/devrandom-labs/cesr/issues/149) — fix(serder): witness
semantics parity in builders — prior wits, toad default + bounds, dedup/cut/add validation
**Depends on:** #147 (`ample`, closed) · **Reference:** keripy `de59bc7d`
`src/keri/core/eventing.py` — `incept()` (~lines 624–640), `rotate()` (~lines 788–831)

## Problem

keripy's event factories validate witness configuration; cesr's builders accept anything:

- `RotationBuilder` / `DelegatedRotationBuilder` carry no prior-witness set, default
  `bt` to `0` even alongside non-empty `ba`, and never bounds-check an override.
- `InceptionBuilder` / `DelegatedInceptionBuilder` skip duplicate-witness and toad
  bounds checks.

Our builders therefore emit events keripy's factory refuses to create and keripy
validators reject.

## Decision: prior wits are required via typestate

The rotation builders gain a `NeedsPriorWitnesses` typestate (user decision, chosen
over an optional setter with empty default and over not carrying prior wits):

```
RotationBuilder:          NeedsPrefix → NeedsPriorSaid → NeedsKeys → NeedsPriorWitnesses → Ready
DelegatedRotationBuilder: NeedsPrefix → NeedsPriorSaid → NeedsKeys → NeedsPriorWitnesses → Ready
```

`prior_witnesses(Vec<Prefixer<'static>>)` transitions `NeedsPriorWitnesses → Ready`.
An identifier with no witnesses states that explicitly with `vec![]`. Rationale:
the cut/add set relations and the toad default are functions of the prior set;
making it required renders the dependency visible in the type system instead of
keripy's silent `wits=None → []` default.

Prior wits are **validation-only input** — a `rot`/`drt` event serializes only
`br` (cuts), `ba` (adds), `bt` (toad); the prior list never appears on the wire.

**This is a breaking change** (MINOR bump under 0.x): CHANGELOG entry + PR callout.

## Validation semantics (exact keripy port)

New `pub(crate)` domain module `cesr/src/serder/builder/witness.rs`, shared by all
four establishment builders. All failures are `SerderError::Validation` naming the
offending field. `Prefixer` equality is `Matter`'s derived `Eq` (code + raw + soft
⇔ qb64 identity, matching keripy's string-set semantics); witness lists are small,
so duplicate/membership checks are pairwise `==` over slices — no `Hash`/`Ord`,
no allocation beyond the returned new set.

**Inception (`icp`/`dip`)** — keripy `incept()`:
1. `wits` must be duplicate-free.
2. toad default: `0` if no wits, else `ample(len(wits))` (already implemented).
3. toad bounds: wits non-empty ⇒ `1 ≤ toad ≤ len(wits)`; wits empty ⇒ `toad == 0`.

**Rotation (`rot`/`drt`)** — keripy `rotate()`, in keripy's order:
1. `wits` (prior), `cuts`, `adds` each duplicate-free.
2. `cuts ⊆ wits`.
3. `adds ∩ wits = ∅`.
4. `cuts ∩ adds = ∅`.
5. New set = `(wits − cuts) ∪ adds`. keripy's subsequent size check
   (`len(newitset) != len(wits) - len(cuts) + len(adds)`) is provably redundant
   given 1–4 (keripy's own source comments `# redundant?`); documented here,
   not ported — no input can trigger it.
6. toad default: `0` if new set empty, else `ample(len(new set))` — replaces the
   current `unwrap_or(0)`.
7. toad bounds: as inception, against the **post-rotation** set.

## Parity harness updates (`cesr/src/keripy_parity/validation.rs`)

- `replay_rotate` / `replay_deltate` pass `.prior_witnesses(prefixers(p, "wits"))`.
- The 4 `INEXPRESSIBLE` rows (`dup_wits_prior`, `cut_not_in_wits`,
  `add_already_in_wits`, `toad_gt_new_wits`) become expressible and join the live
  sweep; the table empties.
- `TRACKED` (8 rows) empties; the `#[ignore]` probe
  `tracked_validation_rows_reject_149` is deleted — its documented purpose is to
  fail while the gap is open, and the live sweep now asserts every row.
- The stale-entry guard (`tracked_tables_match_corpus`) keeps the tables honest.

## Call-site updates

`cesr/examples/kel_chain.rs`, `cesr/tests/kel_chain.rs`,
`cesr/src/keripy_parity/validation.rs`, `keri/tests/common/mod.rs`, and doc
examples in `builder.rs`/`mod.rs`/`lib.rs` gain `.prior_witnesses(...)`.

## Tests

1. **Per keripy `ValueError` case, one typed builder test** asserting
   `SerderError::Validation` on the owning builder — rot and drt each: dup prior
   wits, dup cuts, dup adds, cut not in wits, add already in wits, cuts∩adds,
   toad > new set, toad 0 with non-empty new set, toad ≠ 0 with empty set;
   icp and dip each: dup wits, toad > wits, toad 0 with wits, toad ≠ 0 without wits.
2. **toad default = `ample`** on rot/drt: 4 prior − 1 cut + 2 adds → `bt` =
   `ample(5)` = `"4"`; and icp regression stays.
3. **Round-trip** with witnesses through the new chain.
4. **Weighted-threshold half-gap** (acceptance item): at least one builder test
   constructs a valid weighted-threshold event end-to-end (build → deserialize →
   assert `kt`).
5. **Gate:** `nix flake check` — keystate differential and parity sweeps stay green.

## Acceptance (from #149)

- [x] Each keripy `ValueError` case has a matching typed `SerderError::Validation` builder test
- [x] keystate differential stays green
- [x] Weighted-threshold half-gap closed: one valid weighted-threshold event built end-to-end
