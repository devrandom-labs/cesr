# #68 — Self-addressing builder prefixes (write/read parity)

**Issue:** [#68](https://github.com/devrandom-labs/cesr/issues/68) — *Builders emit only `Identifier::Basic` prefixes — cannot construct a self-addressing KEL chain*
**Type:** correctness / write-path–read-path parity gap (Mandatory-Rule-3)
**Breaking:** yes (pre-1.0 MINOR) — three public setter signatures change; called out in PR + CHANGELOG.

## Problem

The deserializer accepts self-addressing (transferable) KELs that the builders can
never emit. A rotation/interaction event's identifier prefix (`"i"`), and a delegated
inception's delegator (`"di"`), can only be produced as `Identifier::Basic` by the
builders — so a genuine `icp → ixn → rot` chain (where every `"i"` equals the
inception SAID) is unconstructible through the public API.

The narrowing is **only at the builder setters**. Everything downstream already
speaks `Identifier`:

- Event structs already store `Identifier<'static>`: `RotationEvent` (`src/keri/event/rotation.rs:15`), `InteractionEvent` (`src/keri/event/interaction.rs:14`), `InceptionEvent` (`src/keri/event/inception.rs:15`), `DelegatedInceptionEvent` (`src/keri/event/delegation.rs:14`).
- Serialization dispatches both variants: `identifier_to_qb64_string` (`src/serder/primitives.rs:41`).
- Read path decodes both variants: `parse_qb64_identifier` for `"i"`/`"di"` (`src/serder/deserialize.rs:83,122,168,204,214`).

The choke point: builder setters take `Prefixer<'static>` and `build()` calls
`prefix.into()`, and `From<Prefixer> for Identifier` yields `Identifier::Basic`
(`src/keri/identifier.rs:51`). Every builder-produced rot/ixn `"i"` is therefore `Basic`.

## Reference-implementation grounding

Both keripy (`de59bc7d`) and signify-ts treat the prefix as a single qb64 string
carried verbatim across the KEL, distinguished by derivation code:

- Self-addressing `"i"` **is** the inception SAID — keripy computes `d` and `i` as
  Blake3-256 over the *same* dummied event bytes (`serdering.py:2952`, `eventing.py:667-678`);
  signify asserts `sad['i'] === sad['d']` (`eventing.ts:395`).
- `rotate()`/`interact()` assign `pre` directly into `"i"` (keripy `eventing.py:844,944`;
  signify `eventing.ts:196,540`).
- Delegator `"di"` is stored verbatim, validated to be any valid prefix code
  (`PreDex` = key **or** digest) — keripy `serdering.py:2205`.
- **Witnesses are non-transferable by mandate** — keripy docstrings `eventing.py:2660,2917`
  ("qb64 **non-transferable** prefixes of witnesses"), enforced at `:2265`.

## Design

No wire-format change, no event-struct change. Remove the artificial `Prefixer`-only
narrowing at the builder seam, and add an ergonomic bridge from an inception's output
to the next event's prefix.

### 1. Widen three setters

| File / line | Setter | Change |
|-------------|--------|--------|
| `src/serder/builder/rot.rs:82` | `prefix` | param `Prefixer<'static>` → `impl Into<Identifier<'static>>` |
| `src/serder/builder/ixn.rs:62` | `prefix` | param `Prefixer<'static>` → `impl Into<Identifier<'static>>` |
| `src/serder/builder/dip.rs:98` | `delegator` | param `Prefixer<'static>` → `impl Into<Identifier<'static>>` |

- Builder struct fields change `Option<Prefixer<'static>>` → `Option<Identifier<'static>>`
  (`rot.rs:46`, `ixn.rs:42`, `dip.rs:45`).
- In each `build()`, the stored value is already an `Identifier` — pass it straight to
  `RotationEvent::new` / `InteractionEvent::new` / `DelegatedInceptionEvent::new`,
  dropping the `.into()` that collapsed to `Basic` (`rot.rs:253`, `ixn.rs:126`, `dip.rs:211`).
- `impl Into<Identifier<'static>>` keeps every existing `Prefixer` call site compiling
  (via `From<Prefixer>`), while newly accepting `Saider` (via `From<Saider>`) and
  `Identifier` directly.

**Witnesses are untouched** — `b`/`ba`/`br` stay `Vec<Prefixer<'static>>` in both
builders and events. This matches the read path (`parse_qb64_prefixer_array` →
`Vec<Prefixer>`, `deserialize.rs:90,130,211`) and keripy's non-transferable mandate.
Widening them would introduce a *new* write/read asymmetry — the same Mandatory-Rule-3
violation in the other direction.

### 2. The bridge

- Add `SerializedEvent::identifier(&self) -> Option<Identifier<'static>>` in
  `src/serder/serialize.rs`, returning `self.prefix.clone().map(Identifier::SelfAddressing)`.
  `Some(..)` for icp/dip (which store the computed SAID prefix), `None` for rot/ixn.
  This carries the inception's SAID-prefix forward with no JSON re-parse — the same
  "reuse `pre` verbatim" pattern as keripy/signify.
- **Enable owned identifiers for chaining.** `Matter` currently has *no* `Clone` impl,
  so neither do `Saider`/`Prefixer`/`Identifier`. Add `#[derive(Clone)]` to
  `Matter<'a, C>` (`src/core/matter/matter.rs:16`) — every code enum is already
  `Copy + Clone`, so the derive's `where C: Clone` bound is satisfied. This flows `Clone`
  to all primitive aliases (`Saider`, `Prefixer`, `Verfer`, `Diger`, …). Then add
  `#[derive(Clone)]` to `Identifier` (`src/keri/identifier.rs:15`). Result: one
  `identifier()` value can feed both the `ixn` and the `rot` in a chain via `.clone()`.
  `Clone` is opt-in — it adds a capability without forcing any allocation on existing
  paths (cloning a borrowed `Cow` stays borrowed).

### 3. Chaining shape (what a consumer writes)

```rust
// typestate order preserved; only the prefix type widens.
let icp = InceptionBuilder::new().keys(keys)/* …thresholds, next_keys… */.build()?;
let id  = icp.identifier().expect("inception prefix is self-addressing");

let ixn = InteractionBuilder::new()
    .prefix(id.clone())                      // now accepts a self-addressing Identifier
    .prior_event_said(icp.said().clone())
    .sn(1)
    .build()?;

let rot = RotationBuilder::new()
    .prefix(id)                              // same identifier, verbatim
    .prior_event_said(ixn.said().clone())
    .keys(new_keys)/* …next_keys, thresholds… */
    .sn(2)
    .build()?;
```

## Testing

Categories-first (Mandatory-Rule-6), highest-value first:

1. **Round-trip KEL chain (the safeguard that would have caught this).**
   Build `icp → ixn → rot`, feeding each `prefix` from `icp.identifier()` and each
   `prior_said` from the previous event's `said()`. Serialize + deserialize each event;
   assert every event's `"i"` decodes to `Identifier::SelfAddressing` **and** equals the
   inception SAID. Assert the chain is internally consistent (sn increments; each
   `prior_said` = previous `said`).
2. **Delegated variant.** `dip` with a self-addressing `delegator`, round-tripped;
   assert `"di"` decodes back to `Identifier::SelfAddressing`.
3. **Basic path preserved.** Keep the existing `Basic`-prefix builder tests
   (`make_prefixer()` fabrication) — they still exercise a valid path; add
   self-addressing counterparts rather than replacing them.
4. **Setter ergonomics.** Assert `.prefix(prefixer)`, `.prefix(saider)`, and
   `.prefix(identifier)` all compile and produce the expected variant.

## Runnable examples (closes #32 #5/#6)

Add two examples under `examples/` with `required-features = ["serder"]` (matching
`incept_aid.rs` / `multisig_threshold_icp.rs` and their `[[example]]` entries in `Cargo.toml`):

- `kel_chain.rs` — the `icp → ixn → rot` walk-through above, printing each serialized event.
- `delegated_inception.rs` — a self-addressing `dip` with a delegator prefix.

These are gated behind `nix flake check` (`cargo test --doc` / build); they must compile
and run cleanly. `examples/` code may use `expect`/`?` for brevity (not production `src/`).

## Out of scope (evidence-based deviations from the issue checklist)

- **Widening witness fields** — read path is `Prefixer`-only and keripy mandates
  non-transferable witnesses; widening would create a new asymmetry.
- **Renaming the `Prefixer = Matter<VerKeyCode>` alias** — it correctly types keys and
  witnesses; only its *use as the identifier* was the bug, which this change removes.

## Verification

Single gate: `nix flake check` (clippy god-level, fmt, taplo, audit, deny, nextest across
feature combos, doctest, wasm build, no_std build). No production `unwrap`/`expect`/panic;
no bare arithmetic on sizes/offsets; imports at file top.

## Breaking-change note (PR + CHANGELOG)

- `RotationBuilder::prefix`, `InteractionBuilder::prefix`, `DelegatedInceptionBuilder::delegator`
  change parameter type `Prefixer<'static>` → `impl Into<Identifier<'static>>`. Existing
  `Prefixer` call sites keep compiling; new self-addressing call sites are now expressible.
- Additive: `SerializedEvent::identifier()`; `#[derive(Clone)]` on `Matter` (flows to all
  primitive aliases) and on `Identifier`.
