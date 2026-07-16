# Rung 6 — Zero-copy `KeriEvent<'a>` (#129, #171)

> **Status:** approved design, pre-plan.
> **Parent:** #171 serder domain redesign, rung 6 of 6 (the final numbered rung). Closes **#129**.
> **Baseline:** `main` @ `422f77f` (rung 5 merged — single JSON writer, serde-free production).
> **Companions:** #79 seam design §3.5 (borrowed read path), rungs-4-6 handoff
> (`docs/superpowers/plans/2026-07-14-171-rungs-4-6-handoff.md` §Rung 6).

## 1 · Goal and honest framing

Reshape the five event structs (`InceptionEvent`, `RotationEvent`, `InteractionEvent`,
`DelegatedInceptionEvent`, `DelegatedRotationEvent`) and the `KeriEvent` enum from
owned-`'static` to **borrowed `<'a>`** with `Vec<T<'a>>` lists, threading the
lifetime through serder's deserialize / serialize / builder paths and keri-rs.

> **Amendment (compiler-verified, 2026-07-16):** #129 scoped `Cow<'a, [T]>` lists.
> A rustc variance probe (scratchpad `variance_probe.rs`) proved that `Cow`'s
> `ToOwned` projection makes any containing struct **invariant** in `'a` —
> `&'e Event<'static>` would no longer coerce to `&'e Event<'e>`, forcing a second
> lifetime parameter onto `EventRef`, `Signed`, and every event-reference-storing
> type. `Vec<T<'a>>` lists keep the events **covariant** (probe compiles), preserve
> element-level zero-copy fully (`Matter<'a>` borrows wire bytes — the qb2 payoff),
> and give up only whole-list borrowing at construction, which has no caller this
> rung. Decision: **Vec lists**; #129's wording amended via the PR.

**This rung is API shape, not performance.** The load-bearing fact (verified at
`cesr/src/core/matter/builder.rs:194`): a `Matter`'s decoded `raw` is `Cow::Owned`
*by construction* — base64 decode produces new bytes, so borrowed decoded payloads
are impossible from a qb64/JSON input. #129's own notes concede this ("zero-copy
only materializes for borrow-able formats"). On today's JSON-only read path the
lifetime threading changes almost no allocations. What it delivers:

- **Readiness for a qb2/CESR-native reader** (future card): binary wire bytes ARE
  the raw payload and borrow directly into `Matter<'a>` — the event shape will
  already be there.
- **keri-rs stops pinning `<'static>`** in its signatures; the fold consumes
  events at whatever lifetime the caller holds.
- **One genuine JSON-path borrow**: opaque seal payloads are verbatim text (no
  decode), so `OpaqueSeal<'a>(Cow<'a, str>)` borrows its span for free.

**Byte-identity is law.** Zero wire bytes change. The #145 keripy corpora, the
structural-oracle proptests, and the fixpoint suites gate every commit.

## 2 · Prior state (verified at `422f77f`)

- The strict parser is **already zero-copy**: `canonical.rs`'s `ParsedIcp<'a>`,
  `ParsedRot<'a>`, `ParsedIxn<'a>`, `ParsedDip<'a>`, `ParsedSeal<'a>`,
  `ParsedTholder<'a>` hold only `&'a str` views (canonical.rs:134-157). All owning
  happens in the `build_*` → `parse_qb64_*` conversion layer
  (deserialize.rs:194-513), which calls `.into_static()` on every primitive.
- `Identifier<'a>` is already lifetime-generic (identifier.rs:16); the event
  structs pin it to `<'static>`.
- `Matter::into_static()` is near-free on parsed primitives (raw already owned;
  only the 0-4-byte `soft` clones — matter.rs:148-163).
- keri-rs consumers already borrow (`KeyState<'e>` holds `&'e [Verfer<'static>]`,
  state.rs:79-95) — but they **name `'static` explicitly**, so relaxing the event
  types forces keri-rs signature changes in the same PR (workspace must compile).
- `Seal` has no lifetime; `OpaqueSeal(String)` owns its payload (seal.rs:78);
  the read path allocates it via `(*raw).to_owned()` (deserialize.rs:386-389).

## 3 · Design (single lifetime, Vec lists — #129 amended per the variance probe)

### 3.1 Type shape (`cesr/src/keri/`)

```rust
pub struct InceptionEvent<'a> {
    prefix: Identifier<'a>,                    // unpinned, type already generic
    sn: SequenceNumber,                        // scalar — no lifetime
    said: Saider<'a>,
    keys: Vec<Verfer<'a>>,
    threshold: SigningThreshold,               // pure numbers — no lifetime
    next_keys: Vec<Diger<'a>>,
    next_threshold: SigningThreshold,
    witnesses: Vec<Prefixer<'a>>,
    witness_threshold: Toad,
    config: Vec<ConfigTrait>,                  // lifetime-free items, plain Vec
    anchors: Vec<Seal<'a>>,
    threshold_form: ThresholdForm,
}
```

Same pattern for the other four (`RotationEvent<'a>` adds
`prior_event_said: Saider<'a>` + `witness_additions`/`witness_removals` Vec lists;
`InteractionEvent<'a>` is prefix/sn/said/prior/anchors;
`DelegatedInceptionEvent<'a>` wraps `InceptionEvent<'a>` + `delegator:
Identifier<'a>`; `DelegatedRotationEvent<'a>` wraps `RotationEvent<'a>`).
`KeriEvent<'a>` enum wraps the five.

- **Scalars stay owned**: `SequenceNumber`, `Toad`, `SigningThreshold`,
  `ThresholdForm`, `ConfigTrait` carry no text payload — no lifetime.
- **`Seal<'a>`** — forced, its fields are Matters. Variant shapes unchanged.
- **`OpaqueSeal<'a>(Cow<'a, str>)`** — `new()` keeps the compact-JSON scanner and
  `OpaqueSealError` exactly as today; only the storage generalizes. The read path
  passes the borrowed span instead of `to_owned()`.
- **`into_static()`** on every event type, `Seal`, and `OpaqueSeal`, mirroring
  `Matter::into_static`: recurses through contained Matters and the opaque
  seal's `Cow<'a, str>`. Near-free on JSON-parsed events (raws already owned). This is
  the detach-from-buffer escape hatch for consumers that outlive the input.
- **Accessors keep their current return shapes** (`&[Verfer<'a>]`,
  `&Identifier<'a>`, scalar copies) so the writer and fold code read identically.
- **Covariance is a tested invariant**: with Vec lists the events are covariant
  in `'a` (`&'e Event<'static>` coerces to `&'e Event<'e>`); a compile-time
  coercion probe lands in each event module's tests so a future field change
  that reintroduces invariance fails loudly.
- Existing `is_send_sync_static` assertion tests re-target the `<'static>`
  instantiation (the generic type is `Send + Sync` for any `'a`).

### 3.2 Read path (`serder/deserialize.rs`)

```rust
pub fn deserialize_event(raw: &[u8]) -> Result<KeriEvent<'_>, SerderError>
```
and the five typed fns likewise return `…Event<'_>` borrowing `raw`. Changes are
confined to the `build_*` layer: drop the `.into_static()` calls (Matter `soft`
fields stay `Cow::Borrowed`), pass the opaque-seal span through borrowed. The
`Parsed*<'a>` layer and the SAID scratch copy (`said.rs:127` — inherent to
verification, overwrites the `d`/`i` spans before hashing) are untouched. The
module doc states the decode-allocates constraint plainly so nobody mistakes this
for a JSON-path performance feature.

`KeriDeserialize` (traits.rs) — `fn deserialize(raw: &[u8]) -> Result<Self, …>`
with `Self = InceptionEvent<'static>`? No: the trait gains the lifetime the
GAT-free way — implement on the borrowed type via a lifetime on the impl:
`impl<'a> … for InceptionEvent<'a>` is not expressible with the current
`fn deserialize(raw: &[u8]) -> Result<Self>` (no connection between `raw` and
`Self`'s lifetime). **Decision:** the trait keeps returning owned events —
`fn deserialize(raw: &[u8]) -> Result<Self>` where `Self: 'static` (implemented
for the `<'static>` instantiations by parsing borrowed then `into_static()`,
which is near-free). The borrowed forms are reached through the free
`deserialize_*` fns. This keeps the trait object-safe and avoids GATs; callers
wanting borrows use the fns directly (keri-rs does).

### 3.3 Write path (builders + `serialize/json.rs`)

- Builders keep producing **owned** events: `SerializedEvent<InceptionEvent<'static>>`
  etc., constructing lists via `Cow::Owned` — zero behavior change (#129: "may keep
  constructing `'static` via `Cow::Owned`").
- `EventRef<'e>` holds `&'e …Event<'e>` — one lifetime suffices because the
  events are covariant with Vec lists (callers' `&…Event<'static>` coerce). The writer's accessor-driven rendering is unchanged —
  **zero wire bytes** (corpora + oracle prove it).
- New capability documented but not exercised: constructing events with
  `Cow::Borrowed` lists lent from existing state.

### 3.4 keri-rs ripple + bundled cleanup (one pass, same PR)

Forced by the relaxation (`state.rs`, `authority.rs` name `Verfer<'static>` etc.):

- `KeyState<'e>`, `Signed<'e>`, `Authority<'e>`, `Commitment<'e>` relax the inner
  `'static` to `'e` (covariance makes callers' longer-lived events coerce; slices
  and Matters coerce independently of the event type). A second lifetime
  parameter is added **only where the compiler proves one lifetime is
  insufficient** — start single, escalate per-site with justification in the PR.

Bundled (pending since rungs 1-2, same files, both mechanical + breaking):

- `KeyState.witness_threshold: u32` → `Toad`.
- `KeyState::sn(&self) -> &SequenceNumber` → by-value `-> SequenceNumber`
  (the type is `Copy`; event accessors are already by-value).

### 3.5 Errors

No new variants; no validation moves. `OpaqueSeal::new` keeps its scanner and
`OpaqueSealError`.

## 4 · Public API delta (breaking — MINOR under 0.x)

- Every event type, `KeriEvent`, `Seal`, `OpaqueSeal` gain `<'a>` (existing code
  naming them bare must write `<'static>` or elide `<'_>`).
- Constructor params keep their `Vec<T>` shape (now `Vec<T<'a>>`) — call sites
  are unchanged apart from lifetime inference.
- `deserialize_*` return types borrow the input.
- keri-rs: `KeyState` field/method signature changes incl. bundled `Toad` +
  by-value `sn()`.
- CHANGELOG documents each; PR calls them out.

## 5 · Test plan

1. **Byte identity (the law):** corpora, structural-oracle, fixpoint,
   `*_strict_equals_reference` — all unchanged and green throughout.
2. **Borrow proof:** parse an event with an opaque seal from a buffer; assert the
   seal payload is `Cow::Borrowed` (the compiler enforces the rest of the lifetime
   story — a `KeriEvent<'a>` outliving its buffer is a compile error, which is the
   feature).
3. **`into_static` round-trips:** for each event type, parse → `into_static` →
   re-serialize byte-equal; assert deep equality with the borrowed original.
4. **Allocation pin:** `DESERIALIZE_ALLOCS` (35) re-derived after the
   `into_static()` drops — expected unchanged or lower; any delta documented,
   never silently bumped. `SERIALIZE_ALLOCS` (36) must not change (write path
   untouched).
5. **keri-rs fold differentials** (`keri/tests/differential.rs`) unchanged and
   green — the fold consumes borrowed events through relaxed signatures.
6. Gate: `nix flake check` on committed state, per house rule.

## 6 · Out of scope

- The qb2/CESR-native reader — the card that makes borrowing *pay*; spawns as its
  own issue after this rung.
- Matter-layer decode changes; escrow/attachment/receipt types; any `bytes::Bytes`
  integration (stream module's own arc).
- Exercising write-path `Cow::Borrowed` construction (capability lands, callers
  come with the keri-rs escrow work).

## 7 · Risks

| Risk | Mitigation |
|---|---|
| Lifetime threading changes wire bytes via accessor drift | Corpora + oracle + fixpoint gate every commit; accessors keep identical return shapes |
| keri-rs needs a second lifetime somewhere unforeseen | Escalation rule in §3.4: start single-lifetime, add per-site only on compiler proof, justify in PR. The Cow-invariance trap is already excluded by the Vec decision + covariance probe tests |
| `KeriDeserialize` trait can't express borrowed returns | Decided §3.2: trait stays owned-returning (`into_static`, near-free); borrowed forms via free fns |
| Hidden `'static` bound somewhere (collections, threads) | Surface map found none in keri-rs; fuzz/bench call sites are local scopes; compiler is the final auditor |
