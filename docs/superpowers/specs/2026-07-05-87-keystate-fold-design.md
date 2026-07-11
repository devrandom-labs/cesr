# K1 · `KeyState` + pure key-state fold (Kever, minus the database)

**Issue:** [#87](https://github.com/devrandom-labs/cesr/issues/87) (milestone: KERI · sans-io core)
**Date:** 2026-07-05
**Status:** Design approved
**Depends on:** #96 (K0 workspace + `keri-rs` crate — done). **Enables:** K2–K5, K8.
**Spawns:** [#129](https://github.com/devrandom-labs/cesr/issues/129) (C-a),
[#130](https://github.com/devrandom-labs/cesr/issues/130) (C-b) — see
[Follow-up cards](#follow-up-cards).

## Problem & decision

K1 is the foundation of the sans-io KERI core: a `KeyState` value type and a **pure
key-state fold** — keripy's `Kever` (`src/keri/core/eventing.py` L1814–3999) with the
~20 direct `self.db.*` calls removed. Everything downstream (escrow K2, duplicity K3,
delegation K4, receipts K5) consumes it.

**It lives in the `keri-rs` crate, not `cesr`.** The reasoning:

- **Semver blast radius (decisive).** `cesr-rs` is the frozen-ish primitives crate (#86).
  `KeyState` is the churning heart of the state machine — K2–K5 each add fields and
  semantics to it. In `cesr` every such change would force a `cesr` bump, gutting the
  frozen-surface promise. In `keri-rs` it versions independently. This is the K0 mantra:
  *features partition compile-time, crates partition semver.*
- **Layering.** `cesr` = CESR encoding + KERI primitives/wire DTOs. `keri-rs` = KERI
  protocol logic. `KeyState` is the *product of folding events* — it has no meaning
  without the fold. It belongs with the fold.
- **Live API test.** `keri-rs` consumes **only** `cesr`'s public API, so K1 is a standing
  test that the frozen surface is sufficient. Fold-in-`cesr` would erase that.
- **Nothing of value is displaced.** Today's `cesr::keri::KeyState` is a logic-free DTO
  mechanically parked by the keri-core extraction; the fold never existed. K1 removes it
  and builds the real thing in `keri-rs`.

## The nexus decide/apply split

A **candidate** event is validated (fallible); an **accepted** event is folded
(infallible) — the nexus `Handle`/`apply` pattern, which keeps the later KEL-as-aggregate
integration a thin mapping. **No nexus dependency in `cesr`/`keri-rs`** — only the shapes
stay congruent.

```rust
// fallible: candidate event + current state -> verdict (no IO, no mutation, no signature verify)
fn validate(
    state: Option<&KeyState<'_>>,
    event: &KeriEvent,        // owned today; borrowed after card C-a
    sigs: &[Siger<'_>],       // controller signatures — already crypto-verified upstream
    wigs: &[Siger<'_>],       // witness signatures / receipts
) -> Result<Accepted<'_>, Rejection>;   // no signature verification; may hash for next-key commitment

// infallible: fold an ACCEPTED event (facts don't fail)
fn apply(state: Option<KeyState<'_>>, accepted: &Accepted<'_>) -> KeyState<'_>;
```

## Scope

**In scope (K1):**
- `KeyState<'a>` value type in `keri-rs`.
- `validate` / `apply` pure fns + a `fold(state, impl IntoIterator)` convenience.
- Inception / rotation / interaction validation rules ported from keripy (see
  [Validation rules](#validation-rules-ported-from-keripy)).
- Threshold satisfaction — **both** simple and weighted — over an already-verified signer
  index-set (see [Thresholds](#thresholds)).
- `Accepted` / `Rejection` types; `RejectionReason` **placeholder** enum for K2.
- Property tests + keripy happy-path differential chains; no_std + wasm32 green.

**cesr change (minimal):** remove the vestigial owned `cesr::keri::KeyState` and its
re-exports (`cesr/src/keri/mod.rs`, `cesr/src/lib.rs`). Breaking — recorded in `CHANGELOG`.
This is essentially the entire `cesr`-side footprint of K1.

**Out of scope (isolated cards):** escrow taxonomy (K2), duplicity/superseding (K3),
delegation semantics beyond the delegator field (K4), witness receipt collection / TOAD
beyond threshold arithmetic (K5), any storage trait (K6). Plus the two follow-up cards
below.

## Trust boundary — signature verification happens upstream

`validate` does **NOT verify signatures.** It receives a set of `Siger`s that a caller
(the future stream/parse seam) has **already cryptographically verified** against the
canonical event bytes, and it reasons only about KERI *rules* (sequence, prior-digest,
next-key commitment, witnesses) and *threshold satisfaction* over the signed indices.

Rationale: an event's identity is its **SAID**, a digest over its canonical serialized
bytes; the version string bakes the serialization kind into those bytes. **Signature**
verification is the only part of the fold that would need the whole-event serialized bytes
— which is IO/serialization-adjacent. Keeping it at the seam (where the bytes still exist)
lets the fold be serialization-agnostic: by the time an event reaches it, the event is a
bag of typed primitives, indistinguishable whether it arrived as CESR, JSON, CBOR, or an
at-rest archive.

**This is a security-critical seam and MUST be documented on `validate`:** folding an event
whose signatures were never verified is a soundness bug in the caller. The signer index-set
`validate` trusts is the set of indices whose signatures the caller verified.

### The one hash the fold *does* compute — next-key commitment

Rotation must check that the newly-revealed keys match the digests the prior establishment
event committed to (keripy `Diger(ser=verfer.qb64b)` membership in prior `ndigers`). That
is a **hash, not a signature verification**, and — critically — it hashes each key's *own*
qualified-base64 (`Verfer::to_qb64b`), which is **serialization-independent** (a primitive's
canonical CESR form, identical whether the event came from JSON or CBOR). So it neither
breaks serialization-genericity nor is IO. keri-rs therefore enables `cesr`'s **`crypto`**
feature *only* to call `cesr::crypto::digest(code, data)` for this commitment check — never
for signature verification. Concretely, for each revealed key `v` and committed digest `d`:
`digest(d.code(), &v.to_qb64b())?.raw() == d.raw()`.

## Architecture / layering

```
bytes ──(cesr serder: deserialize)──▶ KeriEvent ──(keri-rs)──▶ validate ──▶ Accepted ──▶ apply ──▶ KeyState
        │  wire / IO concern         │            crypto-verify (upstream, at the seam)  │  pure protocol logic
        └─ cesr / serder ────────────┘──────────────── sans-io line ─────────────────────┴─ keri-rs
```

`keri-rs` gains `cesr` features `["core", "keri", "crypto", "alloc"]` (needs `KeriEvent`,
`Siger`, `Tholder`, the typed primitives, and `crypto::digest` for the next-key-commitment
hash — see the [trust boundary](#the-one-hash-the-fold-does-compute--next-key-commitment)).
It stays **off** `serder` and does **no signature verification**.

## Types

### `KeyState<'a>`

Mirrors keripy `Kever`'s state attributes, built from `cesr`'s Cow-backed primitives
(`Verfer<'a> = Matter<'a, VerKeyCode>`, etc.). `Seqner` and `Tholder` are owned (no
lifetime). Lists are **`Cow<'a, [T]>`** — borrow-capable so a future arena parser can
lend a whole slice with zero heap, own a `Vec` otherwise; no dependency, no arbitrary cap.

```rust
pub struct KeyState<'a> {
    prefix: Identifier<'a>,           // Basic|SelfAddressing — a self-addressing AID is a Saider, not a Prefixer
    sn: Seqner,
    latest_said: Saider<'a>,
    latest_ilk: Ilk,
    keys: Cow<'a, [Verfer<'a>]>,
    threshold: Tholder,
    next_keys: Cow<'a, [Diger<'a>]>,
    next_threshold: Tholder,
    witnesses: Cow<'a, [Prefixer<'a>]>,
    witness_threshold: u32,          // TOAD
    config: Cow<'a, [ConfigTrait]>,  // estOnly, doNotDelegate
    delegator: Option<Prefixer<'a>>,
    transferable: bool,
    last_est: EstablishmentRef<'a>,  // sn + said of last establishment event
}
```

- **Borrow-capable, but the fold yields `Cow::Owned`.** State accumulates across events and
  must outlive any single input buffer, so `apply` produces owned data. The `<'a>` +
  `Cow` shape satisfies the acceptance ("zero-copy-friendly borrows") and future-proofs for
  card C-a without forcing `String` getters (the cesride anti-pattern #87 calls out).
- **Getters return typed primitives / borrowed slices** — never `String`/`Vec<String>`.
- `EstablishmentRef<'a>` = `(Seqner, Saider<'a>)` of the last establishment event
  (keripy `lastEst`), needed for rotation prior-digest and superseding logic (K3).
- **`prefix` is `Identifier<'a>`** (not `Prefixer<'a>`): a self-addressing AID (`icp`/`dip`)
  is a `Saider`, a basic AID a `Prefixer`; `Identifier` already models both.
- **`apply` narrows the `KeriEvent` variant once** in `fold::apply` and passes the inner
  event to each ilk's `apply`, so no per-ilk `apply` carries an unreachable arm (keeps the
  no-`panic`/no-`unreachable!` rule clean).

### Event input

K1 consumes today's **owned** `cesr::keri::KeriEvent` (`InceptionEvent`, `RotationEvent`
with `prior_event_said` + `witness_additions`/`witness_removals`, `InteractionEvent`, and
the two delegated variants). Input events are copied at deserialize; since `KeyState`
owns regardless, acceptance still holds. Card C-a later makes `KeriEvent` borrowed so the
fold can take zero-copy input; K1's signatures are written lifetime-generic to absorb that
change without a re-shape of `validate`/`apply`.

### `Accepted<'a>`

A validation certificate: proof the event passed, carrying the **pre-resolved deltas** so
`apply` is a pure, infallible move (no re-derivation, no re-validation).

```rust
pub struct Accepted<'a> {
    event: &'a KeriEvent,             // borrowed candidate
    resolved_witnesses: Cow<'a, [Prefixer<'a>]>, // after applying cuts/adds (rotation)
    // ...precomputed fields apply needs (new sn, new said, key/next sets)
}
```

### `Rejection`

```rust
pub struct Rejection {
    reason: RejectionReason,
    // ...context (expected vs actual sn/digest) for diagnostics
}

// PLACEHOLDER — K2 expands this into the full escrow taxonomy.
#[non_exhaustive]
pub enum RejectionReason {
    OutOfOrder,            // sn gap — K2 will route to out-of-order escrow
    LikelyDuplicitous,     // prior-digest mismatch — K3
    MissingSignatures,     // threshold not satisfied — K2 partial-signed escrow
    InvalidEvent,          // structural rule violation (arity, transferable, ilk)
    // K2/K3 add variants; #[non_exhaustive] keeps that additive.
}
```

`#[non_exhaustive]` so K2/K3 add variants without a breaking change to matching callers.

## Validation rules (ported from keripy)

Semantics verbatim from keripy; behavior confirmed against the keripy differential corpus
(K9). Line refs into `src/keri/core/eventing.py`:

- **Inception (`icp`/`dip`)** — L2228–2316: `sn == 0`; transferable/non-transferable
  consistency vs prefix code; `verfers` arity ≥ 1 and consistent with `keys`; `ndigers`
  (next-key digests) arity vs `next_threshold`; witness list well-formed, `toad` within
  `[0, len(wits)]`; config traits parsed (`estOnly`, `doNotDelegate`); prefix
  self-addressing check (SAID over inception config) where applicable.
- **Rotation (`rot`/`drt`)** — L2483–2531: `sn` sequential (`== state.sn + 1` for the
  in-order path; out-of-order/superseding is K2/K3); `prior_event_said` matches
  `state.latest_said`; **next-key commitment** — the new `keys` must match the digests
  committed in the prior state's `next_keys` under `state.next_threshold`; witness
  cut (`witness_removals`) ⊆ current witnesses and add (`witness_additions`) disjoint from
  the post-cut set; new `toad` within range; `estOnly` forbids non-establishment events if
  set on the state.
- **Interaction (`ixn`)** — `sn` sequential; `prior_event_said` matches `state.latest_said`;
  **no key/threshold/witness change** (anchors only); rejected outright if `estOnly`.
- **Threshold satisfaction** — controller `sigs` satisfy `state.threshold` (current keys)
  and, for rotation, the prior `next_threshold` commitment; witness `wigs` count toward
  `witness_threshold` (TOAD arithmetic only — receipt collection is K5).

Anything that is a *deferral* rather than an *accept* (sn gap, prior-digest mismatch,
partial signatures) becomes a typed `Rejection` whose `reason` K2 routes to the right
escrow; K1 never panics on any input.

## Thresholds

`cesr`'s `Tholder` already carries the data K1 needs:

```rust
pub enum Tholder { Simple(u64), Weighted(Vec<Vec<(u64, u64)>>) }
```

- **Simple (M-of-N):** satisfied when `|signed indices| >= M`.
- **Weighted (fractional):** each key carries a fraction; a clause is satisfied when the
  fractions at the *signed positions within that clause* sum to `>= 1`; a multi-clause
  threshold (`Vec<Vec<_>>`) is satisfied when **every** clause is independently satisfied
  (AND-of-ORs). Positions map to clauses in order.

K1 implements satisfaction in **`keri-rs`**, matching the public `Tholder` enum — **no
`cesr` change**. Arithmetic is **exact rational** (sum `a/b` over a common denominator via
`checked_*`; compare to 1 with no floats — per the arithmetic-safety rule; overflow →
`Rejection::InvalidEvent`, never a saturating cap). `Tholder::satisfy(count)` (which
returns `false` for weighted today) is left untouched; card C-b later promotes a proper
`satisfied_by(indices)` onto the type alongside a leaner representation.

## Error model

- `Rejection` is a single `thiserror` enum for the validation domain (one variant per
  failure domain), `#[non_exhaustive]`, matchable by tests without stringifying.
- `validate` returns `Result<Accepted, Rejection>`; `apply` is infallible (`-> KeyState`).
- Adding/removing a `RejectionReason` variant is a breaking change on the public enum —
  called out in the PR + `CHANGELOG` per active-development policy (`#[non_exhaustive]`
  keeps *additions* non-breaking for external matchers).

## Testing

Per the CLAUDE.md categories, highest-value first:

1. **Round-trip / sequence** — multi-event chains: `icp → rot → ixn → rot`; folding a KEL
   yields the expected `KeyState` at each step; re-applying an already-applied event is
   caught (idempotence/duplicity boundary).
2. **Defensive boundary** — every `Rejection` path is hit by a crafted event (sn gap,
   wrong prior digest, next-key commitment miss, under-threshold sigs, witness cut of a
   non-witness, `ixn` under `estOnly`, oversize `toad`). Each returns the *specific* typed
   variant; none panics.
3. **Cross-feature** — builds/tests under `keri-rs` feature combos; no_std + alloc and
   wasm32 stay green (the flake's `cesr-nostd`/`cesr-wasm` extended to `keri-rs`).
4. **Property (`proptest`)** — threshold satisfaction (simple + weighted, boundaries
   `0`, `1`, exactly-met, one-short, clause groups); sequence monotonicity; next-key
   commitment holds iff keys match the committed digests.
5. **Differential vs keripy (K9 corpus)** — happy-path chains: fold the same KEL in
   `keri-rs` and assert the resulting state matches keripy's `Kever` state field-for-field.

Test quality bars from CLAUDE.md apply: call the real `validate`/`apply`, assert exact
expected state, no `println!`-as-assertion, each invariant tested once canonically.

## Follow-up cards

Filed on the CESR board (GitHub Project #5), milestone *KERI · sans-io core*:

- **C-a — zero-copy event input** ([#129](https://github.com/devrandom-labs/cesr/issues/129)). Reshape `cesr::keri::KeriEvent` + variants to borrowed
  (`<'a>`, `Cow<'a, [T]>` lists), threading lifetimes through `serder`
  serialize/builder/deserialize (~18 files). Unlocks borrowed input into the fold; K1's
  lifetime-generic signatures absorb it without change.
- **C-b — lean `Tholder`** ([#130](https://github.com/devrandom-labs/cesr/issues/130)). Replace `Vec<Vec<(u64, u64)>>` with a leaner/borrowed
  representation (allocation reduction) and promote `satisfied_by(indices)` onto the type,
  moving K1's satisfaction logic behind the primitive it belongs to.

## Acceptance mapping (#87)

| #87 criterion | Where satisfied |
|---|---|
| `KeyState` plain value type, serializable, no_std-clean, zero-copy-friendly borrows, no owned-`String` API | `KeyState<'a>`, Cow-backed, typed getters |
| validate/apply pure fns with property tests (sequence, threshold, commitment) | [The fold](#the-nexus-decideapply-split) + [Testing](#testing) §4 |
| Semantic differential vectors vs keripy (happy-path chains) | [Testing](#testing) §5 |
| no_std + wasm32 build stays green | [Testing](#testing) §3 |
