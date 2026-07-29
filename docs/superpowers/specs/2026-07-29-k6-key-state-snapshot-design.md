# K6 — Key-state snapshot duality: the sans-io seam (issue #92, reframed)

**Date:** 2026-07-29
**Issue:** [#92](https://github.com/devrandom-labs/cesr/issues/92) (body to be rewritten to this scope)
**Crate:** `keri-rs` (`crates/keri`)
**Status:** approved design, pre-implementation

## 1. Reframe — why the original #92 is dead

The original #92 (2026-07-05, pre-K1) proposed a `KelProvider` storage-lookup trait,
a verdict-output `Acceptance` struct, and a `MemKel` in-memory reference store. All
three were derived from keripy's `Kever`/`Kevery` ↔ `Baser` architecture. That
derivation was the mistake: keripy is a conformance oracle for **wire and
validation semantics only**, never an architecture template. keripy needs a
50-table `Baser` because Python has no event-sourcing substrate; we have one as a
sibling project (mnesis).

The future KERI identity implementation will be built nexus-side on
**mnesis + mnesis-store + the fjall adapter**. In that model the KEL is not a
thing `keri-rs` builds or abstracts over — **the KEL is the event stream the host
already persists**. Cross-identifier evidence (a delegator's sealing event, witness
receipts) arrives *inside the command* (fat-command pattern, enriched by the
host's runtime/saga), never through a synchronous lookup from inside validation.

Therefore:

- **No `KelProvider` trait.** Nothing in `keri-rs` looks anything up.
- **No `MemKel`.** The host's in-memory adapter already exists.
- **No `Acceptance` verdict struct.** `Result<KeyState, Rejection>` already is the
  verdict; escrow classification of `Rejection` variants is K2's job.
- **No mnesis dependency — ever.** `keri-rs` stays dependency-pure sans-io.
  Compatibility is **by shape, not by dependency** (§5).

What remains — the real K6 — is the seam `keri-rs` must expose so an
event-sourced host can hold key state: an **owned snapshot** of the borrowed
`KeyState<'e>`, and a **total, infallible trusted fold** for replay.

## 2. Architecture — two folds over one domain

| | Validating fold (exists, K1) | Trusted fold (new, K6) |
|---|---|---|
| Surface | `KeyState::incept(&Signed)` / `KeyState::ingest(&Signed)` | `KeyStateSnapshot::genesis(&InceptionEvent)` / `KeyStateSnapshot::advance(&KeriEvent)` |
| Time | decide — an event is *proposed* | apply/replay — an event is *settled* |
| Input | parsed event + signed bytes + signatures + receipts | parsed event only (no signatures — facts carry no proof obligations) |
| Crypto | full: controller signatures, next-key commitment, witness receipts | none |
| Fallibility | `Result<_, Rejection>` | total, infallible |
| State | `KeyState<'e>` — borrows the events the caller keeps alive | `KeyStateSnapshot` — owned, `'static`, `Send + Sync` |

The host's decide step (mnesis `Handle` or anything else) rehydrates or loads a
`KeyStateSnapshot`, lends the zero-copy working view via `.view()`, runs the
validating fold, and on `Ok` records the event. The host's apply/replay step
folds recorded events with `advance` — crypto-free rehydration. keripy re-verifies
signatures on every boot inside `Kever.update`; the trusted fold is what makes our
rehydration cheap.

The duality is the `PathBuf`/`Path`, `String`/`str` idiom: one owned carrier, one
borrowed working view, conversions both ways.

## 3. Types

All additions live in `crates/keri/src/state.rs` alongside `KeyState` (same
module → private-field access; **no public change to `KeyState`**, K1 tests
untouched).

```rust
/// Owned snapshot of a [`KeyState`]: the storage-facing carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStateSnapshot {
    prefix: Identifier<'static>,
    sn: Number,
    latest_said: Said<'static>,
    latest_message_type: MessageType,
    keys: Vec<VerifyingKey<'static>>,
    threshold: SigningThreshold,
    next_keys: Vec<Digest<'static>>,
    next_threshold: SigningThreshold,
    witnesses: Vec<BasicPrefix<'static>>,
    witness_threshold: Toad,
    config: Vec<ConfigTrait>,
    delegator: Option<BasicPrefix<'static>>,
    transferability: Transferability,
    last_est_sn: Number,
    last_est_said: Said<'static>,
}

impl KeyStateSnapshot {
    /// Lend the zero-copy working view (the `PathBuf → &Path` edge).
    #[must_use]
    pub fn view(&self) -> KeyState<'_>;

    /// Trusted seed: fold an ACCEPTED inception. Total, crypto-free.
    #[must_use]
    pub fn genesis(icp: &InceptionEvent<'_>) -> Self;

    /// Trusted step: fold one ACCEPTED event. Total, crypto-free.
    #[must_use]
    pub fn advance(self, event: &KeriEvent<'_>) -> Self;
}

/// Own everything out of a working state (the `&Path → PathBuf` edge).
impl From<&KeyState<'_>> for KeyStateSnapshot;
```

`'static` fields are owned cesr primitives obtained via the existing
`into_static()` — no leaks, no new primitive machinery. `view()` constructs a
`KeyState<'a>` whose borrows point into the snapshot's owned fields.

## 4. Totality of the trusted fold — the one subtle rule

`advance` must be a total function: no `Result`, no panic, no `unwrap`, no
`debug_assert` safety theater. Accepted events were already validated at decide
time, so the error branches of the validating fold are unreachable *on real
input*; totality is achieved **by construction**, not by assertion:

- **Witness cut/add** becomes idempotent set algebra: cutting an absent prefix is
  a no-op; adding a present prefix is a skip. (The validating fold's
  `WitnessSetError` branches reject these at decide time; the trusted fold just
  computes.)
- **Interactions** skip the establishment-only config check and the
  prior-SAID/sequence check; sequence number and latest SAID are taken from the
  event.
- **Rotations** roll keys/thresholds/commitment forward without opening the
  commitment (no digest verification).
- **A second inception** or a `dip`/`drt` in the stream folds deterministically:
  `dip`/`drt` carry their fields as-is minus delegation checks until K4 extends
  both folds; a repeated `icp` re-seeds. On corrupted input `advance` stays
  deterministic instead of panicking — garbage in, deterministic garbage out,
  and the host's store integrity (hash-chained, SAID-addressed events) is the
  layer that makes corrupted input unreachable.

On every genuinely accepted sequence the trusted fold computes **identically** to
the validating fold — pinned by the differential property in §6.

## 5. Host-compatibility constraints (shape, not dependency)

The future identity impl hosts `keri-rs` through mnesis. `keri-rs` never names
mnesis; these shapes keep the seam frictionless:

1. `KeyStateSnapshot` is `Send + Sync + Debug + 'static` + `Clone` — satisfies an
   `AggregateState`-style bound as-is.
2. `advance` is total and crypto-free — satisfies the "apply is infallible;
   validation happens in handlers" law.
3. `KeyState::ingest(&Signed) -> Result<_, Rejection>` is a pure function of
   (state, command) — a decide surface; `Rejection` is the command-rejection
   error.
4. `KeriEvent::into_static()` (exists, keri-events) yields the owned `'static`
   event a host's `DomainEvent` newtype wraps (orphan rule solved host-side).
5. Cross-identifier evidence (K4 delegation, K5 receipts beyond inline `wigs`)
   will be **typed function arguments** on the validating fold — fat-command
   shaped — never lookup traits.

## 6. Testing (categories first)

1. **Round-trip:** `KeyStateSnapshot::from(&state).view() == state` for states
   produced by the validating fold (field-wise equality via a `PartialEq`
   between `KeyState` and view, or field assertions).
2. **The differential invariant — the heart of K6:** for any accepted event
   sequence,
   `trusted_fold(events) == KeyStateSnapshot::from(&validating_fold(signed_events))`.
   Property test over generated KELs (inceptions, rotations with cut/add,
   interactions), boundaries included: 0/1/many witnesses, empty next-keys
   (non-transferable), max-length key sets.
3. **Defensive boundary:** `advance` on adversarial sequences (duplicate icp,
   out-of-order sn, overlapping cut/add) must return deterministically and never
   panic — proptest + the existing fuzz harness pattern.
4. **Cross-feature:** no_std + wasm32 stay green (`nix flake check` gates).

## 7. Out of scope

- Snapshot serialization / KSN wire format — keri-codec, later card.
- Escrow classification of `Rejection` (retriable vs terminal) — K2.
- Delegation evidence types and `dip`/`drt` validation — K4.
- Receipt evidence beyond inline `wigs` — K5.
- The nexus-side host aggregate (`Handle`/`AggregateState` impls, `DomainEvent`
  newtype, fjall wiring) — nexus repo card (agency#137).
- Rewriting issue #92's body to this scope — done at PR time.

## 8. Naming

`KeyStateSnapshot` — "key state" is the KERI domain concept; "snapshot" is the
KERI-spec sense (a Key State Notice conveys a snapshot of key state), not the
storage-pattern sense. `genesis`/`advance` — domain verbs, distinct from the
validating `incept`/`ingest` so call sites read as trusted vs validating at a
glance. Considered and rejected: `KeyStateRecord` (keripy lexicon),
`OwnedKeyState` (mechanism, not domain), `apply` (collides with host
vocabulary).
