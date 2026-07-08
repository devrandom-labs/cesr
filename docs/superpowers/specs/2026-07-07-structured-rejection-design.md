# Design — structured `Rejection`: source-carrying error enum for the fold

**Date:** 2026-07-07
**Type:** keri breaking API change (allowed pre-1.0; CHANGELOG note). cesr untouched.

## Problem

Every validation helper in the fold returns `Rejection` — the union verdict type — and hand-constructs it via `Rejection::new(RejectionReason::X)`. Two smells:

1. **Lossy.** ~8 distinct rule violations (malformed threshold, TOAD-exceeds-count, transferability/next-key, witness-set cut/add errors, sn overflow, wrong ilk, `sn != 0`, EstOnly-interaction) all collapse to one `RejectionReason::InvalidEvent`. The escrow router the taxonomy exists for cannot tell them apart. `check_well_formed` returns a precise `ThresholdError` that keri immediately discards with `.map_err(|_| InvalidEvent)`.
2. **`Rejection` is a struct with optional fields** (`expected_sn`, `actual_sn`) that only apply to `OutOfOrder` — data modelled as "sometimes present" that belongs in one variant.

The single-domain helpers also violate the convention *"a single-domain fallible operation returns its bare error type, never wrap a lone error in a union."* The `From<IndexedVerifyError> for Rejection` added earlier is the seam to generalize.

Predicates stay bool (confirmed): `Tholder::satisfy`, `Diger::verify`, `Identifier::is_transferable`, `KeyState::is_establishment_only`. cesr primitives answer questions; the keri fold assigns the domain meaning. `false` there is a valid answer whose *meaning is caller-dependent* (e.g. `satisfy() == false` maps to `MissingSignatures` at one callsite, `NextKeyCommitmentMismatch` at another) — cesr must stay neutral.

## Design

`Rejection` becomes a `thiserror` enum whose variants carry their source. `RejectionReason` is removed (merged in). Three new keri sub-error enums model the keri-owned domains.

```rust
#[derive(Debug, thiserror::Error)]          // NOT PartialEq: carried cesr errors aren't
#[non_exhaustive]
pub enum Rejection {
    #[error("out of order: expected sn {expected}, got {actual}")]
    OutOfOrder { expected: u128, actual: u128 },

    #[error("prior-event digest does not match current state")]
    PriorDigestMismatch,

    #[error("signing threshold not satisfied")]
    MissingSignatures,                                 // satisfy() == false (controller)

    #[error(transparent)]
    UnverifiedSignature(#[from] IndexedVerifyError),   // cesr source

    #[error(transparent)]
    MalformedThreshold(#[from] ThresholdError),        // cesr source

    #[error("revealed keys do not match prior next-key commitment")]
    NextKeyCommitmentMismatch,                         // verify()/satisfy() == false (next)

    #[error(transparent)]
    WitnessSet(#[from] WitnessSetError),               // keri domain

    #[error("witness threshold {toad} exceeds {count} witnesses")]
    WitnessThresholdExceeded { toad: u32, count: usize },

    #[error(transparent)]
    Transferability(#[from] TransferabilityError),     // keri domain

    #[error("delegated events are not yet supported (K4)")]
    DelegationUnsupported,

    #[error(transparent)]
    Structural(#[from] StructuralError),               // keri domain (residue)
}
```

Sub-enums (each `#[derive(Debug, thiserror::Error, PartialEq, Eq)]` — no `String`/foreign fields, so `PartialEq` is free and lets tests match them precisely):

```rust
pub enum WitnessSetError {         // resolve_witnesses cut/add algebra
    RemovalNotCurrent,             // cut a prefix not currently a witness
    CutAddOverlap,                 // a prefix appears in both cut and add
    AdditionAlreadyPresent,        // add a prefix already resolved
}

pub enum TransferabilityError {    // decide_transferability rules
    NonTransferableCommitsNextKeys,   // non-transferable prefix commits next keys
    SelfAddressingWithoutNextKeys,    // self-addressing prefix commits none
}

pub enum StructuralError {         // residue that was InvalidEvent
    NotInception,                     // incept() on a non-inception event
    NonZeroGenesisSn { sn: u128 },    // genesis with sn != 0
    DuplicateInception,               // a second inception in ingest()
    InteractionOnEstablishmentOnly,   // ixn under the EstOnly config trait
    SequenceNumberOverflow,           // prior_sn + 1 overflowed u128
    WitnessCountOverflow,             // witness count exceeded u32/u128 (defensive guard)
}
```

`WitnessThresholdExceeded { toad, count }` is a top-level variant used by **both** inception (`check_witness_threshold`, declared witnesses) and rotation (`resolve_witnesses`, resolved witnesses) — one meaning, two callsites.

### `From` impls

`#[from]` generates `From<IndexedVerifyError>`, `From<ThresholdError>`, `From<WitnessSetError>`, `From<TransferabilityError>`, `From<StructuralError>` for `Rejection` automatically. So helpers return bare domain errors and transitions use `?`:

```rust
fn check_established_threshold(keys, tholder) -> Result<(), ThresholdError>   // bare
fn resolve_witnesses(...) -> Result<Vec<Prefixer>, WitnessSetError>          // bare (toad check stays Rejection-level, see below)
fn decide_transferability(icp) -> Result<Transferability, TransferabilityError>
// transitions:
check_established_threshold(icp.keys(), icp.threshold())?;   // ThresholdError -> Rejection
```

`resolve_witnesses`'s TOAD check produces `WitnessThresholdExceeded` (top-level), not a `WitnessSetError`; to keep it a bare-error function, the TOAD check moves to the caller (`rotate`) after `resolve_witnesses` returns the set, or `resolve_witnesses` returns `Result<_, Rejection>`. Decision: **move the TOAD check into `rotate`** so `resolve_witnesses` stays single-domain (cut/add only). Implementation detail settled in TDD.

## Old → new mapping (behaviour preserved, finer reasons)

| Old callsite | Old reason | New |
|---|---|---|
| incept: non-inception | InvalidEvent | `Structural(NotInception)` |
| incept: sn != 0 | InvalidEvent (sn) | `Structural(NonZeroGenesisSn { sn })` |
| ingest: second inception | InvalidEvent | `Structural(DuplicateInception)` |
| ingest: delegated | DelegationUnsupported | `DelegationUnsupported` |
| rotate/interact: prior digest | PriorDigestMismatch | `PriorDigestMismatch` |
| interact: EstOnly | InvalidEvent | `Structural(InteractionOnEstablishmentOnly)` |
| verify_controller_sigs: threshold | MissingSignatures | `MissingSignatures` |
| verify_controller_sigs: sig fail / index | InvalidSignature / InvalidEvent | `UnverifiedSignature(_)` |
| check_established_threshold | InvalidEvent | `MalformedThreshold(_)` |
| check_commitment (all) | NextKeyCommitmentMismatch | `NextKeyCommitmentMismatch` |
| resolve_witnesses cut/add | InvalidEvent | `WitnessSet(_)` |
| check_witness_threshold / rotate TOAD | InvalidEvent | `WitnessThresholdExceeded { toad, count }` |
| decide_transferability | InvalidEvent | `Transferability(_)` |
| check_next_sn: overflow | InvalidEvent | `Structural(SequenceNumberOverflow)` |
| check_next_sn: gap | OutOfOrder (sn) | `OutOfOrder { expected, actual }` |

`InvalidSignature` merges into `UnverifiedSignature(IndexedVerifyError)` (out-of-range index + crypto failure both live in the cesr error already).

## Error handling

- No `PartialEq` on `Rejection` (its `#[from]` cesr sources aren't `PartialEq`, and adding it to cesr crypto errors is a tail-wags-dog change). The three keri sub-enums *are* `PartialEq`/`Eq`.
- `Display` via `thiserror`; `#[error(transparent)]` forwards to the source for the wrapping variants.
- `Rejection::new`/`Rejection::sn` constructors removed.

## Testing (TDD)

- **Migrate every rejection assertion** from `assert_eq!(r.reason, RejectionReason::X)` to `assert!(matches!(r, Rejection::X { .. }))` (CLAUDE.md-preferred). `transitions.rs` (~10 sites) and `properties.rs` (`.map_err(|r| r.reason)` → match on the variant).
- Each previously-`InvalidEvent` test now asserts its **specific** new variant — a strict improvement (a test for the TOAD rule now fails if it's miscategorized as, say, transferability).
- `error.rs` unit tests: the `From` mappings (`ThresholdError`, `IndexedVerifyError`, and the three keri sub-enums) each produce the right `Rejection` variant.
- All 30 `state.rs` transition tests + property tests stay green (behaviour-preserving: same accept/reject decisions, finer reasons).

## Not in scope

- Predicates stay bool (`satisfy`, `verify`, `is_transferable`, `is_establishment_only`).
- cesr is untouched.
- The rotate/interact sn+prior-digest "chains onto state" dedup remains a separate future polish.
