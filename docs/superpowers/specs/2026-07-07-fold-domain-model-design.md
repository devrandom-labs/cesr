# Design — modeling the fold's domain: Authority, Commitment, Establishment

**Date:** 2026-07-07
**Type:** keri additive types + transition refactor. Additive public surface (new `Authority`, `Commitment`, `Establishment`); behavior-preserving. cesr untouched.

## Problem

`incept`/`rotate`/`interact` read as flat procedural checklists that mask the domain:

1. **The authority model is hidden in an argument.** `verify_controller_sigs`'s first argument is `icp.keys()` / `rot.keys()` (the event's own keys — establishment is self-certifying) vs `self.keys` (the current keys — interaction). This "who may sign" decision is *the* central KERI rule, expressed as which variable is passed.
2. **`incept` and `rotate` are the same event kind (establishment), copied.** Both validate an establishment threshold, verify against the event's own keys, resolve/check witnesses, and install (keys, threshold, next_keys, next_threshold, witnesses). cesr's `Ilk::is_establishment` already recognizes the kind; the fold doesn't use it.
3. **Heterogeneous steps in one uniform.** event-intrinsic checks, succession checks, authentication, and value-producing derivations all read as `foo(...)?;`.

The consequence is a recipe, not a model. `Tholder::satisfy` even carries two meanings depending on callsite (`MissingSignatures` vs `NextKeyCommitmentMismatch`).

## Design decisions (confirmed with user)

- **Full model, keri-owned.** `Authority`, `Commitment` as borrowed views; `Establishment` as a keri trait impl'd for cesr's `InceptionEvent`/`RotationEvent`. cesr stays the primitives layer.
- **Names:** `Authority` (current keys + threshold), `Commitment` (pre-rotation next-key commitment).
- **Phases are structure, not a framework type** — transitions read as authenticate / authorize / apply via the typed operations, not via a `Phase`/`Applicator` abstraction.

## Types (keri, borrowed — zero-copy)

```rust
/// Who may sign: the controlling keys and their signing threshold. The unit an
/// event is authenticated against.
pub struct Authority<'e> {
    keys: &'e [Verfer<'static>],
    threshold: &'e Tholder,
}

impl<'e> Authority<'e> {
    pub(crate) const fn new(keys: &'e [Verfer<'static>], threshold: &'e Tholder) -> Self;
    #[must_use] pub fn keys(&self) -> &[Verfer<'static>];
    #[must_use] pub fn threshold(&self) -> &Tholder;

    /// The threshold is well-formed for the key count (also rejects an empty set).
    fn well_formed(&self) -> Result<(), ThresholdError>;

    /// `sigs` authenticate against this authority: each verifies against the key it
    /// indexes and the verified set satisfies the threshold.
    fn verify(&self, bytes: &[u8], sigs: &[Siger<'_>]) -> Result<(), Rejection>;
}

/// The pre-rotation commitment to the *next* authority.
pub struct Commitment<'e> {
    next_digests: &'e [Diger<'static>],
    next_threshold: &'e Tholder,
}

impl<'e> Commitment<'e> {
    pub(crate) const fn new(next_digests: &'e [Diger<'static>], next_threshold: &'e Tholder) -> Self;

    /// `revealed` opens this commitment: its keys hash to the committed digests
    /// positionally (full-rotation form) and its key count satisfies the next
    /// threshold.
    fn opened_by(&self, revealed: &Authority<'_>) -> Result<(), Rejection>;
}

/// An event that establishes control: the authority it declares and the commitment
/// it makes to the next one.
pub trait Establishment {
    fn authority(&self) -> Authority<'_>;
    fn commitment(&self) -> Commitment<'_>;
}
impl Establishment for InceptionEvent { /* keys()+threshold(), next_keys()+next_threshold() */ }
impl Establishment for RotationEvent  { /* same */ }
```

`Authority::verify` is the current `verify_controller_sigs` body (`verify_indexed(...).collect()? ` then `threshold.satisfy(...)` → `MissingSignatures`). `Commitment::opened_by` is the current `check_commitment` body (positional `Diger::verify` + `next_threshold.satisfy(0..n)` → `NextKeyCommitmentMismatch`). Splitting these onto two types is what gives each `satisfy` one meaning.

### KeyState views

```rust
impl<'e> KeyState<'e> {
    #[must_use] pub fn authority(&self) -> Authority<'e>;     // current keys + threshold
    #[must_use] pub fn commitment(&self) -> Commitment<'e>;   // current next-key commitment
}
```

## Transitions (authenticate / authorize / apply)

```rust
pub fn incept(signed) -> Result<Self, Rejection> {
    let KeriEvent::Inception(icp) = signed.event else { return Err(StructuralError::NotInception.into()) };
    if icp.sn().value() != 0 { return Err(StructuralError::NonZeroGenesisSn { sn }.into()) }
    // authenticate (genesis is self-certifying against its own authority)
    icp.authority().well_formed()?;
    icp.authority().verify(signed.signed_bytes, &signed.sigs)?;
    // authorize (seed rules: transferability/next-key, witnesses)
    let transferability = decide_transferability(icp)?;
    check_witness_threshold(icp.witnesses().len(), icp.witness_threshold())?;
    // apply
    Ok(Self::seed(icp, transferability))
}

fn rotate(self, rot) -> Result<Self, Rejection> {
    // authorize succession
    self.check_chains_onto(rot.sn().value(), rot.prior_event_said())?;
    self.commitment().opened_by(&rot.authority())?;
    // authenticate (self-certifying)
    rot.authority().well_formed()?;
    rot.authority().verify(signed.signed_bytes, &signed.sigs)?;
    // apply
    let witnesses = resolve_witnesses(&self, rot)?;
    check_witness_threshold(witnesses.len(), rot.witness_threshold())?;
    self.rotated(rot, witnesses)
}

fn interact(self, ixn) -> Result<Self, Rejection> {
    self.reject_establishment_only()?;
    self.check_chains_onto(ixn.sn().value(), ixn.prior_event_said())?;   // authorize
    self.authority().verify(signed.signed_bytes, &signed.sigs)?;         // authenticate (current)
    self.advanced(ixn)                                                   // apply
}
```

`Self::seed`, `self.rotated`, `self.advanced` are the named apply steps (the current struct-builds, extracted). incept's `seed` establishes the invariant fields (`prefix`, `transferability`, `config`, `delegator`); `rotated` carries them via `..self`. They are **not** shared code — incept has no prior self — but each is one named operation.

## Scope boundaries (deliberate)

- **apply is not unified** across incept/rotate (incept seeds the invariants rotate carries). authenticate + authorize are the shared phases.
- **Witnesses stay as free helpers** (`resolve_witnesses`, `check_witness_threshold`) in apply. A `WitnessSet` type is a possible follow-up, not in scope.
- **`Establishment` is minimal** (`authority` + `commitment`). Witnesses/config differ between icp/rot and stay per-event.
- **Delegated events** are rejected before establishment logic (K4), so `Establishment` is impl'd only for icp/rot.
- **Grouping into phases reorders some checks — deliberately, with one honest caveat.** The accept/reject *boundary* is identical: every event accepted before is accepted now, every rejected event is still rejected. But grouping (authorize → authenticate → apply) moves a few checks across phase lines (e.g. `well_formed` now follows `commitment` in `rotate`). For an event that violates **two or more** rules at once, this can change *which* `Rejection` variant is returned first. `well_formed` stays before `verify` within *authenticate*, so single-domain cases (e.g. empty key set → `MalformedThreshold`) are unaffected. Every rejection test is single-violation by design, so none observe the change; it is called out here and in the commit as an intentional precedence change, not a silent one.

## Error handling

- `Authority::verify`, `Commitment::opened_by` return `Rejection` (keri types; reuse existing `MissingSignatures` / `NextKeyCommitmentMismatch` / `UnverifiedSignature`). No new error type.
- `Authority::well_formed` returns bare `ThresholdError` (single-domain, `?`-lifts to `MalformedThreshold`).

## Testing (TDD)

- **New unit tests** (keri): `Authority::verify` (accepts a threshold-signed set; rejects under-signed → `MissingSignatures`; rejects a forged sig → `UnverifiedSignature`; out-of-range index → `UnverifiedSignature`), `Authority::well_formed` (→ `ThresholdError`), `Commitment::opened_by` (opens with the revealed authority; wrong key/arity → `NextKeyCommitmentMismatch`), and `Establishment::authority`/`commitment` for both event types.
- **Behavior preservation:** all 30 `transitions.rs` + 8 `error.rs` + property tests stay green unchanged — same accept/reject decisions and the same `Rejection` variants (single-violation, so unaffected by the phase reordering above). This is the guard that the domain remodel is faithful.
