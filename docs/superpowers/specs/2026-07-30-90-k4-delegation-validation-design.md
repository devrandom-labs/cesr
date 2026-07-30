# K4 · Delegation validation over typed evidence (#90, completes #83)

Approved 2026-07-30. Extends both folds (`keri-rs`) to accept `dip`/`drt` with
every cross-KEL fact supplied by the caller as a typed argument. Sans-io: the
delegator's KEL is the host's stream; the core judges, never walks.

## Conformance anchors

- KERI spec (trustoverip/kswg-keri-specification, main), §Cooperative
  Delegation: *"A Validator MUST be given or find the delegating seal in the
  delegator's KEL before the event may be accepted as valid."* Evidence-as-
  argument is the spec's "be given" arm.
- Spec §Configuration Traits: *"A Validator MUST invalidate, i.e., drop any
  delegated events whose Delegator has this configuration trait"* (`DND`).
  A validator MUST, therefore inside the fold — which forces delegator-side
  facts into the evidence type.
- Spec §Delegated Rotation body: `drt` has **no** `di` field — *"It uses the
  Delegator AID provided by the associated Delegated Inception event's
  Delegator AID."* The drt delegator comes from state.
- Seal shape: Key Event seal `[i, s, d]` (delegate prefix, hex sn, delegate
  SAID); the delegating event may be a rotation **or** an interaction.
- keripy (main `9161a705`) `Kever.validateDelegation` eventing.py:3009-3501:
  acceptance never recurses — the recursive climb exists only in the
  drt-over-drt superseding cascade, which K3 (#89) already models as the
  host-supplied `DelegationContest` slice. K4 evidence is a **single**
  delegating event; no chain, no depth bound.
- keripy's `locallyOwned`/`locallyMembered`/`locallyWitnessed`
  accept-without-seal exception (eventing.py:3281-3284) is implementation
  role-policy, not spec. It stays representable as an explicit host assertion
  (`HostAccepted`), decided by the host, never by the fold.

## Types — new module `crates/keri/src/delegation.rs`

```rust
/// Everything the fold needs from the delegator's side. That
/// `delegating_event` is ACCEPTED in the delegator's KEL is host-asserted —
/// the same trust contract as `Signed::signed_bytes`.
pub struct AnchoredDelegation<'e> {
    /// Delegator's current key state (host folds the delegator's stream).
    pub delegator: &'e KeyState<'e>,
    /// Accepted event in the delegator's KEL carrying the anchoring seal.
    pub delegating_event: &'e KeriEvent<'e>,
}

/// Delegation evidence, supplied fat-command style with the delegated event.
pub enum DelegationEvidence<'e> {
    /// Spec path: seal anchored in the delegator's KEL.
    Anchored(AnchoredDelegation<'e>),
    /// Host policy accepts without an anchor (keripy controller/witness
    /// roles). Signatures, thresholds, and witnessing are still enforced;
    /// only the seal/delegator checks are skipped. The host decides WHEN —
    /// the fold never does.
    HostAccepted,
}
```

### Anchored checks (all pure, digest-only)

1. `delegator.prefix()` == expected delegator — dip: the event's `di`
   (`dip.delegator()`); drt: `state.delegator()` established at inception.
2. `delegating_event.prefix() == delegator.prefix()` — the anchor belongs to
   the delegator's KEL.
3. A `Seal::Event { i, s, d }` matching the delegate event's
   `(prefix, sn, said)` appears in `delegating_event.anchors()` — reuse
   `seal_position` (moves from `duplicity.rs` to `delegation.rs` as
   `pub(crate)`; duplicity imports it back).
4. `delegator.config()` does not contain `ConfigTrait::DoNotDelegate`
   (spec MUST → Terminal).

## Fold entries

```rust
impl<'e> KeyState<'e> {
    // unchanged; dip/drt now reject Awaiting(DelegationEvidence)
    pub fn incept(signed: &Signed<'e>) -> Result<Self, Rejection>;
    pub fn ingest(self, signed: &Signed<'e>) -> Result<Self, Rejection>;

    /// dip only: full inception rules (zero sn, self-certifying authority,
    /// transferability, witness threshold, witnessing) + Anchored checks;
    /// seeds `delegator` from the event's `di`.
    pub fn incept_delegated(
        signed: &Signed<'e>,
        evidence: &DelegationEvidence<'e>,
    ) -> Result<Self, Rejection>;

    /// drt only: full rotation rules (chains-onto, revealed authority,
    /// prior-next commitment exposure, witnessing) + Anchored checks
    /// against `state.delegator()`.
    pub fn ingest_delegated(
        self,
        signed: &Signed<'e>,
        evidence: &DelegationEvidence<'e>,
    ) -> Result<Self, Rejection>;
}
```

Dedicated entries make invalid states unrepresentable: no evidence-less dip
fold, no evidence on a plain icp. Plain-entry dip/drt is the K2 park signal;
the host's saga enriches the command and re-drives through the delegated
entry (mnesis fat-command dispatch).

## Rejection reshape (breaking)

`Rejection::DelegationUnsupported` retired. New failure domain:

```rust
/// Delegation-rule violations (K4).
pub enum DelegationError {
    /// dip/drt reached a plain fold entry without evidence.
    EvidenceRequired,             // Awaiting(DelegationEvidence)
    /// No matching Event seal in the supplied delegating event
    /// (keripy: nullify + escrow — better evidence cures).
    SealNotFound,                 // Awaiting(DelegationEvidence)
    /// Supplied delegator state does not match the event's delegator
    /// (dip `di` / drt state) or the delegating event's prefix.
    DelegatorMismatch,            // Awaiting(DelegationEvidence)
    /// Delegator carries the DND config trait (spec MUST drop).
    Denied,                       // Terminal
}
// Rejection::Delegation(#[from] DelegationError)
```

Plus `StructuralError::NotDelegatedInception` / `NotDelegatedRotation`
(Terminal) when a delegated entry receives the wrong event type — the
`NotInception` precedent. `EvidenceKind::DelegationEvidence` is unchanged;
`disposition()` stays total with no wildcard.

## Delegator widening (breaking)

`KeyState.delegator: Option<&'e Identifier<'e>>` and
`KeyStateSnapshot.delegator: Option<Identifier<'static>>`. The spec's `di`
example is self-addressing (`E…`); `BasicPrefix` cannot hold it (flagged in
K6 #92, fixed here).

## Trusted fold

`KeyStateSnapshot::advance` dip branch gains
`delegator = Some(dip.delegator().clone().into_static())`; drt carries the
delegator over (already does via `..self`). No signature change — the
trusted fold folds ACCEPTED events; validation happened at decide time.

## Out of scope

Evidence acquisition (host queries, OOBI, mailboxes); escrow storage; the
delegation approval ceremony; `DelegateIsDelegator` (`DID`) trait semantics
(noted in rustdoc, no fold behavior); the superseding cascade (K3, landed).

## Tests

- **Differential invariant**: trusted fold ≡ snapshot of validating fold
  over delegated KELs (extends the K1/K6 invariant suite).
- **Negative suite**: tampered seal digest, wrong delegator (both mismatch
  arms), DND delegator, missing evidence via plain entries, HostAccepted
  still rejects bad signatures, wrong-type events at delegated entries,
  revoked-then-used delegation — judge + re-fold path (the W8 demo).
- **K9 differential vectors** vs a keripy-generated delegation corpus
  (acceptance path is intact at the pin; the broken keripy paths are
  cascade-only, already carved out in #89).
- **Proptest** boundary coverage on seal position/sn; `nix flake check`
  green including no_std + wasm32.

## #83 closure

Rustdoc boundary statement on `DelegatedInceptionEvent`/
`DelegatedRotationEvent` and the `keri` crate docs: structural verification
lives in the fold's evidence checks; KEL-walking, evidence acquisition, and
duplicity handling live above. `lib.rs` delegation paragraph rewritten.
