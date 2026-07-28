# #243 event-model consolidation — rot/drt + icp/dip builder twins — design

**Date:** 2026-07-28
**Issue:** #243 (follow-up to #193 / PR #241; deferred thread from
`2026-07-26-keri-events-role-newtypes-design.md`).
**Branch:** `refactor/243-event-model-consolidation` off `main`.
**Blast radius:** `keri-codec` only. `keri-events`, `cesr`, `cesr-stream`, `keri-rs`
see zero change.

## Status of the issue's three bullets (re-mapped 2026-07-28)

The issue was filed against the pre-#242 tree. Two of its three bullets are already
resolved; only the builder layer still duplicates.

1. **Doubled `.ilk()` map — DONE (by #242).** Tag strings live once in
   `keri-events/src/message_type.rs` (`as_code`/`from_code`); each event type carries
   a `MESSAGE_TYPE` const; `KeriEvent::message_type()` and `EventRef::message_type()`
   both read those consts. Nothing left to do.
2. **Parse layer — already consolidated.** `ParsedRot` backs both
   `ParsedEvent::Rotation` and `ParsedEvent::DelegatedRotation`
   (`keri-codec/src/codec/event.rs`); only the `"rot"`/`"drt"` tag dispatch differs.
   Nothing left to do.
3. **Builder layer — the real remaining twin.**
   - `builder/drt.rs` (736 lines) ≈ `builder/rot.rs` (724 lines). Production delta:
     one import, the `SnBelowMinimum` label string, and the final
     `DelegatedRotationEvent::new(rotation)` wrap. The five type-state structs, the
     four chain impls, every setter, and every default are byte-for-byte duplicates.
   - `builder/dip.rs` vs `builder/icp.rs`: delta is one inserted `NeedsDelegator`
     type-state plus the final wrap.
   - `drt.rs`'s test module wholesale-copies rot's witness-validation tests
     (duplicate-witness, cut-not-prior, toad bounds, …) — violates the
     each-invariant-tested-once rule.

## Decision — keep the domain distinction, parameterize the builders (Option A)

**Domain layer is untouched.** `DelegatedRotationEvent(RotationEvent)` and
`DelegatedInceptionEvent { inception, delegator }` stay. The newtype is ~87 lines and
load-bearing: `keri/src/state.rs` rejects delegated events by matching
`KeriEvent::DelegatedInception(_) | DelegatedRotation(_)` — delegation validation
(delegator-seal anchoring) differs from plain rotation in the KERI spec, and the
variant match makes future delegation support a compile-forced exhaustiveness change
rather than a runtime flag nobody checks. Collapsing rot/drt (Option B) would trade
that away — the same compile-time-safety instinct that motivated #241's newtypes.

The duplication is mechanical and lives one layer down, so the fix lives there: one
type-state chain per event family, parameterized by a sealed delegation marker.

### Rotation family — `builder/rot.rs` absorbs `drt.rs` (file deleted)

```rust
pub struct Direct;
pub struct Delegated;   // drt stores no delegator (resolved from the KEL) — ZST

pub trait RotationKind: sealed::Sealed {
    // pub because it bounds a public struct; sealed supertrait keeps it closed,
    // same pattern as the existing `EventBuilderState`.
    /// `SnBelowMinimum` label: "rotation" / "delegated rotation".
    const LABEL: &'static str;
    fn seal(rotation: RotationEvent<'static>) -> Result<SerializedEvent, CodecError>;
}
// Direct::seal    = rotation.serialize()
// Delegated::seal = DelegatedRotationEvent::new(rotation).serialize()

pub struct RotationBuilder<State = NeedsPrefix, Kind = Direct>
where
    State: EventBuilderState,
    Kind: RotationKind,
{
    state: State,
    kind: PhantomData<Kind>,
}

pub type DelegatedRotationBuilder<State = NeedsPrefix> = RotationBuilder<State, Delegated>;
```

One chain (`NeedsPrefix → NeedsPriorSaid → NeedsKeys → NeedsPriorWitnesses → Ready`),
every impl generic over `Kind: RotationKind`. **One** `build()`, generic: shared
validation (`sn == 0` check via `Kind::LABEL`, `KeyConfiguration::validate`,
`WitnessRotation::validate`) + shared `RotationEvent::new`, tail is
`Kind::seal(rotation)`. Monomorphizes into exactly today's two functions — zero-cost —
and the compiler proves both wire tags share every validation rule, which the
copy-paste twin never guaranteed.

### Inception family — `builder/icp.rs` absorbs `dip.rs` (file deleted)

Inception's delegated marker is data-bearing (`dip` has a `di` field on the wire; the
chains genuinely diverge today because dip inserts a `NeedsDelegator` state). The
mid-chain state dies: the delegator becomes a constructor argument, still
compile-time-required — enforced by signature instead of type-state.

```rust
pub struct Delegated {
    delegator: Identifier<'static>,
}

pub trait InceptionKind: sealed::Sealed {   // sealed, same as RotationKind
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError>;
}
// Direct::seal    = inception.serialize()             (self is a ZST, ignored)
// Delegated::seal = DelegatedInceptionEvent::new(inception, self.delegator).serialize()

pub struct InceptionBuilder<State = NeedsKeys, Kind = Direct> {
    state: State,
    kind: Kind,          // carries the delegator for Delegated; ZST for Direct
}

pub type DelegatedInceptionBuilder<State = NeedsKeys> = InceptionBuilder<State, Delegated>;

impl DelegatedInceptionBuilder {
    pub fn new(delegator: impl Into<Identifier<'static>>) -> Self { /* … */ }
}
```

Chain `NeedsKeys → Ready` shared generic over Kind; setter block and `build()` written
once; tail is `self.kind.seal(inception)`.

**API break (called out):** `DelegatedInceptionBuilder::new(delegator)` replaces the
`.keys(..).delegator(..)` chain step. Breaking MINOR bump on `keri-codec` per the 0.x
convention; CHANGELOG entry required.

The two `Delegated` marker types live in their own family's module (`rot.rs`,
`icp.rs`) and are never named by callers — the public vocabulary stays
`DelegatedRotationBuilder` / `DelegatedInceptionBuilder` (domain naming law).

## Testing

- **Wire law (frozen):** keripy differential corpus + byte-identity round-trips must
  stay green untouched. The refactor moves code, not bytes: `build()` output for all
  four tags is byte-identical by construction (same validation, same event
  construction, same serializers).
- **Test dedup:** Kind-independent validation invariants (duplicate witnesses,
  cut-not-prior-witness, add-already-witness, toad bounds, empty keys, sn=0,
  threshold defaults/bounds) are tested **once**, canonical in the Direct chain's
  test module. The copied tests in drt.rs die.
- **drt keeps only** what exercises the Delegated path: `t == "drt"` /
  `message_type() == Drt`, round-trip via `DelegatedRotationEvent::deserialize`,
  `said_code` read through `.rotation()`, self-addressing prefix.
- **dip keeps only:** `di` field rendering, tag, round-trip, delegator accessor.
- Gate: `nix flake check` (nextest all feature combinations, wasm, no_std,
  fn-ratchet — no new free `pub fn`s; `seal` is a trait method).

## Non-goals

- No domain reshaping: `KeriEvent`, `EventRef`, `ParsedEvent` stay three pipeline
  stages (issue's explicit NOT-duplication list — merging any two forces a clone,
  parse-time allocation, or loses `into_static`).
- No `keri-events` change of any kind.
- No keri-rs fold changes (`Rejection::DelegationUnsupported` stays).
- No new capability: builders produce the same four wire tags with the same defaults.

## Expected outcome

`drt.rs` and `dip.rs` deleted; ~900 net lines removed; one type-state chain per event
family; validation-rule drift between a tag and its delegated twin becomes a compile
error instead of a review hazard.
