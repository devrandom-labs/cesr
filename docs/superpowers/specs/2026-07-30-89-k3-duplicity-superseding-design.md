# K3 · Duplicity + superseding-recovery — design (#89)

Date: 2026-07-30
Issue: #89 (K3) — milestone "KERI · sans-io core"
keripy oracle: main `9161a705`

## Problem

An event arrives carrying a sequence number the host's KEL already occupies.
KERI's rules decide whether it is an idempotent duplicate, evidence of a
duplicitous controller, or a legitimate superseding recovery that forks the
KEL at that point. keripy decides this inside `Kevery.processEvent` /
`Kever.rotate` / `Kever.validateDelegation` with database lookups
(`db.kels.getLast`, `fetchDelegatingEvent` recursion). The sans-io core must
make the same judgment as a pure function of `KeyState` plus host-supplied
evidence — the host owns the stream and already knows what is recorded; the
core judges.

## Decisions (settled at brainstorm)

1. **Seam**: new `Disposition::Contested` routes hosts to a separate judge
   method. The K1 fold (`ingest`) is untouched; judgment is a distinct entry
   point called only when the fold has rejected an event as stale.
2. **Evidence shape**: the drt-over-drt cascade takes a slice of pairs
   (`&[DelegationContest]`), one delegating-event pair per level, tail to
   root. The judge computes seal positions itself — the host supplies events,
   never judgment-adjacent data.
3. **Verdict shape**: five variants. Each keripy exit keeps its identity:
   duplicate (idempotent log), superseding recovery (accept), likely
   duplicitous (escrow/report), cascade loss (bare drop), undecided
   (missing-delegation escrow).
4. **Naming**: module `crates/keri/src/duplicity.rs` — the KERI spec domain
   term. Entry `KeyState::judge_same_sn`, verdict `SameSnVerdict`.

## Layer placement

Judgment is a function of `KeyState` (`sn`, `last_est`, prefix) and parsed
events. `KeyState` lives only in `keri-rs`; cesr/cesr-stream/keri-codec are
substrate, framing, and wire codec respectively and carry no key-state
semantics. New module sits beside `state.rs`. The only lower-layer ingredient
is seal comparison — plain `==` on existing `keri-events` types.

## Types — `crates/keri/src/duplicity.rs`

```rust
/// Judgment on an event contesting an already-occupied sn.
pub enum SameSnVerdict<'a> {
    /// Same SAID as recorded — idempotent; host may log late-arriving sigs.
    Duplicate,
    /// A recovery rule fired. The host rewinds its stream to sn-1, re-folds,
    /// and re-ingests the incoming event through the K1 validating fold —
    /// signature/commitment/witness validation and the prior-digest check
    /// against the recorded sn-1 event all happen there, never here.
    Supersedes,
    /// Different SAID and no recovery rule applies — duplicity evidence.
    /// Carries the recorded SAID for watcher reporting.
    Duplicitous { recorded: &'a Said<'a> },
    /// Cascade loss (B2: same delegating event, seal position not later) —
    /// an inferior recovery claim. Drop quietly; not duplicity evidence.
    Yields,
    /// Delegation-chain evidence exhausted before a decision. Park and
    /// re-judge when deeper chain evidence arrives.
    Undecided,
}

/// One level of the delegation-chain climb.
pub struct DelegationContest<'a> {
    /// Delegating event on the recorded (incumbent) side.
    pub incumbent: &'a KeriEvent<'a>,
    /// Delegating event on the incoming (challenger) side.
    pub challenger: &'a KeriEvent<'a>,
}

/// Host-supplied evidence is inconsistent with the state or itself.
/// Boundary validation — a typed error, never a verdict.
#[derive(thiserror::Error)]
pub enum EvidenceError {
    IncomingNotStale { incoming_sn: u128, state_sn: u128 },
    RecordedSnMismatch { incoming_sn: u128, recorded_sn: u128 },
    /// A delegating event at `level` carries no event-seal matching the
    /// (i, s, d) of the delegated event below it. keripy crashes on this
    /// (`nseals.index` raises); we type it.
    SealNotFound { level: usize },
}

impl KeyState<'_> {
    pub fn judge_same_sn<'a>(
        &self,
        incoming: &KeriEvent<'_>,
        recorded: &'a KeriEvent<'a>,
        delegation_chain: &[DelegationContest<'_>],
    ) -> Result<SameSnVerdict<'a>, EvidenceError>;
}
```

Rule functions are private to the module (each separately unit-tested
in-module); the method entry adds no free `pub fn` — fn-ratchet unaffected.

## Gate — A rules

Oracle: `Kevery.processEvent` eventing.py 4396–4413 (gate), 4362–4392 (icp
branch), 4447–4478 (duplicate-vs-duplicitous); `Kever.rotate` 2620–2646
(stale/recovery enforcement).

Boundary checks first: `incoming.sn > state.sn` → `IncomingNotStale`;
`recorded.sn != incoming.sn` → `RecordedSnMismatch`.

With `sn = incoming.sn`, `le = last_est.sn`:

| incoming | rule | verdict |
|---|---|---|
| icp / dip | inception never supersedes | SAID == recorded → `Duplicate`, else `Duplicitous` |
| ixn | supersedes nothing (A2) | SAID-compare |
| rot | `le < sn` → `Supersedes` (A1 = the bound itself) | else SAID-compare |
| drt | `le <= sn` and recorded is ixn → `Supersedes`; recorded is drt → cascade | else SAID-compare |

- **A0 derived, not checked**: `sn > le` forces every recorded event in
  `(le, state.sn]` to be an interaction, so "rot may only override ixn state"
  holds by construction. keripy's `self.ilk != Ilks.ixn` check
  (eventing.py 2638) is redundant defense; we document rather than re-check.
- **drt vs recorded icp/dip/rot**: no keripy-sane path reaches this (a
  delegated identifier's establishment events are dip/drt only). Falls to
  SAID-compare → `Duplicitous`. Divergence note, covered by a unit test.

## Cascade — B/C rules

Oracle: `Kever.validateDelegation` eventing.py 3413–3492.

Walk `delegation_chain` pairwise, tracking the delegated pair
`(old, new)` starting at `(recorded, incoming)`. Per level:

1. Seal positions: filter each delegating event's seals to event-seals;
   position of the seal matching the delegated event's `(i, s, d)` within
   that filtered sequence (keripy filters to `SealEvent._fields` then
   `.index`). Absent → `SealNotFound { level }`.
2. **B1**: `challenger.sn > incumbent.sn` → `Supersedes`.
3. **B3**: challenger is drt and incumbent is ixn → `Supersedes`.
4. **B2**: same SAID (same delegating event) → challenger's seal position >
   incumbent's ? `Supersedes` : `Yields`.
5. **C**: otherwise climb — `(old, new) = (incumbent, challenger)`, next pair.

Slice exhausted → `Undecided`.

- keripy climbs even when `challenger.sn < incumbent.sn` (no explicit check
  at 3444–3447) — we mirror; parity beats intuition here.
- **C1 divergence**: the issue text says "root reached undecided → discard";
  keripy source escrows (`MissingDelegationError` via `escrowPDEvent`) when
  the chain cannot be extended. We follow source: `Undecided` is an
  awaiting-evidence disposition, not a drop.
- No recursion and no depth parameter: the bound is `chain.len()`, set by the
  host. The issue's "depth bound with typed error" acceptance item is
  satisfied structurally — an adversarial recursion bomb is unrepresentable.
- Worst case O(chain.len() × seals-per-event).

## `error.rs` changes (breaking — CHANGELOG)

- New `Disposition::Contested`: "the sn is already occupied — fetch the
  recorded event (plus delegation-chain evidence for drt) and consult
  `judge_same_sn`". Exhaustive enum: hosts get a compile error, not a
  silently dropped recovery.
- Stale `OutOfOrder` (`actual <= expected`): `Terminal` → `Contested`.
- `Structural(DuplicateInception)`: `Terminal` → `Contested` — keripy routes
  a second inception to the duplicate/duplicitous branch; the icp gate row
  is unreachable unless hosts are routed there.
- Existing K2 disposition tests for these two paths updated deliberately.

## Testing

- **Per-rule unit tests** (in-module, private fns): gate table — each row ×
  same/diff SAID × sn boundaries `le-1, le, le+1, state.sn`; cascade B1, B2
  (both outcomes), B3, climb-then-decide at level ≥ 1, exhausted slice,
  `SealNotFound`, empty chain; boundary-check errors.
- **proptest**: totality — arbitrary (state, incoming, recorded, chain)
  yields a verdict or typed error, never a panic; antisymmetry —
  `judge(a, b) == Supersedes ⟹ judge(b, a) != Supersedes` over generated
  contest pairs (mirrored chains). Ranges include sn `0, 1, MAX-1, MAX`,
  chain length `0, 1, deep`.
- **K9 differential vectors** (#95): keripy-generated superseding +
  duplicitous scenarios → identical winners. Test names contain "keripy"
  (nightly filter requirement). Fixtures forged from corpus events need
  SAID re-seal via the keri-codec dev-dep.
- **Round-trip with the fold**: after a `Supersedes` verdict, rewind + re-fold
  + re-ingest through `KeyState::ingest` accepts the recovery event and the
  resulting state matches keripy's post-recovery key state.
- Gate: `nix flake check` (covers no_std + wasm + all feature combinations).

## Out of scope

First-seen policy, duplicity reporting/propagation (watcher runtime), storage
of competing events, escrow tables/timers (K2 routes dispositions), delegated
event folding in `ingest` (K4 — the fold still rejects dip/drt; the judge is
pure over evidence and lands first).
