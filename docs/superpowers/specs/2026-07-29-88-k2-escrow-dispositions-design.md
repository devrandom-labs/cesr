# K2 · Escrow dispositions — design (#88)

Date: 2026-07-29
Issue: https://github.com/devrandom-labs/cesr/issues/88
Status: approved (verified against keripy + KERI spec, classifications evidence-backed)

## Goal

Escrow as a pure classification on the fold's verdict. The K1 fold returns
`Result<KeyState, Rejection>`; K2 adds the one thing a host cannot derive: for each
`Rejection`, is it **terminal** (never acceptable) or **awaiting evidence** (acceptable
the moment something specific arrives)? No tables, no timers, no storage — the host
(mnesis saga) owns parking and re-driving.

## Classification rule

> **Awaiting** iff more host-supplied evidence (attachments, prior events, receipts,
> delegator approval) can change the verdict on re-drive.
> **Terminal** iff the verdict is a function of the event's own content plus accepted
> state alone — re-driving the same event can never succeed.

## Evidence base

Verified 2026-07-29 against:

- keripy `src/keri/core/eventing.py` (local checkout, v2 dev line) — line anchors below.
- KERI spec (ToIP `tswg-keri-specification`, `spec/spec-body.md`) — the spec's only
  *normative* escrow text is the signature-threshold rule; all other escrows
  (`.ooes`, `.pwes`, `.pdes`) are keripy implementation strategy, spec-silent.

Key spec quotes:

- Sig threshold (spec-body.md:1266): "Events that have a non-empty set of attached
  signatures which set does not satisfy the REQUIRED thresholds SHOULD escrow the
  event… A Validator that receives a key event … that does not have attached at least
  one verifiable Controller signature MUST drop that message (i.e., not escrow or
  otherwise accept it)."
- Config traits (spec-body.md:367, 377): violations "MUST invalidate, i.e., drop".

## Surface

New types in `crates/keri/src/error.rs` (verdict domain). Both **exhaustive**
(no `#[non_exhaustive]`): a new `EvidenceKind` at K4/K5 must be a compile error in
hosts — a wildcard arm would silently park events awaiting evidence the host never
re-drives. Pre-1.0 breaking-minor per policy.

```rust
/// What a host should do with a rejected event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Never acceptable — drop or report. (Duplicity routing detail is K3.)
    Terminal,
    /// Acceptable once this evidence arrives — park and re-drive.
    Awaiting(EvidenceKind),
}

/// The specific evidence whose arrival makes a parked event acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// The missing prior event(s). keripy `.ooes`.
    PriorEvents { expected_sn: u128 },
    /// More controller signatures. keripy `.pses`.
    Signatures,
    /// More witness receipts. keripy `.pwes`.
    WitnessReceipts { valid: usize, required: u32 },
    /// The delegator's authorizing evidence. keripy `.pdes`/`.udes`.
    DelegationEvidence,
}

impl Rejection {
    pub const fn disposition(&self) -> Disposition { /* exhaustive match, no wildcard */ }
}
```

No `ReceiptorEstablishment` variant — K5 adds it (YAGNI; exhaustive enum makes the
addition a deliberate breaking change, as intended).

## Breaking change to `Rejection` (called out for PR/CHANGELOG)

`MissingSignatures` becomes `MissingSignatures { verified: usize }`.

Why: the spec's DDoS rule splits on verified-signature count — zero verifiable sigs
MUST drop, one-or-more below threshold SHOULD escrow. `Authority::verify`
(authority.rs) already holds the verified `indices`; it populates `verified` with
`indices.len()`. Under our abort-on-bad-sig semantics (see divergences), all provided
sigs verified when this variant fires, so `verified == 0` ⇔ empty attached sig set.

`OutOfOrder { expected, actual }` keeps its shape — both numbers already carried;
`disposition()` branches on them.

## Per-variant classification

| `Rejection` variant | Disposition | Evidence |
|---|---|---|
| `OutOfOrder{expected, actual}`, `actual > expected` (gap) | `Awaiting(PriorEvents{expected_sn: expected})` | keripy `sn > sno` → `escrowOOEvent`/`.ooes` + `OutOfOrderError` (eventing.py:4399-4406; also 4356-4359 for no-prior-state non-inception) |
| `OutOfOrder{expected, actual}`, `actual < expected` (stale) | `Terminal` | keripy `sn <= sno` is the stale/duplicity path: idempotent duplicate-log or `.ldes` (eventing.py:4447-4478), or superseding recovery (4408-4412) — K3 domain, never `.ooes`. Awaiting would park forever: the "missing prior" already exists. |
| `MissingSignatures{verified: 0}` | `Terminal` | Spec MUST-drop rule (spec-body.md:1266); keripy zero-verified = bare `ValidationError` drop (eventing.py:2821-2823) |
| `MissingSignatures{verified: ≥1}` | `Awaiting(Signatures)` | Spec SHOULD-escrow (spec-body.md:1266); keripy `escrowPSEvent`/`.pses` + `MissingSignatureError` (eventing.py:2861-2869) |
| `InsufficientWitnessReceipts{valid, required}` | `Awaiting(WitnessReceipts{valid, required})` | keripy `escrowPWEvent`/`.pwes` + `MissingWitnessSignatureError` (eventing.py:2907-2918); spec-silent |
| `DelegationUnsupported` | `Awaiting(DelegationEvidence)` | keripy `escrowPDEvent`/`.pdes` + `MissingDelegationError` for missing delegator KEL / missing anchoring seal (eventing.py:3296-3301, 3322-3329, 3381-3391). K4 builds the re-drive path; until then hosts park delegated events. |
| `PriorDigestMismatch` | `Terminal` | Fires at in-order sn (`check_chains_onto`, state.rs). keripy exact analog: bare `ValidationError` drop (eventing.py:2561-2565 ixn, 2666-2669 rot). `.ldes` is same-sn-after-acceptance duplicity — different situation, K3. |
| `UnverifiedSignature(_)` | `Terminal` | Under our abort-on-bad-sig semantics, re-drive of the same event always fails. See divergence D1. |
| `MalformedThreshold(_)` | `Terminal` | keripy invalid sith = `ValidationError` drop (eventing.py:2679-2681) |
| `NextKeyCommitmentMismatch` | `Terminal` | Content-determined: the event's own key list contradicts the prior commitment. See divergence D2. |
| `WitnessSet(_)` | `Terminal` | Cut/add algebra violation is event-content-determined; keripy `deriveBacks` raises bare `ValidationError` = drop (eventing.py:2722-2746) |
| `WitnessThresholdExceeded{..}` | `Terminal` | keripy out-of-bounds toad = `ValidationError` drop (eventing.py:2892-2905) |
| `Transferability(_)` | `Terminal` | Inception-content-determined. `NonTransferableCommitsNextKeys`: keripy bare `ValidationError` drop (eventing.py:2374-2377). `SelfAddressingWithoutNextKeys`: no keripy analog — keripy accepts empty next list as an abandoned identifier; ours is deliberately stricter (K1 decision, see divergence D3). |
| `Structural(_)` | `Terminal` | Spec: config-trait violations MUST drop (spec-body.md:367, 377); shape/arity/range violations content-determined |

Host policy explicitly *not* modeled: misfit (local-vs-remote source, keripy
`.misfits`, eventing.py:2843-2852) and delegable-approval (`.delegables`,
eventing.py:2930-2942) — the pure core never knows where bytes came from.

## Recorded divergences (not K2's to fix)

- **D1 — signature filtering.** keripy `verifySigs` *filters* invalid signatures and
  proceeds with the valid subset (accept if threshold met, `.pses` escrow if partial,
  drop if zero). Our `Authority::verify` aborts on the first bad signature
  (`UnverifiedSignature`). An event with threshold-satisfying valid sigs plus one
  forged sig: keripy accepts, we reject. Belongs with the K1 audit line (#133) /
  exposeds semantics (#132); K9 differential must account for it.
- **D2 — next-key commitment.** keripy has no positional digest check; uncommitted
  keys simply contribute no ondices, so its analog outcome is `.pses` escrow
  (eventing.py:2872-2885). Our positional full-rotation check makes the mismatch
  content-determined, hence Terminal. #132 (ondex-based exposeds) revisits;
  K9 differential must account for it.

- **D3 — self-addressing without next keys.** keripy accepts a transferable
  inception with an empty next-digest list (an abandoned identifier whose rotations
  are later rejected, eventing.py:2672-2675). Our K1 fold rejects it at inception
  (`SelfAddressingWithoutNextKeys`). Disposition unaffected (Terminal under both
  readings); K9 differential must account for it.

All divergences get doc mentions on the relevant variant rustdoc so K9 finds them.

## Documentation duty (acceptance criterion)

Every `Rejection` variant's rustdoc gains: its disposition, its keripy
escrow-outcome equivalent (table name + error class), and the re-drive trigger.
The stale prose on `InsufficientWitnessReceipts` ("terminal rejection") is rewritten
— it is formally `Awaiting` now.

## Tests

- One unit test per variant (and per branch of the two data-driven variants)
  asserting the exact `Disposition` with `assert_eq!` — `Eq` derives make this direct.
- Boundary probes on the branchy variants: `OutOfOrder` with `actual = expected + 1`,
  `actual = expected - 1`; `MissingSignatures` with `verified = 0`, `verified = 1`.
- Exhaustive-match guarantee is compile-time: `disposition()` itself is the
  no-wildcard match (acceptance criterion), no test needed.
- K9 differential vectors (keripy escrow-vs-drop reproduction) are K9's deliverable
  (#95); K2 lands the rustdoc mapping they consume.

## Out of scope

Escrow storage, timeouts, retry scheduling, cue emission (host runtime). Duplicity
and superseding recovery (K3). Delegation validation (K4). Receipt evidence kinds
(K5). Fixing D1/D2 (#132/#133).

## Acceptance (from #88, updated)

- [ ] `Rejection::disposition()` total, compile-time exhaustive match, no wildcard arm
- [ ] `MissingSignatures` carries `verified: usize` (breaking; PR + CHANGELOG note)
- [ ] Every variant rustdoc names keripy escrow-outcome equivalent + re-drive trigger
- [ ] Unit test per variant/branch asserting exact disposition
- [ ] no_std + wasm32 green (`nix flake check`)
