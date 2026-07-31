# keripy Parity — Semantic differential (K9, #95)

**Semantic parity of the fold as a process**: given the same keripy-generated
event sequence in the same *delivery order*, cesr and keripy reach the same
**per-event verdict** — `accepted` / `escrowed(kind)` / `rejected` /
`contested` — and the same resulting key state. Byte-level parity
(matter/counter/indexer/stream/events) and the per-facet verdict suites
(K1/K3/K4/K5) do not cover this: K2's escrow taxonomy had no keripy
differential until this corpus.

- Generator: `scripts/keripy_semantics_gen.py`
- Corpus: `crates/keri-codec/tests/corpus/semantics/{happy,escrow}.jsonl`
  (10 scenarios: 3 happy, 4 escrow, 3 reject — reject/contested live in
  `escrow.jsonl`, the `family` field distinguishes)
- Consumer: `crates/keri-codec/tests/keripy_semantics.rs`
  (`keripy_semantics_happy_verdicts_and_state`,
  `keripy_semantics_escrow_verdicts`, plus a corpus-consumption count guard;
  the nightly CI filter `cargo test --all-features keripy` matches the test
  names)
- Pin: keripy `v2.0.0.dev5-1030-gde59bc7d` (`scripts/KERIPY_PIN` = de59bc7d),
  KERI/CESR V1 JSON

Regenerate (keripy checkout at the pin, `scripts/KERIPY_PIN` de59bc7d):

```bash
python3 scripts/keripy_semantics_gen.py \
  --keripy <keripy-checkout-at-pin de59bc7d> \
  --out-dir crates/keri-codec/tests/corpus/semantics
```

keripy import needs its deps (hio, lmdb, libsodium) importable — e.g. the
keripy repo's own venv.

The corpus is checked in (not regenerated nightly — same precedent as the
duplicity/delegation/keystate corpora).

## Oracle mechanism

keripy side: one bare validator-role `keri.core.eventing.Kevery` (fresh LMDB,
no local habs — `locallyOwned`/`locallyMembered`/`locallyWitnessed` all False,
so every escrow path runs) per scenario; each delivery is one
`Kevery.processEvent` call and the verdict is the raised exception class (or
acceptance):

| keripy outcome | verdict | escrow |
|---|---|---|
| no exception, kever accepted the event | `accepted` | — |
| `OutOfOrderError` | `escrowed` / `prior_events` | `.ooes` |
| `MissingSignatureError` | `escrowed` / `signatures` | `.pses` |
| `MissingWitnessSignatureError` | `escrowed` / `witness_receipts` | `.pwes` |
| `MissingDelegationError` | `escrowed` / `delegation` | `.pdes`/`.udes` |
| bare `ValidationError` | `rejected` (drop) | — |
| `LikelyDuplicitousError` | `contested` (duplicity branch) | `.ldes` |

Re-drives run through the matching escrow processor — verified at the pin:
`processEscrowOutOfOrders` (eventing.py:5891), `processEscrowPartialSigs`
(:6019), `processEscrowPartialWigs` (:6174), `processEscrowPartialDels` (:6325).
The processors are silently idempotent (a still-unprocessable escrow is
re-parked without signal), so the re-drive verdict is derived from whether
the kever advanced (`kvy.kevers[pre].sner`).

cesr side: `keri::KeyState::incept` / `ingest` returning `Rejection`,
classified by `Rejection::disposition()`: `Awaiting(EvidenceKind)` ↔
`escrowed` (the `EvidenceKind` name must match the vector's `evidence`),
`Terminal` ↔ `rejected`, `Contested` ↔ `contested`. The consumer trials a
`clone()` of the state per step because `ingest(self)` consumes the state
even on `Err`; the escrow scenarios depend on the pre-evidence state
surviving a failed delivery.

The `reject_stale_sn` scenario's generator stubs `escrowLDEvent`
(pin defect #1 in `ledger.md`: it calls `db.addLde`, a method the pin's
`Baser` no longer has, crashing *before* the classifying
`LikelyDuplicitousError` raise — the stub removes the broken escrow write;
the classification raise, the oracle signal, is unaffected).

## Vector schema

One JSONL line per scenario (every line is valid JSON — no comment headers):

```json
{
  "scenario": "escrow_out_of_order_gap",
  "family": "escrow",
  "events": [{"raw": "<b64 serder.raw>", "sigs_qb64": ["<qb64 siger>"], "wigs_qb64": []}],
  "delivery": [0, 2, 1, 2],
  "expected": [
    {"event": 0, "verdict": "accepted"},
    {"event": 2, "verdict": "escrowed", "keripy_error": "OutOfOrderError", "evidence": "prior_events"},
    {"event": 1, "verdict": "accepted"},
    {"event": 2, "verdict": "accepted", "redrive": true}
  ],
  "final_state": {"prefix_qb64": "...", "sn": 2, "keys_qb64": ["..."],
                   "threshold_sith": "...", "next_keys_qb64": ["..."],
                   "next_threshold_sith": "...", "witness_threshold": 0,
                   "witnesses_qb64": [], "said_qb64": "..."},
  "keripy_version": "v2.0.0.dev5-1030-gde59bc7d",
  "note": "<one-line intent>"
}
```

- `sigs_qb64`/`wigs_qb64` are qb64 indexed sigers (index/ondex encoded) —
  the convention every existing corpus uses; the consumer parses them with
  `common::siger_from_qb64`. `wigs_qb64` folds via `Signed.wigs`.
- `delivery` indexes `events`; `expected` is parallel to `delivery`. A
  re-drive is either the same index delivered again (the evidence was a
  different event) or a new `events` entry with the same `raw` and a fuller
  signature set (the cure is more sigs on the same event).
- `final_state` is keripy's `Kever` state after all deliveries AND escrow
  re-processing — the same fields `keripy_keystate_gen.py` emits, plus
  `said_qb64` (`kever.serder.said`). Null when the subject KEL (the last
  delivery's prefix) never accepts an inception.
- A vector that records a documented divergence carries
  `"divergent": "<ledger-id>"` plus `cesr_expected` (parallel to `delivery`);
  the consumer then asserts the documented cesr behavior while `expected`
  stays the keripy record. No checked-in vector is divergent today.

## Verdict-mapping table

Every `Rejection` variant → disposition → keripy exception/escrow. This is
the executable-ledger index of the doc comments in
`crates/keri/src/error.rs`; anchors below are **at the pin** (de59bc7d) —
note that `error.rs` and `ledger.md` cite some line numbers against oracle
main `9161a705`, so their anchors drift a few lines from the pin's (one such
stale anchor: the nontransferable-state drop is eventing.py:2357-2359 at the
pin, not `:2477`).

| `Rejection` variant | Disposition | keripy anchor (pin) |
|---|---|---|
| `OutOfOrder { actual > expected }` | `Awaiting(PriorEvents)` | `.ooes`, `OutOfOrderError` (eventing.py:4232, :4279) |
| `OutOfOrder { actual <= expected }` | `Contested` | stale sn → duplicity branch, `LikelyDuplicitousError` (eventing.py:4351) |
| `PriorDigestMismatch` | `Terminal` | bare `ValidationError` at the in-order sn (eventing.py:2443-2447) |
| `MissingSignatures { verified: 0 }` | `Terminal` | bare `ValidationError` "No verified signatures" (eventing.py:2703-2705) — spec MUST drop, DDoS guard |
| `MissingSignatures { verified >= 1 }` | `Awaiting(Signatures)` | `.pses`, `MissingSignatureError` (eventing.py:2750) |
| `MalformedThreshold` | `Terminal` | bare `ValidationError` (invalid sith) |
| `PriorNextThresholdUnsatisfied` | `Awaiting(Signatures)` | `.pses`, `MissingSignatureError` on prior nsith (eventing.py:2766) |
| `WitnessSet` (cut/add algebra) | `Terminal` | bare `ValidationError` (backer derivation) |
| `WitnessThresholdExceeded` | `Terminal` | bare `ValidationError` (out-of-bounds toad, eventing.py:2786-2795) |
| `InsufficientWitnessReceipts` | `Awaiting(WitnessReceipts)` | `.pwes`, `MissingWitnessSignatureError` (eventing.py:2799) |
| `Transferability` | `Terminal` | bare `ValidationError` (inception self-contradictory) |
| `NonTransferableState` | `Terminal` | bare `ValidationError` "nontransferable or abandoned state" (eventing.py:2357-2359) |
| `Delegation(EvidenceRequired)` | `Awaiting(DelegationEvidence)` | `.pdes`/`.udes`, `MissingDelegationError` (eventing.py:3182) |
| `Delegation(SealNotFound)` | `Awaiting(DelegationEvidence)` | keripy nullifies the couple and escrows (`MissingDelegationError`) |
| `Delegation(DelegatorMismatch)` | `Awaiting(DelegationEvidence)` | `MissingDelegationError` |
| `Delegation(DelegatorUnknown)` | `Terminal` | bare `ValidationError` |
| `Delegation(Denied)` | `Terminal` | bare `ValidationError` (doNotDelegate) |
| `Structural(DuplicateInception)` | `Contested` | second inception → duplicate/duplicitous branch, `LikelyDuplicitousError` (eventing.py:4266) |
| `Structural(_)` (other variants) | `Terminal` | bare `ValidationError` (e.g. est-only ixn, eventing.py:2431-2433); config-trait violations are spec MUST-drop |

`EvidenceKind::ReceiptorEstablishment` is not a fold verdict — it classifies
receipt-path failures (`ReceiptedEvent::endorsed_by`, K5), keripy's
unverified transferable-receipt escrow (`UnverifiedTransferableReceiptError`)
— and therefore appears in no scenario here.

## Scenario coverage

| scenario | family | exercises |
|---|---|---|
| `happy_single_sig_ladder` | happy | icp → ixn → rot → ixn → rot, all accepted; final state sn 4 |
| `happy_multisig_weighted` | happy | weighted `["1/2","1/2","1/2"]` threshold satisfaction in-fold |
| `happy_partial_rotation` | happy | 5-key commitment, rotation reveals a non-contiguous subset — sigs carry `ondex != index` (CESR big-both code) |
| `escrow_out_of_order_gap` | escrow | `.ooes`: sn-2 before sn-1; re-drive via `processEscrowOutOfOrders` accepted |
| `escrow_partial_signatures` | escrow | `.pses`: 1-of-3 sigs on a sith-2 icp; redelivery with all sigs accepted |
| `escrow_partial_witness` | escrow | `.pwes`: toad-2 icp, no receipts; cesr reaches the verdict via plain `incept` (`wigs: []` → `InsufficientWitnessReceipts`) — receipt re-drive is K5's suite |
| `escrow_missing_delegation` | escrow | `.pdes`: dip without anchor seal; cesr verdict via plain `incept` (`DelegationError::EvidenceRequired`) — cure path is K4's suite |
| `reject_unverifiable_sigs` | reject | forged-only sig → keripy bare `ValidationError`; cesr `MissingSignatures{verified: 0}` → `Terminal` |
| `reject_stale_sn` | reject | distinct event at occupied sn → keripy duplicitous branch; cesr `OutOfOrder{actual <= expected}` → `Contested` (the K3 same-sn judge owns the outcome; this corpus asserts routing) |
| `reject_nontransferable_state` | reject | event on a non-transferable state → keripy bare `ValidationError`; cesr `NonTransferableState` → `Terminal` |

## Coverage honesty

| family | where |
|---|---|
| verdict stream + final state (this card) | `keripy_semantics.rs` + `corpus/semantics/` |
| final state (K1 happy paths) | `differential.rs` + `keystate.jsonl` / `kels.jsonl` |
| duplicity same-sn judge (K3) | `keripy_duplicity.rs` + `duplicity.jsonl` — pin defects in `ledger.md`: `escrowLDEvent` crash, B2/B3/C cascade dead at runtime, superseding-drt exposure checks the incumbent's commitment |
| delegation (K4) | `keripy_delegation.rs` + `delegation.jsonl` |
| receipts (K5) | `keripy_receipts.rs` + `parity/receipts.jsonl` |
| custody derivation (K7) | `keripy_salt.rs`, `keripy_custody.rs` |
| byte-level wire parity | `corpus/keripy/parity/` (events, formulas, codex, said-codes, seals, validation) |

## Semantic divergence ledger

Deliberate, documented divergences surfaced by (or relevant to) the
fold-verdict stream. Anything the corpus surfaces that is not listed here is
a bug; the generator asserts intended verdicts at generation time and a
checked-in corpus never contains `error:*` verdicts.

### SEM-D1 — Tholder.satisfy duplicate-index dedup (fail-closed)

keripy counts duplicate index entries toward numeric thresholds:
`Tholder(sith=2).satisfy([0, 0]) == True` at the pin. cesr's `Tholder::satisfy`
deduplicates the index list before counting — a threshold counts **distinct**
verified signers. Deliberate fail-closed security choice (full entry in
`ledger.md`; raw-API corpus row in `formulas.jsonl`). **Not reachable through
the fold-verdict stream**: both implementations deduplicate at the
verification layer before threshold satisfaction (keripy `verifySigs` returns
unique verified sigers; cesr `Authority::verify` counts distinct valid
indices), so no delivery order can surface this divergence through
`incept`/`ingest` — it lives at the raw `Tholder` API level only.

### No divergences surfaced by this corpus

All 10 checked-in scenarios agree with the documented mapping above: the
generator's per-scenario verdict asserts held at generation time (zero
`error:*` outcomes), and no scenario required a `divergent` marker or a
`cesr_expected` override. Two scenario-shape notes, neither a divergence:

- `escrow_partial_witness`: the fold surfaces `InsufficientWitnessReceipts`
  from plain `incept` with no host-supplied receipt evidence (empty `wigs`),
  matching keripy's bare-validator `MissingWitnessSignatureError` — no
  special casing and no ledger carve-out was needed.
- `reject_stale_sn`: the keripy-side classification requires stubbing the
  pin's broken `escrowLDEvent` (pin defect #1, `ledger.md`); that is an
  oracle-defect workaround, not a cesr↔keripy divergence.
